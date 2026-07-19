# Lantern M3 修改与验收报告

日期：2026-07-18  
模块：`lantern-history`  
状态：M3 已完成；M4 尚未开始，等待用户确认

## 1. 本轮目标与结论

M3 已实现独立于 M2 的真实 append-only Merkle Mountain Range（MMR），而
不是用 JMT 的历史版本替代 append-only audit history。实现提供稳定的零基
叶索引、标准 postorder MMR 节点位置、每个精确 prefix 的 root、单记录
inclusion proof、old-root-to-new-root append-consistency proof，以及完全不依赖
RocksDB 的 verifier。

M3 只通过 M1 的 `ReadStore` 和 `StoreBatch` 接触持久化状态。它不打开
RocksDB、不删除/覆盖历史节点，也不独立 commit。M4 将负责把 M2、M3、
records/archive/index 和 block metadata 合并为一个 M1 原子 batch。

| 验收项 | 结果 | 证据 |
| --- | --- | --- |
| 真正 append-only MMR | 通过 | 按叶顺序执行 peak carry/merge，只写新 postorder 节点 |
| 稳定叶索引 | 通过 | index 进入 leaf hash；append/reopen/checkpoint restore 后保持不变 |
| Inclusion proof | 通过 | 当前/历史 prefix、多位置、独立 verifier 与变异测试 |
| Append-consistency proof | 通过 | 旧 peaks + canonical appended-subtree cover，独立重放 MMR merge |
| `O(log N)` proof | 通过 | proof 只包含 path/peaks 或 canonical range subtrees |
| Storage-independent verifier | 通过 | `--no-default-features` 依赖图不含 M1/RocksDB/M2/JMT |
| 确定性 | 通过 | 4 个副本产生相同 root、节点位置和 storage delta |
| M1 原子边界 | 通过 | 仅向调用方 `StoreBatch` 追加，未提交 batch 时状态不可见 |
| 差分/属性/变异测试 | 通过 | 独立 forest 参考实现、48 个属性用例、root/record/proof 变异 |
| 重启与恢复 | 通过 | RocksDB reopen、M1 checkpoint restore、继续 append 和旧 proof 验证 |
| 依赖安全审计 | 通过 | 122 个 locked packages，0 vulnerabilities，0 warnings |

## 2. 范围控制

本轮只实现需求文档中的 M3：

- `lantern-history`；
- append-only MMR；
- 稳定、单调、持久化的叶索引；
- 精确历史 prefix root；
- 单记录 inclusion proof；
- old-root-to-new-root append-consistency proof；
- 两类 proof 的 storage-independent verifier；
- M1 storage trait 适配和共享原子 batch 边界。

本轮没有实现：

- M4 `HistoryRecordV1` schema、状态转移、epoch close、dual roots 和
  `AppStateCommitment`；
- M5 CometBFT/QC、signer bitmap、validator key/reconfiguration/recovery；
- M6 gateway、proof service、client verifier SDK；
- M7 Krill、M8 Routinator 集成；
- M9 Compose 单机 testbed；
- M10 性能和端到端故障实验。

M3 不依赖 `lantern-latest-map`，也不把 M2 的 JMT historical root 当作
append-only consistency 证明。

## 3. Lantern MMR v1

### 3.1 Leaf commitment

叶索引从 `0` 开始。对 canonical compact record bytes：

```text
HistoryLeafHash(i, record) =
    H(M0-domain-frame("lantern/v1/history-leaf",
      0x00 || u64be(i) || u64be(len(record)) || record))
```

索引进入 leaf commitment，因此同一 record 出现在不同位置时仍是不同的
authenticated leaf。M3 把 record 当作 opaque canonical bytes；M4 必须提供
deterministic-CBOR `HistoryRecordV1`。空 record 被拒绝，单 record 上限为
1 MiB。

### 3.2 Parent commitment

相邻的两个 `h-1` 高度 perfect subtree 合并为：

```text
HistoryParentHash(h, left, right) =
    H(M0-domain-frame("lantern/v1/history-node",
      0x00 || u8(h) || left || right))
```

left/right 顺序和 parent height 都进入 hash。叶与内部节点使用 M0 已冻结的
两个不同 domain。

### 3.3 Root/peak commitment

MMR root 不是不带结构的裸 peak 拼接：

```text
HistoryRoot(n, peaks) =
    H(M0-domain-frame("lantern/v1/history-node",
      0x01 || u64be(n) || u16be(peak_count) ||
      each(u8(peak_height) || peak_hash)))
```

peak 采用从左到右、height 降序的唯一顺序，即 `n` 的 set bits。root 显式
绑定 leaf count、peak count、每个 height 和 hash。空 history 使用相同公式
且 `n=0`、peak count 为 0，因而也有唯一 authenticated root。

### 3.4 Postorder position 与 append-only 行为

节点使用标准零基 MMR postorder position。`n` 个叶后的节点数为：

```text
2*n - popcount(n)
```

M3 v1 最大支持 `2^63` 个叶，使 node count 和位置可由 `u64` 表示。每次
append 先写新 leaf，然后按二进制 carry 规则合并同高度的末尾 peaks。所有
leaf/internal node 和精确 prefix root 使用新 key；若 would-be future key 已
存在，prepare 失败并拒绝覆盖。逻辑历史节点永不 delete/prune。

## 4. Proof 设计

### 4.1 Inclusion proof

`HistoryInclusionProofV1` 包含：

- `leaf_index`；
- `leaf_count`；
- 从 leaf 到其所属 peak 的 sibling hashes；
- 该 prefix 的全部 peak hashes。

verifier 从 index/count 唯一派生 path direction、path length、target peak、
peak count 和 peak heights。它计算 exact record leaf、重建 target peak，确认
该 peak 位于正确 ordinal，再重新计算 root。root、index、size、record、任一
sibling 或 peak 发生变化都会失败。

### 4.2 Append-consistency proof

`HistoryConsistencyProofV1` 包含：

- 构成 `old_size` root 的全部 old peaks；
- `[old_size,new_size)` 的 canonical maximal aligned perfect-subtree cover
  对应的 subtree roots。

verifier 首先重建并检查 old root，再把每个 appended subtree 按普通 MMR
carry/merge 规则追加到 old peak stack，最后重建并检查 new root。subtree 的
start/height 和 vector 长度均由 sizes 唯一派生，proof 不能自选结构。

canonical cover 至多包含 `O(log N)` 个 subtree，因此即使 delta 很大，proof
也不会按新增 record 数线性增长。`old_size == new_size` 仅作为 equal-root
identity proof 接受。

### 4.3 Proof envelope

两类 proof 共享严格 envelope header：

| 字段 | 编码 |
| --- | --- |
| magic | `LNHINCL\0` 或 `LNHCONS\0` |
| format version | `u16be(1)` |
| body length | `u32be` |
| body | 固定整数/count 字段和连续 32-byte hashes |

完整 proof 上限 32 KiB。decoder 拒绝错误 magic、未知版本、截断、长度不符、
trailing bytes、超限输入、错误 vector count、越界 index、反向 size 和任何
非 canonical path/range 长度。详细字段布局见
`crates/lantern-history/M3_INTERFACE.md`。

## 5. 持久化与原子边界

### 5.1 M1 键空间

M3 只使用 M1 `mmr_nodes` column family：

| key | value | 性质 |
| --- | --- | --- |
| `lantern/history/v1/node/` + `u64be(postorder_position)` | 32-byte hash | immutable leaf/internal node |
| `lantern/history/v1/root/` + `u64be(leaf_count)` | 32-byte root | immutable exact-prefix root |
| `lantern/history/v1/current-size` | `u64be` | current pointer |
| `lantern/history/v1/current-root` | 32-byte root | current pointer |

compact record bytes 不复制到 MMR CF；M4 将把 record 写入 M1 的 `records`
column family，M3 只保存其 domain-separated leaf commitment。

### 5.2 写入 API

```text
HistoryLog::prepare_append(records)
    -> PreparedHistoryAppend { start/end size, root, stats, writes }

PreparedHistoryAppend::append_to(&mut StoreBatch)
```

records 保持调用方顺序。非空 append 写入全部新节点、每个新 prefix root，
最后写 current-size/current-root。空 append 是零写入 no-op。M3 不暴露
metadata-free commit，也不持有数据库句柄。

M4 必须每个 block 只调用一次 `prepare_append`，并将结果与 M2、records、
archive、indices 和 typed block metadata 一起放入同一个 M1 `StoreBatch`。
若任何 `append_to` 失败，调用方必须丢弃整个 batch。

### 5.3 读取和 fail-closed 行为

`current_state` 同时验证 current size/root、exact-prefix root、peak nodes 和
重新计算的 root。proof generation 还会验证调用方提供的 record 与 persisted
leaf hash 完全一致，并在返回前使用相同独立 verifier 自检。缺失 node、损坏
长度、部分 metadata 或 root 不一致均返回 typed error。

## 6. 公开 API

Proof-only 层：

- `history_leaf_hash`；
- `empty_history_root`；
- `mmr_node_count`；
- `HistoryInclusionProofV1::{from_bytes,to_bytes,leaf_index,leaf_count}`；
- `HistoryConsistencyProofV1::{from_bytes,to_bytes,old_size,new_size}`；
- `verify_history_inclusion`；
- `verify_history_consistency`；
- `HistoryInclusionQueryV1::verify`；
- `HistoryConsistencyQueryV1::verify`；
- 格式版本、record/append/proof/leaf limits。

`storage` feature：

- `HistoryLog::{new,current_state,root_at,prepare_append,inclusion_query,consistency_query}`；
- `PreparedHistoryAppend::{start_size,end_size,root,stats,append_to}`；
- `HistoryState`；
- `HistoryAppendStats`。

错误使用 typed `lantern_history::Error`，区分 invalid input、invalid proof
encoding、proof verification、missing size、missing node、corrupt storage、
M0 error 和 M1 storage error。

## 7. 测试与质量门禁

### 7.1 执行结果

| 命令/检查 | 结果 |
| --- | --- |
| `cargo test -p lantern-history --no-default-features --lib --locked` | 3/3 通过 |
| `cargo test -p lantern-history --lib --locked` | 13/13 通过 |
| `cargo test --workspace --all-targets --locked` | 51/51 通过（M0 17、M1 11、M2 10、M3 13） |
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 通过 |
| `cargo clippy -p lantern-history --no-default-features --all-targets --locked -- -D warnings` | 通过 |
| proof-only dependency graph | 不含 M1、RocksDB、M2、JMT |
| RustSec audit | 122 个 locked packages，0 vulnerabilities，0 warnings |

工具链固定为 Rust/Cargo `1.97.1`。M3 没有引入新的第三方 runtime
dependency；它复用 M0、可选 M1、`thiserror` 和已有 dev dependency
`proptest 1.11.0`。

### 7.2 覆盖的行为

- proof-only inclusion/consistency verification 与 envelope round-trip；
- malformed magic/version/length/oversize 和 hash mutation；
- wrong root、wrong record、wrong domain、wrong index/size；
- independent naive Merkle-forest 参考实现逐 prefix root 差分；
- 48 个 proptest 用例，每例 1–47 次随机 append；
- current/historical prefix inclusion proof；
- empty→new、old→new 和 identity consistency proof；
- 多 record batch append 与空 append；
- 四副本 root、postorder node/storage delta 确定性；
- empty/oversized record、过多 records、future size、反向 size；
- current metadata corruption 和 supplied-record/leaf mismatch；
- 4,096 叶及大 delta proof 大小测试，两类 proof 均小于 2 KiB；
- 真实 RocksDB commit/close/reopen/continue append；
- 真实 M1 checkpoint create/verify/restore 后稳定 index、旧 proof 和继续 append。

4,096 叶测试只验证渐近结构和防止意外线性 proof，不作为生产 latency 或
throughput benchmark。

## 8. 审计与许可证

RustSec 使用 `cargo-audit 0.22.2` 和 advisory database commit
`b5fc89b8be99e96f79194d8a6f11e9b4143b99f0`（数据库时间
`2026-07-17T17:52:38+02:00`）：

- 122 个 locked packages；
- 0 个已知 vulnerability；
- 0 个 informational warning；
- 未配置 ignore。

完整结果保存在 `M3_RUSTSEC_AUDIT.json`。122 项依赖/工作区 package 的名称、
版本、作者、repository、SPDX license 和描述保存在
`M3_DEPENDENCY_LICENSES.tsv`。

## 9. 文件变更

新增：

- `crates/lantern-history/Cargo.toml`；
- `crates/lantern-history/src/lib.rs`；
- `crates/lantern-history/src/error.rs`；
- `crates/lantern-history/src/structure.rs`；
- `crates/lantern-history/src/proof.rs`；
- `crates/lantern-history/src/storage.rs`；
- `crates/lantern-history/src/tests.rs`；
- `crates/lantern-history/M3_INTERFACE.md`；
- `M3_RUSTSEC_AUDIT.json`；
- `M3_DEPENDENCY_LICENSES.tsv`；
- 本报告 `M3_REPORT.md`。

更新：

- workspace `Cargo.toml`/`Cargo.lock`：登记 M3 workspace crate；
- `README.md`：说明 M0–M3 能力、边界和 proof-only 命令。

M0、M1、M2 的实现没有在 M3 中重写。

## 10. 已知限制

1. M3 认证 opaque canonical record bytes；`HistoryRecordV1` 字段、CBOR schema、
   record archive 与 intent binding 必须在 M4 冻结。
2. M3 当前提供单记录 inclusion proof，不提供 multiproof。本实现没有依赖一个
   自带 multiproof 的 MMR 库；需求中的 multiproof 是“若库支持”，因此不作为
   M3 阻塞项。后续若增加，必须使用新的 proof type/version，不能改变 v1。
3. 为保证任意 prefix proof 和审计恢复，M3 保存全部逻辑节点和每个 prefix
   root，不做 pruning。磁盘增长、cold/cached proof latency 和 snapshot size
   由 M10 测量。
4. consistency proof 证明两个已知 roots 之间的 append-only 关系，但不证明
   root 已获得 BFT finality；root/QC/AppHash binding 属于 M4/M5/M6。
5. M3 不能单独证明 latest effective state；完整双认证判定必须同时使用 M2
   latest membership 和 M3 history inclusion/consistency。
6. 本轮没有 BFT、QC、signer bitmap、key management、reconfiguration、Krill
   或 Routinator，不能把 M3 测试结果外推为端到端系统结果。
7. 本轮没有生产性能声明。单机测试只支持实现正确性；最终 M9/M10 必须固定
   容器镜像和系统包并报告单机共置限制。

## 11. 下一审批点

M3 已结束。下一模块为 M4 `lantern-state`：冻结 `HistoryRecordV1` 和 latest
value schema，实现 deterministic transaction/control transition、epoch close、
M2+M3 原子双写、dual roots 和 `AppStateCommitment`，并执行四副本 deterministic
replay 与 P1–P7 fixtures。

只有在用户确认 M3 后才开始 M4。
