# Lantern M2 修改与验收报告

日期：2026-07-18  
模块：`lantern-latest-map`  
状态：M2 已完成；M3 尚未开始，等待用户确认

## 1. 本轮目标与结论

M2 已实现一个真实的、可持久化的版本化 latest-state authenticated map，
而不是把旧 Merkle 原型包装成新协议结果。实现采用精确锁定的
`jmt 0.12.0`，通过 M1 的 `ReadStore`/`StoreBatch` 接口访问持久化状态，
并提供不依赖 RocksDB 的 membership、non-membership 与 historical-version
证明验证器。

本轮达到的验收结论如下：

| 验收项 | 结果 | 证据 |
| --- | --- | --- |
| JMT latest map | 通过 | `LatestMap::prepare_update`、精确历史 root 与增量节点写入 |
| Membership proof | 通过 | 当前版本与历史版本查询、独立验证及变异测试 |
| Non-membership proof | 通过 | 空树、未出现 CA、删除后状态测试 |
| Historical-version query | 通过 | 多版本 set/delete 后查询旧 root、旧 value 与 proof |
| 独立 verifier | 通过 | `--no-default-features` 构建图不含 M1/RocksDB，3/3 测试通过 |
| 确定性 | 通过 | 4 个独立副本产生逐字节相同的 root 和 storage delta |
| M1 原子边界 | 通过 | M2 只追加到调用方 `StoreBatch`，不自行 open/commit RocksDB |
| 差分/属性/变异测试 | 通过 | 独立 JMT `MockTreeStore` 差分、48 个属性用例、root/key/value/domain/proof 变异 |
| 持久化恢复 | 通过 | 真实 RocksDB commit、关闭、重开及历史证明查询 |
| 依赖安全审计 | 通过 | RustSec：121 个锁定依赖，0 个漏洞、0 个 warning |

## 2. 范围控制

本轮只实现需求文档中的 M2：

- `lantern-latest-map`；
- JMT latest-state map；
- membership/non-membership proof；
- historical-version query；
- storage-independent verifier；
- M1 storage trait 适配和共享原子 batch 边界。

以下内容没有在本轮实现，也没有作为 M2 实验结论：

- M3 append-only MMR、inclusion proof 和 consistency proof；
- M4 latest-state value 的完整协议结构、entry count 与状态转移；
- M5 CometBFT/ABCI/QC、validator bitmap、重配置和恢复；
- M6 gateway、proof service 和 client verifier SDK；
- M7 Krill、M8 Routinator 集成；
- M9 Compose/容器化复现；
- M10 性能与端到端故障实验。

## 3. 设计与实现

### 3.1 模块分层

`lantern-latest-map` 分为两个编译层：

1. 默认始终存在的 proof 层负责 key derivation、leaf framing、proof envelope
   编解码和验证，只依赖 M0 及纯 Rust 密码/编解码依赖；
2. `storage` feature 增加 `LatestMap`、JMT storage adapter 和
   `PreparedLatestUpdate`，此层才依赖 M1。

因此 RP、Krill adapter 或离线审计工具将来可以只链接 proof 层，而无需
链接 RocksDB。验证器输入仅为 `(root, key, value-or-none, proof)`，proof
service 不会成为信任根。

### 3.2 密钥与叶子域分离

对 32 字节 `CA_ID`：

```text
LatestKey = SHA-256(M0-domain-frame("lantern/v1/latest-key", CA_ID))
```

该 32 字节结果直接作为 JMT `KeyHash`，不进行第二次散列。非空 raw latest
value 先编码为：

```text
M0-domain-frame("lantern/v1/latest-leaf", canonical_latest_value)
```

再作为 JMT value。这样 Lantern 的 `latest-key`、`latest-leaf` 域与 JMT
自身的叶子/内部节点域保持分离。M2 拒绝空 value，并设置 1 MiB 的防御性
上限；M4 应在冻结 latest value schema 后施加更小且语义明确的上限。

### 3.3 版本与确定性规则

- genesis 版本为 `0`；
- 每次 update 必须是已提交版本的精确后继，不允许 gap 或覆盖；
- 空 mutation 集仍会物化新版本 root；
- mutation 按派生后的 `LatestKey` 排序后提交给 JMT；
- 同一批次内重复/碰撞 key 直接拒绝，不使用 last-write-wins；
- 历史节点、value/tombstone 和 stale-node index 均保留，M2 不执行 pruning。

四副本测试验证：相同有序状态转移前缀会产生相同 root、相同节点/value
写入和相同 batch 顺序。单个 CA 更新只改变 JMT 路径，JMT 工作复杂度为
`O(log C)`，其中 `C` 是 map 中的 key 数量。

### 3.4 写入与原子提交边界

公开写路径为：

```text
LatestMap::prepare_update(version, mutations)
    -> PreparedLatestUpdate { root, stats, uncommitted writes }

PreparedLatestUpdate::append_to(&mut StoreBatch)
```

M2 实现不打开 RocksDB，也不独立 commit。它只把确定性的 JMT 节点、value
history、stale index、version root 和 latest-version 写入调用方提供的 M1
`StoreBatch`。M4 必须把 M2、M3 及 block metadata 合并到同一个 batch 后，
通过 M1 一次性 commit。若 `append_to` 返回错误，调用方必须丢弃该 batch。

真实 RocksDB 测试只用于验证 M1/M2 组合可以 commit、关闭、重开并读取历史
证明；它不改变上述实现边界。

### 3.5 历史查询

`LatestMap::query_ca(ca_id, version)` 在精确历史 root 上生成 membership 或
non-membership proof。JMT path 查询为 `O(log C)`。每个 key 的 value/tombstone
使用 append-only ordinal index 保存，历史 value 通过二分查找获得，额外需要
`O(log U_CA)` 次 point read；`U_CA` 表示该 CA 的更新次数。

查询生成后会立即调用相同的独立 verifier 自检。若持久化节点、value framing
或 root 不一致，API 返回 typed corruption error，不会把不可验证的查询结果
交给上层。

### 3.6 Proof envelope

`LatestProofV1` 使用 Lantern 自有的严格 envelope：

| 字段 | 编码 |
| --- | --- |
| magic | 8 字节 `LNLTPRF\0` |
| format version | 2 字节 big-endian，当前为 `1` |
| body length | 4 字节 big-endian |
| body | `jmt 0.12.0` `SparseMerkleProof<Sha256>` 的严格 Borsh 编码 |

完整 proof 最大 32 KiB。解码拒绝错误 magic、未知版本、截断、声明长度不符、
trailing bytes、超限输入和无效 Borsh。将来升级 JMT 或改变 proof 表示时必须
增加 Lantern envelope 版本并生成新的兼容向量，不能静默改变 v1 字节语义。

### 3.7 M1 键空间

M2 只使用 M1 的 `latest_tree_nodes` column family：

| key/prefix | value | 用途 |
| --- | --- | --- |
| `lantern/latest/v1/node/` + Borsh `NodeKey` | Borsh `Node` | 版本化 JMT 节点 |
| `lantern/latest/v1/value-count/` + key | `u64be` | 每个 key 的历史条目数 |
| `lantern/latest/v1/value/` + key + ordinal | version/tag/length/value | append-only value/tombstone |
| `lantern/latest/v1/stale/` + Borsh index | 空字节串 | 保留的 stale-node index |
| `lantern/latest/v1/root/` + `u64be(version)` | 32-byte root | 精确历史 root |
| `lantern/latest/v1/latest-version` | `u64be` | 后继版本约束 |

详细且冻结的接口说明见
`crates/lantern-latest-map/M2_INTERFACE.md`。

## 4. 公开 API

Proof 层（无 RocksDB）：

- `latest_key`；
- `latest_leaf_bytes`；
- `verify_latest_proof`；
- `LatestProofV1::{from_bytes,to_bytes}`；
- `LatestQueryV1::verify`；
- proof/value 格式版本和大小上限常量。

`storage` feature：

- `LatestMap::{new,latest_version,root,prepare_update,query_ca,query_key}`；
- `LatestMutationV1::{set,delete}`；
- `PreparedLatestUpdate::{version,root,stats,append_to}`；
- `LatestUpdateStats`。

错误均为 typed `lantern_latest_map::Error`，区分 invalid input、invalid proof
encoding、proof verification、missing version、non-successor version、corrupt
storage、JMT error、M0 error 和 M1 storage error。

## 5. 测试与质量门禁

### 5.1 执行结果

| 命令/检查 | 结果 |
| --- | --- |
| `cargo test -p lantern-latest-map --no-default-features --lib --locked` | 3/3 通过 |
| `cargo test -p lantern-latest-map --lib --locked` | 10/10 通过 |
| `cargo test --workspace --all-targets --locked` | 38/38 通过（M0 17、M1 11、M2 10） |
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 通过 |
| `cargo clippy -p lantern-latest-map --no-default-features --all-targets --locked -- -D warnings` | 通过 |
| proof-only dependency graph 检查 | 不含 `lantern-store`、`rocksdb`、`librocksdb` |
| RustSec audit | 121 个 locked dependencies，0 vulnerabilities，0 warnings |

Rust/Cargo 工具链精确固定为 `1.97.1`。关键新增依赖精确固定为
`jmt 0.12.0`、`borsh 1.8.0`、`sha2 0.10.9`（JMT hasher）和
`proptest 1.11.0`。

### 5.2 覆盖的安全/正确性行为

- proof-only verifier 的 membership 验证；
- proof envelope round-trip；
- 截断、错误 magic、未知版本、长度不符、trailing/oversized/invalid Borsh；
- root、key、value、domain、proof 任一变异后拒绝；
- membership 与 non-membership 不可互换；
- 历史 set/update/delete 后的 membership/non-membership；
- 空 genesis 和空 successor 版本；
- 四副本 root 及 storage delta 确定性；
- M2 只追加共享 M1 batch、不自行持久化；
- version gap/overwrite、重复 key、空 value、超限 value；
- 48 个 proptest 差分用例，每例 1–39 个随机版本，与独立 JMT
  `MockTreeStore` 比较 root、query 与 proof；
- 真实 RocksDB commit/reopen 和历史查询。

完整 RustSec 结果保存在 `M2_RUSTSEC_AUDIT.json`，依赖及许可证清单保存在
`M2_DEPENDENCY_LICENSES.tsv`。

## 6. 文件变更

新增：

- `crates/lantern-latest-map/Cargo.toml`；
- `crates/lantern-latest-map/src/lib.rs`；
- `crates/lantern-latest-map/src/error.rs`；
- `crates/lantern-latest-map/src/proof.rs`；
- `crates/lantern-latest-map/src/storage.rs`；
- `crates/lantern-latest-map/src/tests.rs`；
- `crates/lantern-latest-map/M2_INTERFACE.md`；
- `M2_RUSTSEC_AUDIT.json`；
- `M2_DEPENDENCY_LICENSES.tsv`；
- 本报告 `M2_REPORT.md`。

更新：

- workspace `Cargo.toml` 和 `Cargo.lock`：加入 M2 crate 及精确锁定依赖；
- `README.md`：说明 M0–M2 能力、边界和验证命令。

M0、M1 的协议/存储实现没有在 M2 中被重写。

## 7. 已知限制与后续落点

1. proof v1 body 与 `jmt 0.12.0` 数据结构绑定。依赖升级必须使用新 envelope
   版本并补充跨版本兼容向量。
2. 为支持历史证明，M2 当前不 pruning。磁盘增长、proof 大小和延迟由 M10
   量化；在此之前不作生产性能声明。
3. M2 只认证 opaque canonical value；latest-state value 的完整字段、状态转移、
   latest entry count 和 block-level commitment 属于 M4。
4. M2 的历史 value lookup 为 `O(log U_CA)`；JMT proof path 为 `O(log C)`。
5. M2 不提供 MMR append-only audit history；该安全结构必须由独立的 M3
   实现，不能以 JMT 历史版本替代。
6. 当前单机 scratch 环境构建 bundled RocksDB 时曾出现原生 C++ object 被
   临时文件系统清零的问题；已通过重新生成纯构建产物完成全部验证，源代码和
   运行时数据库格式不受影响。M9 应用固定镜像 digest、系统包和容器构建消除
   环境不确定性。
7. 本轮没有实现 BFT/QC、signer bitmap、validator key management、
   reconfiguration/recovery，也没有连接 Krill/Routinator；这些不能从 M2
   结果外推。

## 8. 下一审批点

M2 已结束。下一模块为 M3 `lantern-history`：独立实现 append-only MMR、
record inclusion proof、old-root-to-new-root consistency proof、恢复和独立
verifier 测试。只有在用户确认 M2 后才开始 M3。
