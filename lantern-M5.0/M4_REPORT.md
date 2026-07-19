# Lantern M4 修改说明与验证报告

## 1. 本轮结论

M4 已实现为独立 crate `lantern-state`，并通过真实 M1 RocksDB、M2 JMT、
M3 MMR 路径完成确定性状态转换、epoch close、双根更新和单批原子提交。
本轮没有实现或伪造 CometBFT QC，也没有开始 M5。

本轮同时修复两个 M4 前置接口问题：

1. 初次 `Enable` 的 admin public key 现在位于签名覆盖的 action 内；
2. M1 使用 `Option<u64>` 区分“尚无 head”与“epoch 0 已关闭”，snapshot
   format 从 1 升至 2。

具体勘误见 `M4_REQUIREMENTS_ERRATA.md`，冻结接口见
`crates/lantern-state/M4_INTERFACE.md`。

## 2. 新增模块与接口

### 2.1 `lantern-types` canonical schemas

新增并严格验证：

- `HistoryEventTypeV1`、`CaStatusV1`、`EpochProfileV1`；
- `HistoryRecordV1`、`LatestValueV1`、`CaStateV1`；
- `PublicationTransactionV1`、`ControlTransactionV1`、
  `StateTransactionV1`；
- `TransactionResultV1` 与稳定结果码；
- `StateConfigV1`。

所有对象继续使用 definite-length fixed-array canonical CBOR，解码后执行
validate、重新编码和逐字节比较。publication 输入在状态变更前执行 manifest、
signature、certificate-chain 的数量和字节上限。新增 domain：
`HistoryRecord`、`CaState`、`StateTransaction`、`TransactionResults`、
`EpochBundle`、`AdminRegistry`、`SchemaConfig`。

M0 `Enable` 黄金向量已重新生成；向 action 替换 admin key 后，原签名验证失败。

### 2.2 Publication authorization boundary

`PublicationAuthorizer` 接收：

- canonical intent 与原始 canonical bytes；
- exact manifest DER；
- detached intent signature；
- EE certificate chain；
- consensus block time。

它返回独立解析出的 CA ID、manifest number/hash 和 algorithm。M4 在 adapter
成功后再次比较所有返回字段，并对 exact bytes 重新计算 manifest hash。
transaction 中不存在 `validated=true` 或其它可信布尔捷径。

幂等 exact replay 不重复调用 adapter，而是返回原始、已经 committed 的 typed
result；同 CA/nonce 的不同 canonical transaction 在 adapter 前拒绝，且不覆盖
原映射。

M4 测试 authorizer 是明确标注的 strict fixture：它解析测试 envelope、验证
fixture EE key、strict Ed25519 intent signature、exact bytes hash 和 algorithm。
它不是 RPKI validator，也未作为 Krill 集成结果报告。M7 必须在同一 trait 后面
接入真实 manifest CMS/RPKI chain validation。

### 2.3 Control transitions

实现的状态矩阵：

- `Enable`：仅 absent/disabled；初次使用 action 内嵌 key 自举；rollover
  successor 必须匹配预授权 key；
- `Publish`：仅 enabled；验证 expected/previous hash、递增 manifest number 和
  EE authorization；
- `Disable`：仅 enabled，保留 effective manifest 和历史；
- `Cancel`：仅可引用当前 latest Publish 的精确 version/hash，并恢复其已认证
  predecessor；不删除 target record 或 publication archive；
- `Rollover`：旧 CA 原子 terminal，successor key 预授权；
- `Terminal`：不可逆，旧 key 后续事件全部拒绝。

所有后续 control event 必须满足 exact next admin sequence、exact
`previous_state_hash` 和 strict Ed25519 authorization。accepted control 的完整
canonical transaction 按 `authorization_digest` 保存，compact M3 record 因而可
回查并验证签名。Cancel 的 latest value 同时保留被恢复 publication 的
`effective_intent_digest`，不会把 admin signature 冒充 EE intent signature。

### 2.4 Deterministic block and atomic commit

每个 block 的固定路径为：

1. 读取并交叉检查 M1 metadata、M2 version/root、M3 size/root、M4 AppState；
2. 检查 exact successor height 与非回退 consensus time；
3. 在当前交易之前关闭全部到期 epoch；
4. 按 block 顺序执行 typed transaction；
5. 暂存 records、authorization archives、proof indices、idempotency result；
6. 每个受影响 CA 只保留最终 latest value，调用一次 M2 update；
7. 将所有 accepted compact records 按交易顺序调用一次 M3 append；
8. 把 M2、M3、M4、head、config 和 idempotency writes 放进一个 M1
   `StoreBatch`；
9. 计算并验证 `AppStateCommitmentV1`/`AppHash`；
10. 仅 `PreparedBlock::commit` 可调用 M1 `BlockStore::commit_block`。

丢弃 `PreparedBlock` 不产生可见写入。重启后，任一 metadata/root/size/config
不一致都会 fail closed，不能继续下一个 height。

### 2.5 Epoch and head semantics

支持 integration 30 秒与 paper 300 秒 profile。epoch `e` 为
`[genesis + e*Delta, genesis + (e+1)*Delta)`。block time 位于 epoch `k` 时，
所有 `< k` 且未关闭的 epoch 先使用 pre-block roots 关闭；当前交易属于 `k`，
因此边界交易不会泄漏到已结束 head。

catch-up 数量由 config 的非零 `max_epoch_catchup` 限制。超过上限时只允许空
catch-up block；非空 block 返回 typed block error。`HeadID` 只 hash canonical
body，不含 QC。`AppState` 绑定 post-block roots 和最后 closed HeadID。

## 3. 安全性质与实现对应

| 性质 | M4 实现与测试 | 声明边界 |
| --- | --- | --- |
| Determinism | canonical inputs、BTree ordered final state、ordered result/bundle accumulators；四 RocksDB replica 逐字段相等 | M5 才证明 BFT safety/liveness |
| Authorization soundness | publication adapter + M4 独立比较；control strict signature/key ID/sequence/previous-state hash | production RPKI soundness 依赖 M7 adapter |
| Atomic visibility | M2/M3/M4/metadata 单 M1 batch；drop-before-commit 测试 | 不替代 OS/硬件 Byzantine 模型 |
| Append-only accountability | 每个 accepted transition 恰好一条 M3 record；Cancel 不删除 target/archive | repository delivery fact 不由 Cancel 证明 |
| Idempotency | exact replay 返回原 result；same nonce/different bytes 稳定冲突且不覆盖 | malformed non-canonical input在交易解码边界直接失败 |
| Terminality | rollover/terminal 后旧 CA 永久拒绝；successor key signature-bound | key rotation/quorum reconfiguration 属于 M5 |
| Epoch isolation | close-before-transactions；边界测试 head history length 不含当前 block record | QC 的一块认证延迟属 M5/M10 |
| Recovery consistency | commit/reopen/continue 与 M1/M2/M3/M4 cross-check | snapshot orchestration继续复用 M1 |

CA admin registry commitment 当前定义为 domain-separated、按 accepted control
transaction ID 顺序推进的 accumulator；完整 accepted control authorization 被保留，
可确定性重放重建 registry。M5 不得在不更新 schema config hash 的情况下改变此
定义。

## 4. P1–P7 fixture

`crates/lantern-state/M4_P1_P7_FIXTURES.md` 给出 fixture 矩阵。测试通过真实
M2 membership proof、M3 inclusion proof、M4 proof index、head body 和
AppState 构造 P1–P7 输入：disabled、enabled matching、older within/beyond
grace、absent index、conflicting body ID 和四副本一致性均覆盖。

这些是 M4 authenticated fixtures，不是 M8 的 Routinator routing verdict，也不
包含 M5 QC。

## 5. 前置模块兼容修改

- M0：`Enable` action 从 `[1, manifest_hash]` 改为
  `[1, manifest_hash, initial_admin_key]`；向量和 substitution negative test 更新。
- M1：commit/snapshot 的 closed epoch 改为 optional pair；fixed-width commit
  metadata 长度不变；snapshot format version=2；新增 epoch-zero
  commit/reopen/checkpoint/restore 测试。
- M2：公开 `empty_latest_root()`，并与真实 empty JMT version root 回归比较，
  解决首个 block 在交易前关闭空 epoch 的 pre-state root 需求。
- M3：无格式变化；M4 继续只调用一次 `prepare_append`。

## 6. 验证结果

工具链：Rust 1.97.1；workspace dependencies 由 `Cargo.lock` 锁定。

执行并通过：

```text
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo test -p lantern-latest-map --no-default-features --lib --locked
cargo test -p lantern-history --no-default-features --lib --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

全工作区共 63 项测试通过，其中 M4 9 项；proof-only 回归各 3 项。M4 覆盖：

- enable/publish/epoch-close/cancel；
- wrong publication authorization 无状态影响；
- exact replay 与 nonce conflict；
- drop-before-commit；
- commit/reopen/cross-check/continue；
- rollover terminality 与 successor preauthorization；
- 四副本 deterministic replay；
- P1–P7 fixture matrix；
- 10,000 范围内随机 epoch boundary property。

固定文件摘要：

```text
M0 vector  8a161f209495ec166165d2b5919d919718ccb9a73ee1c9909b2a501e8c4e0852
Cargo.lock de6d571559ace1cf414dab0802a20a664db1d60b83f179b76489758a177382d2
```

RustSec：`cargo-audit 0.22.2`，advisory database commit
`b5fc89b8be99e96f79194d8a6f11e9b4143b99f0`，更新时间
`2026-07-17T17:52:38+02:00`，123 个 lockfile dependencies，0 vulnerability，
0 warning。原始 JSON 为 `M4_RUSTSEC_AUDIT.json`。

许可证清单由 `cargo-license 0.7.0` 生成，共 123 dependency rows，见
`M4_DEPENDENCY_LICENSES.tsv`。

## 7. 单机复现

Ubuntu 24.04 单机需要 GCC/G++、Clang 18 和 libclang 18（含 Clang resource
headers）。不需要 WAN、Kubernetes 或外部 consensus cluster。

```sh
rustup toolchain install 1.97.1 --profile minimal --component rustfmt,clippy
rustup override set 1.97.1
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

若系统不自动发现 libclang，可设置 `LIBCLANG_PATH` 指向包含 `libclang.so` 的
LLVM 18 lib directory。

## 8. 明确未实现项

以下内容仍属于 M5 及以后，本报告不作完成声明：

- CometBFT ABCI++ transport、四 validator BFT/QC、one-block binding；
- signer bitmap、validator key management、reconfiguration、backup/recovery cost；
- HTTP submit/proof service；
- Krill CA publisher 与真实 RPKI manifest EE adapter；
- Routinator plugin、Compose E2E 与 routing verdict；
- WAN/Kubernetes、故障注入和论文性能图表。

因此下一步应在作者确认 M4 后进入 M5，不应把 strict fixture authorizer 或四个
独立确定性 replica 测试描述成“已经实现 BFT/QC”。
