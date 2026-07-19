# Lantern M1 交付报告

状态：完成，等待作者审批进入 M2  
日期：2026-07-16  
模块：`lantern-store 0.1.0`

## 1. 本轮范围

本轮只实现需求规格中的 M1。workspace 当前包含已验收的 M0
`lantern-types` 和本轮 `lantern-store`，没有创建 M2–M10 的 crate、服务或
占位实现。

已完成：

- 固定 `rocksdb = 0.24.0`，transitive resolution 写入 `Cargo.lock`；
- 精确的 RocksDB column-family 布局与数据库身份绑定；
- 后端无关的 `ReadStore`、`SnapshotSource`、`BlockStore` 接口；
- 可组合、未提交的 `StoreBatch` 与防御性大小/重复键校验；
- 一个 block 的全部 CF 操作和 typed commit metadata 单 `WriteBatch` 提交；
- WAL 强制开启、`Wal`/`SyncWal` 两种明确 durability；
- monotonic height、history size、closed epoch/HeadID 不变量；
- 一致性 read snapshot；
- 带逐文件 SHA-256 的 RocksDB checkpoint manifest；
- checkpoint 完整验证、staging restore 和原子目录发布；
- 重开、丢弃 batch、跨 CF 原子性、`SIGKILL` WAL recovery 测试；
- corrupted/truncated/wrong-chain/old-schema snapshot 负向测试。

## 2. 低耦合接口与职责边界

### 2.1 M2/M3 可使用的接口

M2 和 M3 只能使用：

- `ReadStore::get`：按 logical CF/key 读取；
- `SnapshotSource::read_snapshot`：获取一致 sequence-number 读视图；
- `StoreBatch::put/delete`：把尚未持久化的节点操作加入共享 batch。

它们不能取得 raw RocksDB handle 或 column-family handle，也没有公开的
metadata-free commit 方法。

### 2.2 M4 才可使用的提交接口

`BlockStore::commit_block(batch, metadata, durability)` 是唯一应用状态提交
入口。它在同一 coordination mutex 内完成：

1. 校验 metadata 和 immutable config hash；
2. 读取前一 committed metadata；
3. 校验高度恰为 successor，并拒绝 history/epoch 回退；
4. 把 fixed-width typed metadata 加入同一 batch；
5. 把全部操作翻译为一个 RocksDB `WriteBatch`；
6. 仅调用一次 `DB::write_opt`，显式 `disable_wal(false)`。

因此 M2/M3 不能独立提交半棵树，M4 也不能把 roots/counts/height/AppHash 与
records 分成多次可见写入。

## 3. Column-family 布局

除 RocksDB 必需但不使用的 `default` 外，M1 要求以下九个 CF：

| Stable name | 内容/后续 owner |
| --- | --- |
| `metadata` | store identity、height、AppHash、roots、counts、closed head |
| `records` | immutable accepted transition records |
| `intent_archive` | canonical publication intents |
| `latest_tree_nodes` | M2 latest map nodes |
| `mmr_nodes` | M3 MMR nodes |
| `proof_index` | committed proof lookup indices |
| `idempotency` | replay keys 与 committed outcomes |
| `config_reconfiguration` | application/validator configuration data |
| `snapshots_manifest` | snapshot manifest archive entries |

新数据库创建全部 CF。现有数据库必须与此集合逐项完全相等；missing/unknown
CF 均拒绝，不能静默创建或忽略。数据库首次创建时同步写入 schema version、
chain ID 和 immutable config hash；以后用不同身份打开会 fail closed。

## 4. 原子性、WAL 与恢复语义

- `Options::set_unordered_write(false)`，不启用会削弱 snapshot/atomic guarantee
  的 relaxed path；
- `Options::set_manual_wal_flush(false)`；
- `Options::set_atomic_flush(true)`，增强多 CF flush 一致性；
- 每次写入都显式 `WriteOptions::disable_wal(false)`；
- `Durability::Wal` 等待 WAL write 返回，但不声称抵抗 OS page-cache/power loss；
- `Durability::SyncWal` 同时设置 `sync=true`，用于要求存储设备确认的生产提交；
- `current_metadata()` 是重启后 ABCI `Info` 的唯一持久化来源；M4 不应维护第二份
  height/AppHash 文件。

测试中，子进程完成真实 RocksDB WAL batch 后写入 ready marker，父进程随后对
子进程执行 `SIGKILL`，确保 Rust/C++ destructors 均不运行。重开数据库后，跨 CF
数据和 commit metadata 同时存在。

## 5. Snapshot/checkpoint

`create_checkpoint` 与 block commit 共用 coordination mutex，防止 manifest 中的
height/roots 与物理 checkpoint 跨越不同提交。manifest 至少绑定：

- snapshot format、store schema、chain ID；
- app height/AppHash；
- latest root、history root/size；
- last closed epoch/HeadID；
- validator config hash、application config hash；
- 所有 RocksDB checkpoint regular file 的 sorted relative path、size、SHA-256。

`verify_checkpoint` 在解析前限制 manifest 为 1 MiB，并拒绝 unknown JSON field、
非小写 canonical hash、path traversal、symlink/special file、重复/乱序 path、
missing/extra file、size/hash mismatch、wrong chain/config/schema。

`restore_checkpoint` 先完整验证，再复制到 destination 的 sibling staging
directory，fsync 后用预期 identity 打开 staged DB，并逐字段比对 DB commit
metadata 与 manifest；最后才 rename 发布。destination 必须事先不存在。

## 6. 文件清单

| 文件 | 作用 |
| --- | --- |
| `crates/lantern-store/Cargo.toml` | M1 精确依赖 |
| `src/cf.rs` | frozen CF enum/name layout |
| `src/batch.rs` | backend-neutral batch、limits、durability、receipt |
| `src/metadata.rs` | store identity 与 fixed-width commit metadata |
| `src/store.rs` | traits、RocksDB open/read/snapshot/atomic block commit |
| `src/snapshot.rs` | checkpoint manifest、digest、verify、atomic restore |
| `src/error.rs` | typed storage errors |
| `tests/store_contract.rs` | M1 合约、原子性、恢复和负向测试 |
| `M1_INTERFACE.md` | 面向 M2–M4 的接口与持久化契约 |
| `Cargo.lock` | RocksDB 及全部 transitive dependency resolution |

## 7. 工具链与依赖

- `rustc 1.97.1 (8bab26f4f 2026-07-14)`；
- `rocksdb 0.24.0`，default features disabled；
- `librocksdb-sys 0.17.3+10.4.2`，bundled RocksDB 10.4.2；
- 本机 C++ compiler：Ubuntu G++ 13.3.0；
- bindgen runtime：Ubuntu libclang 18.1.3 及 resource headers；
- Rust direct/transitive dependency 全部由 `Cargo.lock` 固定。

禁用 RocksDB crate 默认 compression feature 是 M1 最小正确性基线，不改变 logical
CF/wire/state semantics。是否启用 LZ4/Zstd 必须在后续性能阶段通过显式依赖变更和
兼容性测试，不能静默改变 artifact。

## 8. 验证结果

最终在 `--locked --offline` 下成功执行：

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked --offline
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --offline
cargo run --quiet --locked --offline --example generate_vectors | cmp - crates/lantern-types/test-vectors/v1.json
cargo metadata --locked --offline --no-deps --format-version 1
```

结果：

- M1 integration tests：11 passed、0 failed、0 ignored；
- M0 regression tests：17 passed、0 failed、0 ignored；
- workspace 合计：28 passed；
- Clippy：`-D warnings` 通过；
- rustdoc：`-D warnings` 通过；
- M0 golden vector generator：逐字节一致；
- 最终 bundled RocksDB build directory：0 个 zero-byte object。

M1 覆盖重点：

- exact CF layout 和 unknown CF rejection；
- store identity mismatch；
- records/tree/MMR/index/idempotency/config 与 metadata 单批提交；
- successor height、history regression、same-epoch HeadID mutation；
- consistent read snapshot；
- `FinalizeBlock` 后未调用 commit 的 batch 丢弃与重开；
- WAL commit 后 `SIGKILL`、重开与完整恢复；
- checkpoint create/verify/restore round trip；
- file corruption、wrong chain、old schema、truncated manifest；
- 所有失败 restore 均不发布 destination。

## 9. 本地构建环境说明

当前 scratch filesystem 在多次完整编译 bundled RocksDB 后，偶发观察到 1–2 个随机
`.o` 文件为 0 字节，而 Cargo/cc build script 没有报告对应编译失败；同一源文件用相同
G++/flags 单独重编可稳定生成有效 ELF object。最终验证前已重编受影响的纯派生对象、
更新静态 archive、扫描确认无 0 字节对象，并重新链接/运行全部测试且无 linker warning。

这不是 Lantern 源码 workaround，临时 compiler wrapper 和本地 libclang 展开目录不在
交付归档中。M9 的 clean-host Docker build 必须在普通 overlay2/ext4 文件系统重新执行
无人工介入的完整构建；该项在完成前不能声称 artifact 已满足 clean-host reproduction。

## 10. 已知限制与后续归属

1. M1 不实现 JMT/latest proof；属于 M2。
2. M1 不实现 MMR/history proof；属于 M3。
3. M1 只持久化 typed roots/AppHash metadata，不计算它们；属于 M4。
4. snapshot manifest 可作为 `snapshots_manifest` CF 的 value 加入后续 block batch，
   `create_checkpoint` 不在 checkpoint 完成后偷偷执行 metadata-free write。
5. snapshot restore 只支持发布到不存在的新目录；live-volume swap、CometBFT replay 与
   recovery cost 统计属于 M5/M9/M10。
6. `SyncWal` 提供 RocksDB/OS 暴露的同步语义，但本轮未做断电/存储设备 cache 实验。
7. M1 没有性能 benchmark；RocksDB/JMT/MMR 的组合开销在 M2–M4 正确性稳定后、M10
   统一测量。

## 11. M2 审批门

建议下一模块严格限于 `lantern-latest-map`：基于 `jmt 0.12.0` 实现 latest map、
membership/non-membership/historical-version proof 和独立 verifier。M2 只使用 M0 类型、
M1 `ReadStore`/`StoreBatch`，不得直接打开 RocksDB，也不引入 MMR、CometBFT 或服务。

作者审批 M1 后才开始 M2。
