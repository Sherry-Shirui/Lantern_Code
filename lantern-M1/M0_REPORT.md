# Lantern M0 交付报告

状态：完成，等待作者审批进入 M1  
日期：2026-07-16  
模块：`lantern-types 0.1.0`

## 1. 本轮范围

本轮只实现需求规格中的 M0，没有创建 M1–M10 的 crate、服务或占位实现。workspace 当前只包含 `lantern-types`。

已完成：

- Rust 1.97.1 精确工具链和直接依赖版本固定；
- fixed-schema deterministic CBOR 与严格 decode/re-encode canonicality 检查；
- 1 MiB defensive wire-object limit；
- `PublicationIntentV1`、`ControlEventV1`、`HeadBodyV1`、`AppStateCommitmentV1`；
- validator configuration、unsigned update、2-of-3 governance authorization types；
- 全部 v1 domain labels、统一 length-delimited framing 与 SHA-256 helper；
- `CA_ID`、intent/control ID、`HeadID`、`AppHash`、validator config/update ID；
- strict Ed25519 control/governance signing and verification；
- publication intent 的算法无关 signing message；
- checked-in golden/negative vectors 与可重复生成器；
- wire-format 规范说明、API rustdoc、invariant/negative tests。

## 2. 关键协议落实

### 2.1 Head/QC 边界

M0 固定 `HeadID = H(HeadBody domain, canonical body)`；QC 不进入 HeadID。`AppStateCommitmentV1.closed_head_id` 显式绑定 HeadID，供 M5 实现 `SignedHeader.AppHash -> AppStateCommitment -> HeadID` 的一块延迟认证路径。

M0 没有定义或模拟 CometBFT QC，也没有生成伪 signer bitmap。

### 2.2 Publication authorization

`PublicationIntentV1` 将 signature algorithm 纳入签名对象，并提供精确 domain-framed signing message。M0 没有假设 manifest EE key 为 Ed25519；RSA/ECDSA/Ed25519 的 EE certificate 一致性和实际验证由 M7 Krill/RPKI adapter 完成。

### 2.3 Administrative/governance authorization

CA control event 使用 strict Ed25519 verification，并绑定独立 key ID。validator update 使用本地配置的三个 governance key 中 2 或 3 个唯一 signer，signature 按 signer index 排序；proof service 不能在对象中替换 governance public keys。

### 2.4 Canonicality

公开 API 只提供 `validate`、`to_canonical_cbor`、`from_canonical_cbor`。crate 内部的 permissive decode primitive 不向下游暴露。公开 decoder 必须完成：size limit → decode one object → no trailing data → semantic validation → canonical re-encode byte comparison。

## 3. 主要文件

| 文件 | 作用 |
| --- | --- |
| `Cargo.toml`、`Cargo.lock`、`rust-toolchain.toml` | workspace、依赖和 Rust 工具链 pin |
| `crates/lantern-types/src/cbor.rs` | canonical wire-object boundary |
| `src/domain.rs`、`src/hash.rs` | v1 domains、framing、identifiers |
| `src/intent.rs` | publication intent 与 EE algorithm declaration |
| `src/control.rs`、`src/signature.rs` | control transition types 与 strict Ed25519 |
| `src/head.rs` | HeadBody/AppStateCommitment |
| `src/validator.rs` | equal-weight validator config 与 2-of-3 governance update |
| `WIRE_FORMAT.md` | 字段级 wire 规范 |
| `test-vectors/v1.json` | 跨进程 golden/negative vectors |
| `examples/generate_vectors.rs` | 只向 stdout 输出候选向量，不自动覆盖已审核文件 |
| `tests/vectors.rs`、`tests/invariants.rs` | golden、negative 与语义不变量测试 |

## 4. 工具链与依赖

- `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- `cargo 1.97.1 (c980f4866 2026-06-30)`
- `minicbor = 2.2.2`
- `sha2 = 0.11.0`
- `ed25519-dalek = 3.0.0`
- `thiserror = 2.0.18`
- `hex = 0.4.3`
- test only：`serde = 1.0.228`、`serde_json = 1.0.150`

全部 direct dependency 使用 exact version；transitive resolution 固定在 `Cargo.lock`。

## 5. 验证结果

以下检查均成功：

```text
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo run --quiet --example generate_vectors | cmp - crates/lantern-types/test-vectors/v1.json
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo test --workspace --all-targets --release --locked
cargo test --workspace --all-targets --locked --offline
```

测试数量：17 个集成测试，全部通过；0 ignored、0 failed。

覆盖重点：

- exact manifest hash、TA digest 与 CA_ID golden values；
- publication/control/head/app/validator canonical CBOR round trip；
- all domain labels 与 same-payload domain separation；
- non-minimal integer、indefinite array、trailing bytes、错误数组长度；
- unknown protocol version、非法 network ID、非法 timestamp；
- previous-manifest、previous-head、closed-epoch/head pair 不变量；
- wrong key ID、wrong control signature、wrong governance key；
- governance signature threshold、排序和重复 signer；
- validator 数量、等权、canonical order、公钥/address 对应；
- 1 MiB size limit 在 CBOR parse 前生效；
- vector generator 输出与 checked-in JSON 逐字节相同。

## 6. 已知限制与后续归属

这些限制是按模块拆分保留的边界，不应被描述为已经实现：

1. M0 不解析 manifest DER/CMS、不验证 RPKI chain，也不调用 Krill signer；属于 M7 feasibility/integration。
2. M0 不包含 JMT、MMR 或 RocksDB；分别属于 M1–M3。
3. Control transition 只有 typed schema 和无状态不变量；Enable/Cancel/Rollover 的前后态执行属于 M4。
4. M0 不实现 epoch close、P1–P7 predicate 或 deterministic application transition；属于 M4。
5. M0 不解析 CometBFT protobuf、不验证 CommitSig/bitmap/ValidatorSet，也不执行 `H+2` reconfiguration；属于 M5。
6. `ValidatorUpdateV1` 当前验证 2-of-3 governance authorization，但“一次只替换一个 validator”和 old/new config 连续性需要 M5 在持有当前状态时执行。
7. Golden vectors 可被任意语言/进程消费，但本轮自动测试 oracle 仍是 Rust 实现；后续独立实现必须以 checked-in bytes 为准，不能重新解释字段。

## 7. M1 审批门

建议下一模块严格限于 `lantern-store`：RocksDB column-family layout、storage trait、single atomic WriteBatch、WAL/metadata、crash/reopen tests 和 snapshot abstraction。M1 不应引入 JMT、MMR、CometBFT 或 HTTP 服务。

作者审批 M0 后才开始 M1。
