# Lantern v1 wire format（M0）

本文档是 `lantern-types` 的规范接口说明。字段次序、域标签或 framing 的任何变化都属于协议变化，必须更新 golden vectors 并经过单独审核。

## 1. Canonical CBOR

- 协议对象使用 definite-length CBOR array，不使用 map。
- 整数必须使用最短编码，byte/text string 必须使用 definite length。
- optional value 编码为其正常值或 CBOR `null`。
- decoder 先施加 1 MiB 对象上限，再解码一个对象、检查无 trailing bytes、验证语义、重新编码并逐字节比较。
- 未知协议版本、未知 enum code、错误数组长度、indefinite container 和非最短整数均拒绝。
- `NetworkId` 为 1–49 字节，只允许 ASCII 字母、数字、`.`、`_`、`-`。
- `TimestampV1` 为 `[seconds: i64, nanos: u32]`，且 `nanos < 1_000_000_000`。

## 2. Domain framing

hash 和签名消息统一使用：

```text
"LANTERN\0" || u16be(domain_length) || domain_ascii
              || u64be(payload_length) || payload
```

协议 v1 固定域：

| 枚举 | ASCII label |
| --- | --- |
| `CaId` | `lantern/v1/ca-id` |
| `Intent` | `lantern/v1/intent` |
| `Control` | `lantern/v1/control` |
| `LatestKey` | `lantern/v1/latest-key` |
| `LatestLeaf` | `lantern/v1/latest-leaf` |
| `HistoryLeaf` | `lantern/v1/history-leaf` |
| `HistoryNode` | `lantern/v1/history-node` |
| `HeadBody` | `lantern/v1/head-body` |
| `AppState` | `lantern/v1/app-state` |
| `ValidatorConfig` | `lantern/v1/validator-config` |
| `Governance` | `lantern/v1/governance` |
| `Ed25519KeyId` | `lantern/v1/ed25519-key-id` |

所有协议对象 ID 都是 `SHA-256(domain_separated_message(domain, canonical_cbor))`。例外只有论文明确要求对外部原始 bytes 计算的 plain SHA-256：exact manifest DER、TA SPKI digest 和 validator address 的 CometBFT 派生。

`CA_ID` 的 payload 在进入 `CaId` domain 前编码为：

```text
u32be(2)
|| u64be(32) || TAKeyDigest
|| u64be(resource_ca_spki_length) || resource_ca_spki_der
```

## 3. PublicationIntentV1

顶层 array 长度为 9：

| Index | 字段 | CBOR 类型/约束 |
| ---: | --- | --- |
| 0 | `protocol_version` | unsigned；必须为 1 |
| 1 | `network_id` | validated text |
| 2 | `event_type` | unsigned；`1 = Publish` |
| 3 | `ca_id` | 32-byte bstr |
| 4 | `manifest_number` | non-zero unsigned |
| 5 | `manifest_hash` | 32-byte bstr，exact DER plain SHA-256 |
| 6 | `previous_manifest_hash` | 32-byte bstr 或 null |
| 7 | `nonce` | 16-byte bstr |
| 8 | `signature_algorithm` | `1 = RSA-PKCS1-v1_5/SHA-256`；`2 = ECDSA-P256/SHA-256`；`3 = Ed25519` |

`intent_id` 使用 `Intent` domain。`publication_signing_message` 返回完整 domain-framed message，不在 M0 中假设 EE key 算法。Krill/RPKI adapter 必须检查声明算法和 manifest EE certificate 一致，并使用该 certificate 对应的同一私钥。

## 4. ControlEventV1

顶层 array 长度为 7：

| Index | 字段 | CBOR 类型/约束 |
| ---: | --- | --- |
| 0 | `protocol_version` | 必须为 1 |
| 1 | `network_id` | validated text |
| 2 | `ca_id` | 32-byte bstr |
| 3 | `admin_sequence` | non-zero unsigned |
| 4 | `previous_state_hash` | 32-byte bstr 或 null；只有首次 Enable 可为 null |
| 5 | `nonce` | 16-byte bstr |
| 6 | `action` | 下表中的 typed array |

Action schemas：

| Action | Array |
| --- | --- |
| Enable | `[1, initial_manifest_hash]` |
| Disable | `[2, non_zero_reason_code]` |
| Cancel | `[3, target_version, target_manifest_hash, restore_manifest_hash, non_zero_reason_code]` |
| Rollover | `[4, successor_ca_id, successor_admin_ed25519_public_key]` |
| Terminal | `[5, non_zero_reason_code]` |

Control signature 使用 `Control` domain 和 strict Ed25519 verification。`Ed25519AuthorizationV1` 编码为 `[key_id: bstr32, signature: bstr64]`，其中 key ID 使用 `Ed25519KeyId` domain。

## 5. HeadBodyV1

顶层 array 长度为 13：

| Index | 字段 |
| ---: | --- |
| 0 | `protocol_version` |
| 1 | `network_id` |
| 2 | `epoch` |
| 3 | `epoch_start` |
| 4 | `epoch_end` |
| 5 | `issued_at` |
| 6 | `latest_root` |
| 7 | `history_root` |
| 8 | `previous_head_id` 或 null |
| 9 | `bundle_hash` |
| 10 | `history_length` |
| 11 | `latest_entry_count` |
| 12 | `key_epoch` |

必须满足 `epoch_start < epoch_end <= issued_at`、`latest_entry_count <= history_length`；只有 epoch 0 省略 previous HeadID。

`HeadID = SHA-256(domain(HeadBody, canonical HeadBodyV1))`。QC 不进入 HeadID。M0 不定义 CometBFT `SignedHeader/Commit` wire type；该绑定属于 M5，但必须使用本 HeadID。

## 6. AppStateCommitmentV1

顶层 array 长度为 14：

| Index | 字段 |
| ---: | --- |
| 0 | `protocol_version` |
| 1 | `network_id` |
| 2 | `app_height`（non-zero） |
| 3 | `pending_latest_root` |
| 4 | `pending_history_root` |
| 5 | `history_length` |
| 6 | `latest_entry_count` |
| 7 | `last_closed_epoch` 或 null |
| 8 | `closed_head_id` 或 null |
| 9 | `validator_config_hash` |
| 10 | `ca_admin_registry_hash` |
| 11 | `governance_config_hash` |
| 12 | `transaction_results_hash` |
| 13 | `schema_config_hash` |

`last_closed_epoch` 和 `closed_head_id` 必须同时存在或同时缺失。`AppHash` 使用 `AppState` domain。M5 必须验证 CometBFT header 的 AppHash 与本对象一致，并验证 `closed_head_id` 等于相应 `HeadBodyV1` 的 HeadID。

## 7. Validator configuration 与 governance update

`ValidatorInfoV1 = [address: bstr20, public_key: bstr32, voting_power]`。MVP 只接受 power 1，address 必须是 `SHA-256(public_key)[0..20]`。

`ValidatorConfigV1` array 长度为 5：

```text
[protocol_version, network_id, key_epoch, effective_height,
 [validator_0, validator_1, validator_2, validator_3]]
```

validator 按 voting power 降序、再按 address 升序；公钥和地址均不得重复。configuration ID 使用 `ValidatorConfig` domain。

`UnsignedValidatorUpdateV1`：

```text
[protocol_version, network_id, sequence, current_config_hash, next_config]
```

`GovernanceSignatureV1 = [signer_index, key_id, signature]`。完整 `ValidatorUpdateV1 = [unsigned_update, signatures]`，signature 数量为 2 或 3，按唯一 signer index 升序。签名消息和 update ID 都使用 `Governance` domain；verifier 使用本地配置的三个 governance public keys，不信任 proof service 提供的替代 key。

M0 只定义授权和 canonical types。一次只替换一个 validator、旧/新 config 的连续性以及 CometBFT `H+2` activation 在 M5 状态机中执行。

## 8. Golden 与 negative vectors

`test-vectors/v1.json` 固定以下内容：

- TA digest、CA_ID、exact manifest hash；
- publication/control/head/app-state/validator-config canonical CBOR 与 ID；
- publication/control/governance signing messages；
- strict Ed25519 control 与 2-of-3 governance signatures；
- non-canonical integer、trailing data、wrong array length/version/network 和 wrong signature negative cases。

`cargo run --quiet --example generate_vectors | cmp - test-vectors/v1.json` 必须无差异。

