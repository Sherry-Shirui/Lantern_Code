# Lantern M5 需求冻结文档：真实 CometBFT/QC、重配置与恢复

状态：**作者已确认；M5.0 compatibility gate 已实现，等待作者验收后再进入 M5.1**  
基线：作者已确认 M4；恢复归档 `lantern-m4.tar.gz` 的 SHA-256 为
`4186df832165846fe6c0233f5eb9411ec99acab9be6830a03c63223ab8463162`。  
适用范围：M5 `lantern-comet`，以及实现真实重配置所必需的 M0/M4 窄接口勘误。

## 1. M5 的唯一目标

M5 必须把 M4 的确定性应用状态机接到真实 CometBFT 0.38.23 上，并交付：

1. 四个相互独立的 CometBFT validator 进程、四个 ABCI++ 应用副本和四个
   RocksDB 数据目录；
2. 来自真实 CometBFT `Commit` 的 QC，而不是应用层拼接的签名列表；
3. 可离线、storage-independent 验证的 `SignedHeader + ValidatorSet +
   signer bitmap` 路径；
4. 由 2-of-3 governance keys 授权、一次替换一个 validator、`H+2` 生效的
   validator reconfiguration；
5. test-only validator key provisioning、anti-double-sign state 管理、key loss
   rotation、重启和应用数据库恢复流程；
6. 单机可复现的正确性、故障和成本报告。

M5 的完成声明只能是“single-host real BFT/QC integration”。不得把本轮结果解释为
WAN 性能、生产密钥托管、互联网规模可扩展性或 Krill/Routinator 端到端结果。

## 2. 冻结决策

| 项目 | M5 决策 |
| --- | --- |
| CometBFT | 固定 `v0.38.23`、commit `feb2aea`；不得使用 `main`、mock consensus 或单节点 dev mode |
| Rust CometBFT 库 | 候选固定为同一 release family 的 `tendermint`、`tendermint-proto`、`tendermint-rpc`、`tendermint-abci` `0.40.4`；必须先通过 M5.0 compatibility gate，失败即暂停并提交勘误，不自行手写一套未经对照的签名字节 |
| 拓扑 | 一台 Linux 主机，4 个 validator + 4 个 ABCI app，`n=4, f=1`，每个 voting power 为 1 |
| 进程隔离 | 每个 validator 使用独立 home、node key、private-validator key/state、P2P/RPC/ABCI 端口和 RocksDB；禁止共享可写数据库 |
| 本轮编排 | 使用本机进程测试夹具；Docker Compose 仍归 M9，不在 M5 提前实现；不做 WAN/Kubernetes |
| ABCI transport | loopback TCP socket ABCI++；不得把应用编译成 CometBFT 进程内 mock |
| 应用持久化 | `FinalizeBlock` 只准备；`Commit` 才调用 M1 单批 `SyncWal` 持久化 |
| QC 绑定 | block `h` 产生 `AppHash_h`；block `h+1` header 携带该值；block `h+1` 的真实 Commit 认证 closed head，接受一块认证延迟 |
| QC 签名 | 使用 CometBFT 原生 Ed25519 precommit signature vector；不实现 BLS、threshold signature 或自定义聚合签名 |
| signer bitmap | 只表示原生 Commit 中哪些 validator 对 envelope 的 block ID 投了有效 commit vote；bitmap 不替代签名，也不得被表述为密码学签名聚合 |
| reconfiguration | 3 个独立 test governance keys，2-of-3；恰好 4 个等权 validator；一次原子替换一个；在 `FinalizeBlock(H)` 返回 update 后从 `H+2` 生效 |
| trust root | verifier 从本地受信 genesis/checkpoint 的 initial validator config 与 governance public keys 开始；不信任 proof source 自报的 validator set |
| key storage | M5 使用 CometBFT file private-validator，仅用于单机实验；不实现 HSM、KMS、remote signer 或生产备份系统 |
| recovery | M5 测试 M1 checkpoint 的离线 restore + CometBFT block replay；ABCI state sync 网络协议不作为本轮验收项 |

版本依据：CometBFT
[`v0.38.23` release](https://github.com/cometbft/cometbft/releases/tag/v0.38.23)
包含 nil-vote、blocksync、light-client 和 ABCI socket 修复；官方 v0.38
[ABCI++ 行为说明](https://docs.cometbft.com/v0.38/spec/abci/abci%2B%2B_comet_expected_behavior)
规定 `FinalizeBlock` 后执行 `Commit`。官方 v0.38.23
[`updateState`](https://github.com/cometbft/cometbft/blob/v0.38.23/state/execution.go)
明确 validator update 在返回高度的 next-next height 生效。

## 3. 明确非目标与模块边界

M5 不得实现或宣称完成：

- M6 的 transaction gateway、proof HTTP service、OpenAPI、cache 或 client policy；
- M7 的 Krill signer/CA publisher/RFC 8181 hard gate 或 production RPKI authorizer；
- M8 的 Routinator observe/enforce hook、VRP/RTR 输出；
- M9 的 Docker Compose、一键全 E2E、网络分区或容器故障矩阵；
- M10 的 WAN/多 failure-domain 性能结果和论文最终图表；
- BLS、opaque threshold signature、vote extension 认证或自定义共识；
- 云 KMS、HSM、remote signer、Kubernetes、Helm；
- 自动化 ABCI state sync；M5 只测经验证的 M1 checkpoint restore 与 block replay；
- 把 M4 strict fixture publication authorizer 误称为生产 RPKI 验证。

`lantern-qc` 不得依赖 RocksDB、M1、M2、M3、M4、ABCI server、RPC client或异步
runtime。M6/M7/M8 后续必须复用它，不能分别重写 QC 验证。

## 4. 编码前必须确认的 M4 窄接口勘误

### 4.1 为什么不能直接在 M5 外围“补一个 update”

已确认的 M4 有三个真实接口缺口：

1. `StateTransactionV1` 只有 publication/control，没有 validator update；
2. `StateConfigV1.validator_config_hash` 与 `key_epoch` 当前被 M4 当作永久静态值；
3. `TransactionResultV1` 必须带 CA/history/version 三元组，不能诚实表达一个不属于
   CA 历史的 validator update，也不能表达恶意 proposer 夹带的 non-canonical raw tx。

若 M5 在 `FinalizeBlock` 外围直接返回 ABCI validator update，update 不会进入 M4
原子 batch、`transaction_results_hash` 或 `AppHash`。这会产生“CometBFT validator
set 已改变，但 Lantern application commitment 没有承诺授权更新”的分裂状态。因此
禁止使用外围 side effect、特殊管理员 API或未承诺的本地配置文件绕过该问题。

### 4.2 新增顶层 consensus transaction/result，不破坏现有 CA 对象

M5.1 在 `lantern-types` 新增以下 canonical CBOR v1 对象；现有
`StateTransactionV1` 和 `TransactionResultV1` wire format 保持不变：

```text
ConsensusTransactionV1 =
  [1, StateTransactionV1]
  [2, ValidatorUpdateV1]

ConsensusResultV1 =
  [1, TransactionResultV1]
  [2, ValidatorUpdateResultV1]
  [3, MalformedTransactionResultV1]
```

`ValidatorUpdateResultV1` 至少绑定 update ID、block height、transaction index、
stable result code、sequence、old/new Lantern validator-config hash、proposed height、
effective height 和 old/new key epoch。`MalformedTransactionResultV1` 至少绑定 raw
transaction SHA-256、height、index 和 stable malformed/oversize code；不得归档任意大
的恶意 raw bytes。

`FinalizeBlock` 的每个输入 byte string 必须产生一个同位置 ABCI result 和一个
`ConsensusResultV1`。accepted/rejected/malformed 均按 block order 进入新的
domain-separated consensus-result accumulator；只有 accepted publication/control
改变 CA/M2/M3，只有 accepted validator update 改变 reconfiguration state。

accepted validator update 也进入该 epoch 的 ordered admitted bundle；rejected 和
malformed transaction 不进入 admitted bundle。

### 4.3 Governance trust configuration

新增：

```text
GovernanceConfigV1 =
  [protocol_version, network_id, [key_0, key_1, key_2]]
```

三个 Ed25519 public key 必须唯一并按固定 index 存放。MVP 不支持 governance-key
自身在线重配置。`governance_config_hash` 必须由该 canonical object 在独立
`lantern/v1/governance-config` domain 下计算，不能继续使用任意 tagged fixture hash。

### 4.4 持久化 reconfiguration state

新增 canonical `ReconfigurationStateV1`，至少包含：

- last accepted governance sequence；
- `certifying_config_hash` 与 `certifying_key_epoch`；
- last effective height；
- optional pending update ID、pending config hash、pending key epoch、pending effective height。

完整 `ValidatorConfigV1` 按 config hash 存放；完整 accepted `ValidatorUpdateV1` 按
sequence/update ID 存放于 M1 `config_reconfiguration` column family。所有配置、M4
状态、M2/M3、result accumulator、`AppStateCommitmentV1` 和 M1 metadata 必须位于
同一个 `StoreBatch`，只能由 `PreparedBlock::commit` 一次提交。

`StateConfigV1` 中现有 validator hash/key epoch 字段在 M5 后明确表示 genesis/initial
配置；运行时当前值必须来自持久化 `ReconfigurationStateV1`。现有 M4-only
`prepare_block` 可以保留为无 reconfiguration 的兼容 wrapper；ABCI 必须调用新的
raw consensus-block API。

### 4.5 `validator_config_hash` 的精确时间语义

对 `FinalizeBlock(h)` 生成的 `AppStateCommitment_h`：

```text
AppStateCommitment_h.validator_config_hash
  = Lantern hash of the authorized validator configuration that must equal
    Header_(h+1).ValidatorsHash after conversion to a CometBFT ValidatorSet.
```

即该字段承诺“将签署携带本 AppHash 的下一块 header 的 validator config”，不是
模糊的“最新配置”。`HeadBodyV1.key_epoch` 使用同一 certifying config 的 key epoch。

若 update 在 `FinalizeBlock(H)` 被接受：

| 高度/对象 | 必须使用的集合 |
| --- | --- |
| `Header_H.ValidatorsHash` | old |
| `Header_(H+1).ValidatorsHash` | old |
| `Header_(H+1).NextValidatorsHash` | new |
| `Header_(H+2).ValidatorsHash` | new |
| `AppState_H.validator_config_hash` | old，因为它由 `Header_(H+1)` 认证 |
| `AppState_(H+1).validator_config_hash` | new，因为它由 `Header_(H+2)` 认证 |

M4/M5 在 `FinalizeBlock(H+1)` 处理交易和关闭 epoch 前，把 pending config 切换为
certifying config；切换必须与 CometBFT request 中的 `NextValidatorsHash` 经独立转换后
一致，否则 fail closed。update 在 H 已通过 result accumulator 和完整 update archive
进入 `AppHash_H`，即使 certifying hash 到 H+1 才切换也不存在未承诺 side effect。

### 4.6 兼容与迁移规则

- 新对象新增独立 domain：`governance-config`、`consensus-transaction`、
  `consensus-results`、`reconfiguration-state` 和 `qc-envelope`；
- M0 golden/negative vectors增加新对象，既有对象的 bytes/hash 不应无故变化；
- schema/config hash 必须变化；旧 M4 数据库因此 fail closed；
- 当前没有生产数据，本轮不实现原地 migration；测试从新 genesis 启动；
- M1 column-family 集合不改变，避免存储层与 CometBFT 耦合；
- 所有接口变化必须记录在 `M5_REQUIREMENTS_ERRATA.md` 和最终 `M5_REPORT.md`。

## 5. ABCI++ 应用需求

### 5.1 `Info` 与 `InitChain`

- `Info` 只能读取 M1 committed metadata；空库返回 height 0/empty AppHash，非空库
  返回完全一致的 last height/AppHash；
- `InitChain` 验证 chain ID、initial height、genesis time、四个 Ed25519 validators、
  全部 power=1、initial validator config hash 和 governance config hash；
- genesis 与本地 immutable config 不一致必须拒绝启动，不得覆盖已存在数据库；
- 日志只能记录 public key/address/config hash，不得记录 private key 或 governance seed。

### 5.2 `CheckTx`、`PrepareProposal` 与 `ProcessProposal`

- `CheckTx` 执行 byte/item/depth 上限、canonical decode、network/version 和便宜的当前
  状态预检；它只节省 mempool 资源，不是授权信任边界；
- `PrepareProposal` 保持 CometBFT 已给定 transaction 顺序，只从尾部移除超出
  `max_tx_bytes` 的项，不得重排、合并或在本地产生 validator update；
- `ProcessProposal` 对 oversize、non-canonical envelope 和违反 block-level 限制的
  proposal 返回 reject；
- publication/control/governance 的完整规范验证必须在所有副本的
  `FinalizeBlock` 中再次执行；恶意 proposer 绕过 `CheckTx` 不能改变无效状态；
- 所有时间判断只使用 consensus block time，不读取本地 wall clock。

### 5.3 `FinalizeBlock` 与 `Commit`

- 同一高度最多存在一个 pending prepared block；不同 block ID/height 的第二个
  `FinalizeBlock` 必须拒绝；相同请求重放返回相同 response，不重复写数据库；
- raw tx 按 block order 进入 M4 consensus-block API；每个输入返回一个
  `ExecTxResult`，数量必须与输入完全一致；
- `ResponseFinalizeBlock.app_hash` 必须等于 M4 `PreparedBlock::app_hash()`；
- accepted validator update 的 response 必须恰好包含一条 old key power=0 和一条
  new key power=1，按固定 address order 输出；
- `FinalizeBlock` 不持久化；`Commit` 消费唯一 pending block并调用一次 M1
  `commit_block(..., SyncWal)`；
- crash-after-Finalize/before-Commit 后，reopen 的 `Info` 仍返回前一高度，CometBFT
  必须重放；
- crash-after-RocksDB-commit/before-Commit-response 后，reopen 的 `Info` 返回新高度
  和 AppHash，CometBFT handshake 必须恢复，不得二次执行状态转换；
- `Commit` 不返回 AppHash（v0.38 的 AppHash 在 `FinalizeBlock` response 中），仅返回
  M5 明确配置的 retain height。

### 5.4 其余 ABCI 方法

- `Query` 只提供最小的 committed height/AppHash/config diagnostic read；证明查询归 M6；
- vote extension 在 genesis/config 中禁用；`ExtendVote` 返回空，
  `VerifyVoteExtension` 只接受空值；不得把 vote extension 当作 Lantern QC；
- snapshot ABCI methods 在 M5 返回空列表/明确 reject；M5 recovery 使用离线 M1
  checkpoint restore。未来若实现 state sync，必须单独写需求和验收。

## 6. QC envelope 与独立验证

### 6.1 crate 边界

M5 新增两个低耦合单元：

- `lantern-qc`：纯解析、trust-chain、signer bitmap、Commit/AppHash/Head 验证；
- `lantern-comet`：ABCI adapter、M4/M1 integration、Comet RPC QC source 和运行时。

`lantern-qc` 的 verifier-only build 必须在依赖图中排除 RocksDB、M1–M4、ABCI、RPC、
HTTP 和 Tokio。`lantern-comet` 可以依赖 `lantern-qc`，反向依赖禁止。

### 6.2 `QCEnvelopeV1`

M5 的 canonical envelope 至少包含：

```text
[protocol_version,
 network_id,
 close_height_h,
 certified_height_h_plus_1,
 certified_epoch,
 key_epoch,
 signed_header_v0_38_proto,
 validator_set_v0_38_proto,
 signer_bitmap,
 AppStateCommitment_h,
 HeadBody_e,
 ValidatorConfigV1,
 [ValidatorUpdateV1 ... config_chain_segment]]
```

要求：

- `SignedHeader` 内已经包含完整 `Commit`，wire format 不得重复放第二份 Commit；
- protobuf bytes 来自 parsed official v0.38 types 的规范重编码，不接受 JSON bytes；
- protobuf payload、chain length、validator count 和总 envelope size 设置硬上限；
- M5 四节点路径总是携带从 local trusted initial config 到当前 key epoch 的完整 chain；
  M6 以后才可以增加显式 hash-matched cache reference；
- local trust anchor 至少绑定 network/chain ID、initial height、initial
  `ValidatorConfigV1` 和 `GovernanceConfigV1`，不由 proof source替换。

### 6.3 signer bitmap

- validator index 使用 CometBFT canonical order：voting power 降序、address 升序；
- bit `i` 使用 `bitmap[i / 8] & (1 << (i % 8))`，即每字节 LSB-first；
- 长度严格为 `ceil(n/8)`，最后一字节未使用的高 bit 必须为 0；
- 当且仅当 `Commit.Signatures[i].BlockIDFlag == COMMIT`、validator address 匹配、
  vote 指向 envelope block ID 且签名有效时，bit `i=1`；
- absent、nil vote、错误 address、错误 block ID 或无效 signature 不得计入；
- verifier 必须从 Commit 重新导出 expected bitmap，再 constant-time 比较传入 bitmap；
- 4-validator MVP 的 bitmap 为 1 byte，但报告必须同时给出完整 Commit signature
  vector bytes；不得声称这 1 byte 替代了四个签名。

### 6.4 verifier 必须按顺序完成的检查

1. envelope canonical CBOR、版本、大小和 chain ID；
2. `certified_height == close_height + 1`，header/commit height/round/block ID 一致；
3. header hash 等于 commit block ID hash；
4. `ValidatorSet.Hash() == Header.ValidatorsHash`；
5. provided `ValidatorConfigV1` 的四个 address/pubkey/power/order 与 ValidatorSet 完全一致；
6. 从本地 initial config 出发验证每个 update 的 2-of-3 signatures、sequence、
   old/new config hash、key epoch、activation height和 one-validator replacement；
7. 在 header height 生效的 config 等于 provided config，且其 Lantern hash 等于
   `AppStateCommitment.validator_config_hash`；
8. 从该 config 转换得到的 CometBFT set hash 等于 `Header.ValidatorsHash`；
9. 使用 CometBFT v0.38 canonical precommit sign bytes 验证每个计入 vote，包含
   chain ID、height、round、block ID 和 timestamp；
10. 有效 commit power 严格大于 total power 的 `2/3`，MVP 同时要求至少 3-of-4；
11. 重新导出的 bitmap 与 envelope bitmap 逐 bit 相等；
12. `Header.AppHash == app_hash(AppStateCommitment_h)` 且
    `AppStateCommitment_h.app_height == close_height`；
13. `HeadID == AppStateCommitment_h.closed_head_id`，head network/epoch/roots/counts
    与 closed state 一致；
14. `HeadBody.key_epoch` 与认证 header 的 authorized config key epoch 一致；
15. head-chain previous ID 和 recentness 由调用方提供的 trusted/cached previous head
    继续验证；M5 单元测试不把本地 RPC reachability 当作 cryptographic success。

底层 Commit 验证必须调用固定版本 Rust CometBFT verifier/type implementation；Lantern
额外执行 bitmap、governance chain 与 AppHash/Head binding。不得以 proof source 返回的
`valid=true` 布尔值代替上述步骤。

## 7. Validator reconfiguration

### 7.1 admission 条件

一个 update 只有同时满足以下条件才 accepted：

- canonical `ValidatorUpdateV1`，network 正确；
- governance `sequence == last_sequence + 1`；
- `current_config_hash` 等于本地当前 authorized config hash；
- 至少两个唯一 governance signer，key ID、index 和 Ed25519 signature 全部有效；
- `next_config.key_epoch == current.key_epoch + 1`；
- `next_config.effective_height == H + 2`；
- old/new 均为恰好 4 个、power=1、无重复 key/address、canonical order；
- 集合交集恰好 3 个：删除一个 old validator并加入一个 new validator；
- 当前没有尚未达到 effective height 的 pending update；
- 同一 block 不得 accepted 第二个 validator update。

错误 sequence/hash/signature、0/1-of-3、3/5 validators、不等 power、重复 key、
同时替换两个、错误 `H+2`、pending conflict 均确定性 reject且不返回 ABCI
validator update。

为减少 MVP 状态组合，在前一 update 的 `effective_height` 对应 block 已提交前，禁止
接受下一次 update；不做连续高度 pipelined reconfiguration。

### 7.2 activation 与历史验证

- update 的 proposed、included/accepted、ABCI returned 和 effective height 分别记录；
- `Header_(H+1)` 仍由 old set 签署并承诺 new `NextValidatorsHash`；
- `Header_(H+2)` 必须由 new set 签署；
- 被替换节点不得通过“最新 config”验证历史 QC；每个 QC 使用其 header height 的 set；
- 跨 boundary 的两个 QC envelope 必须携带不同 config hash/key epoch 和正确 chain；
- config/update archive 是 append-only，不能因 activation 删除旧 config；
- conflicting valid update sequence、回滚 key epoch 或错误 effective height必须 fail closed。

## 8. Key management 与恢复

### 8.1 key role 分离

测试报告和日志使用以下互异 role 名称：

| Role | 数量 | 私钥位置 | 用途 |
| --- | ---: | --- | --- |
| CometBFT private-validator | 4（rotation 后增加 1） | 各 node local home | precommit/consensus |
| CometBFT node key | 4（新节点另有 1） | 各 node local home | P2P identity |
| governance | 3 | 独立 local test secret directory | 2-of-3 validator update |
| Lantern CA admin | fixture-only | app fixture volume | M4 control event |
| manifest EE | fixture-only | M4 strict test authorizer | publication intent fixture |

任意一种 key 不得复用为另一 role。M5 不生成 Krill BPKI、TA/resource CA、repository
TLS 等 M7/M9 key。

### 8.2 文件与 secret 规则

- 每个 private-validator key 和 node key 文件为 owner-only（目标 mode `0600`），secret
  directory 为 `0700`；测试在启动前检查并拒绝过宽权限；
- private key 不得进入 Git、Docker image、测试归档、QC/proof、日志、panic、metrics
  或成本 JSON；
- test harness 每次运行生成新 key，输出 public address/key digest 与 byte size；不把
  固定测试 seed 冒充 operational key；
- `priv_validator_state.json` 与 private key 分开备份和计量；backup 也必须 owner-only；
- 不得将旧/stale anti-double-sign state 与同一 key直接放回已前进的链；状态丢失或
  无法确认时，规范恢复是生成新 validator key并走 governance reconfiguration；
- 所有运行时 secret/data directory 必须在 `.gitignore` 和交付归档排除清单中。

### 8.3 必测恢复路径

1. 四个 validator/app clean shutdown 后重启，height/AppHash/config chain 一致；
2. 一个 app 在 `FinalizeBlock` 后、`Commit` 前被 `SIGKILL`，重启后由 CometBFT replay；
3. 一个 app 在 RocksDB commit 后、response 前被 test-only failpoint `SIGKILL`，重启
   handshake 不重复应用 block；
4. 一个 validator/app 离线，其他 3 个继续产生 commit；
5. 两个 validator/app 离线，在固定观察窗口内 height 不增加；恢复一个后继续；
6. 丢失一个 app database：从已验证 M1 checkpoint restore 到新目录，再由该节点
   replay 到 current height；记录 restore/replay 时间和读写 bytes；
7. 丢失一个 validator key/anti-double-sign certainty：隔离旧目录，生成新 key，
   由仍在线 3 个 validator commit replacement，在 `H+2` 后由新节点加入；
8. checkpoint 损坏、错误 chain ID/schema/config hash 必须在发布恢复目录前拒绝。

故障测试必须使用可回收的 quarantine/temporary directory，不永久删除用户数据。

## 9. 单机四节点验收矩阵

| ID | 场景 | 验收条件 |
| --- | --- | --- |
| BFT-1 | 4 nodes normal | exact fixture tx 经 RPC 进入真实 block；四 app 的每高度 AppHash 相等 |
| BFT-2 | one validator stopped | 3 nodes继续 finality；真实 Commit power >2/3；bitmap 由实际签名导出 |
| BFT-3 | two validators stopped | 观察至少 `3 × consensus timeout` 无新 commit；不得降级 2-of-4 |
| QC-1 | one-block binding | close at h；仅 h+1 Commit 可使 envelope 通过；h 或 h+2 错配拒绝 |
| QC-2 | mutation | header/AppHash/body/config/bitmap/signature/address/flag/chain 任一变异均拒绝 |
| QC-3 | nil/absent | nil 与 absent vote 不计 power，不得被 bitmap 置 1 |
| QC-4 | offline verifier | verifier 无 RocksDB/RPC/ABCI 依赖，使用保存 fixture独立通过/拒绝 |
| RCFG-1 | valid replacement | H accepted，H+1 old validators，H+2 new validators；chain/key epoch正确 |
| RCFG-2 | invalid updates | signature/sequence/hash/height/count/power/duplicate/multi-replace 全部确定性拒绝 |
| RCFG-3 | boundary QC | H+1/H+2 两个真实 QC 分别使用 old/new set，不能互换历史 set |
| KEY-1 | provisioning | 角色、权限、文件 size、耗时被记录，secret 不进入 report/archive |
| KEY-2 | lost key recovery | 通过新 key + governance update恢复，不恢复未知 anti-double-sign state |
| REC-1 | clean/kill restart | `Info` 与 M1 metadata一致；无双重应用、无 AppHash分叉 |
| REC-2 | checkpoint replay | restore hash全验证；节点追到 current height且最终 AppHash一致 |

四节点正常实验不要求固定 bitmap 为 `0b1111`；CometBFT 实际 commit 可能只包含满足
阈值的 3 个及时签名。测试只要求 bitmap、CommitSig 与有效 voting power完全一致。

## 10. 必报成本与原始数据

M5 最终必须输出 machine-readable CSV/JSON 与 Markdown 汇总，至少包含：

- CometBFT/Rust crate 版本、binary SHA-256、chain ID、run ID、CPU/内存/OS；
- genesis/initial key provisioning wall time、每种 role 的 public/private/state 文件 size；
- tx received、included、FinalizeBlock、Commit、epoch close、QC available 分段时间；
- 一块 QC 认证延迟的 block count 与 wall time；
- signed header、Commit、signature vector、bitmap、validator set、config chain、完整
  QC envelope raw bytes；
- 4/4 与 3/4 commit 的 signer count、power、round、bitmap；
- replacement 的 proposal-to-accepted/effective blocks、wall time和无 commit pause；
- reconfiguration 前后 QC/bitmap/validator-set/config-chain bytes；
- clean restart、两个 `SIGKILL` 点、checkpoint restore、block replay、key-loss rotation
  的 wall time、恢复高度及可测的读写 bytes；
- 两节点离线期间的观察窗口与 height delta=0；
- 所有失败场景的 typed reason，不只记录 true/false。

原始报告不得包含 private key bytes、seed、完整 secret path 内容或环境 credential。
单机共置结果必须标注会低估网络成本，只支持功能和可复现性主张。

## 11. 子模块开发顺序与逐项审批

作者确认本需求文档后，也不能一次性实现全部 M5。严格按以下顺序进行；每一项提交
变更、测试、已知限制和 diff 摘要，作者确认后才进入下一项：

| 阶段 | 唯一交付 | 明确不做 |
| --- | --- | --- |
| M5.0 compatibility gate | 固定 CometBFT binary/source checksum；证明 Rust 0.40.4 可解析 v0.38.23 SignedHeader/ValidatorSet、生成一致 set hash/sign bytes并跑通最小 ABCI `Info/FinalizeBlock/Commit` probe | 不接 M4、不跑四节点 |
| M5.1 schema/state errata | 本文第 4 节 canonical types、golden vectors、动态 reconfiguration state、raw block result accumulator、M4 原子提交 | 不启动 CometBFT |
| M5.2 ABCI adapter | `lantern-comet` 的 Info/InitChain/proposal/Finalize/Commit/replay 单元与单节点 protocol tests | 不实现 QC service，不做四节点结论 |
| M5.3 independent QC | `lantern-qc`、QC envelope、bitmap、config-chain与 mutation fixtures；verifier-only dependency gate | 不实现 HTTP，不做 reconfiguration运行实验 |
| M5.4 reconfiguration | ABCI validator update、H+2 timeline、old/new QC boundary tests | 不做 key-loss运营流程 |
| M5.5 key/recovery | key generator/permissions、anti-double-sign规则、failpoints、checkpoint replay、rotation流程 | 不做 Docker/WAN/Krill/Routinator |
| M5.6 local 4-node acceptance | 本机四进程 harness、BFT/QC/fault/recovery完整矩阵、成本原始数据和 M5 报告 | 不扩展到 M6–M10 |

若 M5.0 发现 Rust library 与 v0.38.23 存在 wire/hash/sign-byte 不兼容，必须停止并由
作者在以下两条路线中另行选择：固定经过 byte-for-byte 对照的其他 Rust release，或增加
一个使用 CometBFT v0.38.23 官方 Go types 的最小验证 sidecar。不得在未确认时静默改为
自写 protobuf/signature implementation。

## 12. 每阶段通用质量门

- `cargo fmt --all --check`；
- `cargo test --workspace --all-targets --locked`；
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`；
- `lantern-qc` verifier-only `--no-default-features` 依赖图检查；
- canonical/golden/negative/property/mutation tests；
- CometBFT binary/source SHA-256 与 dependency lockfile；
- RustSec audit 与 dependency license inventory；
- 源码中 `unsafe_code = forbid`，禁止 `panic`/`unwrap` 进入可达恶意输入路径；
- secret scan：交付源码、报告、fixtures 和归档不含 operational/test runtime private key；
- 所有 integration test 有 bounded timeout、进程清理和可诊断日志。

## 13. M5 最终交付物

M5.6 通过后才生成：

- `crates/lantern-qc/`；
- `crates/lantern-comet/`；
- `crates/lantern-qc/M5_QC_INTERFACE.md`；
- `crates/lantern-comet/M5_ABCI_INTERFACE.md`；
- `M5_REQUIREMENTS_ERRATA.md`；
- `M5_REPORT.md`；
- `M5_COSTS.csv` 与 `M5_COSTS.json`；
- `M5_DEPENDENCY_LICENSES.tsv` 与 `M5_RUSTSEC_AUDIT.json`；
- 不含 secret/data/target 的 `lantern-m5.tar.gz` 及 SHA-256。

M5 报告必须明确列出本轮修改过的 M0/M4 文件及原因，不得把 prerequisite errata 隐藏
在 `lantern-comet` 私有代码中。

## 14. 作者确认清单

开始 M5.0 前，请作者一次性确认：

- [x] 接受 CometBFT `v0.38.23` 与 M5.0 Rust `0.40.4` compatibility gate；
- [x] 接受第 4 节 M4 窄接口勘误，因为不修改就无法让 validator update进入 AppHash；
- [x] 接受 `AppState_h.validator_config_hash` 精确定义为认证它的
  `Header_(h+1)` 所使用的 validator config；
- [x] 接受真实 Commit signature vector + derived signer bitmap，不把 bitmap描述成
  BLS/threshold signature aggregation；
- [x] 接受 2-of-3 governance、4 个等权 validator、一次替换一个、`H+2` 生效且禁止
  pipelined pending update；
- [x] 接受 M5 只做单机本地进程与离线 checkpoint restore，不做 WAN、Kubernetes、
  Docker Compose 或 ABCI state sync；
- [x] 接受 M5.0–M5.6 逐项实现、逐项验收，不一次性编码。

本清单已由作者确认。M5.0 的结果与边界见 `M5_0_REPORT.md`；作者验收 M5.0 后，下一步
只开始 **M5.1 schema/state errata**。
