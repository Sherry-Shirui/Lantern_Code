# `lantern-state` M4 interface and transition contract

## Scope

M4 owns deterministic application transitions, canonical compact state
records, epoch closure, M2/M3 dual updates, transaction/idempotency results,
and `AppStateCommitmentV1`. It consumes M0 canonical types, M1 read/batch/commit
traits, M2 latest-map APIs, and M3 history APIs.

M4 does not implement CometBFT ABCI transport, Commit/QC verification,
validator reconfiguration, signer bitmap/key management, HTTP services,
Krill, Routinator, Compose, or performance evaluation. Those remain M5–M10.

## Required prerequisite corrections

- `ControlActionV1::Enable` includes a signature-bound
  `initial_admin_key`.
- M1 commit/snapshot metadata represents `last_closed_epoch` as
  `Option<u64>`, so `None` and `Some(0)` are distinct.

The detailed rationale and compatibility action are frozen in
`M4_REQUIREMENTS_ERRATA.md`.

## Canonical schemas

M4 extends the M0 canonical-schema owner with:

- `HistoryEventTypeV1`;
- `CaStatusV1`;
- `HistoryRecordV1`;
- `LatestValueV1`;
- `CaStateV1`;
- `PublicationTransactionV1` and `ControlTransactionV1`;
- `StateTransactionV1`;
- `TransactionResultV1` and stable result/rejection codes;
- `StateConfigV1`.

Every object uses a fixed definite-length CBOR array and strict decode,
validate, re-encode, byte-compare canonicality. Exact manifest, signature, and
EE-chain byte/item limits apply before state mutation.

## Publication authorization boundary

M4 calls a local `PublicationAuthorizer` for every publication transaction in
the deterministic block path. The authorizer receives exact manifest DER,
intent bytes/signature, EE certificate chain, and consensus block time. It
must repeat manifest CMS/chain validation, intent-signature verification under
the manifest EE key, CA_ID derivation, manifest number/hash extraction, and
algorithm agreement. No transaction carries a trusted `validated=true` bit.

M4 independently checks the returned derived CA_ID, manifest number/hash, and
signature algorithm against the canonical intent. The M7 RPKI/Krill adapter
will provide the production implementation; M4 fixtures use a deterministic
strict test authorizer.

## Transition rules

All accepted events allocate `version = last_version + 1` for that CA and
append exactly one immutable `HistoryRecordV1`.

| Event | Required pre-state | Result |
| --- | --- | --- |
| Enable | absent or disabled; non-terminal | enabled; binds initial/preauthorized admin key and expected next manifest hash |
| Publish | enabled; exact expected/predecessor hash | installs exact EE-authorized manifest as effective latest |
| Disable | enabled | disabled; effective manifest/history retained |
| Cancel | enabled; latest event is the targeted Publish | appends cancellation and restores that Publish's authenticated predecessor |
| Rollover | enabled/disabled; successor CA absent | old CA terminal; successor admin key preauthorized; old latest links successor |
| Terminal | enabled/disabled | permanently terminal; no self-reversal |

Control events require exact next admin sequence, exact previous CA-state hash,
and strict Ed25519 authorization. Initial Enable verifies with the embedded
key; later events verify with the registered current key. A terminal CA rejects
all later events. Cancel preserves the target publication and its archive in
history and does not claim that repository delivery did or did not occur.

## Deterministic block pipeline

`StateMachine::prepare_block` performs, in order:

1. load and cross-check committed M4/M2/M3 state;
2. enforce successor height and monotonic consensus time;
3. close every due epoch before current-block transactions;
4. process typed transactions in CometBFT block order;
5. stage immutable records/archive/index/idempotency results;
6. call M2 once with each affected CA's final latest value;
7. call M3 once with all accepted compact records in order;
8. append M2, M3, M4, head, and metadata writes to one M1 `StoreBatch`;
9. build and validate `AppStateCommitmentV1` and its `AppHash`;
10. return `PreparedBlock`, which remains invisible until consumed by
    `PreparedBlock::commit` through M1 `BlockStore`.

Rejected transactions do not change CA/latest/history/admin state. Their
stable result codes are included in the transaction-result accumulator so
all replicas commit identical block results. Exact idempotency replay returns
the original result; the same CA/nonce with different canonical bytes is
rejected without overwriting the mapping.

Every accepted publication retains its exact canonical transaction in the M1
intent archive. Every accepted control record retains the exact canonical
`ControlTransactionV1` under its `authorization_digest` in the immutable
records column family. This is required so P2 and Cancel-derived P3 proofs can
verify the administrative signature instead of trusting only the compact
status value.

## Epoch semantics

`StateConfigV1` selects exactly one profile:

- integration: `Delta = 30s`;
- paper: `Delta = 300s`.

Epoch `e` covers `[genesis + e*Delta, genesis + (e+1)*Delta)`. At block time
`t`, all not-yet-closed epochs strictly earlier than `epoch(t)` close against
the pre-block M2/M3 roots. Current-block transactions are assigned to
`epoch(t)` and therefore cannot leak into a previously ended head.

Each `HeadBodyV1` binds both roots, history/latest counts, the ordered admitted
transaction bundle hash, key epoch, time interval, and previous `HeadID`.
`HeadID = H(head-body)` excludes QC. `AppStateCommitmentV1` binds the post-block
pending roots plus the last closed HeadID. M5 applies the one-block CometBFT QC
binding; M4 never fabricates a QC.

## Atomicity and recovery

The only persistence path is:

```text
prepare_block(...) -> PreparedBlock
PreparedBlock::commit(store, durability) -> CommitReceipt
```

Dropping `PreparedBlock` models a crash after FinalizeBlock and before Commit:
no M2/M3/M4 state is visible. M1 commits the shared batch and typed metadata in
one WAL-backed write. On reopen, M4 cross-checks its global state against the
M1 commit metadata and the exact M2/M3 roots/sizes before accepting the next
height.

## P1–P7 fixture boundary

M4 produces deterministic authenticated fixtures for all predicates:

- P1: absent/stale closed head;
- P2: authenticated disabled/legacy latest value;
- P3: enabled latest value matching the observed manifest;
- P4: authenticated older record within grace;
- P5: authenticated older record beyond grace while latest differs;
- P6: absent requested admission record/proof index;
- P7: conflicting head bodies have distinct HeadIDs, while four honest replicas
  cannot diverge for the same ordered input.

Final QC/proof-package/network evaluation and Routinator routing effects remain
M5/M6/M8; M4 fixtures must not be reported as end-to-end enforcement results.
