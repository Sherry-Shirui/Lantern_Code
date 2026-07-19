# `lantern-latest-map` M2 interface and proof contract

## Scope and dependency boundary

M2 implements only the latest-state authenticated map. It does not implement
the MMR, state transitions, entry-count policy, CometBFT, HTTP, Krill, or
Routinator.

The crate has two compile-time layers:

- the always-available proof layer derives keys, frames leaf values, decodes
  and verifies proofs, and depends on M0 plus pure Rust crypto/codec crates;
- the default `storage` feature adds `LatestMap`, the JMT reader adapter, and
  `PreparedLatestUpdate`, and depends on M1's `ReadStore` and `StoreBatch`.

`cargo test -p lantern-latest-map --no-default-features --lib --locked` is the
independent-verifier gate. Its dependency graph contains neither
`lantern-store` nor `rocksdb`.

## Cryptographic inputs

For a 32-byte `CA_ID`, M2 computes:

```text
LatestKey = SHA-256(M0-domain-frame("lantern/v1/latest-key", CA_ID))
```

Those 32 bytes are passed directly to JMT as `KeyHash`; M2 does not hash the
derived key a second time. A non-empty canonical latest-state value is first
encoded as:

```text
M0-domain-frame("lantern/v1/latest-leaf", canonical_latest_value)
```

and that framed byte string is JMT's value. Thus Lantern's protocol domains
remain distinct from JMT 0.12.0's own `JMT::LeafNode` and internal-node hash
domains. The raw value is limited to 1 MiB at M2; M4 may impose a smaller
schema-specific bound.

## Version contract

- The first committed version is 0.
- Every prepared version must be exactly the committed version plus one.
- An empty mutation set still materializes a root node for the new version.
- Mutations are sorted by derived key before entering JMT.
- Duplicate or colliding keys in one version are rejected.
- Old nodes and value entries are retained; M2 performs no pruning.

Consequently, the same ordered transaction prefix produces byte-identical
roots and storage deltas on independent app replicas. One CA update changes a
JMT path rather than rebuilding history; its JMT work is `O(log C)`.

## Public write path

```text
LatestMap::prepare_update(version, mutations)
    -> PreparedLatestUpdate { root, stats, uncommitted writes }

PreparedLatestUpdate::append_to(&mut StoreBatch)
```

M2 never opens RocksDB and never commits independently. M4 must append the M2
and M3 deltas to one caller-owned `StoreBatch`, then use M1's `BlockStore` to
commit that batch with roots, counts, height, and `AppHash` metadata. If
`append_to` fails, the caller discards the partially populated batch.

## Historical read and proof path

```text
LatestMap::query_ca(ca_id, version) -> LatestQueryV1
LatestQueryV1::verify()              -> storage-free verification
verify_latest_proof(root, key, value, proof)
```

`Some(value)` requests membership; `None` requests non-membership. Query
generation verifies its own result before returning, so corrupt node/value
storage fails closed. JMT traversal is `O(log C)`. Per-key values use an
append-only ordinal index and binary search, so a historical value lookup adds
`O(log U_CA)` point reads for `U_CA` updates to that CA.

## Proof envelope

`LatestProofV1` is an opaque envelope:

| Field | Encoding |
| --- | --- |
| magic | 8 bytes, `LNLTPRF\0` |
| format version | 2-byte big-endian, value 1 |
| body length | 4-byte big-endian |
| body | strict Borsh encoding of `jmt 0.12.0` `SparseMerkleProof<Sha256>` |

The complete envelope is limited to 32 KiB. Decoding rejects bad magic,
unknown versions, length mismatch, trailing bytes, oversized input, and
invalid Borsh. Updating JMT or changing its proof representation requires a
new Lantern proof-envelope version and new compatibility vectors.

## `latest_tree_nodes` key space

All entries live only in M1's `latest_tree_nodes` column family.

| Prefix/key | Value | Purpose |
| --- | --- | --- |
| `lantern/latest/v1/node/` + Borsh `NodeKey` | Borsh `Node` | Versioned JMT nodes |
| `lantern/latest/v1/value-count/` + key | `u64be` | Number of history entries for one key |
| `lantern/latest/v1/value/` + key + ordinal | version/tag/length/value | Append-only value/tombstone history |
| `lantern/latest/v1/stale/` + Borsh index | empty | Retained stale-node index; no pruning in M2 |
| `lantern/latest/v1/root/` + `u64be(version)` | 32-byte root | Exact historical root |
| `lantern/latest/v1/latest-version` | `u64be` | Successor-version guard |

Node, value, stale-index, root, and latest-version puts are deterministic and
are appended to the same M1 batch. No M2 operation targets another column
family.

## Security/validation behavior

- Proof verification requires the exact root, derived key, raw value, and
  proof; mutations of any component fail.
- Wrong-domain keys and raw, unframed leaf values fail.
- Non-membership cannot be substituted for membership or vice versa.
- Missing historical roots, malformed persisted nodes, broken value indices,
  invalid length/tag fields, and a generated proof inconsistent with its root
  are typed errors.
- Storage is not trusted by the verifier, and the proof service introduced in
  M6 will not become a trust root.
