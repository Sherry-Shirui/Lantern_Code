# `lantern-history` M3 interface and proof contract

## Scope and dependency boundary

M3 implements only Lantern's append-only history Merkle Mountain Range (MMR).
It does not implement latest-state lookup, state transitions, epoch closure,
`AppHash`, CometBFT/QC, HTTP, Krill, or Routinator.

The crate has two compile-time layers:

- the always-available proof layer hashes history records, decodes proofs, and
  verifies inclusion and append consistency using only M0 and pure Rust code;
- the default `storage` feature adds `HistoryLog`, proof generation, and
  prepared writes through M1's `ReadStore` and `StoreBatch`.

The proof-only dependency graph must contain neither `lantern-store` nor
`rocksdb`. M3 never opens a database and never commits a batch.

## Lantern MMR v1

Leaves have stable zero-based indices. A leaf at index `i` commits the exact
canonical compact history-record bytes `record` as:

```text
HistoryLeafHash(i, record) =
    H(M0-domain-frame("lantern/v1/history-leaf",
      0x00 || u64be(i) || u64be(len(record)) || record))
```

`record` must be non-empty and no larger than 1 MiB. M4 freezes the
`HistoryRecordV1` schema and supplies its deterministic CBOR bytes to M3.

When two adjacent perfect subtrees of height `h-1` merge, their parent is:

```text
HistoryParentHash(h, left, right) =
    H(M0-domain-frame("lantern/v1/history-node",
      0x00 || u8(h) || left || right))
```

The root commits the leaf count and the complete left-to-right peak list:

```text
HistoryRoot(n, peaks) =
    H(M0-domain-frame("lantern/v1/history-node",
      0x01 || u64be(n) || u16be(peak_count) ||
      each(u8(peak_height) || peak_hash)))
```

Peak heights are the set bits of `n` in descending order. This explicit
bagging rule makes the empty root, tree size, peak order, and peak heights
unambiguous. The empty history root is the same formula with `n=0` and no
peaks.

M3 supports at most `2^63` leaves. Nodes use the standard zero-based MMR
postorder position and are only appended. The node count after `n` leaves is
`2*n - popcount(n)`.

## Public write path

```text
HistoryLog::prepare_append(records)
    -> PreparedHistoryAppend { start/end size, root, stats, uncommitted writes }

PreparedHistoryAppend::append_to(&mut StoreBatch)
```

Records are appended in caller order. For every non-empty append, M3 writes
new postorder nodes, each new prefix root, and the final current size/root. It
checks that every would-be new node and prefix-root key is absent before
preparing the update. It never deletes or overwrites a historical node, leaf,
or prefix root. An empty append is a no-op returning the current state.

M4 must place M2, M3, records, archives, indices, and block metadata in one
caller-owned M1 `StoreBatch` and commit it once through `BlockStore`.

## Inclusion proof

```text
HistoryLog::inclusion_query(record, leaf_index, leaf_count)
HistoryInclusionQueryV1::verify()
verify_history_inclusion(root, record, proof)
```

An inclusion proof contains the leaf index/count, the sibling path from the
leaf to its containing peak, and all MMR peak hashes. The verifier derives all
directions, the target peak, path length, peak count, and peak heights from the
index/count; these are not trusted proof inputs. Verification requires only
the root, exact record bytes, and proof.

Proof generation checks the persisted leaf hash against the supplied record
and verifies the generated proof before returning it. A malicious proof
service can therefore affect availability but cannot make an invalid record
verify.

## Append-consistency proof

```text
HistoryLog::consistency_query(old_size, new_size)
HistoryConsistencyQueryV1::verify()
verify_history_consistency(old_root, new_root, proof)
```

A consistency proof contains:

- all peaks that form the exact `old_size` root;
- the roots of a canonical maximal aligned perfect-subtree cover of
  `[old_size, new_size)`.

The verifier first reconstructs and checks `old_root`, then appends every
range subtree to the old peak stack using normal MMR carry/merge operations,
and finally reconstructs and checks `new_root`. The canonical range cover and
all subtree heights/positions are derived from the two sizes. Proof size is
`O(log N)` and does not grow linearly with the number of appended leaves.
`old_size == new_size` is allowed only as an identity proof with equal roots.

## Proof envelopes

Both proof types use a strict Lantern-owned binary envelope:

| Field | Encoding |
| --- | --- |
| magic | 8 bytes: `LNHINCL\0` or `LNHCONS\0` |
| format version | 2-byte big-endian, value 1 |
| body length | 4-byte big-endian |
| body | fixed integers/counts followed by 32-byte hashes |

The complete envelope is limited to 32 KiB. Decoders reject bad magic,
unknown versions, invalid counts, impossible index/size relationships,
non-canonical path lengths, length mismatch, trailing bytes, and oversized
input.

The inclusion body is:

```text
u64be(leaf_index) || u64be(leaf_count) ||
u16be(sibling_count) || u16be(peak_count) ||
sibling_hashes || peak_hashes
```

The consistency body is:

```text
u64be(old_size) || u64be(new_size) ||
u16be(old_peak_count) || u16be(appended_subtree_count) ||
old_peak_hashes || appended_subtree_hashes
```

Every hash is exactly 32 bytes. The verifier derives the only canonical count
for every vector from the sizes/index and rejects any alternative encoding.

## `mmr_nodes` key space

All entries live only in M1's `mmr_nodes` column family.

| Prefix/key | Value | Purpose |
| --- | --- | --- |
| `lantern/history/v1/node/` + `u64be(postorder_position)` | 32-byte hash | Immutable leaf/internal MMR node |
| `lantern/history/v1/root/` + `u64be(leaf_count)` | 32-byte root | Immutable exact-prefix root |
| `lantern/history/v1/current-size` | `u64be` | Current committed leaf count |
| `lantern/history/v1/current-root` | 32-byte root | Current committed root |

M3 does not store compact record bytes; M4 owns immutable records in M1's
`records` column family. M3 stores their domain-separated leaf commitments.

## Complexity and limits

- single-record append: `O(log N)` hashes and new nodes;
- inclusion proof generation/verification: `O(log N)`;
- append-consistency proof generation/verification: `O(log N)`;
- maximum leaves: `2^63`;
- maximum record: 1 MiB;
- maximum records per prepared append: 65,536;
- maximum aggregate input bytes per prepared append: 64 MiB;
- maximum encoded proof: 32 KiB.

M3 performs no pruning or compaction of logical history nodes. Physical
RocksDB compaction cannot change leaf indices because indices and postorder
positions are part of the authenticated/persisted structure.
