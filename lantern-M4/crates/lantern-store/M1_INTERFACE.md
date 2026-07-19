# `lantern-store` M1 interface and persistence contract

## Scope

M1 is the only owner of the physical RocksDB database. M2 and M3 consume the
backend-neutral `ReadStore`, `SnapshotSource`, and `StoreBatch` APIs; they must
not open RocksDB or obtain raw column-family handles. M4 alone consumes the
`BlockStore` commit interface. M1 does not implement authenticated trees, state
transitions, CometBFT, services, Krill, or Routinator.

## Column-family layout

The database has an unused RocksDB `default` column family plus these required
families. Existing databases are opened only when the set is an exact match;
unknown and missing families are rejected instead of silently migrated.

| Stable name | Owner/content |
| --- | --- |
| `metadata` | Store identity and atomically committed block metadata |
| `records` | Immutable accepted transition records |
| `intent_archive` | Canonical publication intents |
| `latest_tree_nodes` | M2 latest-map nodes |
| `mmr_nodes` | M3 append-only MMR nodes |
| `proof_index` | Committed proof lookup indices |
| `idempotency` | Replay keys and committed outcomes |
| `config_reconfiguration` | Application and validator configuration data |
| `snapshots_manifest` | Snapshot manifest archive entries |

The database identity contains schema version 1, chain ID, and immutable
application configuration hash. Opening a database with a different identity
fails closed.

## Atomic write contract

`StoreBatch` contains owned put/delete operations and has no database handle.
It rejects empty/oversized keys, oversized values, duplicate `(CF,key)` pairs,
reserved metadata keys, over one million operations, and over 256 MiB of
key/value payload.

`RocksStore::commit_block` executes this sequence while holding one coordination
mutex:

1. validate metadata and immutable config binding;
2. read the previous committed metadata;
3. enforce successor height and non-regressing history/epoch state;
4. add the typed metadata entry to the same logical batch;
5. translate all operations into exactly one RocksDB `WriteBatch`;
6. call `DB::write_opt` once with WAL explicitly enabled.

There is no public metadata-free commit method. M2/M3 may add operations to a
shared batch but cannot persist a partial tree update independently of the
block metadata and the other authenticated structure.

`Durability::Wal` uses the enabled WAL without forcing the OS page cache;
`Durability::SyncWal` additionally sets RocksDB `sync=true`. Unordered writes
and manual WAL flushing are explicitly disabled. Atomic flush is enabled for
cross-column-family flush consistency.

The reserved block metadata contains, in one fixed-width big-endian value:
schema version, application height/AppHash, latest root, history root/size,
optional last-closed epoch/HeadID, validator configuration hash, and
application config hash. A presence byte distinguishes no closed epoch from
the valid first close `Some(0)`; epoch and HeadID must be simultaneously
present or absent. `current_metadata()` is therefore the single source for
ABCI `Info` after restart.

## Read snapshots

`SnapshotSource::read_snapshot` returns a lifetime-bound RocksDB snapshot that
implements the same `ReadStore` trait. Reads from that object remain at one
sequence number while later atomic commits become visible to the live store.
The wrapper does not expose the RocksDB handle.

## Physical checkpoints and restore

`create_checkpoint` holds the same coordination mutex as commit while reading
metadata and invoking RocksDB's checkpoint API. It writes a versioned JSON
manifest containing chain ID, store schema, height/AppHash, both roots and
history size, optional last-closed epoch/HeadID, validator/config hashes, and the sorted
size/SHA-256 tuple for every checkpoint file. A staging directory is fsynced and
renamed into place only after manifest creation succeeds.

`verify_checkpoint` applies a 1 MiB manifest limit and rejects unknown JSON
fields, wrong schema/chain/config, non-canonical hashes, traversal paths,
symlinks, special files, unsorted/duplicate paths, missing or extra files,
wrong sizes, and digest mismatches.

`restore_checkpoint` verifies first, copies into a sibling staging directory,
fsyncs it, opens the staged database with the expected identity, checks that
database commit metadata exactly matches the manifest, and only then renames
the staging directory to the requested destination. The destination must not
already exist.

## Crash model covered by M1

- Dropping a prepared `StoreBatch` models `FinalizeBlock` followed by process
  death before ABCI `Commit`: no key or metadata becomes visible after reopen.
- A child process writes a real WAL-backed RocksDB batch, reports that the
  write returned, and is then killed by the parent with `SIGKILL` before any
  Rust/C++ destructors run; reopen recovers all CF writes and typed commit
  metadata.
- Checkpoint corruption and wrong-chain restore fail before destination
  publication.

Power-loss durability is controlled by the caller: production consensus commit
uses `SyncWal` when it requires storage-device acknowledgement. M1 does not
claim that `Wal` alone survives loss of the OS page cache or storage hardware.
