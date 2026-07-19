# Lantern implementation

This workspace is intentionally limited to the approved M0 through M4
modules.

`lantern-types` defines Lantern v1 wire objects, deterministic CBOR encoding,
domain-separated SHA-256 identifiers, strict Ed25519 control/governance
signatures, and cross-process test vectors.

`lantern-store` defines the RocksDB column-family layout, backend-neutral read
and atomic-write traits, typed commit metadata, WAL-backed atomic batches,
consistent read snapshots, and verified checkpoint/restore.

`lantern-latest-map` defines the versioned JMT latest-state map, historical
membership/non-membership queries, a deterministic proof envelope, and a
storage-independent verifier. Its `storage` feature is the only part that
depends on `lantern-store`; `--no-default-features` builds and tests the
verifier without RocksDB.

`lantern-history` defines the append-only MMR history, stable zero-based leaf
indices, exact-prefix roots, membership proofs, old-root-to-new-root append
consistency proofs, and storage-independent verifiers. Its `storage` feature
uses only M1's read and shared-batch interfaces; `--no-default-features`
builds and tests both history proof verifiers without RocksDB.

`lantern-state` defines deterministic application transitions, the strict
publication-authorizer boundary, control lifecycle, epoch closure, idempotent
results, M2/M3 dual update, and the single M1 atomic commit path. It emits
head bodies and AppState/AppHash commitments but deliberately emits no QC.

The workspace does not yet contain CometBFT consensus/QC, reconfiguration,
network services, Krill, or Routinator integration; those begin at M5.

## M0–M4 commands

```sh
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo test -p lantern-latest-map --no-default-features --lib --locked
cargo test -p lantern-history --no-default-features --lib --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

`crates/lantern-state/M4_INTERFACE.md` freezes the transition, epoch,
authorization, and persistence contracts. `M4_REQUIREMENTS_ERRATA.md` records
the signed initial-admin-key and epoch-zero-presence prerequisites.

`rocksdb 0.24.0` builds bundled RocksDB 10.4.2. On Ubuntu 24.04 the native
build requires GCC/G++ and libclang 18, including Clang's resource headers.
The final container image will pin these system packages and its base-image
digest in M9; they are not vendored into this source tree.

Golden M0 vectors are checked in at
`crates/lantern-types/test-vectors/v1.json`. The regeneration example prints a
candidate vector document to standard output; updating the checked-in file is
an explicit review step.
