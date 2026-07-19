# Lantern implementation

This workspace is intentionally limited to the approved M0, M1, and M2
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

The workspace does not yet contain the MMR history, deterministic state
machine, consensus, services, Krill, or Routinator integration.

## M0–M2 commands

```sh
cargo fmt --all --check
cargo test --workspace --all-targets --locked
cargo test -p lantern-latest-map --no-default-features --lib --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

`rocksdb 0.24.0` builds bundled RocksDB 10.4.2. On Ubuntu 24.04 the native
build requires GCC/G++ and libclang 18, including Clang's resource headers.
The final container image will pin these system packages and its base-image
digest in M9; they are not vendored into this source tree.

Golden M0 vectors are checked in at
`crates/lantern-types/test-vectors/v1.json`. The regeneration example prints a
candidate vector document to standard output; updating the checked-in file is
an explicit review step.
