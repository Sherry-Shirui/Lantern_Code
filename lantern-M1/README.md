# Lantern implementation

This workspace is intentionally limited to the approved M0 and M1 modules.

`lantern-types` defines Lantern v1 wire objects, deterministic CBOR encoding,
domain-separated SHA-256 identifiers, strict Ed25519 control/governance
signatures, and cross-process test vectors.

`lantern-store` defines the RocksDB column-family layout, backend-neutral read
and atomic-write traits, typed commit metadata, WAL-backed atomic batches,
consistent read snapshots, and verified checkpoint/restore. It deliberately
does not contain authenticated trees, consensus, services, Krill, or
Routinator code.

## M0/M1 commands

```sh
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

`rocksdb 0.24.0` builds bundled RocksDB 10.4.2. On Ubuntu 24.04 the native
build requires GCC/G++ 13 and libclang 18 (including Clang's resource headers).
The final container image will pin these system packages and its base-image
digest in M9; they are not vendored into this source tree.

Golden vectors are checked in at
`crates/lantern-types/test-vectors/v1.json`. The regeneration example prints a
candidate vector document to standard output; updating the checked-in file is
an explicit review step.
