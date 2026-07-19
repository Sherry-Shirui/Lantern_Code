# Lantern implementation

This workspace is intentionally limited to the approved M0 module.

`lantern-types` defines Lantern v1 wire objects, deterministic CBOR encoding,
domain-separated SHA-256 identifiers, strict Ed25519 control/governance
signatures, and cross-process test vectors. It does not contain storage,
authenticated trees, consensus, services, Krill, or Routinator code.

## M0 commands

```sh
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Golden vectors are checked in at
`crates/lantern-types/test-vectors/v1.json`. The regeneration example prints a
candidate vector document to standard output; updating the checked-in file is
an explicit review step.

