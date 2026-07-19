# M5.0 compatibility gate

This directory is an isolated, disposable gate between pinned CometBFT Go
`v0.38.23` and the Rust `tendermint-rs` `0.40.4` family. It is not
`lantern-qc`, is not `lantern-comet`, and has no dependency on Lantern M1--M4.

## What the gate proves

The Go reference generator runs inside the exact upstream CometBFT checkout.
It deterministically creates four Ed25519 validators, a height-42 v0.38
`SignedHeader`, a canonical `ValidatorSet`, and four precommit signatures. The
Go implementation first runs `SignedHeader.ValidateBasic` and
`ValidatorSet.VerifyCommit`, then writes the protobuf bytes and expected
hash/sign-byte values to the checked-in JSON fixture.

The Rust gate independently:

1. decodes and canonically re-encodes the v0.38 `SignedHeader` and
   `ValidatorSet` protobuf messages;
2. converts them with `tendermint` 0.40.4 domain types;
3. recomputes the header and validator-set hashes;
4. reconstructs every canonical precommit sign-byte string;
5. verifies every Ed25519 signature, validator address/order, voting power,
   strict `>2/3` threshold, and LSB-first signer bitmap;
6. rejects a mutated signature, a mismatched validator hash, and truncated
   protobuf bytes.

The separate probe server implements only `Info`, `FinalizeBlock`, and
`Commit`. `run-abci-wire-probe.sh` calls it with the `abci-cli` built from the
same pinned CometBFT source and checks the response AppHash and server-side
method transcript.

## Reproduce

Install exactly Go 1.22.11 and Rust 1.97.1, then run from the repository root:

```sh
timeout --signal=TERM --kill-after=10s 35m \
  bash tools/m5-compat/scripts/run-gate.sh
```

The scripts also enforce inner deadlines. Defaults are: download `5m`, build
and test `20m`, fixture generation and verifier run `5m`, ABCI probe `2m`,
background probe-server lifetime `60s`, readiness and each ABCI request `10s`,
log reads and shutdown `5s`, and short metadata commands `30s`. Override them
with the `M5_*_TIMEOUT` environment variables defined in the scripts. A
timeout fails closed with a non-zero exit status.

Individual steps are:

```sh
timeout --signal=TERM --kill-after=10s 25m \
  bash tools/m5-compat/scripts/fetch-build-comet.sh
timeout --signal=TERM --kill-after=10s 10m \
  bash tools/m5-compat/scripts/generate-reference.sh
timeout --signal=TERM --kill-after=10s 20m \
  cargo test -p lantern-comet-compat --all-targets --all-features --locked
timeout --signal=TERM --kill-after=10s 5m \
  cargo run -p lantern-comet-compat --bin m5-compat-probe --locked
timeout --signal=TERM --kill-after=10s 20m \
  cargo build -p lantern-comet-compat --bin m5-abci-probe-server \
  --features abci-probe --locked
timeout --signal=TERM --kill-after=10s 2m \
  bash tools/m5-compat/scripts/run-abci-wire-probe.sh
```

The ABCI probe server is always started in the background under a `60s`
supervisor and is terminated through a bounded `5s` shutdown path. No script
uses an unbounded readiness loop or foreground service.

Generated upstream checkouts, toolchains, binaries, build output, runtime
transcripts, and runtime keys are excluded by `.gitignore` and must not enter
the source archive.

## Deliberate boundary

M5.0 does not start a CometBFT validator, connect M4, produce a live-chain QC,
exercise nil/absent commits, run four nodes, reconfigure validators, or test
recovery. Those belong to M5.1--M5.6 and require separate author approval.

The pinned `v0.38.23` commit contains an upstream metadata inconsistency:
`version.TMCoreSemVer` is still `0.38.22`, so the correctly pinned binary
reports `0.38.22+feb2aea`. The gate does not patch that source. Identity is
established by exact tag, full commit, source-archive SHA-256, and binary
SHA-256 recorded in `UPSTREAM.lock`.
