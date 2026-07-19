# Lantern M5.0 compatibility gate report

Date: 2026-07-19  
Verdict: **PASS — CometBFT v0.38.23 and tendermint-rs 0.40.4 are compatible for the tested v0.38 wire/hash/sign-byte and ABCI paths.**  
Next action: stop at the M5.0 boundary and wait for author approval before M5.1.

## 1. Scope actually completed

M5.0 implemented only the compatibility gate frozen in `M5_REQUIREMENTS.md`:

- pinned the official CometBFT tag, full Git commit, deterministic source
  archive digest, Linux/amd64 binaries, Go version, Rust version, and all four
  `tendermint-rs` crates;
- generated a deterministic four-validator `SignedHeader` and `ValidatorSet`
  using the official CometBFT Go types at the pinned commit;
- required Go `ValidateBasic` and `ValidatorSet.VerifyCommit` to pass before a
  fixture can be emitted;
- parsed the exact Go protobuf bytes with `tendermint-proto` 0.40.4 and converted
  them with `tendermint` 0.40.4;
- independently matched header hash, validator-set hash, four canonical vote
  sign-byte strings, four Ed25519 signatures, canonical validator order,
  voting power, strict `>2/3` threshold, and LSB-first signer bitmap;
- ran the official v0.38.23 `abci-cli` over loopback TCP against a Rust
  `tendermint-abci` 0.40.4 probe for `Info -> FinalizeBlock -> Commit -> Info`.

No M4 source was connected or modified for consensus. No validator node,
four-node network, live-chain QC, reconfiguration, key lifecycle, recovery,
Krill, Routinator, WAN, Docker, or Kubernetes claim is made.

## 2. Pinned identity and checksums

| Item | Exact value |
| --- | --- |
| CometBFT tag | `v0.38.23` |
| CometBFT full commit | `feb2aea4dc271d612129afc958cb844713ec792b` |
| `git archive` SHA-256 | `a5e53329b0abcd02b4ccdcadc2bc1c232af26922f1f2aff143245ad50a39e048` |
| `cometbft` SHA-256 | `6027531d6420abcfbff11a3e5b4071ac0bde139f35bb021241153ab943026ecc` |
| official `abci-cli` SHA-256 | `8fbe463ba125624c3a9f4330f0305df7209074d96b3eb8ae9f6d1081b7faf3bb` |
| reference fixture SHA-256 | `d3ff1cc6142c3b4f922d3bfde5fd01f94b1ba883613921e428b6e38425b9c0e8` |
| `Cargo.lock` SHA-256 | `628d8d7e3f633bf01af275475e87b8052c9b8920c0a0bcb97a6511e74decd205` |
| Go | `go1.22.11`, official Linux/amd64 tar SHA-256 `0fc88d966d33896384fbde56e9a8d80a305dc17a9f48f1832e061724b1719991` |
| Rust | `rustc 1.97.1 (8bab26f4f ...)` |
| Rust family | `tendermint`, `tendermint-proto`, `tendermint-rpc`, `tendermint-abci` all `0.40.4` |
| Protobuf runtime | `prost 0.13.5` |

The machine-readable copy is `tools/m5-compat/UPSTREAM.lock`; exact crate
resolution is additionally frozen by `Cargo.lock`.

## 3. Cross-language evidence

The reference block uses chain ID `lantern-m5-compat`, height 42, round 2,
four equal-power Ed25519 validators, and four valid commit votes.

| Assertion | Go reference | Rust recomputation | Result |
| --- | --- | --- | --- |
| Header hash | `7a194a6df13e93655871baaefd14f1fba247b56e29735fb758144b4f8eab32e6` | identical | PASS |
| Validator-set hash | `e07f0a7bc6ae4cc614e464793aca9a11ff3d41ff1e9bde58cd843fdcccae2e51` | identical | PASS |
| Canonical vote sign bytes | 4 byte strings | all 4 identical | PASS |
| Ed25519 signatures | Go-generated | all 4 independently verified | PASS |
| Voting power | signed 4 / total 4 | `4 * 3 > 4 * 2` | PASS |
| Signer bitmap | LSB-first `0f` | derived `0f` | PASS |
| Protobuf round trip | Go gogo/protobuf v0.38 bytes | prost decode/re-encode | byte-identical |

Negative tests change only one property at a time:

- one commit signature bit changed: rejected by Ed25519 verification;
- expected validator-set hash changed: rejected by equality check;
- `SignedHeader` protobuf truncated: rejected during v0.38 decode.

## 4. ABCI wire evidence

The probe used the official `abci-cli` built at the pinned commit, not an
in-process Rust client. The observed transcript was:

```json
{
  "info_calls": 2,
  "finalize_calls": 1,
  "commit_calls": 1,
  "tx_count": 2,
  "pending_height": null,
  "committed_height": 1,
  "committed_app_hash_hex": "7392e10f93c1d84eee076859825d972450d7540edda342e8f6dd6c9d688ffbb6"
}
```

The AppHash printed in the official `FinalizeBlock` response matched the
committed transcript value. Both `Info` calls returned the probe application
identity, and every client command exited successfully.

## 5. Tests run

The M5.0-specific results were:

```text
cargo test -p lantern-comet-compat --all-targets --all-features --locked
4 passed; 0 failed

cargo clippy -p lantern-comet-compat --all-targets --all-features --locked -- -D warnings
PASS

run-abci-wire-probe.sh
M5.0 ABCI v0.38 socket probe: PASS
```

`run-gate.sh` also regenerates the Go fixture and requires byte-for-byte `cmp`
equality before running the Rust and ABCI checks. The complete workspace
regression also passed:

```text
cargo fmt --all --check
PASS

cargo test --workspace --all-targets --locked
67 passed; 0 failed

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
PASS
```

The normal-dependency tree of `lantern-comet-compat` contains none of
`lantern-types`, `lantern-store`, `lantern-latest-map`, `lantern-history`, or
`lantern-state`, confirming that the gate did not couple itself to M1--M4.

`cargo-audit 0.22.2` checked 225 lockfile dependencies against advisory DB
commit `b5fc89b8be99e96f79194d8a6f11e9b4143b99f0`: 0 vulnerabilities and one
informational unmaintained warning, `RUSTSEC-2024-0436` for `paste 1.0.15`.
That crate is pulled transitively and unavoidably by `flex-error 0.4.4` in the
frozen `tendermint-rs` 0.40.4 family. It is not a vulnerability, but production
M5 must continue tracking it instead of suppressing it. Raw results are in
`M5_0_RUSTSEC_AUDIT.json`.

`cargo-license 0.7.0` emitted 225 dependency rows in
`M5_0_DEPENDENCY_LICENSES.tsv`. The final archive validation additionally
checks its manifest and scans for runtime secrets.

## 6. Upstream metadata discrepancy

The exact official `v0.38.23` tag resolves to the required full commit, and
the checkout was clean. However, that commit's `version/version.go` still sets
`TMCoreSemVer = "0.38.22"`; consequently the pinned binary reports:

```json
{
  "cometbft": "0.38.22+feb2aea",
  "abci": "2.0.0",
  "block_protocol": 11,
  "p2p_protocol": 8
}
```

M5.0 does not patch upstream metadata. Reproducible identity therefore relies
on exact tag, full commit, source-archive SHA-256, build recipe, and binary
SHA-256. This discrepancy is a reporting limitation, not a wire/hash/sign-byte
incompatibility.

## 7. Known limitations and next-stage boundary

- The fixture is synthetic and deterministic. Its private keys exist only in
  the Go generator process and are not saved or archived; this is not an
  operational key-provisioning test.
- All four fixture validators sign. Nil/absent votes, partial 3-of-4 commits,
  malicious signer bitmaps, trusted validator-chain evolution, and QC envelope
  mutation belong to M5.3 and later.
- `abci-cli finalize_block` does not expose a height argument. The probe maps
  its zero-height test request to the next local height solely to demonstrate
  v0.38 method framing and response compatibility. Real height/replay semantics
  belong to the M5.2 adapter.
- The probe is intentionally in `tools/m5-compat`, has no M1--M4 dependency,
  and must not be promoted as the production ABCI application.
- No conclusion is drawn about live CometBFT consensus, BFT liveness,
  reconfiguration, recovery, WAN behavior, Krill, or Routinator.

The compatibility fallback in the requirements is not triggered: the tested
Rust 0.40.4 path is compatible, so neither a different Rust release nor a Go
verification sidecar is needed. M5.1 must still wait for explicit author
approval.

## 8. Source diff summary

- root `Cargo.toml`/`Cargo.lock`: pin the 0.40.4 family and add only the isolated
  M5.0 tool member;
- `.gitignore`: exclude M5 checkout, toolchain, build, and cache directories;
- `tools/m5-compat/reference/main.go`: official-Go fixture generator;
- `tools/m5-compat/src/lib.rs`: independent v0.38 parser/hash/signature gate;
- `tools/m5-compat/src/bin/*`: evidence CLI and minimal ABCI probe server;
- `tools/m5-compat/tests/reference_fixture.rs`: one positive and three
  fail-closed tests;
- `tools/m5-compat/scripts/*`: pinned build, vector regeneration, ABCI probe,
  and one-command gate;
- documentation: this report, isolated-tool README, upstream lock, root README,
  confirmed M5 requirements status, RustSec output, and dependency-license
  inventory.

No `crates/lantern-*` M0--M4 source file was changed by M5.0.

## 9. Archive controls

The source archive is built reproducibly with sorted paths, a fixed UTC mtime,
numeric owner/group zero, and a single `lantern-m5.0/` root. It excludes
`target`, `.m5-cache`, `.m5-cargo-home`, `.m5-toolchains`, `.git`, runtime
transcripts, downloaded packages, compiled binaries, and all temporary native
toolchains.

A pre-archive scan found no PEM private-key block, CometBFT `priv_key` JSON,
mnemonic/secret assignment, GitHub token, or AWS access-key pattern in the
included source tree. Post-creation validation requires every archive path to
remain under the single root and rejects any excluded directory or generated
binary. The archive SHA-256 is delivered alongside the archive rather than
embedded here, avoiding a self-referential digest.

## 10. Workspace recovery and bounded-run hardening

On 2026-07-19, a later workspace inspection found that the active scratch tree
contained only the M0 source and an empty `.git` placeholder, even though the
persisted M5.0 archive and report had already been produced. The persisted
archive passed its companion SHA-256 check and remained the last authoritative
M5.0 checkpoint. No Cargo, Clippy, Go, CometBFT, ABCI, Docker/Podman, download,
or log-follow process was still running, and no project container runtime was
available in that workspace.

The apparent stall was therefore not a compatibility or test failure. The last
successful operation was the completed M5.0 regression/Clippy pass followed by
source packaging. The recoverable operational defect was that the reproduction
scripts allowed several child commands to run without deadlines.

The recovered source adds fail-closed, configurable deadlines to:

- CometBFT clone and build;
- Go fixture generation;
- Cargo test, run, and build commands;
- the ABCI probe server lifetime, readiness check, each client request, log
  read, and shutdown; and
- the outer compatibility-gate steps.

The ABCI probe server remains a background process and is now supervised by a
finite lifetime plus bounded TERM/KILL cleanup. No unbounded health loop,
foreground service, log follow, or child-process wait remains in the M5.0
scripts.

Per the recovery instruction, the compatibility gate was **not re-executed**.
Only archive integrity, script syntax, timeout-policy inspection, and source
manifest checks were performed after recovery. The cryptographic and ABCI
PASS evidence in Sections 3--5 is the already completed checkpoint, not a new
run.
