#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
SOURCE="${COMET_SOURCE:-$ROOT/.m5-cache/cometbft-v0.38.23}"
EXPECTED_FIXTURE="$ROOT/tools/m5-compat/test-vectors/cometbft-v0.38.23.json"
REGENERATED_FIXTURE="$ROOT/target/m5-compat/regenerated-cometbft-v0.38.23.json"
SCRIPT_TIMEOUT="${M5_SCRIPT_TIMEOUT:-30m}"
TEST_TIMEOUT="${M5_TEST_TIMEOUT:-20m}"
RUN_TIMEOUT="${M5_RUN_TIMEOUT:-5m}"
BUILD_TIMEOUT="${M5_BUILD_TIMEOUT:-20m}"
PROBE_TIMEOUT="${M5_PROBE_TIMEOUT:-2m}"
COMMAND_TIMEOUT="${M5_COMMAND_TIMEOUT:-30s}"

run_with_timeout() {
  local duration="$1"
  shift
  timeout --signal=TERM --kill-after=10s "$duration" "$@"
}

if [[ ! -x "${ABCI_CLI:-$ROOT/.m5-toolchains/bin/abci-cli}" ]]; then
  run_with_timeout "$SCRIPT_TIMEOUT" \
    bash "$ROOT/tools/m5-compat/scripts/fetch-build-comet.sh"
fi
mkdir -p "$(dirname -- "$REGENERATED_FIXTURE")"
run_with_timeout "$SCRIPT_TIMEOUT" \
  bash "$ROOT/tools/m5-compat/scripts/generate-reference.sh" \
  "$SOURCE" "$REGENERATED_FIXTURE"
run_with_timeout "$COMMAND_TIMEOUT" cmp "$EXPECTED_FIXTURE" "$REGENERATED_FIXTURE"

run_with_timeout "$TEST_TIMEOUT" cargo test -p lantern-comet-compat \
  --all-targets --all-features --locked
run_with_timeout "$RUN_TIMEOUT" cargo run -p lantern-comet-compat \
  --bin m5-compat-probe --locked -- "$EXPECTED_FIXTURE"
run_with_timeout "$BUILD_TIMEOUT" cargo build -p lantern-comet-compat \
  --bin m5-abci-probe-server --features abci-probe --locked
run_with_timeout "$PROBE_TIMEOUT" \
  bash "$ROOT/tools/m5-compat/scripts/run-abci-wire-probe.sh"

echo "M5.0 compatibility gate: PASS"
