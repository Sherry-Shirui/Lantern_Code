#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
COMMIT="feb2aea4dc271d612129afc958cb844713ec792b"
TAG="v0.38.23"
SOURCE="${1:-${COMET_SOURCE:-$ROOT/.m5-cache/cometbft-v0.38.23}}"
OUTPUT_INPUT="${2:-$ROOT/tools/m5-compat/test-vectors/cometbft-v0.38.23.json}"
GENERATE_TIMEOUT="${M5_GENERATE_TIMEOUT:-5m}"
COMMAND_TIMEOUT="${M5_COMMAND_TIMEOUT:-30s}"

run_with_timeout() {
  local duration="$1"
  shift
  timeout --signal=TERM --kill-after=10s "$duration" "$@"
}

if [[ ! -d "$SOURCE/.git" ]]; then
  echo "missing CometBFT checkout: $SOURCE" >&2
  exit 1
fi
if [[ "$(run_with_timeout "$COMMAND_TIMEOUT" git -C "$SOURCE" rev-parse HEAD)" != "$COMMIT" ]]; then
  echo "refusing to generate vectors from a source other than $COMMIT" >&2
  exit 1
fi
if [[ "$(run_with_timeout "$COMMAND_TIMEOUT" git -C "$SOURCE" describe --tags --exact-match HEAD)" != "$TAG" ]]; then
  echo "refusing to generate vectors without exact tag $TAG" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$OUTPUT_INPUT")"
OUTPUT_DIR="$(cd -- "$(dirname -- "$OUTPUT_INPUT")" && pwd)"
OUTPUT="$OUTPUT_DIR/$(basename -- "$OUTPUT_INPUT")"
GENERATOR="$ROOT/tools/m5-compat/reference/main.go"
(
  cd "$SOURCE"
  run_with_timeout "$GENERATE_TIMEOUT" env GOTOOLCHAIN=local \
    go run "$GENERATOR" "$OUTPUT"
)
run_with_timeout "$COMMAND_TIMEOUT" sha256sum "$OUTPUT"
