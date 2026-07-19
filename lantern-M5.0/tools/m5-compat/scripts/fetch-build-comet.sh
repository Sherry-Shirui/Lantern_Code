#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
TAG="v0.38.23"
COMMIT="feb2aea4dc271d612129afc958cb844713ec792b"
SOURCE="${COMET_SOURCE:-$ROOT/.m5-cache/cometbft-v0.38.23}"
BIN_DIR="${M5_BIN_DIR:-$ROOT/.m5-toolchains/bin}"
DOWNLOAD_TIMEOUT="${M5_DOWNLOAD_TIMEOUT:-5m}"
BUILD_TIMEOUT="${M5_BUILD_TIMEOUT:-20m}"
COMMAND_TIMEOUT="${M5_COMMAND_TIMEOUT:-30s}"

run_with_timeout() {
  local duration="$1"
  shift
  timeout --signal=TERM --kill-after=10s "$duration" "$@"
}

GO_VERSION="$(run_with_timeout "$COMMAND_TIMEOUT" go version)"
if [[ "$GO_VERSION" != go\ version\ go1.22.11\ * ]]; then
  echo "M5.0 requires exactly Go 1.22.11; got: $GO_VERSION" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$SOURCE")" "$BIN_DIR"
if [[ ! -d "$SOURCE/.git" ]]; then
  run_with_timeout "$DOWNLOAD_TIMEOUT" git clone --branch "$TAG" --depth 1 \
    https://github.com/cometbft/cometbft.git "$SOURCE"
fi

ACTUAL_COMMIT="$(run_with_timeout "$COMMAND_TIMEOUT" git -C "$SOURCE" rev-parse HEAD)"
if [[ "$ACTUAL_COMMIT" != "$COMMIT" ]]; then
  echo "CometBFT source mismatch: expected $COMMIT, got $ACTUAL_COMMIT" >&2
  exit 1
fi
ACTUAL_TAG="$(run_with_timeout "$COMMAND_TIMEOUT" git -C "$SOURCE" describe --tags --exact-match HEAD)"
if [[ "$ACTUAL_TAG" != "$TAG" ]]; then
  echo "CometBFT tag mismatch: expected $TAG, got $ACTUAL_TAG" >&2
  exit 1
fi

run_with_timeout "$BUILD_TIMEOUT" make -C "$SOURCE" build OUTPUT="$BIN_DIR/cometbft"
SHORT_COMMIT="${COMMIT:0:7}"
(
  cd "$SOURCE"
  run_with_timeout "$BUILD_TIMEOUT" env CGO_ENABLED=0 go build \
    -mod=readonly -trimpath -tags cometbft \
    -ldflags "-s -w -X github.com/cometbft/cometbft/version.TMGitCommitHash=$SHORT_COMMIT" \
    -o "$BIN_DIR/abci-cli" ./abci/cmd/abci-cli
)

run_with_timeout "$COMMAND_TIMEOUT" git -C "$SOURCE" status --short
run_with_timeout "$COMMAND_TIMEOUT" "$BIN_DIR/cometbft" version --verbose
run_with_timeout "$COMMAND_TIMEOUT" "$BIN_DIR/abci-cli" version
run_with_timeout "$COMMAND_TIMEOUT" sha256sum "$BIN_DIR/cometbft" "$BIN_DIR/abci-cli"
