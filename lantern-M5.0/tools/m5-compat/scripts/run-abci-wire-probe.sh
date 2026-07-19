#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
ABCI_CLI="${ABCI_CLI:-$ROOT/.m5-toolchains/bin/abci-cli}"
SERVER="${M5_ABCI_SERVER:-$ROOT/target/debug/m5-abci-probe-server}"
PORT="${M5_ABCI_PORT:-28658}"
ADDRESS="127.0.0.1:$PORT"
WORK_DIR="${M5_ABCI_WORK_DIR:-$ROOT/target/m5-compat/abci-wire}"
TRANSCRIPT="$WORK_DIR/transcript.json"
SERVER_LOG="$WORK_DIR/server.log"
SERVICE_TIMEOUT="${M5_SERVICE_TIMEOUT:-60s}"
HEALTH_TIMEOUT="${M5_HEALTH_TIMEOUT:-10s}"
REQUEST_TIMEOUT="${M5_REQUEST_TIMEOUT:-10s}"
SHUTDOWN_TIMEOUT="${M5_SHUTDOWN_TIMEOUT:-5s}"
LOG_TIMEOUT="${M5_LOG_TIMEOUT:-5s}"
COMMAND_TIMEOUT="${M5_COMMAND_TIMEOUT:-30s}"

run_with_timeout() {
  local duration="$1"
  shift
  timeout --signal=TERM --kill-after=5s "$duration" "$@"
}

mkdir -p "$WORK_DIR"
if [[ ! -x "$ABCI_CLI" ]]; then
  echo "missing official v0.38.23 abci-cli: $ABCI_CLI" >&2
  exit 1
fi
if [[ ! -x "$SERVER" ]]; then
  echo "missing Rust ABCI probe server: $SERVER" >&2
  exit 1
fi

run_with_timeout "$SERVICE_TIMEOUT" \
  "$SERVER" "$ADDRESS" "$TRANSCRIPT" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    if ! timeout --signal=TERM --kill-after=1s "$SHUTDOWN_TIMEOUT" \
      tail --pid="$SERVER_PID" -f /dev/null >/dev/null 2>&1; then
      kill -KILL "$SERVER_PID" 2>/dev/null || true
    fi
  fi
  # The bounded TERM/KILL path above has completed; wait only reaps the exited
  # background child and cannot become the lifecycle deadline.
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

if ! run_with_timeout "$HEALTH_TIMEOUT" bash -c '
  while ! grep -q "^READY " "$2" 2>/dev/null; do
    kill -0 "$1" 2>/dev/null || exit 2
    sleep 0.05
  done
' _ "$SERVER_PID" "$SERVER_LOG"; then
  echo "ABCI probe server failed its bounded readiness check" >&2
  run_with_timeout "$LOG_TIMEOUT" sed -n '1,200p' "$SERVER_LOG" >&2 || true
  exit 1
fi

run_with_timeout "$REQUEST_TIMEOUT" \
  "$ABCI_CLI" --address "tcp://$ADDRESS" info >"$WORK_DIR/info-before.txt"
run_with_timeout "$REQUEST_TIMEOUT" \
  "$ABCI_CLI" --address "tcp://$ADDRESS" finalize_block \
  0x6c616e7465726e3d6d352e30 0x776972653d76302e3338 \
  >"$WORK_DIR/finalize-block.txt"
run_with_timeout "$REQUEST_TIMEOUT" \
  "$ABCI_CLI" --address "tcp://$ADDRESS" commit >"$WORK_DIR/commit.txt"
run_with_timeout "$REQUEST_TIMEOUT" \
  "$ABCI_CLI" --address "tcp://$ADDRESS" info >"$WORK_DIR/info-after.txt"

run_with_timeout "$LOG_TIMEOUT" grep -Eq '"?info_calls"?[[:space:]]*:[[:space:]]*2' "$TRANSCRIPT"
run_with_timeout "$LOG_TIMEOUT" grep -Eq '"?finalize_calls"?[[:space:]]*:[[:space:]]*1' "$TRANSCRIPT"
run_with_timeout "$LOG_TIMEOUT" grep -Eq '"?commit_calls"?[[:space:]]*:[[:space:]]*1' "$TRANSCRIPT"
run_with_timeout "$LOG_TIMEOUT" grep -Eq '"?tx_count"?[[:space:]]*:[[:space:]]*2' "$TRANSCRIPT"
run_with_timeout "$LOG_TIMEOUT" grep -Eq '"?committed_height"?[[:space:]]*:[[:space:]]*1' "$TRANSCRIPT"
run_with_timeout "$LOG_TIMEOUT" grep -q 'data: lantern-m5.0-compat' "$WORK_DIR/info-before.txt"
run_with_timeout "$LOG_TIMEOUT" grep -q 'data: lantern-m5.0-compat' "$WORK_DIR/info-after.txt"
COMMITTED_HASH="$(run_with_timeout "$LOG_TIMEOUT" sed -n \
  's/.*"committed_app_hash_hex": "\([0-9a-f]*\)".*/\1/p' "$TRANSCRIPT")"
if [[ -z "$COMMITTED_HASH" ]]; then
  echo "ABCI transcript has no committed app hash" >&2
  exit 1
fi
run_with_timeout "$LOG_TIMEOUT" grep -qi \
  "data.hex: 0x$COMMITTED_HASH" "$WORK_DIR/finalize-block.txt"

echo "M5.0 ABCI v0.38 socket probe: PASS"
run_with_timeout "$COMMAND_TIMEOUT" sha256sum "$ABCI_CLI"
run_with_timeout "$LOG_TIMEOUT" sed -n '1,120p' "$TRANSCRIPT"
