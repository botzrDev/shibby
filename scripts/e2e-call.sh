#!/usr/bin/env bash
# HLX-108 exit proof: two daemons on loopback, uat dial asserts Completed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UAT_BIN="${UAT_BIN:-}"
UAT_NODE_BIN="${UAT_NODE_BIN:-}"

if [[ -z "$UAT_BIN" || -z "$UAT_NODE_BIN" ]]; then
  if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    : # prefer explicit env
  fi
  # Prefer cargo-built binaries next to this workspace.
  for candidate in \
    "$ROOT/target/debug/uat" \
    "$ROOT/target/release/uat"; do
    if [[ -z "$UAT_BIN" && -x "$candidate" ]]; then
      UAT_BIN="$candidate"
    fi
  done
  for candidate in \
    "$ROOT/target/debug/uat-node" \
    "$ROOT/target/release/uat-node"; do
    if [[ -z "$UAT_NODE_BIN" && -x "$candidate" ]]; then
      UAT_NODE_BIN="$candidate"
    fi
  done
fi

if [[ -z "${UAT_BIN:-}" || -z "${UAT_NODE_BIN:-}" ]]; then
  echo "e2e-call: set UAT_BIN and UAT_NODE_BIN, or cargo build -p uat-cli -p uat-node first" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/uat-hlx108-e2e.XXXXXX")"
cleanup() {
  if [[ -n "${CALLEE_PID:-}" ]] && kill -0 "$CALLEE_PID" 2>/dev/null; then
    kill -TERM "$CALLEE_PID" 2>/dev/null || true
    wait "$CALLEE_PID" 2>/dev/null || true
  fi
  if [[ -n "${CALLER_PID:-}" ]] && kill -0 "$CALLER_PID" 2>/dev/null; then
    kill -TERM "$CALLER_PID" 2>/dev/null || true
    wait "$CALLER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

CALLEE_HOME="$WORKDIR/callee"
CALLER_HOME="$WORKDIR/caller"
mkdir -p "$CALLEE_HOME" "$CALLER_HOME"

CALLER_ID="$(UAT_HOME="$CALLER_HOME" "$UAT_BIN" identity)"
CALLEE_ID="$(UAT_HOME="$CALLEE_HOME" "$UAT_BIN" identity)"

if [[ -z "$CALLER_ID" || -z "$CALLEE_ID" ]]; then
  echo "e2e-call: identity produced empty pubkey" >&2
  exit 1
fi
if [[ "$CALLER_ID" == *$'\n'* || "$CALLEE_ID" == *$'\n'* ]]; then
  echo "e2e-call: identity must be one line" >&2
  exit 1
fi

CALLEE_LOG="$WORKDIR/callee.log"
CALLER_LOG="$WORKDIR/caller.log"

UAT_HOME="$CALLEE_HOME" "$UAT_NODE_BIN" listen --allow "$CALLER_ID" >"$CALLEE_LOG" 2>&1 &
CALLEE_PID=$!
UAT_HOME="$CALLER_HOME" "$UAT_NODE_BIN" listen --allow "$CALLEE_ID" >"$CALLER_LOG" 2>&1 &
CALLER_PID=$!

# Wait until both socks exist and callee printed an addr.
for _ in $(seq 1 100); do
  if [[ -S "$CALLEE_HOME/node.sock" && -S "$CALLER_HOME/node.sock" ]] \
    && grep -q '^addr=' "$CALLEE_LOG" 2>/dev/null \
    && grep -q '^node_id=' "$CALLEE_LOG" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$CALLEE_PID" 2>/dev/null || ! kill -0 "$CALLER_PID" 2>/dev/null; then
    echo "e2e-call: daemon exited early" >&2
    cat "$CALLEE_LOG" "$CALLER_LOG" >&2 || true
    exit 1
  fi
  sleep 0.1
done

if [[ ! -S "$CALLEE_HOME/node.sock" || ! -S "$CALLER_HOME/node.sock" ]]; then
  echo "e2e-call: timed out waiting for node.sock" >&2
  cat "$CALLEE_LOG" "$CALLER_LOG" >&2 || true
  exit 1
fi

PEER="$(grep -m1 '^node_id=' "$CALLEE_LOG" | sed 's/^node_id=//')"
ADDR="$(grep -m1 '^addr=' "$CALLEE_LOG" | sed 's/^addr=//')"
if [[ -z "$PEER" || -z "$ADDR" ]]; then
  echo "e2e-call: failed to parse callee listen banner" >&2
  cat "$CALLEE_LOG" >&2
  exit 1
fi
if [[ "$PEER" != "$CALLEE_ID" ]]; then
  echo "e2e-call: callee node_id ($PEER) != uat identity ($CALLEE_ID)" >&2
  exit 1
fi

OUTCOME="$(
  printf 'hlx-108-e2e' | UAT_HOME="$CALLER_HOME" "$UAT_BIN" dial "$PEER" \
    --deadline 30000 \
    --content-type text/plain \
    --addr "$ADDR"
)"

echo "$OUTCOME"
if [[ "$OUTCOME" != "outcome=Completed" ]]; then
  echo "e2e-call: expected outcome=Completed, got: $OUTCOME" >&2
  exit 1
fi

echo "e2e-call: ok"
