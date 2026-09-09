#!/usr/bin/env bash
# HLX-109: callee-side helper — listen with relay on, dump CallRecords under $UAT_HOME/records.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UAT_NODE_BIN="${UAT_NODE_BIN:-}"

if [[ -z "$UAT_NODE_BIN" ]]; then
  for candidate in \
    "$ROOT/target/release/uat-node" \
    "$ROOT/target/debug/uat-node"; do
    if [[ -x "$candidate" ]]; then
      UAT_NODE_BIN="$candidate"
      break
    fi
  done
fi

if [[ -z "${UAT_NODE_BIN:-}" ]]; then
  echo "two-host-listen: set UAT_NODE_BIN or cargo build -p uat-node first" >&2
  exit 1
fi

if [[ -z "${UAT_HOME:-}" ]]; then
  echo "two-host-listen: set UAT_HOME to a per-host directory (identity + records)" >&2
  exit 1
fi

mkdir -p "$UAT_HOME/records"

# Default: relay on for multi-network. Pass --no-relay to force off (CI should use e2e-call.sh instead).
RELAY_ARGS=(--relay)
FILTERED=()
for arg in "$@"; do
  if [[ "$arg" == "--no-relay" ]]; then
    RELAY_ARGS=()
  else
    FILTERED+=("$arg")
  fi
done

export UAT_RELAY="${UAT_RELAY:-1}"
echo "two-host-listen: UAT_HOME=$UAT_HOME bin=$UAT_NODE_BIN records=$UAT_HOME/records" >&2
echo "two-host-listen: after the call, copy JSON from records/ into docs/m1-two-host-run/artifacts/" >&2
exec env UAT_HOME="$UAT_HOME" "$UAT_NODE_BIN" listen "${RELAY_ARGS[@]}" "${FILTERED[@]}"
