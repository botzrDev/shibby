#!/usr/bin/env bash
# HLX-109: caller-side helper — dial peer with relay-capable daemon or one-shot uat-node dial.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UAT_BIN="${UAT_BIN:-}"
UAT_NODE_BIN="${UAT_NODE_BIN:-}"

usage() {
  cat >&2 <<'USAGE'
Usage:
  two-host-dial.sh <peer-endpoint-id> --addr <ip:port> [--addr ...] [--oneshot]

Requires UAT_HOME. Prefers an already-running `uat-node listen --relay` and uses
`uat dial` via node.sock. Pass --oneshot to use `uat-node dial --relay` instead
(no long-lived caller daemon).

Captures stdout (rtt_ms + outcome). Copy CallRecords from $UAT_HOME/records/
into docs/m1-two-host-run/artifacts/ after a real two-network run.
USAGE
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

PEER="$1"
shift

ONESHOT=0
ADDR_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --addr)
      shift
      [[ $# -gt 0 ]] || { echo "two-host-dial: --addr needs ip:port" >&2; exit 1; }
      ADDR_ARGS+=(--addr "$1")
      shift
      ;;
    --oneshot)
      ONESHOT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "two-host-dial: unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ${#ADDR_ARGS[@]} -eq 0 ]]; then
  echo "two-host-dial: need at least one --addr <ip:port>" >&2
  exit 1
fi

if [[ -z "${UAT_HOME:-}" ]]; then
  echo "two-host-dial: set UAT_HOME" >&2
  exit 1
fi
mkdir -p "$UAT_HOME/records"

if [[ -z "$UAT_BIN" ]]; then
  for candidate in "$ROOT/target/release/uat" "$ROOT/target/debug/uat"; do
    if [[ -x "$candidate" ]]; then UAT_BIN="$candidate"; break; fi
  done
fi
if [[ -z "$UAT_NODE_BIN" ]]; then
  for candidate in "$ROOT/target/release/uat-node" "$ROOT/target/debug/uat-node"; do
    if [[ -x "$candidate" ]]; then UAT_NODE_BIN="$candidate"; break; fi
  done
fi

export UAT_RELAY="${UAT_RELAY:-1}"

if [[ "$ONESHOT" -eq 1 ]]; then
  if [[ -z "${UAT_NODE_BIN:-}" ]]; then
    echo "two-host-dial: need UAT_NODE_BIN for --oneshot" >&2
    exit 1
  fi
  echo "two-host-dial: oneshot uat-node dial (relay on)" >&2
  exec env UAT_HOME="$UAT_HOME" "$UAT_NODE_BIN" dial "$PEER" --relay "${ADDR_ARGS[@]}"
fi

if [[ -z "${UAT_BIN:-}" ]]; then
  echo "two-host-dial: set UAT_BIN or cargo build -p uat-cli first" >&2
  exit 1
fi

if [[ ! -S "$UAT_HOME/node.sock" ]]; then
  echo "two-host-dial: no node.sock at $UAT_HOME — start ./scripts/two-host-listen.sh on this host, or pass --oneshot" >&2
  exit 1
fi

echo "two-host-dial: uat dial via node.sock (daemon should have --relay)" >&2
printf 'hlx-109-two-host' | env UAT_HOME="$UAT_HOME" "$UAT_BIN" dial "$PEER" \
  --deadline 30000 \
  --content-type text/plain \
  "${ADDR_ARGS[@]}"
