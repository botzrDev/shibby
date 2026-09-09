# M1 two-host run (HLX-109)

**Status:** prep only. This directory is the place for artifacts from a **real**
two-machine, two-network recorded run. Loopback / same-host e2e does **not**
close HLX-109.

Do **not** invent or check in fake CallRecords. After you complete the run on
two hosts on different networks, drop the artifacts under
[`artifacts/`](artifacts/) (see checklist below).

This runbook makes **no reliability claims**. One dial. Not a success rate.

## Exit criteria (ticket)

- [ ] Two machines on **different networks** (not loopback, not same host)
- [ ] One completed call
- [ ] Printed **RTT** (`rtt_ms=...`)
- [ ] Peer is **non-loopback**
- [ ] Two `CallRecord` JSON files (caller + callee) that **agree** on:
  - `task`
  - `outcome`
  - `path`
- [ ] Artifacts committed (or attached) under `docs/m1-two-host-run/artifacts/`

## Build

On **both** hosts, from the same commit:

```bash
cargo build -p uat-cli -p uat-node --release
export UAT_BIN="$(pwd)/target/release/uat"
export UAT_NODE_BIN="$(pwd)/target/release/uat-node"
```

Or use debug binaries from `target/debug/`.

## Identities and allowlist

Use separate `UAT_HOME` directories (example: `~/uat-hlx109`).

**Callee host:**

```bash
export UAT_HOME="$HOME/uat-hlx109"
"$UAT_BIN" identity   # prints callee pubkey (one hex line)
```

**Caller host:**

```bash
export UAT_HOME="$HOME/uat-hlx109"
"$UAT_BIN" identity   # prints caller pubkey
```

Exchange the two pubkeys out of band. Callee must allow the caller:

```bash
# callee
"$UAT_NODE_BIN" listen --relay --allow "<caller-pubkey>"
```

Caller daemon (for `uat dial` via sock) should allow the callee if it will also
answer, but for a one-way dial only the callee allowlist is required:

```bash
# caller
"$UAT_NODE_BIN" listen --relay --allow "<callee-pubkey>"
```

## Relay / discovery

Same-host CI keeps relay **off** (default). For multi-network:

| Mechanism | Effect |
|-----------|--------|
| `--relay` on `uat-node listen` / `uat-node dial` | `RelayMode::Default` (n0 relays; `presets::N0` discovery stays on) |
| `UAT_RELAY=1` (or `true` / `yes`) | Same as `--relay` |

When relay is off, listen banner prints `relay=off`. When on: `relay=on`.

### Path field note

`CallRecord.path` is set from iroh `Connection::paths()`:

- Selected (or sole) **relay** transport → `path: { "relayed": { "relay": "<url>" } }`
- Otherwise → `path: "direct"` (including hole-punched IP after relay assist)

If a run uses relay for NAT traversal but upgrades to a direct path before the
record is emitted, both sides may legitimately show `"direct"`. That still
satisfies agreement; the peer must still be non-loopback.

## Listen (callee)

Helper (from repo root):

```bash
UAT_HOME="$HOME/uat-hlx109" \
  ./scripts/two-host-listen.sh --allow "<caller-pubkey>"
```

Or manually:

```bash
UAT_HOME="$HOME/uat-hlx109" UAT_RELAY=1 \
  "$UAT_NODE_BIN" listen --relay --allow "<caller-pubkey>"
```

Banner lines to capture:

```
node_id=...
addr=<ip:port>          # may be several; prefer a non-loopback addr
sock=...
relay=on
records_dir=.../records
listening (SIGTERM to stop)
```

Share `node_id` and at least one reachable `addr` (or rely on discovery once
both sides have relay on — still pass `--addr` when you have it).

## Dial (caller)

Helper:

```bash
UAT_HOME="$HOME/uat-hlx109" \
  ./scripts/two-host-dial.sh <callee-node-id> --addr <ip:port>
```

Or via sock client (daemon must already be listening with `--relay`):

```bash
printf 'hlx-109' | UAT_HOME="$HOME/uat-hlx109" \
  "$UAT_BIN" dial <callee-node-id> \
    --deadline 30000 \
    --content-type text/plain \
    --addr <ip:port>
```

Or one-shot `uat-node dial` (also writes a CallRecord under `$UAT_HOME/records/`):

```bash
UAT_HOME="$HOME/uat-hlx109" \
  "$UAT_NODE_BIN" dial <callee-node-id> --relay --addr <ip:port>
```

Expected dialer lines:

```
rtt_ms=<number>
outcome=Completed
```

(`uat-node dial` prints `rtt_ms` from connect; `uat dial` prints `rtt_ms` from
the daemon's DialResult.)

## CallRecord dump

After each call, both hosts write JSON under:

```
$UAT_HOME/records/{unix_ms}_{inbound|outbound}_{peer12}.json
```

Copy **one inbound** (callee) and **one outbound** (caller) record from the
same call into:

```
docs/m1-two-host-run/artifacts/
  caller-callrecord.json
  callee-callrecord.json
  dialer-stdout.txt          # includes rtt_ms= and outcome=
  notes.md                   # networks used, peer addrs, non-loopback proof
```

## Assert agreement

```bash
# example with jq
jq '{task, outcome, path, peer}' docs/m1-two-host-run/artifacts/caller-callrecord.json
jq '{task, outcome, path, peer}' docs/m1-two-host-run/artifacts/callee-callrecord.json
```

Require:

1. `task` equal (same Submit task id hex)
2. `outcome` equal (e.g. `"completed"`)
3. `path` equal (`"direct"` or the same `relayed` URL)
4. `peer` on each side is the other's node id, and **not** a loopback-only story
   (document non-loopback dial addrs / public IPs in `notes.md`)

## Checklist matching HLX-109

- [ ] Callee: `relay=on`, allowlist has caller
- [ ] Caller: dial with peer + addr (or discovery), `rtt_ms` printed
- [ ] `outcome=Completed` on dialer
- [ ] Caller CallRecord JSON saved
- [ ] Callee CallRecord JSON saved
- [ ] Records agree on `task` / `outcome` / `path`
- [ ] Peer / addrs are non-loopback; hosts on different networks
- [ ] Artifacts placed under `docs/m1-two-host-run/artifacts/`
- [ ] No reliability / success-rate claims in notes

## What this prep intentionally does not do

- Does not fake a two-network run in CI
- Does not mark HLX-109 Done until artifacts exist
- Does not change same-host e2e (`scripts/e2e-call.sh`) off `RelayMode::Disabled`
