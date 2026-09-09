# shibby

Universal Agent Telephony (UAT). One authenticated QUIC connection per task.

**Build target:** PRD v0.2 + Amendment 1. **ALPN:** `/uat/0.2`.

## Workspace (M0 / HLX-97)

```
crates/
  uat-core/    types, codec, state machines — no tokio, no iroh, no I/O
  uat-policy/  answering policy, Biscuit, spent set, rate limits
  uat-node/    iroh endpoint and the only iroh dependency
  uat-mcp/     MCP stdio server binary
  uat-cli/     dial / listen / identity CLI (`uat`)
```

`uat-core` owns `NodeId([u8; 32])`. `uat-node` converts to iroh's public key at the edge.

## Develop

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
# HLX-108 loopback call (after cargo build -p uat-cli -p uat-node):
#   ./scripts/e2e-call.sh
# HLX-109 two-host prep (relay on; real run is manual — see docs):
#   ./scripts/two-host-listen.sh --allow <peer>
#   ./scripts/two-host-dial.sh <peer> --addr <ip:port>
#   docs/m1-two-host-run/README.md
```

Pinned MSRV: see `rust-toolchain.toml` and `workspace.package.rust-version`.

## CI

GitHub Actions: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (also mirrored at `docs/ci.yml.example`).

Locally:

```bash
cargo build --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
