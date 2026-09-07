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
```

Pinned MSRV: see `rust-toolchain.toml` and `workspace.package.rust-version`.

## CI

The intended GitHub Actions workflow is in [`docs/ci.yml.example`](docs/ci.yml.example).
Copy it to `.github/workflows/ci.yml` once the GitHub token has the `workflow` scope
(or add it via the GitHub UI). Until then, run locally:

```bash
cargo build --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
