//! Minimal `uat-node` binary: listen or dial a one-shot stub call (HLX-104).
//!
//! CLI polish is HLX-108. This binary is enough for a manual two-process exit check.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::{EndpointAddr, EndpointId, TransportAddr};
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use uat_core::{ContentType, Deadline, Message, Outcome, TaskId};
use uat_node::{public_key_to_node_id, Allowlist, Node, Verify};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_usage();
        bail!("missing subcommand");
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "listen" => cmd_listen(args).await,
        "dial" => cmd_dial(args).await,
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            bail!("unknown subcommand: {other}");
        }
    }
}

fn print_usage() {
    eprintln!(
        "\
uat-node (HLX-104/107)

  uat-node listen [--allow <endpoint-id>]...
  uat-node dial <endpoint-id> --addr <ip:port> [--addr <ip:port>]...

Listen also binds $UAT_HOME/node.sock (mode 0600) for uat-cli / local clients.

Environment:
  UAT_HOME   identity + node.sock directory (default ~/.uat)
"
    );
}

async fn cmd_listen(args: Vec<String>) -> Result<()> {
    let mut allow = Allowlist::empty();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--allow" => {
                i += 1;
                let id = args
                    .get(i)
                    .context("--allow requires an endpoint id")?
                    .parse::<EndpointId>()
                    .context("parse --allow endpoint id")?;
                allow.insert(public_key_to_node_id(&id));
                i += 1;
            }
            other => bail!("unknown listen arg: {other}"),
        }
    }

    let home = uat_home_dir()?;
    let cancel = CancellationToken::new();
    let node = Node::bind_at(&home, Arc::new(allow) as Arc<dyn Verify>, cancel.clone()).await?;
    node.spawn_accept_loop();
    node.spawn_local_socket(&home).await?;

    println!("node_id={}", node.endpoint().id());
    for addr in node.addr().ip_addrs() {
        println!("addr={addr}");
    }
    if let Some(sock) = node.local_sock_path().await {
        println!("sock={}", sock.display());
    }
    println!("listening (SIGTERM to stop)");

    wait_sigterm(cancel.clone()).await;
    node.shutdown().await;
    Ok(())
}

async fn cmd_dial(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        bail!("dial requires <endpoint-id>");
    }
    let peer_id: EndpointId = args[0].parse().context("parse peer endpoint id")?;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                let a = args
                    .get(i)
                    .context("--addr requires ip:port")?
                    .parse::<SocketAddr>()
                    .context("parse --addr")?;
                addrs.push(a);
                i += 1;
            }
            other => bail!("unknown dial arg: {other}"),
        }
    }
    if addrs.is_empty() {
        bail!("dial requires at least one --addr");
    }

    let home = uat_home_dir()?;
    let cancel = CancellationToken::new();
    // Dialer allowlist unused for outbound; empty is fine.
    let node = Node::bind_at(
        &home,
        Arc::new(Allowlist::empty()) as Arc<dyn Verify>,
        cancel.clone(),
    )
    .await?;

    let transports = addrs.into_iter().map(TransportAddr::Ip);
    let peer = EndpointAddr::from_parts(peer_id, transports);

    let submit = Message::Submit {
        task: TaskId::from_u128(1),
        deadline: Deadline::new(30_000).context("deadline")?,
        content_type: ContentType::new("application/octet-stream").context("content-type")?,
        credential: None,
        body: Vec::new(),
    };

    let outcome = tokio::select! {
        _ = wait_sigterm(cancel.clone()) => {
            node.shutdown().await;
            bail!("cancelled before call completed");
        }
        result = node.dial(peer, submit) => result?,
    };

    println!("outcome={outcome:?}");
    match outcome {
        Outcome::Completed => {}
        other => bail!("call did not complete: {other:?}"),
    }
    node.shutdown().await;
    Ok(())
}

fn uat_home_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("UAT_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = env::var_os("HOME").context("HOME unset and UAT_HOME unset")?;
    Ok(PathBuf::from(home).join(".uat"))
}

async fn wait_sigterm(cancel: CancellationToken) {
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            cancel.cancelled().await;
            return;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => {
            cancel.cancelled().await;
            return;
        }
    };
    tokio::select! {
        _ = sigterm.recv() => {
            cancel.cancel();
        }
        _ = sigint.recv() => {
            cancel.cancel();
        }
        _ = cancel.cancelled() => {}
        // Keep the future alive if signals somehow both fail to register.
        _ = tokio::time::sleep(Duration::from_secs(365 * 24 * 3600)) => {
            cancel.cancel();
        }
    }
}
