//! Minimal CLI client of `$UAT_HOME/node.sock` (HLX-107). Polish is HLX-108.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use uat_core::{ContentType, Deadline, Message, Outcome, TaskId};
use uat_node::{dial_via_sock, inbox_via_sock, LocalClientError, LocalResponse};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_usage();
        bail!("missing subcommand");
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "dial" => cmd_dial(args).await,
        "inbox" => cmd_inbox().await,
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
uat (HLX-107 minimal — talks to uat-node via $UAT_HOME/node.sock)

  uat dial <endpoint-id> --addr <ip:port> [--addr <ip:port>]...
  uat inbox

Environment:
  UAT_HOME   directory with node.sock (default ~/.uat)
"
    );
}

async fn cmd_dial(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        bail!("dial requires <endpoint-id>");
    }
    let peer_id = args[0].clone();
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
    let submit = Message::Submit {
        task: TaskId::from_u128(1),
        deadline: Deadline::new(30_000).context("deadline")?,
        content_type: ContentType::new("application/octet-stream").context("content-type")?,
        credential: None,
        body: Vec::new(),
    };

    let outcome = dial_via_sock(&home, &peer_id, &addrs, submit)
        .await
        .map_err(format_client_err)?;
    println!("outcome={outcome:?}");
    match outcome {
        Outcome::Completed => Ok(()),
        other => bail!("call did not complete: {other:?}"),
    }
}

async fn cmd_inbox() -> Result<()> {
    let home = uat_home_dir()?;
    let resp = inbox_via_sock(&home).await.map_err(format_client_err)?;
    match resp {
        LocalResponse::InboxIdle => {
            println!("inbox=idle");
            Ok(())
        }
        LocalResponse::InboxEvent { peer, outcome } => {
            println!("inbox=event peer={peer} outcome={outcome:?}");
            Ok(())
        }
        LocalResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected inbox response: {other:?}"),
    }
}

fn format_client_err(err: LocalClientError) -> anyhow::Error {
    // Preserve actionable Display text (NotRunning / StaleSocket) without wrapping noise.
    anyhow::Error::msg(err.to_string())
}

fn uat_home_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("UAT_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = env::var_os("HOME").context("HOME unset and UAT_HOME unset")?;
    Ok(PathBuf::from(home).join(".uat"))
}
