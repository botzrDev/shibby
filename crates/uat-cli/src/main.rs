//! `uat` CLI: dial / listen / identity — local socket client only (HLX-108).
//!
//! Peer stack and answering live in `uat-node`. This binary never opens iroh
//! connections; it talks to `$UAT_HOME/node.sock` (Dial / Inbox) or reads the
//! identity file for `uat identity`.

use std::env;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::signal::unix::{signal, SignalKind};
use uat_core::{ContentType, Deadline, Message, Outcome, TaskId};
use uat_node::{
    dial_via_sock, inbox_via_sock, load_or_create_at, LocalClientError, LocalResponse,
    IDENTITY_FILE,
};

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
        "listen" => cmd_listen().await,
        "identity" => cmd_identity(),
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
uat — client of $UAT_HOME/node.sock (HLX-108)

  uat dial <peer> --deadline <ms> --content-type <mime> --addr <ip:port> [--addr ...]
      Body from stdin. Prints rtt_ms=... then outcome=<Debug>. Exit 0 iff Completed.
      Requires a running daemon (`uat-node listen`) with node.sock.
      --addr is required for M1; discovery/relay via daemon `UAT_RELAY=1` / `--relay`.

  uat listen
      Long-running Inbox poller. The daemon (`uat-node listen`) already answers
      inbound calls with StubComplete; this command only observes via Inbox
      (no new sock vocabulary). Prints each event; Ctrl-C / SIGTERM to stop.

  uat identity
      Print this node's public key (one hex line, pipeable). Loads or creates
      $UAT_HOME/identity.key — does not require the daemon.

  uat inbox
      One-shot Inbox poll (same sock as listen).

Environment:
  UAT_HOME   identity + node.sock directory (default ~/.uat)
"
    );
}

struct DialArgs {
    peer: String,
    deadline_ms: u32,
    content_type: String,
    addrs: Vec<SocketAddr>,
}

fn parse_dial_args(args: Vec<String>) -> Result<DialArgs> {
    if args.is_empty() {
        bail!("dial requires <peer>");
    }
    let peer = args[0].clone();
    let mut deadline_ms: Option<u32> = None;
    let mut content_type: Option<String> = None;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--deadline" => {
                i += 1;
                let raw = args.get(i).context("--deadline requires <ms>")?;
                deadline_ms = Some(raw.parse::<u32>().context("parse --deadline")?);
                i += 1;
            }
            "--content-type" => {
                i += 1;
                let raw = args
                    .get(i)
                    .context("--content-type requires <mime>")?
                    .clone();
                content_type = Some(raw);
                i += 1;
            }
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
    let deadline_ms = deadline_ms.context("dial requires --deadline <ms>")?;
    let content_type = content_type.context("dial requires --content-type <mime>")?;
    if addrs.is_empty() {
        bail!("dial requires at least one --addr <ip:port> (M1 / no discovery yet)");
    }
    Ok(DialArgs {
        peer,
        deadline_ms,
        content_type,
        addrs,
    })
}

fn read_stdin_body() -> Result<Vec<u8>> {
    let mut body = Vec::new();
    io::stdin()
        .read_to_end(&mut body)
        .context("read dial body from stdin")?;
    Ok(body)
}

async fn cmd_dial(args: Vec<String>) -> Result<()> {
    let parsed = parse_dial_args(args)?;
    let body = read_stdin_body()?;
    let home = uat_home_dir()?;

    let submit = Message::Submit {
        task: TaskId::from_u128(1),
        deadline: Deadline::new(parsed.deadline_ms).context("deadline")?,
        content_type: ContentType::new(parsed.content_type).context("content-type")?,
        credential: None,
        body,
    };

    let (outcome, rtt_ms) = dial_via_sock(&home, &parsed.peer, &parsed.addrs, submit)
        .await
        .map_err(format_client_err)?;
    // Pipeable lines for HLX-108 / HLX-109 runbook capture.
    if let Some(ms) = rtt_ms {
        println!("rtt_ms={ms}");
    } else {
        println!("rtt_ms=unknown");
    }
    println!("outcome={outcome:?}");
    match outcome {
        Outcome::Completed => Ok(()),
        other => bail!("call did not complete: {other:?}"),
    }
}

/// Poll Inbox forever; daemon StubComplete is the answerer (sock client only).
async fn cmd_listen() -> Result<()> {
    let home = uat_home_dir()?;
    // Fail fast with the same actionable errors as dial if the daemon is down.
    let _ = inbox_via_sock(&home).await.map_err(format_client_err)?;

    let mut sigterm = signal(SignalKind::terminate()).context("register SIGTERM")?;
    let mut sigint = signal(SignalKind::interrupt()).context("register SIGINT")?;

    eprintln!("uat listen: polling Inbox on node.sock (daemon answers with StubComplete)");
    loop {
        tokio::select! {
            biased;
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            result = inbox_via_sock(&home) => {
                match result.map_err(format_client_err)? {
                    LocalResponse::InboxIdle => {
                        tokio::select! {
                            biased;
                            _ = sigterm.recv() => return Ok(()),
                            _ = sigint.recv() => return Ok(()),
                            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                        }
                    }
                    LocalResponse::InboxEvent { peer, outcome } => {
                        println!("inbox=event peer={peer} outcome={outcome:?}");
                    }
                    LocalResponse::Error { message } => bail!("{message}"),
                    other => bail!("unexpected inbox response: {other:?}"),
                }
            }
        }
    }
    Ok(())
}

fn cmd_identity() -> Result<()> {
    let home = uat_home_dir()?;
    let identity = load_or_create_at(&home.join(IDENTITY_FILE)).context("load identity")?;
    // Same Display form as `uat-node listen` node_id= / dial <peer> (hex).
    println!("{}", identity.secret_key().public());
    Ok(())
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
    anyhow::Error::msg(err.to_string())
}

fn uat_home_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("UAT_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = env::var_os("HOME").context("HOME unset and UAT_HOME unset")?;
    Ok(PathBuf::from(home).join(".uat"))
}
