//! HLX-107/108: `uat` binary drives a full call through node.sock.
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;
use uat_node::{load_or_create_at, Allowlist, Node, Verify, IDENTITY_FILE};

fn temp_uat_home(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uat-hlx108-cli-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uat_cli_dials_through_socket_and_errors_without_daemon() {
    let callee_home = temp_uat_home("callee");
    let caller_home = temp_uat_home("caller");

    let caller_id = load_or_create_at(&caller_home.join(IDENTITY_FILE)).expect("caller id");
    let caller_node_id = caller_id.node_id();

    let callee = Node::bind_at(
        &callee_home,
        Arc::new(Allowlist::allow(caller_node_id)) as Arc<dyn Verify>,
        CancellationToken::new(),
    )
    .await
    .expect("bind callee");
    callee.spawn_accept_loop();

    let caller = Node::bind(
        caller_id,
        Arc::new(Allowlist::empty()) as Arc<dyn Verify>,
        CancellationToken::new(),
    )
    .await
    .expect("bind caller");
    caller.spawn_accept_loop();
    caller
        .spawn_local_socket(&caller_home)
        .await
        .expect("sock");

    let peer = callee.addr();
    let addr = peer.ip_addrs().next().expect("addr").to_string();
    let peer_id = peer.id.to_string();

    let uat_bin = env!("CARGO_BIN_EXE_uat");
    let output = tokio::process::Command::new(uat_bin)
        .env("UAT_HOME", &caller_home)
        .arg("dial")
        .arg(&peer_id)
        .arg("--deadline")
        .arg("30000")
        .arg("--content-type")
        .arg("application/octet-stream")
        .arg("--addr")
        .arg(&addr)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn uat");

    // Empty body via closed stdin.
    let mut child = output;
    drop(child.stdin.take());
    let output = child.wait_with_output().await.expect("wait uat");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "uat dial failed status={} stdout={stdout} stderr={stderr}",
        output.status
    );
    assert!(
        stdout.lines().any(|l| l == "outcome=Completed"),
        "missing outcome=Completed in dial stdout={stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.starts_with("rtt_ms=")),
        "missing rtt_ms= in dial stdout={stdout}"
    );

    let lonely = temp_uat_home("lonely");
    let output = tokio::process::Command::new(uat_bin)
        .env("UAT_HOME", &lonely)
        .arg("dial")
        .arg(&peer_id)
        .arg("--deadline")
        .arg("1000")
        .arg("--content-type")
        .arg("text/plain")
        .arg("--addr")
        .arg(&addr)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn uat no-daemon");
    let err_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "expected failure without daemon");
    assert!(
        err_text.contains("not running") && err_text.contains("uat-node listen"),
        "actionable cli error missing: {err_text}"
    );

    caller.shutdown().await;
    callee.shutdown().await;
    let _ = std::fs::remove_dir_all(&callee_home);
    let _ = std::fs::remove_dir_all(&caller_home);
    let _ = std::fs::remove_dir_all(&lonely);
}

#[tokio::test]
async fn uat_identity_prints_one_line_pubkey() {
    let home = temp_uat_home("identity");
    let uat_bin = env!("CARGO_BIN_EXE_uat");
    let output = tokio::process::Command::new(uat_bin)
        .env("UAT_HOME", &home)
        .arg("identity")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn identity");
    assert!(
        output.status.success(),
        "identity failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim_end_matches('\n');
    assert!(
        !line.is_empty() && !line.contains('\n'),
        "identity must be one non-empty line, got {stdout:?}"
    );
    // Hex public key (64 chars) from iroh Display.
    assert_eq!(line.len(), 64, "expected 64-char hex pubkey, got {line}");
    assert!(
        line.chars().all(|c| c.is_ascii_hexdigit()),
        "pubkey not hex: {line}"
    );

    let again = tokio::process::Command::new(uat_bin)
        .env("UAT_HOME", &home)
        .arg("identity")
        .output()
        .await
        .expect("identity again");
    assert_eq!(
        String::from_utf8_lossy(&again.stdout).trim(),
        line,
        "identity must be stable across restarts"
    );
    let _ = std::fs::remove_dir_all(&home);
}
