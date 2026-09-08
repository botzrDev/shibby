//! HLX-107: `uat` binary drives a full call through node.sock.
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
    let dir = std::env::temp_dir().join(format!("uat-hlx107-cli-{label}-{nanos}"));
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
        .arg("--addr")
        .arg(&addr)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn uat");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "uat dial failed status={} stdout={stdout} stderr={stderr}",
        output.status
    );
    assert!(
        stdout.contains("outcome=Completed"),
        "missing Completed in stdout={stdout}"
    );

    let lonely = temp_uat_home("lonely");
    let output = tokio::process::Command::new(uat_bin)
        .env("UAT_HOME", &lonely)
        .arg("dial")
        .arg(&peer_id)
        .arg("--addr")
        .arg(&addr)
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
