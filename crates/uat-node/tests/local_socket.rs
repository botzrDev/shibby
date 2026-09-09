//! HLX-107 exit proof: dial through `$UAT_HOME/node.sock`, actionable no-daemon errors.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;
use uat_core::{ContentType, Deadline, Message, Outcome, TaskId};
use uat_node::{
    dial_via_sock, inbox_via_sock, load_or_create_at, sock_path, Allowlist, LocalClientError,
    LocalResponse, Node, Verify, IDENTITY_FILE, SOCK_FILE,
};

fn temp_uat_home(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uat-hlx107-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn sample_submit() -> Message {
    Message::Submit {
        task: TaskId::from_u128(0x107),
        deadline: Deadline::new(60_000).expect("deadline"),
        content_type: ContentType::new("application/octet-stream").expect("ct"),
        credential: None,
        body: b"hlx-107".to_vec(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dial_through_local_socket_completes() {
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
        .expect("bind node.sock");

    let peer = callee.addr();
    let addrs: Vec<_> = peer.ip_addrs().copied().collect();
    assert!(!addrs.is_empty(), "callee should advertise ip addrs");

    let (outcome, _rtt_ms) = dial_via_sock(
        &caller_home,
        &peer.id.to_string(),
        &addrs,
        sample_submit(),
    )
    .await
    .expect("dial via sock");
    assert_eq!(outcome, Outcome::Completed);

    let idle = inbox_via_sock(&caller_home).await.expect("inbox");
    assert!(matches!(idle, LocalResponse::InboxIdle));

    caller.shutdown().await;
    callee.shutdown().await;
    assert!(
        !sock_path(&caller_home).exists(),
        "sock file cleaned up on shutdown"
    );
    let _ = std::fs::remove_dir_all(&callee_home);
    let _ = std::fs::remove_dir_all(&caller_home);
}

#[tokio::test]
async fn no_daemon_yields_actionable_error() {
    let home = temp_uat_home("missing");
    let err = dial_via_sock(
        &home,
        "0000000000000000000000000000000000000000000000000000000000000000",
        &["127.0.0.1:1".parse().unwrap()],
        sample_submit(),
    )
    .await
    .expect_err("must fail");
    let msg = err.to_string();
    assert!(
        matches!(err, LocalClientError::NotRunning { .. }),
        "expected NotRunning, got {err:?}"
    );
    assert!(
        msg.contains("not running") && msg.contains("uat-node listen"),
        "actionable message missing: {msg}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test]
async fn stale_socket_yields_actionable_error() {
    let home = temp_uat_home("stale");
    let path = home.join(SOCK_FILE);
    std::fs::write(&path, b"").expect("touch stale sock");
    // A plain file is not an accepting Unix socket — connect fails → stale.
    let err = dial_via_sock(
        &home,
        "0000000000000000000000000000000000000000000000000000000000000000",
        &["127.0.0.1:1".parse().unwrap()],
        sample_submit(),
    )
    .await
    .expect_err("must fail");
    let msg = err.to_string();
    assert!(
        matches!(err, LocalClientError::StaleSocket { .. }),
        "expected StaleSocket, got {err:?}"
    );
    assert!(
        msg.contains("stale") && msg.contains("uat-node listen"),
        "actionable message missing: {msg}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
