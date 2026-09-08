//! HLX-104 exit proof: two Nodes, allowlisted dial, Submit→Accepted→Completed, clean cancel.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use iroh::endpoint::{presets, ConnectionError};
use iroh::{Endpoint, RelayMode};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uat_core::{CloseCode, ContentType, Deadline, Message, Outcome, TaskId, ALPN};
use uat_node::{
    load_or_create_at, watch_second_stream, Allowlist, Node, Verify, IDENTITY_FILE,
};

fn temp_uat_home(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uat-hlx104-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn sample_submit() -> Message {
    Message::Submit {
        task: TaskId::from_u128(0x104),
        deadline: Deadline::new(60_000).expect("deadline"),
        content_type: ContentType::new("application/octet-stream").expect("ct"),
        credential: None,
        body: b"hlx-104".to_vec(),
    }
}

async fn bind_pair() -> (Arc<Node>, Arc<Node>, PathBuf, PathBuf) {
    let callee_home = temp_uat_home("callee");
    let caller_home = temp_uat_home("caller");

    let caller_id = load_or_create_at(&caller_home.join(IDENTITY_FILE)).expect("caller id");
    let caller_node_id = caller_id.node_id();

    let callee_cancel = CancellationToken::new();
    let caller_cancel = CancellationToken::new();

    let allow = Allowlist::allow(caller_node_id);
    let callee = Node::bind_at(
        &callee_home,
        Arc::new(allow) as Arc<dyn Verify>,
        callee_cancel,
    )
    .await
    .expect("bind callee");
    callee.spawn_accept_loop();

    let caller = Node::bind(
        caller_id,
        Arc::new(Allowlist::empty()) as Arc<dyn Verify>,
        caller_cancel,
    )
    .await
    .expect("bind caller");

    (callee, caller, callee_home, caller_home)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_complete_call_and_shutdown_cleanly() {
    let (callee, caller, callee_home, caller_home) = bind_pair().await;

    let peer = callee.addr();
    let outcome = caller
        .dial(peer, sample_submit())
        .await
        .expect("dial+call");
    assert_eq!(outcome, Outcome::Completed);

    caller.shutdown().await;
    callee.shutdown().await;

    let _ = std::fs::remove_dir_all(&callee_home);
    let _ = std::fs::remove_dir_all(&caller_home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_allowlist_rejects_caller() {
    let callee_home = temp_uat_home("deny-callee");
    let caller_home = temp_uat_home("deny-caller");

    let caller_id = load_or_create_at(&caller_home.join(IDENTITY_FILE)).expect("caller id");

    let callee = Node::bind_at(
        &callee_home,
        Arc::new(Allowlist::empty()) as Arc<dyn Verify>,
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

    let result = caller.dial(callee.addr(), sample_submit()).await;
    match result {
        Err(_) => {}
        Ok(Outcome::PeerLost) | Ok(Outcome::Closed(_)) => {}
        Ok(other) => panic!("expected reject/loss, got {other:?}"),
    }

    caller.shutdown().await;
    callee.shutdown().await;
    let _ = std::fs::remove_dir_all(&callee_home);
    let _ = std::fs::remove_dir_all(&caller_home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_bidirectional_stream_closes_with_protocol_violation() {
    let ep_callee = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .expect("callee ep");
    let ep_caller = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .expect("caller ep");

    let callee_addr = ep_callee.addr();
    let cancel = CancellationToken::new();
    let cancel_watch = cancel.clone();
    let (armed_tx, armed_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let incoming = ep_callee.accept().await.expect("incoming");
        let conn = incoming.await.expect("accept");
        let (_send, _recv) = conn.accept_bi().await.expect("first bi");
        let _ = armed_tx.send(());
        watch_second_stream(conn.clone(), cancel_watch.clone()).await;
        let _ = done_tx.send(());
        // Keep the endpoint alive until the caller observes CONNECTION_CLOSE.
        cancel_watch.cancelled().await;
        ep_callee.close().await;
    });

    let conn = ep_caller
        .connect(callee_addr, ALPN)
        .await
        .expect("connect");
    let (mut s1, _r1) = conn.open_bi().await.expect("first open_bi");
    // QUIC notifies the peer of a stream on first transmit.
    s1.write_all(b"1").await.expect("write first");
    armed_rx.await.expect("watcher armed");

    let (mut s2, _r2) = conn.open_bi().await.expect("second open_bi");
    s2.write_all(b"2").await.expect("write second");

    tokio::time::timeout(std::time::Duration::from_secs(5), done_rx)
        .await
        .expect("watcher did not fire")
        .expect("done dropped");

    let caller_closed = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed())
        .await
        .expect("caller closed timeout");
    match caller_closed {
        ConnectionError::ApplicationClosed(app) => {
            assert_eq!(
                u64::from(app.error_code),
                u64::from(CloseCode::ProtocolViolation.as_u32())
            );
        }
        other => panic!("expected ApplicationClosed(ProtocolViolation), got {other:?}"),
    }

    cancel.cancel();
    let _ = server.await;
    ep_caller.close().await;
}
