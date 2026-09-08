//! HLX-105: paused-clock liveness (L1–L4) + L3 via real QUIC idle.
//! Ordering (callee-fires-first) is pinned in uat-node unit tests (call.rs).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uat_core::{
    CloseCode, ContentType, Deadline, FailureCode, Message, Outcome, TaskId, GRACE_MS,
    QUIC_IDLE_TIMEOUT_MS,
};
use uat_node::{
    drive_chan_call, load_or_create_at, Allowlist, CalleeBehavior, Node, Verify, IDENTITY_FILE,
};

fn submit_ms(ms: u32) -> Message {
    Message::Submit {
        task: TaskId::from_u128(0x105),
        deadline: Deadline::new(ms).expect("deadline"),
        content_type: ContentType::new("application/octet-stream").expect("ct"),
        credential: None,
        body: b"hlx-105".to_vec(),
    }
}

fn temp_uat_home(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uat-hlx105-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[tokio::test(start_paused = true)]
async fn l1_both_ends_terminal_within_deadline_plus_grace() {
    let (caller, callee) =
        drive_chan_call(submit_ms(100), CalleeBehavior::HangAfterAccept, None, None)
            .await
            .expect("drive");
    assert_eq!(callee, Outcome::Failed(FailureCode::DeadlineExceeded));
    assert_eq!(caller, Outcome::Failed(FailureCode::DeadlineExceeded));
}

#[tokio::test(start_paused = true)]
async fn l2_awaiting_input_fails_on_callee_deadline() {
    let (caller, callee) =
        drive_chan_call(submit_ms(250), CalleeBehavior::NeedInputHang, None, None)
            .await
            .expect("drive");
    assert_eq!(callee, Outcome::Failed(FailureCode::DeadlineExceeded));
    assert_eq!(caller, Outcome::Failed(FailureCode::DeadlineExceeded));
}

#[tokio::test(start_paused = true)]
async fn l4_canceling_reaches_terminal() {
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        drive_chan_call(
            submit_ms(80),
            CalleeBehavior::SilentHang,
            Some(rx),
            None,
        )
        .await
    });
    tokio::time::advance(Duration::from_millis(1)).await;
    let _ = tx.send(());
    tokio::time::advance(Duration::from_millis(80 + GRACE_MS + 10)).await;
    let (caller, _) = handle.await.expect("join").expect("drive");
    assert!(
        matches!(
            caller,
            Outcome::Failed(FailureCode::DeadlineExceeded)
                | Outcome::Closed(CloseCode::Timeout)
                | Outcome::Canceled
        ),
        "caller={caller:?}"
    );
}

/// L3: abrupt peer loss → caller task terminates within QUIC idle timeout (real transport).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l3_connection_loss_terminates_within_quic_idle() {
    let callee_home = temp_uat_home("l3-callee");
    let caller_home = temp_uat_home("l3-caller");

    let caller_id = load_or_create_at(&caller_home.join(IDENTITY_FILE)).expect("caller id");
    let caller_node_id = caller_id.node_id();

    let callee = Node::bind_at_with_behavior(
        &callee_home,
        Arc::new(Allowlist::allow(caller_node_id)) as Arc<dyn Verify>,
        CancellationToken::new(),
        CalleeBehavior::HangAfterAccept,
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

    let peer = callee.addr();
    let submit = submit_ms(600_000);

    let dial = tokio::spawn({
        let caller = Arc::clone(&caller);
        async move { caller.dial(peer, submit).await }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    callee.shutdown().await;

    let result = tokio::time::timeout(
        Duration::from_millis(QUIC_IDLE_TIMEOUT_MS + 5_000),
        dial,
    )
    .await
    .expect("caller must finish within idle+slack")
    .expect("dial task join");

    match result {
        Ok(outcome) => {
            assert!(
                matches!(
                    outcome,
                    Outcome::PeerLost
                        | Outcome::Closed(_)
                        | Outcome::Failed(FailureCode::DeadlineExceeded)
                ),
                "unexpected outcome {outcome:?}"
            );
        }
        Err(err) => {
            assert!(!err.to_string().is_empty());
        }
    }

    caller.shutdown().await;
    let _ = std::fs::remove_dir_all(&callee_home);
    let _ = std::fs::remove_dir_all(&caller_home);
}
