//! HLX-113: rate limits enforced before any stream is accepted.
//!
//! Exit: a rate-limited key is closed before any stream is accepted, and both
//! ends' CallRecords agree on `Closed(RateLimited)` with `task: None` and
//! (callee) `authorization: NotReached`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;
use uat_core::{CloseCode, ContentType, Deadline, Message, Outcome, TaskId};
use uat_node::{
    load_or_create_at, Allowlist, AuthOutcome, CalleeBehavior, CallRecordSink, Direction,
    MemoryCallRecordSink, Node, NodeBindOpts, RateLimitConfig, Verify, IDENTITY_FILE,
};

fn temp_uat_home(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uat-hlx113-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn submit_ms(task: u128, ms: u32) -> Message {
    Message::Submit {
        task: TaskId::from_u128(task),
        deadline: Deadline::new(ms).expect("deadline"),
        content_type: ContentType::new("application/octet-stream").expect("ct"),
        credential: None,
        body: b"hlx-113".to_vec(),
    }
}

async fn wait_records(sink: &MemoryCallRecordSink, n: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while sink.len() < n {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {n} records, have {}", sink.len());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct Pair {
    callee: Arc<Node>,
    caller: Arc<Node>,
    callee_records: Arc<MemoryCallRecordSink>,
    caller_records: Arc<MemoryCallRecordSink>,
    callee_home: PathBuf,
    caller_home: PathBuf,
}

impl Pair {
    async fn bind(callee_behavior: CalleeBehavior, rate_limits: RateLimitConfig) -> Self {
        let callee_home = temp_uat_home("callee");
        let caller_home = temp_uat_home("caller");
        let caller_id = load_or_create_at(&caller_home.join(IDENTITY_FILE)).expect("caller id");
        let caller_node_id = caller_id.node_id();

        let callee_records = MemoryCallRecordSink::new().shared();
        let caller_records = MemoryCallRecordSink::new().shared();

        let opts = NodeBindOpts::disabled().with_rate_limits(rate_limits);
        let callee = Node::bind_at_with_opts(
            &callee_home,
            Arc::new(Allowlist::allow(caller_node_id)) as Arc<dyn Verify>,
            CancellationToken::new(),
            callee_behavior,
            Arc::clone(&callee_records) as Arc<dyn CallRecordSink>,
            opts,
        )
        .await
        .expect("bind callee");
        callee.spawn_accept_loop();

        let caller = Node::bind_with_opts(
            caller_id,
            Arc::new(Allowlist::empty()) as Arc<dyn Verify>,
            CancellationToken::new(),
            CalleeBehavior::StubComplete,
            Arc::clone(&caller_records) as Arc<dyn CallRecordSink>,
            NodeBindOpts::disabled(),
        )
        .await
        .expect("bind caller");

        Self {
            callee,
            caller,
            callee_records,
            caller_records,
            callee_home,
            caller_home,
        }
    }

    async fn shutdown(self) {
        self.caller.shutdown().await;
        self.callee.shutdown().await;
        let _ = std::fs::remove_dir_all(&self.callee_home);
        let _ = std::fs::remove_dir_all(&self.caller_home);
    }
}

fn assert_rate_limited_record(r: &uat_node::CallRecord, direction: Direction) {
    assert_eq!(r.direction, direction);
    assert!(
        r.task.is_none(),
        "rate-limited close is pre-Submit; task must be None, got {r:?}"
    );
    assert_eq!(r.outcome, Outcome::Closed(CloseCode::RateLimited));
    if direction == Direction::Inbound {
        assert_eq!(
            r.authorization,
            AuthOutcome::NotReached,
            "rate limit is not an auth decision"
        );
    }
}

/// Concurrent=1 + hanging first call → second dial closed RateLimited before accept_bi.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_cap_closes_rate_limited_before_stream() {
    let pair = Pair::bind(
        CalleeBehavior::HangAfterAccept,
        RateLimitConfig {
            max_concurrent_calls: 1,
            max_calls_per_minute: 100,
            max_live_frames: 100,
        },
    )
    .await;

    // Hold the single concurrent slot open (Accepted, then hang).
    let hang = {
        let caller = Arc::clone(&pair.caller);
        let addr = pair.callee.addr();
        tokio::spawn(async move {
            caller
                .dial(addr, submit_ms(0x11301, 60_000))
                .await
        })
    };
    // Give the hanging call time to be admitted (accept_bi + Submit + Accepted).
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        pair.callee.rate_limiter().in_flight(pair.caller.node_id()),
        1,
        "first call must occupy the concurrent slot"
    );

    // Second dial from the same peer key must be refused at admission.
    let second = pair
        .caller
        .dial(pair.callee.addr(), submit_ms(0x11302, 30_000))
        .await;

    if let Ok(finish) = &second {
        assert_eq!(
            finish.outcome,
            Outcome::Closed(CloseCode::RateLimited),
            "dialer finish={finish:?}"
        );
    }

    // Callee: exactly one rate-limit record (the second dial). First call still hanging.
    wait_records(&pair.callee_records, 1).await;
    // May have only the rate-limit record so far (hang has not finished).
    let rate_limited: Vec<_> = pair
        .callee_records
        .snapshot()
        .into_iter()
        .filter(|r| r.outcome == Outcome::Closed(CloseCode::RateLimited))
        .collect();
    assert_eq!(
        rate_limited.len(),
        1,
        "expected one RateLimited callee record, got {:?}",
        pair.callee_records.snapshot()
    );
    assert_rate_limited_record(&rate_limited[0], Direction::Inbound);

    // Hanging dial has not finished, so only the rate-limited attempt has emitted.
    wait_records(&pair.caller_records, 1).await;
    let caller_rl = pair
        .caller_records
        .snapshot()
        .into_iter()
        .find(|r| r.outcome == Outcome::Closed(CloseCode::RateLimited))
        .expect("caller RateLimited record");
    assert_rate_limited_record(&caller_rl, Direction::Outbound);

    // Both ends agree on the rate-limited outcome.
    assert_eq!(rate_limited[0].outcome, caller_rl.outcome);
    assert!(rate_limited[0].task.is_none() && caller_rl.task.is_none());

    hang.abort();
    pair.shutdown().await;
    let _ = hang.await;
}

/// Calls/minute=1 → second admit attempt closed RateLimited even after first call ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calls_per_minute_cap_closes_rate_limited_and_records_agree() {
    let pair = Pair::bind(
        CalleeBehavior::StubComplete,
        RateLimitConfig {
            max_concurrent_calls: 8,
            max_calls_per_minute: 1,
            max_live_frames: 8,
        },
    )
    .await;

    let first = pair
        .caller
        .dial(pair.callee.addr(), submit_ms(0x11311, 30_000))
        .await
        .expect("first dial");
    assert_eq!(first.outcome, Outcome::Completed);
    wait_records(&pair.callee_records, 1).await;
    wait_records(&pair.caller_records, 1).await;

    let second = pair
        .caller
        .dial(pair.callee.addr(), submit_ms(0x11312, 30_000))
        .await;
    if let Ok(finish) = &second {
        assert_eq!(finish.outcome, Outcome::Closed(CloseCode::RateLimited));
    }

    wait_records(&pair.callee_records, 2).await;
    wait_records(&pair.caller_records, 2).await;

    let callee_rl = pair
        .callee_records
        .snapshot()
        .into_iter()
        .find(|r| r.outcome == Outcome::Closed(CloseCode::RateLimited))
        .expect("callee RateLimited record");
    let caller_rl = pair
        .caller_records
        .snapshot()
        .into_iter()
        .find(|r| r.outcome == Outcome::Closed(CloseCode::RateLimited))
        .expect("caller RateLimited record");

    assert_rate_limited_record(&callee_rl, Direction::Inbound);
    assert_rate_limited_record(&caller_rl, Direction::Outbound);
    assert_eq!(callee_rl.outcome, caller_rl.outcome);

    // First call was a normal Completed with a task id — proves only the second
    // path skipped stream acceptance / Submit.
    let callee_ok = pair
        .callee_records
        .snapshot()
        .into_iter()
        .find(|r| r.outcome == Outcome::Completed)
        .expect("completed record");
    assert_eq!(callee_ok.task, Some(TaskId::from_u128(0x11311)));

    pair.shutdown().await;
}

/// Live-frames=1 with a held connection rejects the next dial the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_frames_cap_closes_before_accept_bi() {
    let pair = Pair::bind(
        CalleeBehavior::HangAfterAccept,
        RateLimitConfig {
            max_concurrent_calls: 100,
            max_calls_per_minute: 100,
            max_live_frames: 1,
        },
    )
    .await;

    let hang = {
        let caller = Arc::clone(&pair.caller);
        let addr = pair.callee.addr();
        tokio::spawn(async move { caller.dial(addr, submit_ms(0x11321, 60_000)).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;

    let second = pair
        .caller
        .dial(pair.callee.addr(), submit_ms(0x11322, 30_000))
        .await;
    if let Ok(finish) = &second {
        assert_eq!(finish.outcome, Outcome::Closed(CloseCode::RateLimited));
    }

    wait_records(&pair.callee_records, 1).await;
    let rl = pair
        .callee_records
        .snapshot()
        .into_iter()
        .find(|r| r.outcome == Outcome::Closed(CloseCode::RateLimited))
        .expect("rate limited");
    assert_rate_limited_record(&rl, Direction::Inbound);

    wait_records(&pair.caller_records, 1).await;
    let caller_rl = pair
        .caller_records
        .snapshot()
        .into_iter()
        .find(|r| r.outcome == Outcome::Closed(CloseCode::RateLimited))
        .expect("caller rate limited");
    assert_eq!(rl.outcome, caller_rl.outcome);

    hang.abort();
    pair.shutdown().await;
    let _ = hang.await;
}
