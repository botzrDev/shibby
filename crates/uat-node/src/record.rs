//! Per-connection call audit records (HLX-106).
//!
//! Exactly one [`CallRecord`] is emitted for every connection the node accepts or
//! opens — success, failure, allowlist deny, and closes before Submit.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use iroh::endpoint::Connection;
use tracing::info;
use uat_core::{CloseCode, NodeId, Outcome, TaskId};

use crate::call::CallError;
use crate::frame_io::FrameIoError;

/// Schema version written into every [`CallRecord`].
pub const CALL_RECORD_SCHEMA_VERSION: u32 = 1;

/// Which side opened the connection from this node's point of view.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Direction {
    /// This node dialed.
    Outbound,
    /// This node accepted.
    Inbound,
}

/// Which M1/M2 rule admitted the peer (seam for answering policy).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AuthRule {
    /// Peer passed the static [`crate::Allowlist`].
    Allowlist,
}

/// Result of the authorization check for this connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthOutcome {
    /// Peer was admitted under `rule`.
    Allowed(AuthRule),
    /// Peer was rejected before or during Submit.
    Denied { reason: String },
    /// No local authorization decision applied (typical for outbound dials).
    NotReached,
}

/// How the QUIC path was established. Relays disabled in M1 → always [`Path::Direct`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Path {
    /// Direct (or hole-punched) path; RelayMode disabled.
    Direct,
    /// Relayed via the named relay (future; not used while relays are off).
    Relayed { relay: String },
}

/// One audit record per accepted or opened connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallRecord {
    /// Wire/schema version; currently [`CALL_RECORD_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// When this node began handling the connection.
    pub started_at: SystemTime,
    /// Submit task id, or `None` if the connection closed before Submit.
    pub task: Option<TaskId>,
    /// Inbound vs outbound from this node.
    pub direction: Direction,
    /// Authenticated peer NodeId (never a claimed identity).
    pub peer: NodeId,
    /// Allowlist / policy decision for this connection.
    pub authorization: AuthOutcome,
    /// How the call ended.
    pub outcome: Outcome,
    /// Direct vs relayed transport path.
    pub path: Path,
    /// QUIC connection-level bytes transmitted (`udp_tx`), when available.
    pub bytes_sent: u64,
    /// QUIC connection-level bytes received (`udp_rx`), when available.
    pub bytes_recv: u64,
    /// Wall time from start to emit, in milliseconds.
    pub wall_time_ms: u64,
}

/// Receives finished [`CallRecord`]s. Log sink in production; vec collector in tests.
pub trait CallRecordSink: Send + Sync {
    /// Emit exactly one finished record. Implementations must not panic.
    fn emit(&self, record: CallRecord);
}

impl<T: CallRecordSink + ?Sized> CallRecordSink for Arc<T> {
    fn emit(&self, record: CallRecord) {
        (**self).emit(record);
    }
}

/// Logs each record at `info` (default node sink).
#[derive(Clone, Copy, Debug, Default)]
pub struct TracingCallRecordSink;

impl CallRecordSink for TracingCallRecordSink {
    fn emit(&self, record: CallRecord) {
        info!(
            schema_version = record.schema_version,
            ?record.direction,
            ?record.peer,
            ?record.task,
            ?record.authorization,
            ?record.outcome,
            ?record.path,
            record.bytes_sent,
            record.bytes_recv,
            record.wall_time_ms,
            "call_record"
        );
    }
}

/// In-memory collector for tests (no files).
#[derive(Clone, Debug, Default)]
pub struct MemoryCallRecordSink {
    records: Arc<Mutex<Vec<CallRecord>>>,
}

impl MemoryCallRecordSink {
    /// Empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Shared handle so the node and the test hold the same buffer.
    #[must_use]
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Snapshot of records emitted so far (clone).
    #[must_use]
    pub fn snapshot(&self) -> Vec<CallRecord> {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Number of records emitted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether no records have been emitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CallRecordSink for MemoryCallRecordSink {
    fn emit(&self, record: CallRecord) {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record);
    }
}

/// Read QUIC connection-level byte counters from iroh stats.
#[must_use]
pub fn connection_bytes(conn: &Connection) -> (u64, u64) {
    let stats = conn.stats();
    (stats.udp_tx.bytes, stats.udp_rx.bytes)
}

/// Map a [`CallError`] onto the closest [`Outcome`] for the audit record.
#[must_use]
pub fn outcome_from_call_error(err: &CallError) -> Outcome {
    match err {
        CallError::Cancelled => Outcome::Canceled,
        CallError::Unauthorized => Outcome::Failed(uat_core::FailureCode::Unauthorized),
        CallError::NetworkTimeout => Outcome::Closed(CloseCode::Timeout),
        CallError::Illegal => Outcome::Closed(CloseCode::ProtocolViolation),
        CallError::Frame(fe) => match fe.close_code() {
            Some(code) => Outcome::Closed(code),
            None => match fe {
                FrameIoError::UnexpectedEnd | FrameIoError::Read(_) | FrameIoError::Write(_) => {
                    Outcome::PeerLost
                }
                _ => Outcome::Closed(CloseCode::ProtocolViolation),
            },
        },
        CallError::StreamSetup(_) | CallError::Connection(_) => Outcome::PeerLost,
    }
}

/// Builds and emits a [`CallRecord`] exactly once (Drop = unwind safety).
pub struct CallRecordGuard {
    sink: Arc<dyn CallRecordSink>,
    started_at: SystemTime,
    start: Instant,
    direction: Direction,
    peer: NodeId,
    task: Option<TaskId>,
    authorization: AuthOutcome,
    outcome: Outcome,
    path: Path,
    conn: Option<Connection>,
    bytes: Option<(u64, u64)>,
    emitted: bool,
}

impl CallRecordGuard {
    /// Start a record for an established connection.
    #[must_use]
    pub fn new(
        sink: Arc<dyn CallRecordSink>,
        direction: Direction,
        peer: NodeId,
        authorization: AuthOutcome,
        conn: Connection,
    ) -> Self {
        Self {
            sink,
            started_at: SystemTime::now(),
            start: Instant::now(),
            direction,
            peer,
            task: None,
            authorization,
            outcome: Outcome::PeerLost,
            path: Path::Direct,
            conn: Some(conn),
            bytes: None,
            emitted: false,
        }
    }

    /// Start a record when only pre-captured byte counts are available.
    #[must_use]
    pub fn new_with_bytes(
        sink: Arc<dyn CallRecordSink>,
        direction: Direction,
        peer: NodeId,
        authorization: AuthOutcome,
        bytes_sent: u64,
        bytes_recv: u64,
    ) -> Self {
        Self {
            sink,
            started_at: SystemTime::now(),
            start: Instant::now(),
            direction,
            peer,
            task: None,
            authorization,
            outcome: Outcome::PeerLost,
            path: Path::Direct,
            conn: None,
            bytes: Some((bytes_sent, bytes_recv)),
            emitted: false,
        }
    }

    /// Record the Submit task id once known.
    pub fn set_task(&mut self, task: TaskId) {
        self.task = Some(task);
    }

    /// Override authorization (e.g. late Submit deny).
    pub fn set_authorization(&mut self, authorization: AuthOutcome) {
        self.authorization = authorization;
    }

    /// Set the terminal outcome before the guard drops.
    pub fn set_outcome(&mut self, outcome: Outcome) {
        self.outcome = outcome;
    }

    /// Apply a call result: `Ok` outcome or mapped [`CallError`].
    pub fn observe_result(&mut self, result: &Result<Outcome, CallError>) {
        match result {
            Ok(outcome) => self.set_outcome(*outcome),
            Err(err) => self.set_outcome(outcome_from_call_error(err)),
        }
    }

    fn emit_now(&mut self) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        let (bytes_sent, bytes_recv) = if let Some(pair) = self.bytes {
            pair
        } else if let Some(conn) = self.conn.as_ref() {
            connection_bytes(conn)
        } else {
            (0, 0)
        };
        let wall_time_ms = duration_ms(self.start.elapsed());
        self.sink.emit(CallRecord {
            schema_version: CALL_RECORD_SCHEMA_VERSION,
            started_at: self.started_at,
            task: self.task,
            direction: self.direction,
            peer: self.peer,
            authorization: self.authorization.clone(),
            outcome: self.outcome,
            path: self.path.clone(),
            bytes_sent,
            bytes_recv,
            wall_time_ms,
        });
    }
}

impl Drop for CallRecordGuard {
    fn drop(&mut self) {
        self.emit_now();
    }
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uat_core::{CloseCode, FailureCode};

    #[test]
    fn memory_sink_collects_every_outcome_variant() {
        let sink = MemoryCallRecordSink::new();
        let peer = NodeId::from_bytes([9u8; 32]);
        let variants = [
            Outcome::Completed,
            Outcome::Canceled,
            Outcome::Failed(FailureCode::DeadlineExceeded),
            Outcome::Closed(CloseCode::Timeout),
            Outcome::PeerLost,
        ];
        for (i, outcome) in variants.into_iter().enumerate() {
            sink.emit(CallRecord {
                schema_version: CALL_RECORD_SCHEMA_VERSION,
                started_at: SystemTime::UNIX_EPOCH,
                task: if i == 4 {
                    None
                } else {
                    Some(TaskId::from_u128(i as u128))
                },
                direction: if i % 2 == 0 {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                },
                peer,
                authorization: AuthOutcome::Allowed(AuthRule::Allowlist),
                outcome,
                path: Path::Direct,
                bytes_sent: i as u64,
                bytes_recv: i as u64 * 2,
                wall_time_ms: i as u64,
            });
        }
        let got = sink.snapshot();
        assert_eq!(got.len(), 5);
        assert!(got.iter().any(|r| r.outcome == Outcome::Completed));
        assert!(got.iter().any(|r| r.outcome == Outcome::Canceled));
        assert!(got
            .iter()
            .any(|r| r.outcome == Outcome::Failed(FailureCode::DeadlineExceeded)));
        assert!(got
            .iter()
            .any(|r| r.outcome == Outcome::Closed(CloseCode::Timeout)));
        assert!(got.iter().any(|r| r.outcome == Outcome::PeerLost && r.task.is_none()));
    }

    #[test]
    fn guard_emits_exactly_once_on_drop() {
        let sink = MemoryCallRecordSink::new().shared();
        let peer = NodeId::from_bytes([1u8; 32]);
        {
            let mut g = CallRecordGuard::new_with_bytes(
                Arc::clone(&sink) as Arc<dyn CallRecordSink>,
                Direction::Inbound,
                peer,
                AuthOutcome::Denied {
                    reason: "not on allowlist".into(),
                },
                10,
                20,
            );
            g.set_outcome(Outcome::Closed(CloseCode::Normal));
        }
        assert_eq!(sink.len(), 1);
        let r = &sink.snapshot()[0];
        assert_eq!(r.schema_version, 1);
        assert!(r.task.is_none());
        assert_eq!(r.bytes_sent, 10);
        assert_eq!(r.bytes_recv, 20);
        assert!(matches!(r.authorization, AuthOutcome::Denied { .. }));
        assert_eq!(r.outcome, Outcome::Closed(CloseCode::Normal));
        assert_eq!(r.path, Path::Direct);
    }
}
