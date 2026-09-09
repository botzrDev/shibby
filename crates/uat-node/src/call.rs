//! One Call task per connection: single bidirectional stream + state machines + timers.
//!
//! Timer semantics (HLX-105 / §5.5):
//! - Callee: on Recv(Submit), Sleep(`deadline`) → Timeout → Failed{DeadlineExceeded}
//! - Caller: on Send(Submit), Sleep(`deadline + GRACE`) → Timeout → CloseCode::Timeout
//! - Asymmetry is intentional: callee always fires first.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::{timeout, Sleep};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use uat_core::{
    callee_step, caller_step, split_frame, AllowAll, CalleeEvent, CalleeState, CallerEvent,
    CallerState, CloseCode, FailureCode, Illegal, Message, NodeId, Outcome, GRACE_MS,
};
use uat_policy::{AuthError, AuthorizedSubmit};

use crate::auth::{authorize_submit_header, Verify};
use crate::frame_io::{read_frame, read_message, write_message, FrameIoError};
use crate::record::{
    AuthOutcome, AuthRule, CallRecordGuard, CallRecordSink, Direction,
};
use crate::timing::{callee_budget, caller_budget, quic_idle_timeout};
use crate::public_key_to_node_id;

/// Errors while driving a call.
#[derive(Debug, Error)]
pub enum CallError {
    /// Failed to open or accept the bidirectional stream.
    #[error("stream setup failed: {0}")]
    StreamSetup(String),

    /// Frame codec / I/O failure.
    #[error(transparent)]
    Frame(#[from] FrameIoError),

    /// State machine rejected an event (protocol violation).
    #[error("illegal state transition")]
    Illegal,

    /// Peer was not allowed to place this call.
    #[error("peer not authorized")]
    Unauthorized,

    /// Call cancelled via [`CancellationToken`] (node shutdown).
    #[error("call cancelled")]
    Cancelled,

    /// Connection to the peer failed.
    #[error("connection failed: {0}")]
    Connection(String),

    /// A network await exceeded its budget (should be unreachable if timers are wired).
    #[error("network operation timed out")]
    NetworkTimeout,
}

impl From<Illegal> for CallError {
    fn from(_: Illegal) -> Self {
        Self::Illegal
    }
}

/// How the stub callee behaves after receiving Submit (real handlers land later).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CalleeBehavior {
    /// Accepted → Completed (empty body). Production default.
    #[default]
    StubComplete,
    /// Accepted, then wait for Cancel / deadline / connection loss (timer tests).
    HangAfterAccept,
    /// Accepted → NeedInput, then wait (L2 AwaitingInput).
    NeedInputHang,
    /// Accepted, then ignore all peer messages (only timer / conn-loss). L4 timer path.
    SilentHang,
}

/// Optional caller-side hooks (tests: inject Cancel).
#[derive(Default)]
pub struct CallerOpts {
    /// When received, send `Cancel` if the call is still non-terminal.
    pub request_cancel: Option<oneshot::Receiver<()>>,
}

/// Close `conn` with a UAT application [`CloseCode`].
pub fn close_with(conn: &Connection, code: CloseCode) {
    conn.close(code.as_u32().into(), code_reason(code));
}

fn code_reason(code: CloseCode) -> &'static [u8] {
    match code {
        CloseCode::Normal => b"normal",
        CloseCode::RateLimited => b"rate_limited",
        CloseCode::FrameTooLarge => b"frame_too_large",
        CloseCode::MalformedFrame => b"malformed_frame",
        CloseCode::ProtocolViolation => b"protocol_violation",
        CloseCode::Timeout => b"timeout",
    }
}

fn close_on_frame_err(conn: &Connection, err: &FrameIoError) {
    if let Some(code) = err.close_code() {
        close_with(conn, code);
    }
}

fn close_code_from_conn_err(err: &iroh::endpoint::ConnectionError) -> CloseCode {
    match err {
        iroh::endpoint::ConnectionError::ApplicationClosed(app) => {
            CloseCode::from_u32(u64::from(app.error_code) as u32).unwrap_or(CloseCode::ProtocolViolation)
        }
        iroh::endpoint::ConnectionError::TimedOut => CloseCode::Timeout,
        _ => CloseCode::ProtocolViolation,
    }
}

/// Watch for a second bidirectional stream; close with ProtocolViolation if seen.
pub async fn watch_second_stream(conn: Connection, cancel: CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {}
        result = conn.accept_bi() => {
            if result.is_ok() {
                warn!("peer opened a second bidirectional stream");
                close_with(&conn, CloseCode::ProtocolViolation);
            }
        }
    }
}

async fn await_network<T, E, F>(budget: Duration, fut: F) -> Result<T, CallError>
where
    F: std::future::Future<Output = Result<T, E>>,
    CallError: From<E>,
{
    match timeout(budget, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(CallError::from(e)),
        Err(_) => Err(CallError::NetworkTimeout),
    }
}

/// Run the caller side of a call on an established connection.
pub async fn run_caller(
    conn: Connection,
    submit: Message,
    cancel: CancellationToken,
    sink: Arc<dyn CallRecordSink>,
) -> Result<Outcome, CallError> {
    run_caller_with(conn, submit, cancel, CallerOpts::default(), sink).await
}

/// Caller entry with optional hooks (Cancel injection for tests).
pub async fn run_caller_with(
    conn: Connection,
    submit: Message,
    cancel: CancellationToken,
    mut opts: CallerOpts,
    sink: Arc<dyn CallRecordSink>,
) -> Result<Outcome, CallError> {
    let peer = public_key_to_node_id(&conn.remote_id());
    let mut record = CallRecordGuard::new(
        sink,
        Direction::Outbound,
        peer,
        AuthOutcome::NotReached,
        conn.clone(),
    );
    if let Message::Submit { task, .. } = &submit {
        record.set_task(*task);
    }

    if !matches!(submit, Message::Submit { .. }) {
        record.set_outcome(Outcome::Closed(CloseCode::ProtocolViolation));
        return Err(CallError::Illegal);
    }

    let (mut send, mut recv) = match timeout(quic_idle_timeout(), conn.open_bi()).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            let err = CallError::StreamSetup(e.to_string());
            record.set_outcome(crate::record::outcome_from_call_error(&err));
            return Err(err);
        }
        Err(_) => {
            let err = CallError::StreamSetup("open_bi timed out".into());
            record.set_outcome(crate::record::outcome_from_call_error(&err));
            return Err(err);
        }
    };

    let guard_cancel = cancel.child_token();
    let stream_guard = tokio::spawn(watch_second_stream(conn.clone(), guard_cancel.clone()));

    let result = caller_loop(
        &conn,
        &mut send,
        &mut recv,
        submit,
        &cancel,
        &mut opts.request_cancel,
    )
    .await;
    guard_cancel.cancel();
    let _ = stream_guard.await;
    record.observe_result(&result);
    result
}

async fn caller_loop(
    conn: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    submit: Message,
    cancel: &CancellationToken,
    request_cancel: &mut Option<oneshot::Receiver<()>>,
) -> Result<Outcome, CallError> {
    let deadline = match &submit {
        Message::Submit { deadline, .. } => *deadline,
        _ => return Err(CallError::Illegal),
    };
    let budget = caller_budget(deadline);

    let mut state = CallerState::Dialing;
    let step = caller_step(state, CallerEvent::Send(submit.clone()))?;
    state = step.state;

    // A1.2.3: caller timer starts at Send(Submit).
    let mut call_timer = Box::pin(tokio::time::sleep(budget));

    if let Err(err) = await_network(budget, write_message(send, &submit)).await {
        if let CallError::Frame(ref fe) = err {
            close_on_frame_err(conn, fe);
        }
        return Err(err);
    }

    loop {
        if let CallerState::Terminal(outcome) = &state {
            let outcome = *outcome;
            close_with(conn, CloseCode::Normal);
            return Ok(outcome);
        }

        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                return Err(CallError::Cancelled);
            }
            _ = &mut call_timer => {
                debug!("caller deadline+GRACE fired");
                match caller_step(state, CallerEvent::Timeout) {
                    Ok(step) => {
                        state = step.state;
                        close_with(conn, CloseCode::Timeout);
                        if let CallerState::Terminal(outcome) = state {
                            return Ok(outcome);
                        }
                        return Ok(Outcome::Closed(CloseCode::Timeout));
                    }
                    Err(Illegal) => {
                        close_with(conn, CloseCode::ProtocolViolation);
                        return Err(CallError::Illegal);
                    }
                }
            }
            err = conn.closed() => {
                let code = close_code_from_conn_err(&err);
                debug!(?code, "caller saw connection close");
                match caller_step(state, CallerEvent::ConnLost(code)) {
                    Ok(step) => {
                        if let CallerState::Terminal(outcome) = step.state {
                            return Ok(outcome);
                        }
                        return Err(CallError::Illegal);
                    }
                    Err(Illegal) => return Err(CallError::Illegal),
                }
            }
            cancel_req = async {
                match request_cancel.as_mut() {
                    Some(rx) => rx.await.ok(),
                    None => std::future::pending().await,
                }
            } => {
                if cancel_req.is_some() {
                    *request_cancel = None;
                    match caller_step(state.clone(), CallerEvent::Send(Message::Cancel)) {
                        Ok(step) => {
                            state = step.state;
                            if let Err(err) = await_network(budget, write_message(send, &Message::Cancel)).await {
                                if let CallError::Frame(ref fe) = err {
                                    close_on_frame_err(conn, fe);
                                }
                                return Err(err);
                            }
                        }
                        Err(Illegal) => {
                            close_with(conn, CloseCode::ProtocolViolation);
                            return Err(CallError::Illegal);
                        }
                    }
                }
            }
            msg = await_network(budget, read_message(recv, &AllowAll)) => {
                let msg = match msg {
                    Ok(m) => m,
                    Err(CallError::NetworkTimeout) => {
                        // Prefer the dedicated call timer path; treat as timeout close.
                        close_with(conn, CloseCode::Timeout);
                        return Ok(Outcome::Closed(CloseCode::Timeout));
                    }
                    Err(CallError::Frame(err)) => {
                        close_on_frame_err(conn, &err);
                        return Err(CallError::Frame(err));
                    }
                    Err(err) => return Err(err),
                };
                debug!(?msg, ?state, "caller recv");
                match caller_step(state, CallerEvent::Recv(msg)) {
                    Ok(step) => {
                        state = step.state;
                    }
                    Err(Illegal) => {
                        close_with(conn, CloseCode::ProtocolViolation);
                        return Err(CallError::Illegal);
                    }
                }
            }
        }
    }
}

/// Run the callee side with the default stub (Accepted → Completed).
pub async fn run_callee(
    conn: Connection,
    peer: NodeId,
    verify: Arc<dyn Verify>,
    cancel: CancellationToken,
    sink: Arc<dyn CallRecordSink>,
) -> Result<Outcome, CallError> {
    run_callee_with(conn, peer, verify, cancel, CalleeBehavior::StubComplete, sink).await
}

/// Callee entry with selectable stub behavior.
pub async fn run_callee_with(
    conn: Connection,
    peer: NodeId,
    verify: Arc<dyn Verify>,
    cancel: CancellationToken,
    behavior: CalleeBehavior,
    sink: Arc<dyn CallRecordSink>,
) -> Result<Outcome, CallError> {
    let mut record = CallRecordGuard::new(
        sink,
        Direction::Inbound,
        peer,
        AuthOutcome::Allowed(AuthRule::Allowlist),
        conn.clone(),
    );

    if !verify.verify_peer(peer) {
        close_with(&conn, CloseCode::Normal);
        record.set_authorization(AuthOutcome::Denied {
            reason: "not on allowlist".into(),
        });
        record.set_outcome(Outcome::Closed(CloseCode::Normal));
        return Err(CallError::Unauthorized);
    }

    let (mut send, mut recv) = match timeout(quic_idle_timeout(), conn.accept_bi()).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            let err = CallError::StreamSetup(e.to_string());
            record.set_outcome(crate::record::outcome_from_call_error(&err));
            return Err(err);
        }
        Err(_) => {
            let err = CallError::StreamSetup("accept_bi timed out".into());
            record.set_outcome(crate::record::outcome_from_call_error(&err));
            return Err(err);
        }
    };

    let guard_cancel = cancel.child_token();
    let stream_guard = tokio::spawn(watch_second_stream(conn.clone(), guard_cancel.clone()));

    let result = callee_loop(
        &conn,
        &mut send,
        &mut recv,
        peer,
        verify.as_ref(),
        &cancel,
        behavior,
        &mut record,
    )
    .await;
    guard_cancel.cancel();
    let _ = stream_guard.await;
    record.observe_result(&result);
    result
}

#[allow(clippy::too_many_arguments)]
async fn callee_loop(
    conn: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    peer: NodeId,
    verify: &dyn Verify,
    cancel: &CancellationToken,
    behavior: CalleeBehavior,
    record: &mut CallRecordGuard,
) -> Result<Outcome, CallError> {
    let idle = quic_idle_timeout();
    let policy = verify.policy();
    let now = std::time::SystemTime::now();

    // F4/S6: read frame → header-only UnverifiedSubmit → verify → only then copy body.
    let frame = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            return Err(CallError::Cancelled);
        }
        _ = conn.closed() => {
            // Closed before Submit: task stays None.
            return Ok(Outcome::PeerLost);
        }
        frame = await_network(idle, read_frame(recv)) => {
            match frame {
                Ok(f) => f,
                Err(CallError::Frame(err)) => {
                    close_on_frame_err(conn, &err);
                    return Err(CallError::Frame(err));
                }
                Err(CallError::NetworkTimeout) => {
                    close_with(conn, CloseCode::Timeout);
                    return Ok(Outcome::Closed(CloseCode::Timeout));
                }
                Err(err) => return Err(err),
            }
        }
    };

    let (header, body) = match split_frame(&frame) {
        Ok(parts) => parts,
        Err(err) => {
            close_on_frame_err(conn, &FrameIoError::Codec(err.clone()));
            return Err(CallError::Frame(FrameIoError::Codec(err)));
        }
    };

    let authorized = match authorize_submit_header(header, policy, peer, now) {
        Ok(a) => a,
        Err(err) => {
            let reason = match &err {
                AuthError::Denied(_) => "submit denied by allowlist".to_string(),
                AuthError::TokenNotImplemented => "biscuit token not implemented".to_string(),
                other => other.to_string(),
            };
            let failed = Message::Failed {
                code: FailureCode::Unauthorized,
            };
            let _ = write_message(send, &failed).await;
            let _ = send.finish();
            close_with(conn, CloseCode::Normal);
            record.set_authorization(AuthOutcome::Denied { reason });
            return Err(CallError::Unauthorized);
        }
    };

    // Body materialization only after verify (S6). Handlers take AuthorizedSubmit only.
    let authorized = authorized.with_body(body.to_vec());
    record.set_authorization(AuthOutcome::Allowed(authorized.rule));
    handle_authorized_submit(conn, send, recv, peer, cancel, behavior, record, authorized).await
}

/// Drive the call after a verified [`AuthorizedSubmit`] (body already attached).
#[allow(clippy::too_many_arguments)]
async fn handle_authorized_submit(
    conn: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    peer: NodeId,
    cancel: &CancellationToken,
    behavior: CalleeBehavior,
    record: &mut CallRecordGuard,
    submit: AuthorizedSubmit,
) -> Result<Outcome, CallError> {
    let deadline = submit.deadline();
    record.set_task(submit.task());
    debug!(?peer, ?deadline, rule = ?submit.rule, "callee received authorized submit");

    // Callee timer starts at receipt of Submit.
    let mut call_timer = Box::pin(tokio::time::sleep(callee_budget(deadline)));
    // Caller-facing upper bound for network ops on this call.
    let net_budget = caller_budget(deadline);

    let mut state = CalleeState::Offered;

    match behavior {
        CalleeBehavior::StubComplete => {
            emit_callee(conn, send, &mut state, Message::Accepted, net_budget).await?;
            emit_callee(
                conn,
                send,
                &mut state,
                Message::Completed { body: Vec::new() },
                net_budget,
            )
            .await?;
        }
        CalleeBehavior::HangAfterAccept | CalleeBehavior::SilentHang => {
            emit_callee(conn, send, &mut state, Message::Accepted, net_budget).await?;
        }
        CalleeBehavior::NeedInputHang => {
            emit_callee(conn, send, &mut state, Message::Accepted, net_budget).await?;
            emit_callee(conn, send, &mut state, Message::NeedInput, net_budget).await?;
        }
    }

    // Drive until terminal: timer, peer messages, cancel, or connection loss.
    let ignore_peer = matches!(behavior, CalleeBehavior::SilentHang);
    let outcome = callee_wait_terminal(
        conn,
        send,
        recv,
        &mut state,
        &mut call_timer,
        cancel,
        net_budget,
        ignore_peer,
    )
    .await?;

    if let Err(err) = send.finish() {
        // Finish may fail if we already closed; ignore when terminal via close.
        debug!(?err, "callee send.finish");
    }

    // Wait briefly for caller to observe terminal / close Normal.
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            close_with(conn, CloseCode::Normal);
        }
        _ = conn.closed() => {}
        _ = tokio::time::sleep(Duration::from_millis(GRACE_MS)) => {
            close_with(conn, CloseCode::Normal);
        }
    }

    Ok(outcome)
}

async fn emit_callee(
    conn: &Connection,
    send: &mut iroh::endpoint::SendStream,
    state: &mut CalleeState,
    msg: Message,
    budget: Duration,
) -> Result<(), CallError> {
    let step = match callee_step(state.clone(), CalleeEvent::Send(msg.clone())) {
        Ok(s) => s,
        Err(Illegal) => {
            close_with(conn, CloseCode::ProtocolViolation);
            return Err(CallError::Illegal);
        }
    };
    *state = step.state;
    if let Err(err) = await_network(budget, write_message(send, &msg)).await {
        if let CallError::Frame(ref fe) = err {
            close_on_frame_err(conn, fe);
        }
        return Err(err);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn callee_wait_terminal(
    conn: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    state: &mut CalleeState,
    call_timer: &mut std::pin::Pin<Box<Sleep>>,
    cancel: &CancellationToken,
    net_budget: Duration,
    ignore_peer_msgs: bool,
) -> Result<Outcome, CallError> {
    if let CalleeState::Terminal(outcome) = *state {
        return Ok(outcome);
    }

    loop {
        if let CalleeState::Terminal(outcome) = *state {
            return Ok(outcome);
        }

        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                return Err(CallError::Cancelled);
            }
            _ = &mut *call_timer => {
                debug!("callee deadline fired");
                match callee_step(state.clone(), CalleeEvent::Timeout) {
                    Ok(step) => {
                        *state = step.state;
                        if let Some(msg) = step.emit {
                            let _ = await_network(net_budget, write_message(send, &msg)).await;
                        }
                        if let CalleeState::Terminal(outcome) = *state {
                            close_with(conn, CloseCode::Normal);
                            return Ok(outcome);
                        }
                        return Err(CallError::Illegal);
                    }
                    Err(Illegal) => {
                        close_with(conn, CloseCode::ProtocolViolation);
                        return Err(CallError::Illegal);
                    }
                }
            }
            err = conn.closed() => {
                let code = close_code_from_conn_err(&err);
                match callee_step(state.clone(), CalleeEvent::ConnLost(code)) {
                    Ok(step) => {
                        *state = step.state;
                        if let CalleeState::Terminal(outcome) = *state {
                            return Ok(outcome);
                        }
                        return Err(CallError::Illegal);
                    }
                    Err(Illegal) => return Err(CallError::Illegal),
                }
            }
            msg = async {
                if ignore_peer_msgs {
                    std::future::pending::<Result<Message, CallError>>().await
                } else {
                    await_network(net_budget, read_message(recv, &AllowAll)).await
                }
            } => {
                let msg = match msg {
                    Ok(m) => m,
                    Err(CallError::NetworkTimeout) => {
                        // Fall through to timer semantics.
                        continue;
                    }
                    Err(CallError::Frame(err)) => {
                        // Stream ended / peer gone often surfaces as read error.
                        if matches!(
                            err,
                            FrameIoError::UnexpectedEnd
                                | FrameIoError::Read(_)
                                | FrameIoError::Write(_)
                        ) {
                            match callee_step(state.clone(), CalleeEvent::ConnLost(CloseCode::Normal)) {
                                Ok(step) => {
                                    *state = step.state;
                                    if let CalleeState::Terminal(outcome) = *state {
                                        return Ok(outcome);
                                    }
                                }
                                Err(Illegal) => return Err(CallError::Illegal),
                            }
                            return Ok(Outcome::PeerLost);
                        }
                        close_on_frame_err(conn, &err);
                        return Err(CallError::Frame(err));
                    }
                    Err(err) => return Err(err),
                };
                debug!(?msg, ?state, "callee recv");
                match callee_step(state.clone(), CalleeEvent::Recv(msg)) {
                    Ok(step) => {
                        *state = step.state;
                        if let Some(emit) = step.emit {
                            if let Err(err) = await_network(net_budget, write_message(send, &emit)).await {
                                if let CallError::Frame(ref fe) = err {
                                    close_on_frame_err(conn, fe);
                                }
                                return Err(err);
                            }
                        }
                    }
                    Err(Illegal) => {
                        close_with(conn, CloseCode::ProtocolViolation);
                        return Err(CallError::Illegal);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory harness for paused-clock timer tests (no QUIC).
// ---------------------------------------------------------------------------

/// Side-channel event for ordering / liveness proofs in tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimerEvent {
    CalleeDeadlineFired,
    CallerGraceFired,
}

/// Drive both sides over channels with real tokio Sleep timers (pause-friendly).
pub async fn drive_chan_call(
    submit: Message,
    behavior: CalleeBehavior,
    request_cancel: Option<oneshot::Receiver<()>>,
    events: Option<mpsc::UnboundedSender<TimerEvent>>,
) -> Result<(Outcome, Outcome), CallError> {
    let (c2s_tx, mut c2s_rx) = mpsc::unbounded_channel::<Message>();
    let (s2c_tx, mut s2c_rx) = mpsc::unbounded_channel::<Message>();
    let closed = Arc::new(Notify::new());
    let closed_c = Arc::clone(&closed);
    let closed_s = Arc::clone(&closed);

    let events_c = events.clone();
    let events_s = events;

    let caller = tokio::spawn(async move {
        drive_caller_chan(submit, &mut s2c_rx, c2s_tx, closed_c, request_cancel, events_c).await
    });
    let callee = tokio::spawn(async move {
        drive_callee_chan(&mut c2s_rx, s2c_tx, closed_s, behavior, events_s).await
    });

    let caller_out = caller.await.map_err(|e| CallError::Connection(e.to_string()))?;
    let callee_out = callee.await.map_err(|e| CallError::Connection(e.to_string()))?;
    Ok((caller_out?, callee_out?))
}

async fn drive_caller_chan(
    submit: Message,
    rx: &mut mpsc::UnboundedReceiver<Message>,
    tx: mpsc::UnboundedSender<Message>,
    closed: Arc<Notify>,
    mut request_cancel: Option<oneshot::Receiver<()>>,
    events: Option<mpsc::UnboundedSender<TimerEvent>>,
) -> Result<Outcome, CallError> {
    let deadline = match &submit {
        Message::Submit { deadline, .. } => *deadline,
        _ => return Err(CallError::Illegal),
    };
    let budget = caller_budget(deadline);
    let mut state = CallerState::Dialing;
    let step = caller_step(state, CallerEvent::Send(submit.clone()))?;
    state = step.state;
    let mut call_timer = Box::pin(tokio::time::sleep(budget));
    tx.send(submit).map_err(|_| CallError::Connection("callee gone".into()))?;

    loop {
        if let CallerState::Terminal(outcome) = state {
            drop(tx);
            return Ok(outcome);
        }

        tokio::select! {
            biased;
            _ = &mut call_timer => {
                if let Some(ev) = &events {
                    let _ = ev.send(TimerEvent::CallerGraceFired);
                }
                let step = caller_step(state, CallerEvent::Timeout)?;
                state = step.state;
                // Drop the sender so the peer observes end-of-stream.
                drop(tx);
                if let CallerState::Terminal(outcome) = state {
                    return Ok(outcome);
                }
                return Ok(Outcome::Closed(CloseCode::Timeout));
            }
            cancel_req = async {
                match request_cancel.as_mut() {
                    Some(rx) => rx.await.ok(),
                    None => std::future::pending().await,
                }
            } => {
                if cancel_req.is_some() {
                    request_cancel = None;
                    let step = caller_step(state, CallerEvent::Send(Message::Cancel))?;
                    state = step.state;
                    let _ = tx.send(Message::Cancel);
                }
            }
            msg = rx.recv() => {
                let Some(msg) = msg else {
                    let step = caller_step(state, CallerEvent::ConnLost(CloseCode::Normal))?;
                    if let CallerState::Terminal(outcome) = step.state {
                        return Ok(outcome);
                    }
                    return Ok(Outcome::PeerLost);
                };
                let step = caller_step(state, CallerEvent::Recv(msg))?;
                state = step.state;
            }
            _ = closed.notified() => {
                let step = caller_step(state, CallerEvent::ConnLost(CloseCode::Normal))?;
                if let CallerState::Terminal(outcome) = step.state {
                    return Ok(outcome);
                }
                return Ok(Outcome::PeerLost);
            }
        }
    }
}

async fn drive_callee_chan(
    rx: &mut mpsc::UnboundedReceiver<Message>,
    tx: mpsc::UnboundedSender<Message>,
    closed: Arc<Notify>,
    behavior: CalleeBehavior,
    events: Option<mpsc::UnboundedSender<TimerEvent>>,
) -> Result<Outcome, CallError> {
    let submit = rx.recv().await.ok_or(CallError::Connection("caller gone".into()))?;
    let deadline = match &submit {
        Message::Submit { deadline, .. } => *deadline,
        _ => return Err(CallError::Illegal),
    };

    let mut call_timer = Box::pin(tokio::time::sleep(callee_budget(deadline)));
    let mut state = CalleeState::Offered;
    let silent = matches!(behavior, CalleeBehavior::SilentHang);

    let send_step = |state: &mut CalleeState, tx: &mpsc::UnboundedSender<Message>, msg: Message| {
        let step = callee_step(state.clone(), CalleeEvent::Send(msg.clone()))?;
        *state = step.state;
        tx.send(msg)
            .map_err(|_| CallError::Connection("caller gone".into()))?;
        Ok::<(), CallError>(())
    };

    match behavior {
        CalleeBehavior::StubComplete => {
            send_step(&mut state, &tx, Message::Accepted)?;
            send_step(&mut state, &tx, Message::Completed { body: Vec::new() })?;
        }
        CalleeBehavior::HangAfterAccept => {
            send_step(&mut state, &tx, Message::Accepted)?;
        }
        CalleeBehavior::NeedInputHang => {
            send_step(&mut state, &tx, Message::Accepted)?;
            send_step(&mut state, &tx, Message::NeedInput)?;
        }
        CalleeBehavior::SilentHang => {
            send_step(&mut state, &tx, Message::Accepted)?;
        }
    }

    if let CalleeState::Terminal(outcome) = state {
        drop(tx);
        return Ok(outcome);
    }

    loop {
        if let CalleeState::Terminal(outcome) = state {
            drop(tx);
            return Ok(outcome);
        }

        tokio::select! {
            biased;
            _ = &mut call_timer => {
                if let Some(ev) = &events {
                    let _ = ev.send(TimerEvent::CalleeDeadlineFired);
                }
                let step = callee_step(state, CalleeEvent::Timeout)?;
                state = step.state;
                if let Some(msg) = step.emit {
                    let _ = tx.send(msg);
                }
                // Drop sender after terminal emit so peer can observe EOF if needed.
                drop(tx);
                if let CalleeState::Terminal(outcome) = state {
                    return Ok(outcome);
                }
                return Err(CallError::Illegal);
            }
            msg = async {
                if silent {
                    std::future::pending::<Option<Message>>().await
                } else {
                    rx.recv().await
                }
            } => {
                let Some(msg) = msg else {
                    let step = callee_step(state, CalleeEvent::ConnLost(CloseCode::Normal))?;
                    if let CalleeState::Terminal(outcome) = step.state {
                        return Ok(outcome);
                    }
                    return Ok(Outcome::PeerLost);
                };
                let step = callee_step(state, CalleeEvent::Recv(msg))?;
                state = step.state;
                if let Some(emit) = step.emit {
                    let _ = tx.send(emit);
                }
            }
            _ = closed.notified() => {
                let step = callee_step(state, CalleeEvent::ConnLost(CloseCode::Normal))?;
                if let CalleeState::Terminal(outcome) = step.state {
                    return Ok(outcome);
                }
                return Ok(Outcome::PeerLost);
            }
        }
    }
}


#[cfg(test)]
mod timing_start_tests {
    use super::*;
    use tokio::time::Instant;
    use uat_core::{ContentType, Deadline, TaskId};

    fn submit_ms(ms: u32) -> Message {
        Message::Submit {
            task: TaskId::from_u128(1),
            deadline: Deadline::new(ms).unwrap(),
            content_type: ContentType::new("text/plain").unwrap(),
            credential: None,
            body: Vec::new(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn l1_hang_reaches_terminal_within_deadline_plus_grace() {
        let submit = submit_ms(100);
        let start = Instant::now();
        let (caller, callee) = drive_chan_call(submit, CalleeBehavior::HangAfterAccept, None, None)
            .await
            .expect("call");
        let elapsed = start.elapsed();
        assert_eq!(
            callee,
            Outcome::Failed(FailureCode::DeadlineExceeded),
            "callee must DeadlineExceeded"
        );
        assert_eq!(
            caller,
            Outcome::Failed(FailureCode::DeadlineExceeded),
            "caller observes Failed, not Timeout"
        );
        assert!(
            elapsed <= Duration::from_millis(100 + GRACE_MS),
            "elapsed {elapsed:?} exceeds deadline+GRACE"
        );
        // Callee fires at deadline; Failed delivered before caller grace.
        assert!(elapsed >= Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn l2_awaiting_input_fails_on_callee_deadline() {
        let submit = submit_ms(200);
        let (caller, callee) = drive_chan_call(submit, CalleeBehavior::NeedInputHang, None, None)
            .await
            .expect("call");
        assert_eq!(callee, Outcome::Failed(FailureCode::DeadlineExceeded));
        assert_eq!(caller, Outcome::Failed(FailureCode::DeadlineExceeded));
    }

    #[tokio::test(start_paused = true)]
    async fn l4_canceling_reaches_terminal_via_caller_timer() {
        // SilentHang ignores Cancel; caller stays in Canceling until deadline+GRACE.
        let submit = submit_ms(50);
        let (tx, rx) = oneshot::channel();
        let drive = tokio::spawn(async move {
            drive_chan_call(submit, CalleeBehavior::SilentHang, Some(rx), None).await
        });
        tokio::time::advance(Duration::from_millis(1)).await;
        let _ = tx.send(());
        tokio::time::advance(Duration::from_millis(50 + GRACE_MS)).await;
        let (caller, callee) = drive.await.expect("join").expect("call");
        // Callee deadline fires first → Failed delivered; caller may see Failed or Timeout
        // if Failed was raced. With SilentHang, Failed is still sent on timeout emit.
        assert!(
            matches!(
                caller,
                Outcome::Failed(FailureCode::DeadlineExceeded)
                    | Outcome::Closed(CloseCode::Timeout)
            ),
            "caller={caller:?}"
        );
        assert_eq!(callee, Outcome::Failed(FailureCode::DeadlineExceeded));
    }

    #[tokio::test(start_paused = true)]
    async fn callee_fires_before_caller_ordering_pinned() {
        let submit = submit_ms(1_000);
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let start = Instant::now();

        let (caller, callee) = drive_chan_call(
            submit,
            CalleeBehavior::HangAfterAccept,
            None,
            Some(ev_tx),
        )
        .await
        .expect("call");

        // Both ends agree on DeadlineExceeded — caller did not win with Timeout.
        assert_eq!(callee, Outcome::Failed(FailureCode::DeadlineExceeded));
        assert_eq!(caller, Outcome::Failed(FailureCode::DeadlineExceeded));

        // Wall-clock under pause equals the callee deadline, not deadline+GRACE.
        assert_eq!(start.elapsed(), Duration::from_millis(1_000));

        // Explicit event ordering: callee timer fired; caller grace did not.
        let fired: Vec<_> = std::iter::from_fn(|| ev_rx.try_recv().ok()).collect();
        assert_eq!(fired, vec![TimerEvent::CalleeDeadlineFired]);
        assert!(
            !fired.contains(&TimerEvent::CallerGraceFired),
            "caller grace must not fire when callee enforces deadline"
        );
    }

    /// When Failed cannot reach the caller, both timers fire — callee first by exactly GRACE.
    #[tokio::test(start_paused = true)]
    async fn both_timers_fire_callee_first_by_grace_when_failed_dropped() {
        let submit = submit_ms(500);
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let (c2s_tx, mut c2s_rx) = mpsc::unbounded_channel::<Message>();
        let (s2c_tx, mut s2c_rx) = mpsc::unbounded_channel::<Message>();
        let closed = Arc::new(Notify::new());

        let drain = tokio::spawn(async move { while s2c_rx.recv().await.is_some() {} });

        let ev_c = ev_tx.clone();
        let closed_c = Arc::clone(&closed);
        let (_keep_tx, mut unused) = mpsc::unbounded_channel::<Message>();
        let caller = tokio::spawn(async move {
            drive_caller_chan(submit, &mut unused, c2s_tx, closed_c, None, Some(ev_c)).await
        });

        let ev_s = ev_tx;
        let closed_s = closed;
        let callee = tokio::spawn(async move {
            drive_callee_chan(
                &mut c2s_rx,
                s2c_tx,
                closed_s,
                CalleeBehavior::HangAfterAccept,
                Some(ev_s),
            )
            .await
        });

        // Drive until both complete (auto-advances paused clock to next wakeups).
        let caller_out = caller.await.unwrap().unwrap();
        let callee_out = callee.await.unwrap().unwrap();
        drain.abort();

        assert_eq!(caller_out, Outcome::Closed(CloseCode::Timeout));
        assert_eq!(callee_out, Outcome::Failed(FailureCode::DeadlineExceeded));

        let first = ev_rx.recv().await.expect("first event");
        let second = ev_rx.recv().await.expect("second event");
        assert_eq!(first, TimerEvent::CalleeDeadlineFired);
        assert_eq!(second, TimerEvent::CallerGraceFired);
    }
}
