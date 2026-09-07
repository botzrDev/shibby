//! One Call task per connection: single bidirectional stream + state machines.

use std::sync::Arc;

use iroh::endpoint::Connection;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use uat_core::{
    callee_step, caller_step, AllowAll, CalleeEvent, CalleeState, CallerEvent, CallerState,
    CloseCode, FailureCode, Illegal, Message, NodeId, Outcome,
};

use crate::auth::{PeerSubmitAuth, Verify};
use crate::frame_io::{read_message, write_message, FrameIoError};

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

    /// Call cancelled via [`CancellationToken`].
    #[error("call cancelled")]
    Cancelled,

    /// Connection to the peer failed.
    #[error("connection failed: {0}")]
    Connection(String),
}

impl From<Illegal> for CallError {
    fn from(_: Illegal) -> Self {
        Self::Illegal
    }
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

/// Run the caller side of a call on an established connection.
///
/// Opens exactly one bidirectional stream, sends `submit`, and drives
/// [`caller_step`] until a terminal outcome.
pub async fn run_caller(
    conn: Connection,
    submit: Message,
    cancel: CancellationToken,
) -> Result<Outcome, CallError> {
    if !matches!(submit, Message::Submit { .. }) {
        return Err(CallError::Illegal);
    }

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| CallError::StreamSetup(e.to_string()))?;

    let guard_cancel = cancel.child_token();
    let guard = tokio::spawn(watch_second_stream(conn.clone(), guard_cancel.clone()));

    let result = caller_loop(&conn, &mut send, &mut recv, submit, &cancel).await;
    guard_cancel.cancel();
    let _ = guard.await;
    result
}

async fn caller_loop(
    conn: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    submit: Message,
    cancel: &CancellationToken,
) -> Result<Outcome, CallError> {
    let mut state = CallerState::Dialing;
    let step = caller_step(state, CallerEvent::Send(submit.clone()))?;
    state = step.state;
    if let Err(err) = write_message(send, &submit).await {
        close_on_frame_err(conn, &err);
        return Err(err.into());
    }

    loop {
        if let CallerState::Terminal(outcome) = &state {
            let outcome = *outcome;
            // Stop reading; close Normal after the terminal message is in hand.
            close_with(conn, CloseCode::Normal);
            return Ok(outcome);
        }

        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                return Err(CallError::Cancelled);
            }
            msg = read_message(recv, &AllowAll) => {
                let msg = match msg {
                    Ok(m) => m,
                    Err(err) => {
                        close_on_frame_err(conn, &err);
                        return Err(err.into());
                    }
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

/// Stub callee handler: after a valid Submit, emit Accepted then Completed (empty body).
///
/// Real handlers land later; this proves the daemon exit path.
pub async fn run_callee(
    conn: Connection,
    peer: NodeId,
    verify: Arc<dyn Verify>,
    cancel: CancellationToken,
) -> Result<Outcome, CallError> {
    if !verify.verify_peer(peer) {
        close_with(&conn, CloseCode::Normal);
        return Err(CallError::Unauthorized);
    }

    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| CallError::StreamSetup(e.to_string()))?;

    let guard_cancel = cancel.child_token();
    let guard = tokio::spawn(watch_second_stream(conn.clone(), guard_cancel.clone()));

    let result = callee_loop(&conn, &mut send, &mut recv, peer, verify.as_ref(), &cancel).await;
    guard_cancel.cancel();
    let _ = guard.await;
    result
}

async fn callee_loop(
    conn: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    peer: NodeId,
    verify: &dyn Verify,
    cancel: &CancellationToken,
) -> Result<Outcome, CallError> {
    let auth = PeerSubmitAuth::new(peer, verify);

    let submit = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            return Err(CallError::Cancelled);
        }
        msg = read_message(recv, &auth) => {
            match msg {
                Ok(m) => m,
                Err(FrameIoError::Codec(uat_core::CodecError::SubmitDenied)) => {
                    let failed = Message::Failed {
                        code: FailureCode::Unauthorized,
                    };
                    let _ = write_message(send, &failed).await;
                    let _ = send.finish();
                    close_with(conn, CloseCode::Normal);
                    return Err(CallError::Unauthorized);
                }
                Err(err) => {
                    close_on_frame_err(conn, &err);
                    return Err(err.into());
                }
            }
        }
    };

    if !matches!(submit, Message::Submit { .. }) {
        close_with(conn, CloseCode::ProtocolViolation);
        return Err(CallError::Illegal);
    }
    debug!(?peer, "callee received submit");

    let mut state = CalleeState::Offered;

    let accepted = Message::Accepted;
    let step = match callee_step(state, CalleeEvent::Send(accepted.clone())) {
        Ok(s) => s,
        Err(Illegal) => {
            close_with(conn, CloseCode::ProtocolViolation);
            return Err(CallError::Illegal);
        }
    };
    state = step.state;
    if let Err(err) = write_message(send, &accepted).await {
        close_on_frame_err(conn, &err);
        return Err(err.into());
    }

    let completed = Message::Completed { body: Vec::new() };
    let step = match callee_step(state, CalleeEvent::Send(completed.clone())) {
        Ok(s) => s,
        Err(Illegal) => {
            close_with(conn, CloseCode::ProtocolViolation);
            return Err(CallError::Illegal);
        }
    };
    state = step.state;
    if let Err(err) = write_message(send, &completed).await {
        close_on_frame_err(conn, &err);
        return Err(err.into());
    }

    // Finish the send side so the peer can read to completion, then stop reading.
    // Wait for the caller to close (Normal) rather than racing a local close that
    // can drop still-in-flight frames.
    if let Err(err) = send.finish() {
        return Err(CallError::StreamSetup(err.to_string()));
    }

    let CalleeState::Terminal(outcome) = state else {
        warn!(?state, "callee stub ended non-terminal");
        close_with(conn, CloseCode::ProtocolViolation);
        return Err(CallError::Illegal);
    };

    tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            close_with(conn, CloseCode::Normal);
        }
        _ = conn.closed() => {}
    }

    Ok(outcome)
}
