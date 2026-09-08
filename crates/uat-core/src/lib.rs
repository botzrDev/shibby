//! Pure UAT types. No tokio, no iroh, no I/O.

mod codes;
mod codec;
mod error;
mod message;
mod node_id;
mod outcome;
mod state;
mod types;

pub use codes::{CloseCode, FailureCode};
pub use codec::{
    decode, encode, inspect_submit, AllowAll, CodecError, DenyAll, FrameBuffer, InspectedSubmit,
    SubmitAuthorizer, MAX_FRAME, MAX_HDR_LEN,
};
pub use error::TypeError;
pub use message::Message;
pub use node_id::NodeId;
pub use outcome::Outcome;
pub use state::{
    callee_step, caller_step, CalleeEvent, CalleeState, CallerEvent, CallerState, Illegal, Step,
};
pub use types::{
    ContentType, Credential, Deadline, TaskId, MAX_CONTENT_TYPE_LEN, MAX_CREDENTIAL_DECODED_LEN,
    MAX_DEADLINE_MS,
};

#[cfg(test)]
mod codec_prop;

/// Protocol version is carried only in ALPN. No envelope version field.
pub const ALPN: &[u8] = b"/uat/0.2";

/// Caller timer margin after the callee deadline (protocol-fixed, milliseconds).
///
/// Caller fires at `deadline + GRACE_MS`; callee fires at `deadline`. The asymmetry
/// ensures the callee always emits `DeadlineExceeded` first when both timers run.
pub const GRACE_MS: u64 = 5_000;

/// QUIC max idle timeout for UAT endpoints (milliseconds).
pub const QUIC_IDLE_TIMEOUT_MS: u64 = 10_000;

/// QUIC keep-alive interval for UAT endpoints (milliseconds).
///
/// Must stay below [`QUIC_IDLE_TIMEOUT_MS`] so idle detection works.
pub const QUIC_KEEP_ALIVE_MS: u64 = 3_000;
