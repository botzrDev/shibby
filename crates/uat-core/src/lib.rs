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
