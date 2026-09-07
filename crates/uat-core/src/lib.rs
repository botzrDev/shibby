//! Pure UAT types. No tokio, no iroh, no I/O.
//!
//! State machines land in later M0 tickets.

mod codes;
mod codec;
mod error;
mod message;
mod node_id;
mod types;

pub use codes::{CloseCode, FailureCode};
pub use codec::{
    decode, encode, inspect_submit, AllowAll, CodecError, DenyAll, FrameBuffer, InspectedSubmit,
    SubmitAuthorizer, MAX_FRAME, MAX_HDR_LEN,
};
pub use error::TypeError;
pub use message::Message;
pub use node_id::NodeId;
pub use types::{
    ContentType, Credential, Deadline, TaskId, MAX_CONTENT_TYPE_LEN, MAX_CREDENTIAL_DECODED_LEN,
    MAX_DEADLINE_MS,
};
