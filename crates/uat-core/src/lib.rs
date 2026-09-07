//! Pure UAT types. No tokio, no iroh, no I/O.
//!
//! Codec and state machines land in later M0 tickets.

mod codes;
mod error;
mod message;
mod node_id;
mod types;

pub use codes::{CloseCode, FailureCode};
pub use error::TypeError;
pub use message::Message;
pub use node_id::NodeId;
pub use types::{
    ContentType, Credential, Deadline, TaskId, MAX_CONTENT_TYPE_LEN, MAX_CREDENTIAL_DECODED_LEN,
    MAX_DEADLINE_MS,
};
