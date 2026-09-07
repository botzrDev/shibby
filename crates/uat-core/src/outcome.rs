//! Terminal call outcomes shared by both state machines.

use crate::codes::{CloseCode, FailureCode};
use serde::{Deserialize, Serialize};

/// How a call ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    Failed(FailureCode),
    Canceled,
    /// Connection closed with an application close code.
    Closed(CloseCode),
    /// Peer closed normally with no terminal message.
    PeerLost,
}
