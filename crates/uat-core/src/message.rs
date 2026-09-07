//! The UAT `Message` enum. Bodies are opaque and skipped by serde (A1 / F3).

use crate::codes::FailureCode;
use crate::types::{ContentType, Credential, Deadline, TaskId};
use serde::{Deserialize, Serialize};

/// Wire messages for one call (one bidirectional stream).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// Caller places a call. `task` appears only here (and in the audit record).
    Submit {
        task: TaskId,
        deadline: Deadline,
        content_type: ContentType,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential: Option<Credential>,
        #[serde(skip)]
        body: Vec<u8>,
    },
    /// Callee/node: authorized and queued. Emitted by the node, not the harness.
    Accepted,
    /// Callee: work is underway.
    Progress,
    /// Callee: needs input from the caller (human-in-the-loop).
    NeedInput,
    /// Caller: answer to `NeedInput`.
    Input {
        #[serde(skip)]
        body: Vec<u8>,
    },
    /// Callee: successful terminal result.
    Completed {
        #[serde(skip)]
        body: Vec<u8>,
    },
    /// Callee: task-level failure.
    Failed { code: FailureCode },
    /// Caller: request cancel.
    Cancel,
    /// Callee: acknowledged cancel.
    Canceled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentType, Deadline, TaskId};

    #[test]
    fn submit_body_is_not_in_json_header() {
        let msg = Message::Submit {
            task: TaskId::from_u128(1),
            deadline: Deadline::new(1_000).unwrap(),
            content_type: ContentType::new("application/octet-stream").unwrap(),
            credential: None,
            body: b"secret-payload".to_vec(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("secret-payload"));
        assert!(json.contains("submit"));
        let back: Message = serde_json::from_str(&json).unwrap();
        match back {
            Message::Submit { body, .. } => assert!(body.is_empty()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn failed_carries_failure_code_not_close_code() {
        let msg = Message::Failed {
            code: FailureCode::Rejected,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("rejected"));
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back,
            Message::Failed {
                code: FailureCode::Rejected
            }
        );
    }
}
