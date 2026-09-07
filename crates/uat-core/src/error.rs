//! Typed construction errors for wire newtypes.

use thiserror::Error;

/// Rejection from a newtype constructor / decode boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TypeError {
    /// `TaskId` hex was not exactly 32 lowercase/uppercase hex chars.
    #[error("task id must be exactly 32 hex characters")]
    TaskIdBadHex,

    /// `Deadline` exceeded the protocol maximum.
    #[error("deadline {got} exceeds maximum {max}")]
    DeadlineTooLarge { got: u32, max: u32 },

    /// `ContentType` exceeded 64 bytes.
    #[error("content type is {got} bytes; maximum is {max}")]
    ContentTypeTooLong { got: usize, max: usize },

    /// `Credential` was not valid base64url (no padding).
    #[error("credential is not valid base64url (no padding)")]
    CredentialBadEncoding,

    /// Decoded credential exceeded 2 KiB.
    #[error("credential decodes to {got} bytes; maximum is {max}")]
    CredentialTooLong { got: usize, max: usize },
}
