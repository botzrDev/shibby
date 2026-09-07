//! Task failure codes vs connection close codes — separate channels, separate senders.

use serde::{Deserialize, Serialize};

/// What a callee can say **about the task**, inside `Failed`. Callee only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Unauthorized,
    Rejected,
    DeadlineExceeded,
    HandlerError,
}

/// What either side can say **about the connection**.
///
/// Carried in the QUIC `CONNECTION_CLOSE` application error code.
/// Never sent as a UAT message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum CloseCode {
    Normal = 0,
    RateLimited = 1,
    FrameTooLarge = 2,
    MalformedFrame = 3,
    ProtocolViolation = 4,
    Timeout = 5,
}

impl CloseCode {
    /// Parse a QUIC application error code.
    pub fn from_u32(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Normal),
            1 => Some(Self::RateLimited),
            2 => Some(Self::FrameTooLarge),
            3 => Some(Self::MalformedFrame),
            4 => Some(Self::ProtocolViolation),
            5 => Some(Self::Timeout),
            _ => None,
        }
    }

    /// The application error code to put on `CONNECTION_CLOSE`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}
