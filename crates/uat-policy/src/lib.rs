//! Answering policy (M2). Stub surface for the workspace; real verify lands later.

use thiserror::Error;
use uat_core::NodeId;

/// Errors from policy evaluation.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// No allowlist entry and no credential — default deny.
    #[error("caller {0:?} is not authorized")]
    Unauthorized(NodeId),
}

/// Placeholder admit check: always denies. Real rules arrive in M2.
///
/// Exists so `thiserror` and `uat-core` both have call sites today.
pub fn admit_stub(caller: NodeId) -> Result<(), PolicyError> {
    Err(PolicyError::Unauthorized(caller))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_denies_everyone() {
        let caller = NodeId::from_bytes([1u8; 32]);
        assert!(admit_stub(caller).is_err());
    }
}
