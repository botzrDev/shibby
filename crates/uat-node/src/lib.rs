//! Imperative shell around iroh. The only crate that may depend on iroh.

mod auth;
mod call;
mod frame_io;
mod identity;
mod node;

use iroh::PublicKey;
use thiserror::Error;
use uat_core::NodeId;

pub use auth::{Allowlist, PeerSubmitAuth, Verify};
pub use call::{close_with, run_callee, run_caller, watch_second_stream, CallError};
pub use frame_io::{read_message, write_message, FrameIoError};
pub use identity::{
    identity_path, load_or_create, load_or_create_at, uat_home, Identity, IdentityError,
    DEFAULT_UAT_DIR, IDENTITY_FILE, REQUIRED_MODE,
};
pub use node::{DaemonError, Node};

/// Errors at the iroh identity edge.
#[derive(Debug, Error)]
pub enum NodeError {
    /// Bytes were not a valid iroh / Ed25519 public key.
    #[error("invalid node public key")]
    InvalidPublicKey,
}

/// Convert a UAT [`NodeId`] into iroh's [`PublicKey`].
///
/// This is the only permitted conversion site; `uat-core` never imports iroh.
pub fn node_id_to_public_key(id: NodeId) -> Result<PublicKey, NodeError> {
    PublicKey::from_bytes(id.as_bytes()).map_err(|_| NodeError::InvalidPublicKey)
}

/// Convert iroh's [`PublicKey`] into a UAT [`NodeId`].
#[must_use]
pub fn public_key_to_node_id(key: &PublicKey) -> NodeId {
    NodeId::from_bytes(*key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn node_id_converts_through_iroh_public_key() {
        let secret = SecretKey::from_bytes(&[9u8; 32]);
        let pk = secret.public();
        let id = public_key_to_node_id(&pk);
        let back = node_id_to_public_key(id).expect("valid key");
        assert_eq!(back, pk);
    }
}
