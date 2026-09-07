//! Pure UAT types. No tokio, no iroh, no I/O.
//!
//! Codec and state machines land in later M0 tickets; this crate currently
//! exports the shared identity newtype every other crate must use.

/// A UAT node identity: 32 raw bytes of an Ed25519 public key.
///
/// This is the only identity type shared across crates. `uat-node` converts
/// to and from iroh's public key at the edge; nothing else imports iroh.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Construct from raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_roundtrips_bytes() {
        let bytes = [7u8; 32];
        let id = NodeId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }
}
