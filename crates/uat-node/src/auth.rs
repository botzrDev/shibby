//! Connection and Submit authorization seam (stub until M2 / HLX policy).

use std::collections::HashSet;
use std::sync::Arc;

use uat_core::{Message, NodeId, SubmitAuthorizer};

/// Decides whether a remote [`NodeId`] may place or complete a call.
///
/// M2 replaces this with real answering policy; keep call sites on this trait.
pub trait Verify: Send + Sync {
    /// Return `true` if `peer` is allowed at the connection / Submit seams.
    fn verify_peer(&self, peer: NodeId) -> bool;
}

impl<T: Verify + ?Sized> Verify for Arc<T> {
    fn verify_peer(&self, peer: NodeId) -> bool {
        (**self).verify_peer(peer)
    }
}

impl<T: Verify + ?Sized> Verify for &T {
    fn verify_peer(&self, peer: NodeId) -> bool {
        (**self).verify_peer(peer)
    }
}

/// Explicit allowlist of [`NodeId`]s. Empty deny-all (secure default).
#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    allowed: HashSet<NodeId>,
}

impl Allowlist {
    /// Deny every peer.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            allowed: HashSet::new(),
        }
    }

    /// Allow only `peer`.
    #[must_use]
    pub fn allow(peer: NodeId) -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(peer);
        Self { allowed }
    }

    /// Allow each peer in `peers`.
    #[must_use]
    pub fn allow_many(peers: impl IntoIterator<Item = NodeId>) -> Self {
        Self {
            allowed: peers.into_iter().collect(),
        }
    }

    /// Insert an allowed peer.
    pub fn insert(&mut self, peer: NodeId) {
        self.allowed.insert(peer);
    }

    /// Whether `peer` is currently listed.
    #[must_use]
    pub fn contains(&self, peer: NodeId) -> bool {
        self.allowed.contains(&peer)
    }
}

impl Verify for Allowlist {
    fn verify_peer(&self, peer: NodeId) -> bool {
        self.contains(peer)
    }
}

/// [`SubmitAuthorizer`] that gates Submit body copy on [`Verify`] for a known peer.
#[derive(Clone, Debug)]
pub struct PeerSubmitAuth<V> {
    peer: NodeId,
    verify: V,
}

impl<V> PeerSubmitAuth<V> {
    /// Authorize Submit frames from `peer` using `verify`.
    #[must_use]
    pub const fn new(peer: NodeId, verify: V) -> Self {
        Self { peer, verify }
    }
}

impl<V: Verify> SubmitAuthorizer for PeerSubmitAuth<V> {
    fn authorize_submit(&self, _header: &Message) -> bool {
        self.verify.verify_peer(self.peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_denies() {
        let list = Allowlist::empty();
        assert!(!list.verify_peer(NodeId::from_bytes([1u8; 32])));
    }

    #[test]
    fn allow_one_peer() {
        let peer = NodeId::from_bytes([2u8; 32]);
        let list = Allowlist::allow(peer);
        assert!(list.verify_peer(peer));
        assert!(!list.verify_peer(NodeId::from_bytes([3u8; 32])));
    }
}
