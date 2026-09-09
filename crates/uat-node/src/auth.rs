//! Connection and Submit authorization seam (HLX-110).
//!
//! Connection accept still gates on [`Verify`] (allowlist, or open when biscuit roots are configured). The typed
//! `UnverifiedSubmit` → `verify` → `AuthorizedSubmit` path (in `uat-policy`)
//! is what F4/S6 and handlers use once a `Submit` header is in hand.

use std::sync::Arc;
use std::time::SystemTime;

use uat_core::{Message, NodeId, SubmitAuthorizer};
use uat_policy::{AuthError, AuthorizedSubmit, Policy, PolicySubmitAuth, UnverifiedSubmit};

/// Back-compat name: answering policy (allowlist + optional Biscuit roots).
pub type Allowlist = Policy;

/// Decides whether a remote [`NodeId`] may place or complete a call.
///
/// Implemented by [`Policy`] / [`Allowlist`]. Connection-level checks use this;
/// Submit-level checks go through [`authorize_submit_header`].
pub trait Verify: Send + Sync {
    /// Return `true` if `peer` is on the allowlist (connection / early reject).
    fn verify_peer(&self, peer: NodeId) -> bool;

    /// Borrow the answering [`Policy`] used for typed Submit verify.
    fn policy(&self) -> &Policy;
}

impl<T: Verify + ?Sized> Verify for Arc<T> {
    fn verify_peer(&self, peer: NodeId) -> bool {
        (**self).verify_peer(peer)
    }

    fn policy(&self) -> &Policy {
        (**self).policy()
    }
}

impl<T: Verify + ?Sized> Verify for &T {
    fn verify_peer(&self, peer: NodeId) -> bool {
        (**self).verify_peer(peer)
    }

    fn policy(&self) -> &Policy {
        (**self).policy()
    }
}

impl Verify for Policy {
    fn verify_peer(&self, peer: NodeId) -> bool {
        // Allowlist OR biscuit roots configured (token callers pass the
        // connection gate; Submit still requires a valid token / allowlist).
        self.contains(peer) || self.has_biscuit_roots()
    }

    fn policy(&self) -> &Policy {
        self
    }
}

/// Run F4 authorization on a header-only `Submit`, returning [`AuthorizedSubmit`].
pub fn authorize_submit_header(
    header: Message,
    policy: &Policy,
    peer: NodeId,
    now: SystemTime,
) -> Result<AuthorizedSubmit, AuthError> {
    UnverifiedSubmit::from_header(header)?.verify(policy, peer, now)
}

/// [`SubmitAuthorizer`] that gates Submit body copy on [`Verify`] for a known peer.
///
/// Prefer [`authorize_submit_header`] when the caller needs the [`AuthorizedSubmit`]
/// / [`AuthRule`]. This adapter exists for `decode` / `read_message` call sites.
#[derive(Clone, Debug)]
pub struct PeerSubmitAuth<V> {
    peer: NodeId,
    verify: V,
    now: SystemTime,
}

impl<V> PeerSubmitAuth<V> {
    /// Authorize Submit frames from `peer` using `verify` at wall-clock `now`.
    #[must_use]
    pub const fn new(peer: NodeId, verify: V, now: SystemTime) -> Self {
        Self { peer, verify, now }
    }
}

impl<V: Verify> SubmitAuthorizer for PeerSubmitAuth<V> {
    fn authorize_submit(&self, header: &Message) -> bool {
        PolicySubmitAuth::new(self.verify.policy(), self.peer, self.now).authorize_submit(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uat_policy::AuthRule;

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

    #[test]
    fn authorize_header_allowlist_admits() {
        use uat_core::{ContentType, Deadline, TaskId};
        let peer = NodeId::from_bytes([4u8; 32]);
        let policy = Policy::allow(peer);
        let header = Message::Submit {
            task: TaskId::from_u128(1),
            deadline: Deadline::new(100).unwrap(),
            content_type: ContentType::new("text/plain").unwrap(),
            credential: None,
            body: Vec::new(),
        };
        let auth = authorize_submit_header(header, &policy, peer, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(auth.rule, AuthRule::Allowlist);
    }
}
