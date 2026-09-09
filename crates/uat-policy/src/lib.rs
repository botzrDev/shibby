//! Answering policy (HLX-110 / §6.1).
//!
//! Default deny. An inbound `Submit` is admitted only via allowlist or (later)
//! a verifying Biscuit. There is no answer-everyone flag.
//!
//! `AuthorizedSubmit` has no public constructor outside [`UnverifiedSubmit::verify`].
//! That visibility property is the proof an unauthorized call cannot inhabit a
//! handler — decision-table coverage of `verify` itself is HLX-114.

use std::collections::HashSet;
use std::time::SystemTime;

use serde::Serialize;
use thiserror::Error;
use uat_core::{ContentType, Credential, Deadline, Message, NodeId, TaskId};

/// Errors from [`UnverifiedSubmit::verify`] and related constructors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No allowlist entry and no usable credential — default deny.
    #[error("caller {0:?} is not authorized")]
    Denied(NodeId),

    /// `Submit.credential` was present but Biscuit verification is not wired yet (HLX-111).
    #[error("biscuit token verification is not implemented yet")]
    TokenNotImplemented,

    /// Value was not a `Submit` message.
    #[error("not a Submit message")]
    NotSubmit,

    /// `Submit` already carried a body; only header-only values may enter verify (F4/S6).
    #[error("Submit already has a body; verify requires header-only")]
    NotHeaderOnly,
}

/// Which rule admitted an [`AuthorizedSubmit`] (also reported on the audit record).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRule {
    /// Peer public key is on the node's allowlist.
    Allowlist,
    /// `Submit.credential` verified as a Biscuit (HLX-111).
    Token {
        #[serde(serialize_with = "serialize_biscuit_id_hex")]
        biscuit_id: [u8; 32],
    },
}

fn serialize_biscuit_id_hex<S: serde::Serializer>(
    id: &[u8; 32],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&bytes_to_hex(id))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Node answering policy. Default deny; no path admits everyone.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    allowlist: HashSet<NodeId>,
}

impl Policy {
    /// Deny every peer (secure default).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            allowlist: HashSet::new(),
        }
    }

    /// Allow only `peer`.
    #[must_use]
    pub fn allow(peer: NodeId) -> Self {
        let mut allowlist = HashSet::new();
        allowlist.insert(peer);
        Self { allowlist }
    }

    /// Allow each peer in `peers`.
    #[must_use]
    pub fn allow_many(peers: impl IntoIterator<Item = NodeId>) -> Self {
        Self {
            allowlist: peers.into_iter().collect(),
        }
    }

    /// Insert an allowed peer.
    pub fn insert(&mut self, peer: NodeId) {
        self.allowlist.insert(peer);
    }

    /// Whether `peer` is currently listed.
    #[must_use]
    pub fn contains(&self, peer: NodeId) -> bool {
        self.allowlist.contains(&peer)
    }
}

/// Header-only `Submit` awaiting authorization. Body bytes must not be present (F4/S6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedSubmit {
    message: Message,
}

impl UnverifiedSubmit {
    /// Wrap a parsed `Submit` header (`body` must be empty).
    pub fn from_header(message: Message) -> Result<Self, AuthError> {
        match &message {
            Message::Submit { body, .. } if body.is_empty() => Ok(Self { message }),
            Message::Submit { .. } => Err(AuthError::NotHeaderOnly),
            _ => Err(AuthError::NotSubmit),
        }
    }

    /// Borrow the header-only `Submit` message.
    #[must_use]
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Authorize this header against `policy`.
    ///
    /// Order (pinned for HLX-114): allowlist wins even if a credential is also
    /// present; otherwise a credential selects the stub token path; otherwise deny.
    pub fn verify(
        self,
        policy: &Policy,
        peer: NodeId,
        _now: SystemTime,
    ) -> Result<AuthorizedSubmit, AuthError> {
        let credential = match &self.message {
            Message::Submit { credential, .. } => credential.clone(),
            _ => return Err(AuthError::NotSubmit),
        };

        if policy.contains(peer) {
            return Ok(AuthorizedSubmit {
                rule: AuthRule::Allowlist,
                message: self.message,
            });
        }

        if credential.is_some() {
            // HLX-111 will verify the Biscuit and return AuthRule::Token { biscuit_id }.
            return Err(AuthError::TokenNotImplemented);
        }

        Err(AuthError::Denied(peer))
    }
}

/// A `Submit` that passed [`UnverifiedSubmit::verify`]. Handlers take this type only.
///
/// Fields other than [`Self::rule`] are private so the only constructor is `verify`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedSubmit {
    /// Which of the two admission paths allowed this call.
    pub rule: AuthRule,
    message: Message,
}

impl AuthorizedSubmit {
    /// Attach body bytes after authorization succeeds (S6).
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        if let Message::Submit {
            body: slot, ..
        } = &mut self.message
        {
            *slot = body;
        }
        self
    }

    /// Full `Submit` message (header + any attached body).
    #[must_use]
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Consume into the wire `Message`.
    #[must_use]
    pub fn into_message(self) -> Message {
        self.message
    }

    /// Task id from the authorized header.
    #[must_use]
    pub fn task(&self) -> TaskId {
        match &self.message {
            Message::Submit { task, .. } => *task,
            _ => unreachable!("AuthorizedSubmit always holds Submit"),
        }
    }

    /// Deadline from the authorized header.
    #[must_use]
    pub fn deadline(&self) -> Deadline {
        match &self.message {
            Message::Submit { deadline, .. } => *deadline,
            _ => unreachable!("AuthorizedSubmit always holds Submit"),
        }
    }

    /// Content type from the authorized header.
    #[must_use]
    pub fn content_type(&self) -> &ContentType {
        match &self.message {
            Message::Submit { content_type, .. } => content_type,
            _ => unreachable!("AuthorizedSubmit always holds Submit"),
        }
    }

    /// Optional credential from the authorized header.
    #[must_use]
    pub fn credential(&self) -> Option<&Credential> {
        match &self.message {
            Message::Submit { credential, .. } => credential.as_ref(),
            _ => unreachable!("AuthorizedSubmit always holds Submit"),
        }
    }

    /// Body bytes (empty until [`Self::with_body`]).
    #[must_use]
    pub fn body(&self) -> &[u8] {
        match &self.message {
            Message::Submit { body, .. } => body.as_slice(),
            _ => &[],
        }
    }
}

/// [`uat_core::SubmitAuthorizer`] adapter: runs header-only `verify` before body copy (F4).
#[derive(Clone, Debug)]
pub struct PolicySubmitAuth<'a> {
    policy: &'a Policy,
    peer: NodeId,
    now: SystemTime,
}

impl<'a> PolicySubmitAuth<'a> {
    /// Authorize `Submit` frames from `peer` using `policy` at `now`.
    #[must_use]
    pub const fn new(policy: &'a Policy, peer: NodeId, now: SystemTime) -> Self {
        Self { policy, peer, now }
    }
}

impl uat_core::SubmitAuthorizer for PolicySubmitAuth<'_> {
    fn authorize_submit(&self, header: &Message) -> bool {
        match UnverifiedSubmit::from_header(header.clone()) {
            Ok(unverified) => unverified.verify(self.policy, self.peer, self.now).is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uat_core::{
        decode, encode, inspect_submit, ContentType, Deadline, DenyAll, Message, TaskId,
    };

    fn header_submit(credential: Option<Credential>) -> Message {
        Message::Submit {
            task: TaskId::from_u128(1),
            deadline: Deadline::new(1_000).unwrap(),
            content_type: ContentType::new("application/octet-stream").unwrap(),
            credential,
            body: Vec::new(),
        }
    }

    fn peer(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn empty_policy_denies_without_credential() {
        let policy = Policy::empty();
        let unverified = UnverifiedSubmit::from_header(header_submit(None)).unwrap();
        let err = unverified
            .verify(&policy, peer(1), SystemTime::UNIX_EPOCH)
            .unwrap_err();
        assert_eq!(err, AuthError::Denied(peer(1)));
    }

    #[test]
    fn allowlist_admits_and_records_rule() {
        let p = peer(2);
        let policy = Policy::allow(p);
        let unverified = UnverifiedSubmit::from_header(header_submit(None)).unwrap();
        let authorized = unverified
            .verify(&policy, p, SystemTime::UNIX_EPOCH)
            .unwrap();
        assert_eq!(authorized.rule, AuthRule::Allowlist);
        assert!(authorized.body().is_empty());
    }

    #[test]
    fn allowlist_wins_when_credential_also_present() {
        let p = peer(3);
        let policy = Policy::allow(p);
        let cred = Credential::new("YWJj").unwrap(); // "abc"
        let unverified = UnverifiedSubmit::from_header(header_submit(Some(cred))).unwrap();
        let authorized = unverified
            .verify(&policy, p, SystemTime::UNIX_EPOCH)
            .unwrap();
        assert_eq!(authorized.rule, AuthRule::Allowlist);
    }

    #[test]
    fn credential_without_allowlist_is_token_stub() {
        let policy = Policy::empty();
        let cred = Credential::new("YWJj").unwrap();
        let unverified = UnverifiedSubmit::from_header(header_submit(Some(cred))).unwrap();
        let err = unverified
            .verify(&policy, peer(4), SystemTime::UNIX_EPOCH)
            .unwrap_err();
        assert_eq!(err, AuthError::TokenNotImplemented);
    }

    #[test]
    fn rejects_submit_that_already_has_body() {
        let mut msg = header_submit(None);
        if let Message::Submit { body, .. } = &mut msg {
            *body = b"nope".to_vec();
        }
        assert_eq!(
            UnverifiedSubmit::from_header(msg).unwrap_err(),
            AuthError::NotHeaderOnly
        );
    }

    #[test]
    fn denied_submit_never_copies_body_via_policy_authorizer() {
        let mut encoded = Vec::new();
        let mut submit = header_submit(None);
        if let Message::Submit { body, .. } = &mut submit {
            *body = b"do-not-copy-me".to_vec();
        }
        encode(&submit, &mut encoded).unwrap();

        let inspected = inspect_submit(&encoded).unwrap();
        match &inspected.header {
            Message::Submit { body, .. } => assert!(body.is_empty()),
            other => panic!("expected submit, got {other:?}"),
        }
        assert_eq!(inspected.body_len, b"do-not-copy-me".len());

        let policy = Policy::empty();
        let auth = PolicySubmitAuth::new(&policy, peer(9), SystemTime::UNIX_EPOCH);
        let err = decode(&encoded, &auth).unwrap_err();
        assert_eq!(err, uat_core::CodecError::SubmitDenied);

        // Typed path: verify fails, so with_body is never called.
        let unverified = UnverifiedSubmit::from_header(inspected.header).unwrap();
        assert!(matches!(
            unverified.verify(&policy, peer(9), SystemTime::UNIX_EPOCH),
            Err(AuthError::Denied(_))
        ));
    }

    #[test]
    fn authorized_with_body_only_after_verify() {
        let p = peer(5);
        let policy = Policy::allow(p);
        let unverified = UnverifiedSubmit::from_header(header_submit(None)).unwrap();
        let authorized = unverified
            .verify(&policy, p, SystemTime::UNIX_EPOCH)
            .unwrap()
            .with_body(b"payload".to_vec());
        assert_eq!(authorized.body(), b"payload");
        match authorized.into_message() {
            Message::Submit { body, .. } => assert_eq!(body, b"payload"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn deny_all_codec_seam_still_holds() {
        let mut encoded = Vec::new();
        let mut submit = header_submit(None);
        if let Message::Submit { body, .. } = &mut submit {
            *body = b"secret".to_vec();
        }
        encode(&submit, &mut encoded).unwrap();
        assert_eq!(
            decode(&encoded, &DenyAll).unwrap_err(),
            uat_core::CodecError::SubmitDenied
        );
    }
}
