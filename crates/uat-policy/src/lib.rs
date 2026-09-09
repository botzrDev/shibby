//! Answering policy (HLX-110 / §6.1 + HLX-111 Biscuit facts).
//!
//! Default deny. An inbound `Submit` is admitted only via allowlist or a
//! verifying Biscuit. There is no answer-everyone flag.
//!
//! `AuthorizedSubmit` has no public constructor outside [`UnverifiedSubmit::verify`].
//! That visibility property is the proof an unauthorized call cannot inhabit a
//! handler — decision-table coverage of `verify` itself is HLX-114.
//!
//! # Biscuit facts (HLX-111)
//!
//! Tokens are verified against exactly these facts (no `caller(pk)` — deliberate for M6):
//!
//! | Fact | Required | Check |
//! |------|----------|-------|
//! | `callee(pk)` | yes | bytes equal this node's public key |
//! | `expires(ts)` | yes | `ts > now`; missing fails |
//! | `max_deadline_ms(n)` | no | `Submit.deadline <= n` when present |
//! | `content_type(s)` | no | `Submit.content_type == s` when present |
//! | `one_shot()` | no | token id not in spent set when present |

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{pred, rule, string, Fact, Term};
use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{AuthorizerBuilder, Biscuit, PublicKey};
use serde::Serialize;
use thiserror::Error;
use uat_core::{ContentType, Credential, Deadline, Message, NodeId, TaskId};

/// Re-export for configuring root keys and minting test tokens.
pub use biscuit_auth::{builder, KeyPair};

/// Errors from [`UnverifiedSubmit::verify`] and related constructors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No allowlist entry and no usable credential — default deny.
    #[error("caller {0:?} is not authorized")]
    Denied(NodeId),

    /// `Submit.credential` failed Biscuit verification (signature or facts).
    ///
    /// Call path maps this to `Failed{Unauthorized}` — never `Rejected`.
    #[error("biscuit token unauthorized")]
    TokenUnauthorized,

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

/// Tracks one-shot biscuit ids already consumed (HLX-111 seam; bounded store is HLX-112).
pub trait SpentSet: Send + Sync {
    /// Whether `id` has already been spent.
    fn contains(&self, id: &[u8; 32]) -> bool;

    /// Mark `id` spent. Returns `false` if it was already present.
    fn try_spend(&self, id: [u8; 32]) -> bool;
}

/// In-memory spent set for tests and M2 stubs.
#[derive(Debug, Default)]
pub struct MemorySpentSet {
    inner: Mutex<HashSet<[u8; 32]>>,
}

impl MemorySpentSet {
    /// Empty spent set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SpentSet for MemorySpentSet {
    fn contains(&self, id: &[u8; 32]) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).contains(id)
    }

    fn try_spend(&self, id: [u8; 32]) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id)
    }
}

/// Node answering policy. Default deny; no path admits everyone.
#[derive(Clone)]
pub struct Policy {
    allowlist: HashSet<NodeId>,
    /// Biscuit root public keys used to verify `Submit.credential`.
    root_keys: Vec<PublicKey>,
    /// This node's public key; required `callee(pk)` must equal this.
    self_id: Option<NodeId>,
    spent: Arc<dyn SpentSet>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policy")
            .field("allowlist_len", &self.allowlist.len())
            .field("root_keys_len", &self.root_keys.len())
            .field("self_id", &self.self_id)
            .finish_non_exhaustive()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::empty()
    }
}

impl Policy {
    /// Deny every peer (secure default).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            allowlist: HashSet::new(),
            root_keys: Vec::new(),
            self_id: None,
            spent: Arc::new(MemorySpentSet::new()),
        }
    }

    /// Allow only `peer`.
    #[must_use]
    pub fn allow(peer: NodeId) -> Self {
        let mut allowlist = HashSet::new();
        allowlist.insert(peer);
        Self {
            allowlist,
            root_keys: Vec::new(),
            self_id: None,
            spent: Arc::new(MemorySpentSet::new()),
        }
    }

    /// Allow each peer in `peers`.
    #[must_use]
    pub fn allow_many(peers: impl IntoIterator<Item = NodeId>) -> Self {
        Self {
            allowlist: peers.into_iter().collect(),
            root_keys: Vec::new(),
            self_id: None,
            spent: Arc::new(MemorySpentSet::new()),
        }
    }

    /// Configure Biscuit root key(s) and this node's id for `callee(pk)`.
    #[must_use]
    pub fn with_biscuit_roots(
        mut self,
        self_id: NodeId,
        roots: impl IntoIterator<Item = PublicKey>,
    ) -> Self {
        self.self_id = Some(self_id);
        self.root_keys = roots.into_iter().collect();
        self
    }

    /// Replace the spent-set implementation (one_shot seam).
    #[must_use]
    pub fn with_spent_set(mut self, spent: Arc<dyn SpentSet>) -> Self {
        self.spent = spent;
        self
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

    /// Whether Biscuit root keys are configured (token path enabled).
    #[must_use]
    pub fn has_biscuit_roots(&self) -> bool {
        !self.root_keys.is_empty()
    }

    /// Borrow the spent set (tests / HLX-112).
    #[must_use]
    pub fn spent_set(&self) -> &Arc<dyn SpentSet> {
        &self.spent
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
    /// present; otherwise a credential selects the Biscuit path; otherwise deny.
    pub fn verify(
        self,
        policy: &Policy,
        peer: NodeId,
        now: SystemTime,
    ) -> Result<AuthorizedSubmit, AuthError> {
        let (credential, deadline, content_type) = match &self.message {
            Message::Submit {
                credential,
                deadline,
                content_type,
                ..
            } => (credential.clone(), *deadline, content_type.clone()),
            _ => return Err(AuthError::NotSubmit),
        };

        if policy.contains(peer) {
            return Ok(AuthorizedSubmit {
                rule: AuthRule::Allowlist,
                message: self.message,
            });
        }

        if let Some(cred) = credential {
            let biscuit_id =
                verify_biscuit_credential(policy, &cred, deadline, &content_type, now)?;
            return Ok(AuthorizedSubmit {
                rule: AuthRule::Token { biscuit_id },
                message: self.message,
            });
        }

        Err(AuthError::Denied(peer))
    }
}

fn verify_biscuit_credential(
    policy: &Policy,
    credential: &Credential,
    deadline: Deadline,
    content_type: &ContentType,
    now: SystemTime,
) -> Result<[u8; 32], AuthError> {
    if policy.root_keys.is_empty() {
        return Err(AuthError::TokenUnauthorized);
    }
    let self_id = policy.self_id.ok_or(AuthError::TokenUnauthorized)?;

    let raw = credential.decode().map_err(|_| AuthError::TokenUnauthorized)?;
    let biscuit = Biscuit::from(&raw, |key_id| choose_root(&policy.root_keys, key_id))
        .map_err(|_| AuthError::TokenUnauthorized)?;

    let mut authorizer = AuthorizerBuilder::new()
        .allow_all()
        .build(&biscuit)
        .map_err(|_| AuthError::TokenUnauthorized)?;
    authorizer
        .authorize()
        .map_err(|_| AuthError::TokenUnauthorized)?;

    // Required: callee(pk)
    let callees: Vec<Fact> = authorizer
        .query_all("data($pk) <- callee($pk)")
        .map_err(|_| AuthError::TokenUnauthorized)?;
    if callees.is_empty() {
        return Err(AuthError::TokenUnauthorized);
    }
    for fact in &callees {
        let Term::Bytes(pk) = single_term(fact)? else {
            return Err(AuthError::TokenUnauthorized);
        };
        if pk.as_slice() != self_id.as_bytes().as_slice() {
            return Err(AuthError::TokenUnauthorized);
        }
    }

    // Required: expires(ts); missing fails; all must be strictly after now.
    let expires: Vec<Fact> = authorizer
        .query_all("data($t) <- expires($t)")
        .map_err(|_| AuthError::TokenUnauthorized)?;
    if expires.is_empty() {
        return Err(AuthError::TokenUnauthorized);
    }
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for fact in &expires {
        let Term::Date(ts) = single_term(fact)? else {
            return Err(AuthError::TokenUnauthorized);
        };
        if *ts <= now_secs {
            return Err(AuthError::TokenUnauthorized);
        }
    }

    // Optional: max_deadline_ms(n) → Submit.deadline <= n
    let max_deadlines: Vec<Fact> = authorizer
        .query_all("data($n) <- max_deadline_ms($n)")
        .map_err(|_| AuthError::TokenUnauthorized)?;
    for fact in &max_deadlines {
        let Term::Integer(n) = single_term(fact)? else {
            return Err(AuthError::TokenUnauthorized);
        };
        if *n < 0 || u64::from(deadline.as_u32()) > *n as u64 {
            return Err(AuthError::TokenUnauthorized);
        }
    }

    // Optional: content_type(s) → Submit.content_type == s
    let content_types: Vec<Fact> = authorizer
        .query_all("data($s) <- content_type($s)")
        .map_err(|_| AuthError::TokenUnauthorized)?;
    for fact in &content_types {
        let Term::Str(s) = single_term(fact)? else {
            return Err(AuthError::TokenUnauthorized);
        };
        if s != content_type.as_str() {
            return Err(AuthError::TokenUnauthorized);
        }
    }

    let biscuit_id = biscuit_id_from_token(&biscuit)?;

    // Optional: one_shot() → id not in spent set (then spend).
    let empty: &[Term] = &[];
    let oneshot: Vec<Fact> = authorizer
        .query_all(rule(
            "data",
            &[string("yes")],
            &[pred("one_shot", empty)],
        ))
        .map_err(|_| AuthError::TokenUnauthorized)?;
    if !oneshot.is_empty()
        && (policy.spent.contains(&biscuit_id) || !policy.spent.try_spend(biscuit_id))
    {
        return Err(AuthError::TokenUnauthorized);
    }

    Ok(biscuit_id)
}

fn single_term(fact: &Fact) -> Result<&Term, AuthError> {
    match fact.predicate.terms.as_slice() {
        [term] => Ok(term),
        _ => Err(AuthError::TokenUnauthorized),
    }
}

fn choose_root(roots: &[PublicKey], key_id: Option<u32>) -> Result<PublicKey, biscuit_auth::error::Format> {
    match key_id {
        Some(id) => roots
            .get(id as usize)
            .copied()
            .ok_or(biscuit_auth::error::Format::UnknownPublicKey),
        None => {
            if roots.len() == 1 {
                Ok(roots[0])
            } else {
                roots.first().copied().ok_or(biscuit_auth::error::Format::UnknownPublicKey)
            }
        }
    }
}

/// Stable 32-byte id from the authority block revocation identifier.
fn biscuit_id_from_token(biscuit: &Biscuit) -> Result<[u8; 32], AuthError> {
    let ids = biscuit.revocation_identifiers();
    let id = ids.first().ok_or(AuthError::TokenUnauthorized)?;
    let mut out = [0u8; 32];
    // Ed25519 signatures are 64 bytes; take a prefix for AuthRule / spent-set key.
    let n = id.len().min(32);
    out[..n].copy_from_slice(&id[..n]);
    Ok(out)
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
    use std::time::Duration;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use biscuit_auth::builder::{bytes, date, fact, int, string, Term};
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

    fn header_submit_full(
        deadline_ms: u32,
        content_type: &str,
        credential: Option<Credential>,
    ) -> Message {
        Message::Submit {
            task: TaskId::from_u128(1),
            deadline: Deadline::new(deadline_ms).unwrap(),
            content_type: ContentType::new(content_type).unwrap(),
            credential,
            body: Vec::new(),
        }
    }

    fn peer(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    fn now_secs(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    struct TokenEnv {
        root: KeyPair,
        self_id: NodeId,
        spent: Arc<MemorySpentSet>,
    }

    impl TokenEnv {
        fn new() -> Self {
            Self {
                root: KeyPair::new(),
                self_id: peer(0xAB),
                spent: Arc::new(MemorySpentSet::new()),
            }
        }

        fn policy(&self) -> Policy {
            Policy::empty()
                .with_biscuit_roots(self.self_id, [self.root.public()])
                .with_spent_set(self.spent.clone())
        }

        fn mint(&self, facts: &[Fact]) -> Credential {
            let mut builder = Biscuit::builder();
            for f in facts {
                builder = builder.fact(f.clone()).expect("fact");
            }
            let token = builder.build(&self.root).expect("build biscuit");
            let encoded = URL_SAFE_NO_PAD.encode(token.to_vec().expect("serialize"));
            Credential::new(encoded).expect("credential")
        }

        fn required_facts(&self, expires_at: SystemTime) -> Vec<Fact> {
            vec![
                fact("callee", &[bytes(self.self_id.as_bytes())]),
                fact("expires", &[date(&expires_at)]),
            ]
        }
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
    fn credential_without_roots_is_unauthorized() {
        let policy = Policy::empty();
        let cred = Credential::new("YWJj").unwrap();
        let unverified = UnverifiedSubmit::from_header(header_submit(Some(cred))).unwrap();
        let err = unverified
            .verify(&policy, peer(4), SystemTime::UNIX_EPOCH)
            .unwrap_err();
        assert_eq!(err, AuthError::TokenUnauthorized);
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

    // --- HLX-111 fact matrix -------------------------------------------------

    #[test]
    fn callee_fact_pass() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let cred = env.mint(&env.required_facts(exp));
        let policy = env.policy();
        let authorized = UnverifiedSubmit::from_header(header_submit(Some(cred)))
            .unwrap()
            .verify(&policy, peer(1), now_secs(1_000_000_000))
            .unwrap();
        assert!(matches!(authorized.rule, AuthRule::Token { .. }));
    }

    #[test]
    fn callee_fact_fail_wrong_pk() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let wrong = peer(0xCD);
        let facts = vec![
            fact("callee", &[bytes(wrong.as_bytes())]),
            fact("expires", &[date(&exp)]),
        ];
        let cred = env.mint(&facts);
        let err = UnverifiedSubmit::from_header(header_submit(Some(cred)))
            .unwrap()
            .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
            .unwrap_err();
        assert_eq!(err, AuthError::TokenUnauthorized);
    }

    #[test]
    fn expires_fact_pass() {
        let env = TokenEnv::new();
        let exp = now_secs(1_500_000_000);
        let cred = env.mint(&env.required_facts(exp));
        UnverifiedSubmit::from_header(header_submit(Some(cred)))
            .unwrap()
            .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
            .unwrap();
    }

    #[test]
    fn expires_fact_fail_in_past() {
        let env = TokenEnv::new();
        let exp = now_secs(500_000_000);
        let cred = env.mint(&env.required_facts(exp));
        let err = UnverifiedSubmit::from_header(header_submit(Some(cred)))
            .unwrap()
            .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
            .unwrap_err();
        assert_eq!(err, AuthError::TokenUnauthorized);
    }

    #[test]
    fn token_missing_expires_fails() {
        let env = TokenEnv::new();
        let facts = vec![fact("callee", &[bytes(env.self_id.as_bytes())])];
        let cred = env.mint(&facts);
        let err = UnverifiedSubmit::from_header(header_submit(Some(cred)))
            .unwrap()
            .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
            .unwrap_err();
        assert_eq!(err, AuthError::TokenUnauthorized);
    }

    #[test]
    fn max_deadline_ms_pass() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let mut facts = env.required_facts(exp);
        facts.push(fact("max_deadline_ms", &[int(5_000)]));
        let cred = env.mint(&facts);
        UnverifiedSubmit::from_header(header_submit_full(
            1_000,
            "application/octet-stream",
            Some(cred),
        ))
        .unwrap()
        .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
        .unwrap();
    }

    #[test]
    fn max_deadline_ms_fail_over_limit() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let mut facts = env.required_facts(exp);
        facts.push(fact("max_deadline_ms", &[int(500)]));
        let cred = env.mint(&facts);
        let err = UnverifiedSubmit::from_header(header_submit_full(
            1_000,
            "application/octet-stream",
            Some(cred),
        ))
        .unwrap()
        .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
        .unwrap_err();
        assert_eq!(err, AuthError::TokenUnauthorized);
    }

    #[test]
    fn content_type_fact_pass() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let mut facts = env.required_facts(exp);
        facts.push(fact("content_type", &[string("text/plain")]));
        let cred = env.mint(&facts);
        UnverifiedSubmit::from_header(header_submit_full(1_000, "text/plain", Some(cred)))
            .unwrap()
            .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
            .unwrap();
    }

    #[test]
    fn content_type_fact_fail_mismatch() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let mut facts = env.required_facts(exp);
        facts.push(fact("content_type", &[string("text/plain")]));
        let cred = env.mint(&facts);
        let err = UnverifiedSubmit::from_header(header_submit_full(
            1_000,
            "application/octet-stream",
            Some(cred),
        ))
        .unwrap()
        .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
        .unwrap_err();
        assert_eq!(err, AuthError::TokenUnauthorized);
    }

    #[test]
    fn one_shot_pass_then_fail_on_reuse() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let empty: &[Term] = &[];
        let mut facts = env.required_facts(exp);
        facts.push(fact("one_shot", empty));
        let cred = env.mint(&facts);
        let policy = env.policy();

        let first = UnverifiedSubmit::from_header(header_submit(Some(cred.clone())))
            .unwrap()
            .verify(&policy, peer(1), now_secs(1_000_000_000))
            .unwrap();
        let AuthRule::Token { biscuit_id } = first.rule else {
            panic!("expected token rule");
        };
        assert!(env.spent.contains(&biscuit_id));

        let err = UnverifiedSubmit::from_header(header_submit(Some(cred)))
            .unwrap()
            .verify(&policy, peer(1), now_secs(1_000_000_000))
            .unwrap_err();
        assert_eq!(err, AuthError::TokenUnauthorized);
    }

    #[test]
    fn one_shot_absent_allows_reuse() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let cred = env.mint(&env.required_facts(exp));
        let policy = env.policy();
        UnverifiedSubmit::from_header(header_submit(Some(cred.clone())))
            .unwrap()
            .verify(&policy, peer(1), now_secs(1_000_000_000))
            .unwrap();
        UnverifiedSubmit::from_header(header_submit(Some(cred)))
            .unwrap()
            .verify(&policy, peer(1), now_secs(1_000_000_000))
            .unwrap();
    }

    #[test]
    fn optional_facts_absent_still_pass_with_required_only() {
        let env = TokenEnv::new();
        let exp = now_secs(2_000_000_000);
        let cred = env.mint(&env.required_facts(exp));
        UnverifiedSubmit::from_header(header_submit_full(
            60_000,
            "application/json",
            Some(cred),
        ))
        .unwrap()
        .verify(&env.policy(), peer(1), now_secs(1_000_000_000))
        .unwrap();
    }
}
