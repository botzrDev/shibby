//! Iroh endpoint owner: accept loop, dial, CancellationToken shutdown.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};
use uat_core::{CloseCode, Message, NodeId, Outcome};

use crate::auth::Verify;
use crate::call::{close_with, run_callee_with, run_caller, CallError, CalleeBehavior};
use crate::identity::{load_or_create_at, Identity, IdentityError, IDENTITY_FILE};
use crate::local::{
    bind_sock, remove_sock_file, spawn_local_accept_loop, InboxEvent, LocalBindError, SOCK_FILE,
};
use crate::record::{
    connection_bytes, AuthOutcome, CallRecord, CallRecordSink, Direction, Path as ConnPath,
    TracingCallRecordSink, CALL_RECORD_SCHEMA_VERSION,
};
use crate::timing::uat_transport_config;
use crate::{public_key_to_node_id, NodeError};

/// Errors constructing or running a [`Node`].
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Identity load/create failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),

    /// NodeId ↔ PublicKey conversion failed.
    #[error(transparent)]
    Node(#[from] NodeError),

    /// iroh endpoint failed to bind.
    #[error("endpoint bind failed: {0}")]
    Bind(String),

    /// Outbound connect failed.
    #[error("connect failed: {0}")]
    Connect(String),

    /// In-call failure.
    #[error(transparent)]
    Call(#[from] CallError),

    /// Local `$UAT_HOME/node.sock` bind failed.
    #[error(transparent)]
    LocalSock(#[from] LocalBindError),
}

/// Owns an iroh [`Endpoint`], accept loop, and one Call task per connection.
pub struct Node {
    endpoint: Endpoint,
    identity: Identity,
    verify: Arc<dyn Verify>,
    cancel: CancellationToken,
    tracker: TaskTracker,
    callee_behavior: CalleeBehavior,
    records: Arc<dyn CallRecordSink>,
    /// Notifies local-socket Inbox polls of finished inbound calls (M1 one-shot).
    inbox_tx: mpsc::Sender<InboxEvent>,
    inbox_rx: tokio::sync::Mutex<Option<mpsc::Receiver<InboxEvent>>>,
    /// Directory that owns `node.sock` when the local listener is active.
    sock_home: tokio::sync::Mutex<Option<PathBuf>>,
}

impl Node {
    /// Bind a new endpoint using `identity`, with connection/Submit auth via `verify`.
    ///
    /// Relay is disabled so two processes on one host can dial via [`EndpointAddr`]
    /// direct addresses (exit proof / local CI). Discovery/relay land with later tickets.
    pub async fn bind(
        identity: Identity,
        verify: Arc<dyn Verify>,
        cancel: CancellationToken,
    ) -> Result<Arc<Self>, DaemonError> {
        Self::bind_with_behavior(identity, verify, cancel, CalleeBehavior::StubComplete).await
    }

    /// Bind with an explicit callee stub behavior (timer / liveness tests).
    pub async fn bind_with_behavior(
        identity: Identity,
        verify: Arc<dyn Verify>,
        cancel: CancellationToken,
        callee_behavior: CalleeBehavior,
    ) -> Result<Arc<Self>, DaemonError> {
        Self::bind_with_behavior_and_sink(
            identity,
            verify,
            cancel,
            callee_behavior,
            Arc::new(TracingCallRecordSink),
        )
        .await
    }

    /// Bind with callee behavior and a [`CallRecordSink`] (tests use [`crate::MemoryCallRecordSink`]).
    pub async fn bind_with_behavior_and_sink(
        identity: Identity,
        verify: Arc<dyn Verify>,
        cancel: CancellationToken,
        callee_behavior: CalleeBehavior,
        records: Arc<dyn CallRecordSink>,
    ) -> Result<Arc<Self>, DaemonError> {
        let secret = identity.secret_key().clone();
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![uat_core::ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .transport_config(uat_transport_config())
            .bind()
            .await
            .map_err(|e| DaemonError::Bind(e.to_string()))?;

        let (inbox_tx, inbox_rx) = mpsc::channel(32);
        let node = Arc::new(Self {
            endpoint,
            identity,
            verify,
            cancel,
            tracker: TaskTracker::new(),
            callee_behavior,
            records,
            inbox_tx,
            inbox_rx: tokio::sync::Mutex::new(Some(inbox_rx)),
            sock_home: tokio::sync::Mutex::new(None),
        });
        Ok(node)
    }

    /// Load-or-create identity under `uat_home` and bind.
    pub async fn bind_at(
        uat_home: &Path,
        verify: Arc<dyn Verify>,
        cancel: CancellationToken,
    ) -> Result<Arc<Self>, DaemonError> {
        let identity = load_or_create_at(&uat_home.join(IDENTITY_FILE))?;
        Self::bind(identity, verify, cancel).await
    }

    /// [`Self::bind_at`] with explicit callee stub behavior.
    pub async fn bind_at_with_behavior(
        uat_home: &Path,
        verify: Arc<dyn Verify>,
        cancel: CancellationToken,
        callee_behavior: CalleeBehavior,
    ) -> Result<Arc<Self>, DaemonError> {
        let identity = load_or_create_at(&uat_home.join(IDENTITY_FILE))?;
        Self::bind_with_behavior(identity, verify, cancel, callee_behavior).await
    }

    /// [`Self::bind_at_with_behavior`] plus a custom [`CallRecordSink`].
    pub async fn bind_at_with_behavior_and_sink(
        uat_home: &Path,
        verify: Arc<dyn Verify>,
        cancel: CancellationToken,
        callee_behavior: CalleeBehavior,
        records: Arc<dyn CallRecordSink>,
    ) -> Result<Arc<Self>, DaemonError> {
        let identity = load_or_create_at(&uat_home.join(IDENTITY_FILE))?;
        Self::bind_with_behavior_and_sink(identity, verify, cancel, callee_behavior, records).await
    }

    /// Shared call-record sink (tests).
    #[must_use]
    pub fn record_sink(&self) -> Arc<dyn CallRecordSink> {
        Arc::clone(&self.records)
    }

    /// This node's stable [`NodeId`].
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// iroh addressing details for dialers on the same host / LAN.
    #[must_use]
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Shared cancellation token (SIGTERM / explicit shutdown).
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Borrow the underlying endpoint (tests / advanced dial).
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Spawn the accept loop as a tracked task. Call once after [`Self::bind`].
    pub fn spawn_accept_loop(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.tracker.spawn(async move {
            this.accept_loop().await;
        });
    }

    /// Bind `$UAT_HOME/node.sock` (mode 0600) and accept local Dial/Inbox/Message clients.
    ///
    /// Call once after [`Self::bind`]. Replaces a stale sock file; refuses if another
    /// daemon already accepts on the path.
    pub async fn spawn_local_socket(self: &Arc<Self>, uat_home: &Path) -> Result<(), DaemonError> {
        let listener = bind_sock(uat_home).await?;
        let mut home_guard = self.sock_home.lock().await;
        *home_guard = Some(uat_home.to_path_buf());
        drop(home_guard);

        let mut rx_guard = self.inbox_rx.lock().await;
        let inbox_rx = rx_guard
            .take()
            .ok_or_else(|| DaemonError::Bind("local socket inbox already taken".into()))?;
        drop(rx_guard);

        let latest_inbox = Arc::new(tokio::sync::Mutex::new(None));
        spawn_local_accept_loop(
            Arc::clone(self),
            listener,
            uat_home.to_path_buf(),
            inbox_rx,
            latest_inbox,
        );
        Ok(())
    }

    /// Path of the local socket when listening, if known.
    pub async fn local_sock_path(&self) -> Option<PathBuf> {
        self.sock_home
            .lock()
            .await
            .as_ref()
            .map(|home| home.join(SOCK_FILE))
    }

    /// Task tracker for spawning daemon-owned work (local socket accept loop).
    #[must_use]
    pub fn tracker(&self) -> &TaskTracker {
        &self.tracker
    }

    async fn accept_loop(self: Arc<Self>) {
        info!(node = ?self.node_id(), "accept loop started");
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    info!("accept loop cancelled");
                    break;
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        debug!("endpoint accept returned None");
                        break;
                    };
                    let this = Arc::clone(&self);
                    self.tracker.spawn(async move {
                        if let Err(err) = this.handle_incoming(incoming).await {
                            warn!(?err, "incoming connection handler failed");
                        }
                    });
                }
            }
        }
    }

    async fn handle_incoming(
        self: Arc<Self>,
        incoming: iroh::endpoint::Incoming,
    ) -> Result<(), DaemonError> {
        let started_at = std::time::SystemTime::now();
        let start = Instant::now();
        let conn = incoming
            .await
            .map_err(|e| DaemonError::Connect(e.to_string()))?;
        let peer = public_key_to_node_id(&conn.remote_id());

        if !self.verify.verify_peer(peer) {
            debug!(?peer, "rejecting dialer: not on allowlist");
            close_with(&conn, CloseCode::Normal);
            let (bytes_sent, bytes_recv) = connection_bytes(&conn);
            // Emit here (before Call task): deny must still produce a record, task=None.
            self.records.emit(CallRecord {
                schema_version: CALL_RECORD_SCHEMA_VERSION,
                started_at,
                task: None,
                direction: Direction::Inbound,
                peer,
                authorization: AuthOutcome::Denied {
                    reason: "not on allowlist".into(),
                },
                outcome: Outcome::Closed(CloseCode::Normal),
                path: ConnPath::Direct,
                bytes_sent,
                bytes_recv,
                wall_time_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            });
            return Ok(());
        }

        let cancel = self.cancel.child_token();
        match run_callee_with(
            conn,
            peer,
            Arc::clone(&self.verify),
            cancel,
            self.callee_behavior,
            Arc::clone(&self.records),
        )
        .await
        {
            Ok(outcome) => {
                info!(?peer, ?outcome, "callee call finished");
                let _ = self.inbox_tx.try_send(InboxEvent {
                    peer: format!("{peer:?}"),
                    outcome,
                });
                Ok(())
            }
            Err(CallError::Cancelled) => Ok(()),
            Err(err) => Err(DaemonError::Call(err)),
        }
    }

    /// Dial `peer`, open one stream, run the caller side of `submit`.
    pub async fn dial(
        &self,
        peer: impl Into<EndpointAddr>,
        submit: Message,
    ) -> Result<Outcome, DaemonError> {
        let addr = peer.into();

        let conn = self
            .endpoint
            .connect(addr, uat_core::ALPN)
            .await
            .map_err(|e| DaemonError::Connect(e.to_string()))?;

        let cancel = self.cancel.child_token();
        let outcome = run_caller(conn, submit, cancel, Arc::clone(&self.records)).await?;
        Ok(outcome)
    }

    /// Cancel accept loop and call tasks, wait for them, then close the endpoint.
    pub async fn shutdown(&self) {
        info!("node shutting down");
        self.cancel.cancel();
        self.tracker.close();
        self.tracker.wait().await;
        if let Some(home) = self.sock_home.lock().await.take() {
            remove_sock_file(&home);
        }
        self.endpoint.close().await;
        info!("node shut down complete");
    }
}
