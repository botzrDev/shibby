//! Iroh endpoint owner: accept loop, dial, CancellationToken shutdown.

use std::path::Path;
use std::sync::Arc;

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};
use uat_core::{Message, NodeId, Outcome};

use crate::auth::Verify;
use crate::call::{close_with, run_callee, run_caller, CallError};
use crate::identity::{load_or_create_at, Identity, IdentityError, IDENTITY_FILE};
use crate::{public_key_to_node_id, NodeError};
use uat_core::CloseCode;

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
}

/// Owns an iroh [`Endpoint`], accept loop, and one Call task per connection.
pub struct Node {
    endpoint: Endpoint,
    identity: Identity,
    verify: Arc<dyn Verify>,
    cancel: CancellationToken,
    tracker: TaskTracker,
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
        let secret = identity.secret_key().clone();
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![uat_core::ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .map_err(|e| DaemonError::Bind(e.to_string()))?;

        let node = Arc::new(Self {
            endpoint,
            identity,
            verify,
            cancel,
            tracker: TaskTracker::new(),
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
        let conn = incoming
            .await
            .map_err(|e| DaemonError::Connect(e.to_string()))?;
        let peer = public_key_to_node_id(&conn.remote_id());

        if !self.verify.verify_peer(peer) {
            debug!(?peer, "rejecting dialer: not on allowlist");
            close_with(&conn, CloseCode::Normal);
            return Ok(());
        }

        let cancel = self.cancel.child_token();
        match run_callee(conn, peer, Arc::clone(&self.verify), cancel).await {
            Ok(outcome) => {
                info!(?peer, ?outcome, "callee call finished");
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
        let outcome = run_caller(conn, submit, cancel).await?;
        Ok(outcome)
    }

    /// Cancel accept loop and call tasks, wait for them, then close the endpoint.
    pub async fn shutdown(&self) {
        info!("node shutting down");
        self.cancel.cancel();
        self.tracker.close();
        self.tracker.wait().await;
        self.endpoint.close().await;
        info!("node shut down complete");
    }
}
