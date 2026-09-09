//! Local daemon↔client Unix socket (`$UAT_HOME/node.sock`).
//!
//! **Not a peer transport and not ALPN `/uat/0.2`.** Auth is file mode `0600` only.
//! Vocabulary on this surface is intentionally limited to:
//! - peer [`Message`](uat_core::Message) (carried under `type: "message"`)
//! - `Dial`
//! - `Inbox`
//!
//! Framing reuses the peer codec layout (`len:u32be | hdr_len:u16be | json | body`) so
//! `Message` bodies stay out of the JSON header. Dial/Inbox are a thin control envelope
//! in that same frame shape — documented here so it is not mistaken for a second peer ALPN.

use std::fs::{self, Permissions};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use iroh::{EndpointAddr, EndpointId, TransportAddr};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uat_core::{
    ContentType, Credential, Deadline, Message, Outcome, TaskId, MAX_FRAME, MAX_HDR_LEN,
};

use crate::node::{DaemonError, Node};

/// Filename for the local control socket under `UAT_HOME`.
pub const SOCK_FILE: &str = "node.sock";

/// Required unix mode bits for `node.sock` (`0600`).
pub const SOCK_MODE: u32 = 0o600;

/// Path to `$UAT_HOME/node.sock` (or `uat_home/node.sock`).
#[must_use]
pub fn sock_path(uat_home: &Path) -> PathBuf {
    uat_home.join(SOCK_FILE)
}

/// Inbound call notification for M1 one-shot [`LocalRequest::Inbox`].
#[derive(Clone, Debug)]
pub struct InboxEvent {
    /// Peer that dialed us (hex EndpointId / public key).
    pub peer: String,
    /// How the inbound call ended.
    pub outcome: Outcome,
}

/// Client → daemon request. Only Dial / Inbox / Message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalRequest {
    /// Ask the daemon to open an outbound call via [`Node::dial`].
    Dial {
        /// Peer [`EndpointId`] (`Display` / `FromStr` form).
        peer: String,
        /// Direct IP transport addresses (`ip:port`).
        addrs: Vec<String>,
        task: TaskId,
        deadline: Deadline,
        content_type: ContentType,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential: Option<Credential>,
        #[serde(skip)]
        body: Vec<u8>,
    },
    /// One-shot poll for a recent inbound call event (M1).
    Inbox,
    /// Carry a peer [`Message`] on the local socket (no extra vocabulary).
    Message {
        #[serde(rename = "message")]
        message: Message,
    },
}

/// Daemon → client response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalResponse {
    DialResult {
        outcome: Outcome,
        /// Best-effort RTT in milliseconds after connect (HLX-109).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rtt_ms: Option<u64>,
    },
    /// No inbound event ready (M1 one-shot).
    InboxIdle,
    InboxEvent {
        peer: String,
        outcome: Outcome,
    },
    /// Echo / forward of a peer Message (M1: unused session path).
    Message {
        #[serde(rename = "message")]
        message: Message,
    },
    Error {
        message: String,
    },
}

/// Errors encoding/decoding local socket frames.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LocalCodecError {
    #[error("frame too large")]
    FrameTooLarge,
    #[error("truncated frame")]
    Truncated,
    #[error("len inconsistent with hdr_len")]
    BadLength,
    #[error("malformed header json")]
    MalformedHeader,
    #[error("header too large to encode")]
    HeaderTooLarge,
    #[error("frame too large to encode")]
    EncodeTooLarge,
}

/// Client-side connection / protocol errors with actionable text.
#[derive(Debug, Error)]
pub enum LocalClientError {
    /// No `node.sock` — daemon was never started (or wrong `UAT_HOME`).
    #[error(
        "uat-node is not running (no socket at {path}); start the node with `uat-node listen`"
    )]
    NotRunning { path: PathBuf },

    /// Socket file exists but nothing accepts — stale file after a crash.
    #[error(
        "stale socket at {path} (daemon not running); remove it and start the node with `uat-node listen`"
    )]
    StaleSocket { path: PathBuf },

    /// Daemon returned an error response.
    #[error("{0}")]
    Daemon(String),

    #[error(transparent)]
    Codec(#[from] LocalCodecError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    DaemonCall(#[from] DaemonError),
}

/// Errors binding the local listener.
#[derive(Debug, Error)]
pub enum LocalBindError {
    #[error("uat-node already running (socket {path} accepts connections)")]
    AlreadyRunning { path: PathBuf },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn request_body(req: &LocalRequest) -> &[u8] {
    match req {
        LocalRequest::Dial { body, .. } => body.as_slice(),
        LocalRequest::Message { message } => message_body(message),
        LocalRequest::Inbox => &[],
    }
}

fn response_body(resp: &LocalResponse) -> &[u8] {
    match resp {
        LocalResponse::Message { message } => message_body(message),
        _ => &[],
    }
}

fn message_body(message: &Message) -> &[u8] {
    match message {
        Message::Submit { body, .. }
        | Message::Input { body }
        | Message::Completed { body } => body.as_slice(),
        _ => &[],
    }
}

fn set_message_body(message: &mut Message, body: Vec<u8>) {
    match message {
        Message::Submit { body: b, .. }
        | Message::Input { body: b }
        | Message::Completed { body: b } => *b = body,
        _ => {}
    }
}

fn set_request_body(req: &mut LocalRequest, body: Vec<u8>) -> Result<(), LocalCodecError> {
    match req {
        LocalRequest::Dial { body: b, .. } => {
            *b = body;
            Ok(())
        }
        LocalRequest::Message { message } => {
            if matches!(
                message,
                Message::Submit { .. } | Message::Input { .. } | Message::Completed { .. }
            ) {
                set_message_body(message, body);
                Ok(())
            } else if body.is_empty() {
                Ok(())
            } else {
                Err(LocalCodecError::BadLength)
            }
        }
        LocalRequest::Inbox => {
            if body.is_empty() {
                Ok(())
            } else {
                Err(LocalCodecError::BadLength)
            }
        }
    }
}

fn set_response_body(resp: &mut LocalResponse, body: Vec<u8>) -> Result<(), LocalCodecError> {
    match resp {
        LocalResponse::Message { message } => {
            if matches!(
                message,
                Message::Submit { .. } | Message::Input { .. } | Message::Completed { .. }
            ) {
                set_message_body(message, body);
                Ok(())
            } else if body.is_empty() {
                Ok(())
            } else {
                Err(LocalCodecError::BadLength)
            }
        }
        _ => {
            if body.is_empty() {
                Ok(())
            } else {
                Err(LocalCodecError::BadLength)
            }
        }
    }
}

fn encode_json_frame(header: &[u8], body: &[u8], out: &mut Vec<u8>) -> Result<(), LocalCodecError> {
    if header.len() > usize::from(MAX_HDR_LEN) {
        return Err(LocalCodecError::HeaderTooLarge);
    }
    let len_u = 2usize
        .checked_add(header.len())
        .and_then(|n| n.checked_add(body.len()))
        .ok_or(LocalCodecError::EncodeTooLarge)?;
    if len_u > MAX_FRAME as usize {
        return Err(LocalCodecError::EncodeTooLarge);
    }
    let len = u32::try_from(len_u).map_err(|_| LocalCodecError::EncodeTooLarge)?;
    let hdr_len = u16::try_from(header.len()).map_err(|_| LocalCodecError::HeaderTooLarge)?;
    out.reserve(4 + len_u);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&hdr_len.to_be_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(body);
    Ok(())
}

/// Encode a [`LocalRequest`] (same length-prefixed layout as the peer Message codec).
pub fn encode_request(req: &LocalRequest, out: &mut Vec<u8>) -> Result<(), LocalCodecError> {
    let header = serde_json::to_vec(req).map_err(|_| LocalCodecError::MalformedHeader)?;
    encode_json_frame(&header, request_body(req), out)
}

/// Encode a [`LocalResponse`].
pub fn encode_response(resp: &LocalResponse, out: &mut Vec<u8>) -> Result<(), LocalCodecError> {
    let header = serde_json::to_vec(resp).map_err(|_| LocalCodecError::MalformedHeader)?;
    encode_json_frame(&header, response_body(resp), out)
}

fn decode_parts(buf: &[u8]) -> Result<(&[u8], &[u8]), LocalCodecError> {
    if buf.len() < 4 {
        return Err(LocalCodecError::Truncated);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len > MAX_FRAME {
        return Err(LocalCodecError::FrameTooLarge);
    }
    let len_usize = len as usize;
    if buf.len() < 4 + len_usize {
        return Err(LocalCodecError::Truncated);
    }
    let payload = &buf[4..4 + len_usize];
    if payload.len() < 2 {
        return Err(LocalCodecError::BadLength);
    }
    let hdr_len = u16::from_be_bytes([payload[0], payload[1]]);
    if hdr_len > MAX_HDR_LEN {
        return Err(LocalCodecError::FrameTooLarge);
    }
    let hdr_len_usize = usize::from(hdr_len);
    if payload.len() < 2 + hdr_len_usize {
        return Err(LocalCodecError::BadLength);
    }
    if len_usize < 2 + hdr_len_usize {
        return Err(LocalCodecError::BadLength);
    }
    let header = &payload[2..2 + hdr_len_usize];
    let body = &payload[2 + hdr_len_usize..];
    if 2 + hdr_len_usize + body.len() != len_usize {
        return Err(LocalCodecError::BadLength);
    }
    Ok((header, body))
}

/// Decode a [`LocalRequest`].
pub fn decode_request(buf: &[u8]) -> Result<LocalRequest, LocalCodecError> {
    let (header, body) = decode_parts(buf)?;
    let mut req: LocalRequest =
        serde_json::from_slice(header).map_err(|_| LocalCodecError::MalformedHeader)?;
    set_request_body(&mut req, body.to_vec())?;
    Ok(req)
}

/// Decode a [`LocalResponse`].
pub fn decode_response(buf: &[u8]) -> Result<LocalResponse, LocalCodecError> {
    let (header, body) = decode_parts(buf)?;
    let mut resp: LocalResponse =
        serde_json::from_slice(header).map_err(|_| LocalCodecError::MalformedHeader)?;
    set_response_body(&mut resp, body.to_vec())?;
    Ok(resp)
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, LocalClientError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(LocalClientError::Codec(LocalCodecError::FrameTooLarge));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    let mut frame = Vec::with_capacity(4 + len as usize);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
) -> Result<(), LocalClientError> {
    writer.write_all(frame).await?;
    writer.flush().await?;
    Ok(())
}

/// Bind `$UAT_HOME/node.sock` at mode `0600`, replacing a stale socket file if needed.
pub async fn bind_sock(uat_home: &Path) -> Result<UnixListener, LocalBindError> {
    fs::create_dir_all(uat_home)?;
    let path = sock_path(uat_home);
    if path.exists() {
        match UnixStream::connect(&path).await {
            Ok(_live) => {
                return Err(LocalBindError::AlreadyRunning { path });
            }
            Err(_) => {
                // Stale file left behind after a crash / kill -9.
                fs::remove_file(&path)?;
            }
        }
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, Permissions::from_mode(SOCK_MODE))?;
    let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
    if mode != SOCK_MODE {
        warn!(?path, mode = format!("{mode:o}"), "node.sock mode is not 0600");
    }
    info!(path = %path.display(), "local socket bound");
    Ok(listener)
}

/// Remove the socket file if it still exists (SIGTERM / shutdown).
pub fn remove_sock_file(uat_home: &Path) {
    let path = sock_path(uat_home);
    match fs::remove_file(&path) {
        Ok(()) => info!(path = %path.display(), "local socket removed"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => warn!(path = %path.display(), ?err, "failed to remove local socket"),
    }
}

/// Connect to the daemon's local socket with actionable errors when it is down.
pub async fn connect(uat_home: &Path) -> Result<UnixStream, LocalClientError> {
    let path = sock_path(uat_home);
    if !path.exists() {
        return Err(LocalClientError::NotRunning { path });
    }
    match UnixStream::connect(&path).await {
        Ok(stream) => Ok(stream),
        Err(_) => Err(LocalClientError::StaleSocket { path }),
    }
}

/// Send one request and read one response (M1 one-shot sessions).
pub async fn roundtrip(
    stream: &mut UnixStream,
    req: &LocalRequest,
) -> Result<LocalResponse, LocalClientError> {
    let mut buf = Vec::new();
    encode_request(req, &mut buf)?;
    write_frame(stream, &buf).await?;
    let frame = read_frame(stream).await?;
    Ok(decode_response(&frame)?)
}

/// Dial a peer through a running daemon (library client / tests / CLI).
///
/// `peer` is the iroh [`EndpointId`] string form (`Display` / `FromStr`).
pub async fn dial_via_sock(
    uat_home: &Path,
    peer: &str,
    addrs: &[SocketAddr],
    submit: Message,
) -> Result<(Outcome, Option<u64>), LocalClientError> {
    let Message::Submit {
        task,
        deadline,
        content_type,
        credential,
        body,
    } = submit
    else {
        return Err(LocalClientError::Daemon(
            "dial requires a Submit message".into(),
        ));
    };

    // Prefer daemon-not-running errors over peer parse errors — that is what
    // every new user hits first (HLX-107).
    let mut stream = connect(uat_home).await?;
    let req = LocalRequest::Dial {
        peer: peer.to_string(),
        addrs: addrs.iter().map(ToString::to_string).collect(),
        task,
        deadline,
        content_type,
        credential,
        body,
    };
    match roundtrip(&mut stream, &req).await? {
        LocalResponse::DialResult { outcome, rtt_ms } => Ok((outcome, rtt_ms)),
        LocalResponse::Error { message } => Err(LocalClientError::Daemon(message)),
        other => Err(LocalClientError::Daemon(format!(
            "unexpected response to dial: {other:?}"
        ))),
    }
}

/// One-shot Inbox poll through the local socket.
pub async fn inbox_via_sock(uat_home: &Path) -> Result<LocalResponse, LocalClientError> {
    let mut stream = connect(uat_home).await?;
    roundtrip(&mut stream, &LocalRequest::Inbox).await
}

/// Accept loop for local clients. Spawned by the daemon alongside the iroh accept loop.
pub fn spawn_local_accept_loop(
    node: Arc<Node>,
    listener: UnixListener,
    uat_home: PathBuf,
    mut inbox_rx: mpsc::Receiver<InboxEvent>,
    latest_inbox: Arc<tokio::sync::Mutex<Option<InboxEvent>>>,
) {
    let cancel = node.cancellation_token();
    let node_for_loop = Arc::clone(&node);
    node.tracker().spawn(async move {
        let node = node_for_loop;
        // Forward inbox events into the shared slot for one-shot polls.
        let latest = Arc::clone(&latest_inbox);
        let cancel_fwd = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_fwd.cancelled() => break,
                    ev = inbox_rx.recv() => {
                        match ev {
                            Some(ev) => {
                                *latest.lock().await = Some(ev);
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            let node = Arc::clone(&node);
                            let latest = Arc::clone(&latest_inbox);
                            tokio::spawn(async move {
                                if let Err(err) = handle_client(node, stream, latest).await {
                                    debug!(?err, "local client session ended with error");
                                }
                            });
                        }
                        Err(err) => {
                            warn!(?err, "local socket accept failed");
                            break;
                        }
                    }
                }
            }
        }
        remove_sock_file(&uat_home);
    });
}

async fn handle_client(
    node: Arc<Node>,
    mut stream: UnixStream,
    latest_inbox: Arc<tokio::sync::Mutex<Option<InboxEvent>>>,
) -> Result<(), LocalClientError> {
    let frame = read_frame(&mut stream).await?;
    let req = decode_request(&frame)?;
    let resp = match req {
        LocalRequest::Dial {
            peer,
            addrs,
            task,
            deadline,
            content_type,
            credential,
            body,
        } => match build_dial(peer, addrs, task, deadline, content_type, credential, body) {
            Ok((addr, submit)) => match node.dial(addr, submit).await {
                Ok(finish) => LocalResponse::DialResult {
                    outcome: finish.outcome,
                    rtt_ms: finish.rtt.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                },
                Err(err) => LocalResponse::Error {
                    message: err.to_string(),
                },
            },
            Err(message) => LocalResponse::Error { message },
        },
        LocalRequest::Inbox => {
            let mut slot = latest_inbox.lock().await;
            match slot.take() {
                Some(ev) => LocalResponse::InboxEvent {
                    peer: ev.peer,
                    outcome: ev.outcome,
                },
                None => LocalResponse::InboxIdle,
            }
        }
        LocalRequest::Message { .. } => LocalResponse::Error {
            message: "message forwarding on the local socket requires an active call session (M1 dial is one-shot; use Dial)"
                .into(),
        },
    };
    let mut out = Vec::new();
    encode_response(&resp, &mut out)?;
    write_frame(&mut stream, &out).await?;
    Ok(())
}

fn build_dial(
    peer: String,
    addrs: Vec<String>,
    task: TaskId,
    deadline: Deadline,
    content_type: ContentType,
    credential: Option<Credential>,
    body: Vec<u8>,
) -> Result<(EndpointAddr, Message), String> {
    let peer_id: EndpointId = peer
        .parse()
        .map_err(|e| format!("invalid peer endpoint id: {e}"))?;
    if addrs.is_empty() {
        return Err("dial requires at least one addr".into());
    }
    let mut sock_addrs = Vec::with_capacity(addrs.len());
    for a in addrs {
        let sa: SocketAddr = a
            .parse()
            .map_err(|e| format!("invalid addr {a:?}: {e}"))?;
        sock_addrs.push(sa);
    }
    let addr = EndpointAddr::from_parts(peer_id, sock_addrs.into_iter().map(TransportAddr::Ip));
    let submit = Message::Submit {
        task,
        deadline,
        content_type,
        credential,
        body,
    };
    Ok((addr, submit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uat_core::{ContentType, Deadline, TaskId};

    #[test]
    fn dial_request_roundtrips_with_body() {
        let req = LocalRequest::Dial {
            peer: "abc".into(),
            addrs: vec!["127.0.0.1:9".into()],
            task: TaskId::from_u128(1),
            deadline: Deadline::new(1000).unwrap(),
            content_type: ContentType::new("application/octet-stream").unwrap(),
            credential: None,
            body: b"payload".to_vec(),
        };
        let mut buf = Vec::new();
        encode_request(&req, &mut buf).unwrap();
        let back = decode_request(&buf).unwrap();
        assert_eq!(back, req);
        // Body rides after the JSON header (same layout as peer Message codec).
        let hdr_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let header = &buf[6..6 + hdr_len];
        let json = std::str::from_utf8(header).unwrap();
        assert!(!json.contains("payload"));
        assert_eq!(&buf[6 + hdr_len..], b"payload");
    }

    #[test]
    fn message_carriage_roundtrips() {
        let req = LocalRequest::Message {
            message: Message::Accepted,
        };
        let mut buf = Vec::new();
        encode_request(&req, &mut buf).unwrap();
        assert_eq!(decode_request(&buf).unwrap(), req);
    }
}
