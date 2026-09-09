//! Frame codec: length-prefixed JSON header + raw body. No network.

use crate::codes::CloseCode;
use crate::message::Message;
use thiserror::Error;

/// Maximum value of the frame `len` field (payload after the 4-byte length).
pub const MAX_FRAME: u32 = 65_536;

/// Maximum JSON header length in bytes.
pub const MAX_HDR_LEN: u16 = 4_096;

/// Codec failures. F1 maps to [`CloseCode::FrameTooLarge`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Peer claimed a frame or header larger than the protocol max.
    #[error("frame too large")]
    FrameTooLarge,

    /// Buffer shorter than the length prefix / claimed frame.
    #[error("truncated frame")]
    Truncated,

    /// `len` smaller than `2 + hdr_len`.
    #[error("len inconsistent with hdr_len")]
    BadLength,

    /// JSON header did not deserialize.
    #[error("malformed header json")]
    MalformedHeader,

    /// Header serialized larger than [`MAX_HDR_LEN`].
    #[error("header too large to encode")]
    HeaderTooLarge,

    /// Encoded payload would exceed [`MAX_FRAME`].
    #[error("frame too large to encode")]
    EncodeTooLarge,

    /// `Submit` was denied before the body was copied (F4).
    #[error("submit denied before body copy")]
    SubmitDenied,
}

impl CodecError {
    /// Suggested connection close code, when applicable.
    #[must_use]
    pub const fn close_code(self) -> Option<CloseCode> {
        match self {
            Self::FrameTooLarge => Some(CloseCode::FrameTooLarge),
            Self::MalformedHeader | Self::BadLength | Self::Truncated => {
                Some(CloseCode::MalformedFrame)
            }
            Self::HeaderTooLarge | Self::EncodeTooLarge | Self::SubmitDenied => None,
        }
    }
}

/// Decides whether a parsed `Submit` header may take its body (F4 seam).
pub trait SubmitAuthorizer {
    /// Return `true` to allow copying the `Submit` body.
    fn authorize_submit(&self, header: &Message) -> bool;
}

/// Authorizer that always denies. Used to prove F4 in tests and as the M0 stub.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAll;

impl SubmitAuthorizer for DenyAll {
    fn authorize_submit(&self, _header: &Message) -> bool {
        false
    }
}

/// Authorizer that always allows body materialization.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl SubmitAuthorizer for AllowAll {
    fn authorize_submit(&self, _header: &Message) -> bool {
        true
    }
}

/// Fixed-size decode scratch buffer for F2 (one `MAX_FRAME` payload, not sized by the peer).
pub struct FrameBuffer {
    buf: Box<[u8; MAX_FRAME as usize]>,
}

impl FrameBuffer {
    /// Allocate the reusable buffer once.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Box::new([0u8; MAX_FRAME as usize]),
        }
    }

    /// Borrow the scratch bytes.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut *self.buf
    }
}

impl Default for FrameBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode `message` into `out` (appends). Body bytes are written raw after the JSON header.
pub fn encode(message: &Message, out: &mut Vec<u8>) -> Result<(), CodecError> {
    let header = serde_json::to_vec(message).map_err(|_| CodecError::MalformedHeader)?;
    if header.len() > usize::from(MAX_HDR_LEN) {
        return Err(CodecError::HeaderTooLarge);
    }
    let body = message_body(message);
    let hdr_len = u16::try_from(header.len()).map_err(|_| CodecError::HeaderTooLarge)?;
    let len_u = 2usize
        .checked_add(header.len())
        .and_then(|n| n.checked_add(body.len()))
        .ok_or(CodecError::EncodeTooLarge)?;
    if len_u > MAX_FRAME as usize {
        return Err(CodecError::EncodeTooLarge);
    }
    let len = u32::try_from(len_u).map_err(|_| CodecError::EncodeTooLarge)?;

    out.reserve(4 + len_u);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&hdr_len.to_be_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(body);
    Ok(())
}

/// Decode a full frame, copying bodies only when `auth` allows `Submit` (F4).
pub fn decode(buf: &[u8], auth: &impl SubmitAuthorizer) -> Result<Message, CodecError> {
    let (header_msg, body) = decode_parts(buf)?;
    finish_body(header_msg, body, auth)
}

/// Parse a frame into header + raw body slice without copying the body (F4).
///
/// Prefer this when authorization must run before materializing a `Submit` body.
pub fn split_frame(buf: &[u8]) -> Result<(Message, &[u8]), CodecError> {
    decode_parts(buf)
}

/// Parse length prefix and header without copying the body (F1 checked first).
fn decode_parts(buf: &[u8]) -> Result<(Message, &[u8]), CodecError> {
    if buf.len() < 4 {
        return Err(CodecError::Truncated);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    // F1: reject before any allocation sized by the peer.
    if len > MAX_FRAME {
        return Err(CodecError::FrameTooLarge);
    }
    let len_usize = len as usize;
    if buf.len() < 4 + len_usize {
        return Err(CodecError::Truncated);
    }
    let payload = &buf[4..4 + len_usize];
    if payload.len() < 2 {
        return Err(CodecError::BadLength);
    }
    let hdr_len = u16::from_be_bytes([payload[0], payload[1]]);
    if hdr_len > MAX_HDR_LEN {
        return Err(CodecError::FrameTooLarge);
    }
    let hdr_len_usize = usize::from(hdr_len);
    if payload.len() < 2 + hdr_len_usize {
        return Err(CodecError::BadLength);
    }
    let expected_len = 2 + hdr_len_usize;
    if len_usize < expected_len {
        return Err(CodecError::BadLength);
    }
    let header_bytes = &payload[2..2 + hdr_len_usize];
    let body = &payload[2 + hdr_len_usize..];
    if 2 + hdr_len_usize + body.len() != len_usize {
        return Err(CodecError::BadLength);
    }

    let header_msg: Message =
        serde_json::from_slice(header_bytes).map_err(|_| CodecError::MalformedHeader)?;
    Ok((header_msg, body))
}

fn finish_body(
    mut header_msg: Message,
    body: &[u8],
    auth: &impl SubmitAuthorizer,
) -> Result<Message, CodecError> {
    match &mut header_msg {
        Message::Submit { .. } => {
            if !auth.authorize_submit(&header_msg) {
                return Err(CodecError::SubmitDenied);
            }
            set_body(&mut header_msg, body.to_vec());
        }
        Message::Input { .. } | Message::Completed { .. } => {
            set_body(&mut header_msg, body.to_vec());
        }
        _ => {
            if !body.is_empty() {
                // Non-body messages must have empty body region.
                return Err(CodecError::BadLength);
            }
        }
    }
    Ok(header_msg)
}

fn message_body(message: &Message) -> &[u8] {
    match message {
        Message::Submit { body, .. }
        | Message::Input { body }
        | Message::Completed { body } => body.as_slice(),
        _ => &[],
    }
}

fn set_body(message: &mut Message, body: Vec<u8>) {
    match message {
        Message::Submit { body: b, .. }
        | Message::Input { body: b }
        | Message::Completed { body: b } => *b = body,
        _ => {}
    }
}

/// Header-only view used by tests to show F4 never materializes a denied body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectedSubmit {
    /// Parsed header message (`Submit` with empty body).
    pub header: Message,
    /// Raw body bytes still sitting in the frame buffer (not copied into `header`).
    pub body_len: usize,
}

/// Decode a `Submit` frame's header without copying the body.
pub fn inspect_submit(buf: &[u8]) -> Result<InspectedSubmit, CodecError> {
    let (header, body) = decode_parts(buf)?;
    if !matches!(header, Message::Submit { .. }) {
        return Err(CodecError::MalformedHeader);
    }
    Ok(InspectedSubmit {
        header,
        body_len: body.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentType, Deadline, TaskId};

    fn sample_submit(body: Vec<u8>) -> Message {
        Message::Submit {
            task: TaskId::from_u128(1),
            deadline: Deadline::new(1_000).unwrap(),
            content_type: ContentType::new("application/octet-stream").unwrap(),
            credential: None,
            body,
        }
    }

    #[test]
    fn oversized_len_is_frame_too_large_without_needing_rest_of_buffer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        // Deliberately truncated — F1 must fire on the length field alone.
        let err = decode(&buf, &AllowAll).unwrap_err();
        assert_eq!(err, CodecError::FrameTooLarge);
        assert_eq!(err.close_code(), Some(CloseCode::FrameTooLarge));
    }

    #[test]
    fn oversized_hdr_len_is_frame_too_large() {
        let mut buf = Vec::new();
        let hdr_len = MAX_HDR_LEN as u32 + 1;
        // len = 2 + hdr_len, within MAX_FRAME, but hdr_len itself is over max.
        let len = 2 + hdr_len;
        assert!(len <= MAX_FRAME);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&(hdr_len as u16).to_be_bytes());
        buf.resize(4 + len as usize, 0);
        let err = decode(&buf, &AllowAll).unwrap_err();
        assert_eq!(err, CodecError::FrameTooLarge);
    }

    #[test]
    fn f4_deny_all_does_not_materialize_submit_body() {
        let mut encoded = Vec::new();
        encode(&sample_submit(b"do-not-copy-me".to_vec()), &mut encoded).unwrap();

        let inspected = inspect_submit(&encoded).unwrap();
        match &inspected.header {
            Message::Submit { body, .. } => assert!(body.is_empty()),
            other => panic!("expected submit, got {other:?}"),
        }
        assert_eq!(inspected.body_len, b"do-not-copy-me".len());

        let err = decode(&encoded, &DenyAll).unwrap_err();
        assert_eq!(err, CodecError::SubmitDenied);
    }

    #[test]
    fn allow_all_copies_submit_body() {
        let mut encoded = Vec::new();
        encode(&sample_submit(b"payload".to_vec()), &mut encoded).unwrap();
        let msg = decode(&encoded, &AllowAll).unwrap();
        match msg {
            Message::Submit { body, .. } => assert_eq!(body, b"payload"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn accepted_roundtrips_header_only() {
        let mut encoded = Vec::new();
        encode(&Message::Accepted, &mut encoded).unwrap();
        let msg = decode(&encoded, &AllowAll).unwrap();
        assert_eq!(msg, Message::Accepted);
    }
}
