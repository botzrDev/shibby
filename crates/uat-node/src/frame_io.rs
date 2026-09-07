//! Async length-prefixed frame read/write over iroh streams.

use iroh::endpoint::{ReadExactError, RecvStream, SendStream, WriteError};
use thiserror::Error;
use uat_core::{decode, encode, CodecError, CloseCode, Message, SubmitAuthorizer, MAX_FRAME};

/// Errors reading or writing UAT frames on a stream.
#[derive(Debug, Error)]
pub enum FrameIoError {
    /// Codec rejected the frame.
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// Underlying stream read failed.
    #[error("stream read failed")]
    Read(#[source] ReadExactError),

    /// Underlying stream write failed.
    #[error("stream write failed")]
    Write(#[source] WriteError),

    /// Peer closed the stream before a full frame arrived.
    #[error("stream ended before frame complete")]
    UnexpectedEnd,
}

impl FrameIoError {
    /// Suggested connection close code, when this error should close the connection.
    #[must_use]
    pub fn close_code(&self) -> Option<CloseCode> {
        match self {
            Self::Codec(err) => err.clone().close_code(),
            Self::Read(ReadExactError::FinishedEarly(_)) | Self::UnexpectedEnd => {
                Some(CloseCode::MalformedFrame)
            }
            Self::Read(_) | Self::Write(_) => None,
        }
    }
}

/// Read one full UAT frame and decode it with `auth`.
pub async fn read_message(
    recv: &mut RecvStream,
    auth: &impl SubmitAuthorizer,
) -> Result<Message, FrameIoError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(map_read_exact)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(FrameIoError::Codec(CodecError::FrameTooLarge));
    }
    let mut payload = vec![0u8; len as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(map_read_exact)?;

    let mut frame = Vec::with_capacity(4 + len as usize);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&payload);
    decode(&frame, auth).map_err(FrameIoError::from)
}

/// Encode and write one UAT frame.
pub async fn write_message(send: &mut SendStream, message: &Message) -> Result<(), FrameIoError> {
    let mut buf = Vec::new();
    encode(message, &mut buf)?;
    send.write_all(&buf).await.map_err(FrameIoError::Write)?;
    Ok(())
}

fn map_read_exact(err: ReadExactError) -> FrameIoError {
    match err {
        ReadExactError::FinishedEarly(_) => FrameIoError::UnexpectedEnd,
        other => FrameIoError::Read(other),
    }
}
