use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Errors for the length-prefixed relay framing.
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    TooLarge { length: usize, maximum: usize },
    Truncated,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "frame I/O error: {error}"),
            Self::TooLarge { length, maximum } => {
                write!(formatter, "frame length {length} exceeds maximum {maximum}")
            }
            Self::Truncated => formatter.write_str("truncated frame"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Read one big-endian u32 length-prefixed frame.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0_u8; 4];
    let first = reader.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut header[1..])
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => FrameError::Truncated,
            _ => FrameError::Io(error),
        })?;
    let length = u32::from_be_bytes(header) as usize;
    if length > maximum {
        return Err(FrameError::TooLarge { length, maximum });
    }
    let mut frame = vec![0_u8; length];
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => FrameError::Truncated,
            _ => FrameError::Io(error),
        })?;
    Ok(Some(frame))
}

/// Write one length-prefixed frame, rejecting lengths that do not fit the wire format.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
    maximum: usize,
) -> Result<(), FrameError> {
    if frame.len() > maximum || frame.len() > u32::MAX as usize {
        return Err(FrameError::TooLarge {
            length: frame.len(),
            maximum: maximum.min(u32::MAX as usize),
        });
    }
    writer
        .write_all(&(frame.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(frame).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
#[path = "tests/framing.rs"]
mod tests;
