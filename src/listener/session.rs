use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::core::Session;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> Result<bool, ()> {
        Ok(false)
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), ()> {
        match self.stream.write_all(bytes).await {
            Ok(_) => {
                tracing::trace!(parent: &self.span,
                                event = "write",
                                data = std::str::from_utf8(bytes).unwrap_or_default(),
                                size = bytes.len());
                Ok(())
            }
            Err(err) => {
                tracing::debug!(parent: &self.span,
                                event = "error",
                                class = "io",
                                "Failed to write to stream: {:?}", err);
                Err(())
            }
        }
    }

    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        match self.stream.read(bytes).await {
            Ok(len) => {
                tracing::trace!(parent: &self.span,
                                event = "read",
                                data =  bytes
                                        .get(0..len)
                                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                                        .unwrap_or_default(),
                                size = len);
                Ok(len)
            }
            Err(err) => {
                tracing::debug!(
                    parent: &self.span,
                    event = "error",
                    class = "io",
                    "Failed to read from stream: {:?}", err
                );
                Err(())
            }
        }
    }
}
