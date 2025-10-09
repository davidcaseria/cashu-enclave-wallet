use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB

#[derive(Error, Debug)]
pub enum UnixError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

pub type Result<T> = std::result::Result<T, UnixError>;

/// Client for communicating with the enclave via Unix socket
pub struct UnixClient {
    socket_path: String,
}

impl UnixClient {
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    /// Send a request to the enclave and get the response
    pub async fn send_request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        request: &T,
    ) -> Result<R> {
        // Connect to Unix socket
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| UnixError::Connection(format!("Failed to connect to {}: {}", self.socket_path, e)))?;

        // Serialize request
        let request_json = serde_json::to_vec(request)?;
        let request_len = (request_json.len() as u32).to_le_bytes();

        // Send request length
        stream.write_all(&request_len).await?;

        // Send request data
        stream.write_all(&request_json).await?;
        stream.flush().await?;

        // Read response length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_le_bytes(len_buf) as usize;

        if response_len > MAX_RESPONSE_SIZE {
            return Err(UnixError::InvalidResponse(format!(
                "Response too large: {} bytes",
                response_len
            )));
        }

        // Read response data
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await?;

        // Deserialize response
        let response = serde_json::from_slice(&response_buf)?;
        Ok(response)
    }
}
