#![cfg(feature = "vsock")]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockStream};

const ENCLAVE_CID: u32 = 16; // Default enclave CID
const ENCLAVE_PORT: u32 = 5000;
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB

#[derive(Error, Debug)]
pub enum VsockError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

pub type Result<T> = std::result::Result<T, VsockError>;

/// Client for communicating with the enclave via vsock
pub struct VsockClient {
    pub(crate) cid: u32,
    pub(crate) port: u32,
}

impl VsockClient {
    pub fn new() -> Self {
        Self {
            cid: ENCLAVE_CID,
            port: ENCLAVE_PORT,
        }
    }

    pub fn with_cid(cid: u32) -> Self {
        Self {
            cid,
            port: ENCLAVE_PORT,
        }
    }

    /// Send a request to the enclave and get the response
    pub async fn send_request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        request: &T,
    ) -> Result<R> {
        // Connect to enclave
        let addr = VsockAddr::new(self.cid, self.port);
        let mut stream = VsockStream::connect(addr)
            .await
            .map_err(|e| VsockError::Connection(format!("Failed to connect: {}", e)))?;

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
            return Err(VsockError::InvalidResponse(format!(
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

impl Default for VsockClient {
    fn default() -> Self {
        Self::new()
    }
}
