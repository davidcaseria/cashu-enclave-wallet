use crate::unix::UnixClient;
use crate::vsock::VsockClient;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Vsock error: {0}")]
    Vsock(#[from] crate::vsock::VsockError),

    #[error("Unix error: {0}")]
    Unix(#[from] crate::unix::UnixError),
}

/// Enum wrapper for different enclave client types
pub enum EnclaveClient {
    Vsock(VsockClient),
    Unix(UnixClient),
}

impl EnclaveClient {
    /// Send a request to the enclave and get the response
    pub async fn send_request<T, R>(
        &self,
        request: &T,
    ) -> Result<R, ClientError>
    where
        T: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static,
        R: for<'de> Deserialize<'de> + Send + 'static,
    {
        match self {
            EnclaveClient::Vsock(client) => {
                // Vsock client is now async with tokio-vsock
                client.send_request(request).await.map_err(ClientError::Vsock)
            }
            EnclaveClient::Unix(client) => {
                client.send_request(request).await.map_err(ClientError::Unix)
            }
        }
    }
}
