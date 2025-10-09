use crate::error::{EnclaveError, Result};
use crate::types::{EnclaveRequest, EnclaveResponse, WalletId};
use crate::wallet_manager::WalletManager;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Unix socket server for handling requests in local mode (non-Nitro)
pub struct UnixServer {
    wallet_manager: Arc<WalletManager>,
    socket_path: String,
}

impl UnixServer {
    pub fn new(wallet_manager: Arc<WalletManager>, socket_path: String) -> Self {
        Self {
            wallet_manager,
            socket_path,
        }
    }

    /// Start the Unix socket server
    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting Unix socket server at {}", self.socket_path);

        // Remove existing socket file if it exists
        if std::path::Path::new(&self.socket_path).exists() {
            std::fs::remove_file(&self.socket_path)
                .map_err(|e| EnclaveError::Network(format!("Failed to remove existing socket: {}", e)))?;
        }

        // Create Unix socket listener
        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| EnclaveError::Network(format!("Failed to bind Unix socket: {}", e)))?;

        tracing::info!("Unix socket server listening at {}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tracing::debug!("Accepted Unix socket connection");

                    let wallet_manager = self.wallet_manager.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, wallet_manager).await {
                            tracing::error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Handle a single connection
    async fn handle_connection(
        mut stream: UnixStream,
        wallet_manager: Arc<WalletManager>,
    ) -> Result<()> {
        // Read request length (4 bytes)
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| EnclaveError::Network(format!("Failed to read length: {}", e)))?;

        let request_len = u32::from_le_bytes(len_buf) as usize;

        if request_len > MAX_REQUEST_SIZE {
            return Err(EnclaveError::InvalidRequest(format!(
                "Request too large: {} bytes",
                request_len
            )));
        }

        // Read request data
        let mut request_buf = vec![0u8; request_len];
        stream
            .read_exact(&mut request_buf)
            .await
            .map_err(|e| EnclaveError::Network(format!("Failed to read request: {}", e)))?;

        // Parse request
        let request: EnclaveRequest = serde_json::from_slice(&request_buf)
            .map_err(|e| EnclaveError::InvalidRequest(format!("Invalid JSON: {}", e)))?;

        tracing::debug!("Received request: {:?}", request);

        // Handle request
        let response = Self::handle_request(request, wallet_manager).await;

        // Send response
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| EnclaveError::Serialization(e))?;

        let response_len = (response_json.len() as u32).to_le_bytes();
        stream
            .write_all(&response_len)
            .await
            .map_err(|e| EnclaveError::Network(format!("Failed to write response length: {}", e)))?;

        stream
            .write_all(&response_json)
            .await
            .map_err(|e| EnclaveError::Network(format!("Failed to write response: {}", e)))?;

        stream
            .flush()
            .await
            .map_err(|e| EnclaveError::Network(format!("Failed to flush stream: {}", e)))?;

        tracing::debug!("Sent response");

        Ok(())
    }

    /// Handle a request and return a response
    async fn handle_request(
        request: EnclaveRequest,
        wallet_manager: Arc<WalletManager>,
    ) -> EnclaveResponse {
        use EnclaveRequest::*;

        match request {
            GetAttestation { nonce } => match wallet_manager.get_attestation(nonce) {
                Ok(doc) => EnclaveResponse::Success {
                    data: serde_json::json!({
                        "attestation_document": BASE64.encode(&doc)
                    }),
                },
                Err(e) => EnclaveResponse::Error {
                    message: format!("Failed to get attestation: {}", e),
                },
            },

            InitWallet { encrypted_session_key, encrypted_jwt } => {
                match wallet_manager.init_wallet(&encrypted_session_key, &encrypted_jwt).await {
                    Ok((wallet_id, encrypted_seed, session_id)) => EnclaveResponse::Success {
                        data: serde_json::json!({
                            "wallet_id": wallet_id.to_hex(),
                            "encrypted_seed": encrypted_seed,
                            "session_id": hex::encode(session_id)
                        }),
                    },
                    Err(e) => EnclaveResponse::Error {
                        message: format!("Failed to initialize wallet: {}", e),
                    },
                }
            }

            WalletOperation {
                wallet_id,
                session_id,
                encrypted_jwt,
                encrypted_request,
            } => {
                // Parse wallet ID
                let wallet_id = match WalletId::from_hex(&wallet_id) {
                    Ok(id) => id,
                    Err(e) => {
                        return EnclaveResponse::Error {
                            message: format!("Invalid wallet ID: {}", e),
                        }
                    }
                };

                // Execute operation with session-based encryption
                match wallet_manager
                    .execute_operation(wallet_id, &session_id, &encrypted_jwt, &encrypted_request)
                    .await
                {
                    Ok(encrypted_response) => EnclaveResponse::Success {
                        data: serde_json::json!({
                            "encrypted_data": encrypted_response
                        })
                    },
                    Err(e) => EnclaveResponse::Error {
                        message: format!("Operation failed: {}", e),
                    },
                }
            }
        }
    }
}
