use crate::client::EnclaveClient;
use proto::enclave_service_server::EnclaveService;
use proto::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// gRPC service implementation
pub struct EnclaveServiceImpl {
    client: Arc<EnclaveClient>,
}

impl EnclaveServiceImpl {
    pub fn new(client: Arc<EnclaveClient>) -> Self {
        Self { client }
    }
}

/// Request/Response types matching enclave vsock protocol
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
enum VsockEnclaveRequest {
    GetAttestation { nonce: Option<Vec<u8>> },
    InitWallet {
        encrypted_session_key: String,
        encrypted_jwt: String,
    },
    WalletOperation {
        wallet_id: String,
        session_id: String,
        encrypted_jwt: String,
        encrypted_request: String,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status")]
enum VsockEnclaveResponse {
    Success { data: serde_json::Value },
    Error { message: String },
}

#[tonic::async_trait]
impl EnclaveService for EnclaveServiceImpl {
    async fn get_attestation(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let req = request.into_inner();
        tracing::info!("gRPC: GetAttestation request");

        let vsock_request = VsockEnclaveRequest::GetAttestation { nonce: req.nonce };

        let vsock_response: VsockEnclaveResponse = self
            .client
            .send_request(&vsock_request)
            .await
            .map_err(|e| {
                tracing::error!("Client error: {}", e);
                Status::internal(format!("Failed to communicate with enclave: {}", e))
            })?;

        match vsock_response {
            VsockEnclaveResponse::Success { data } => {
                let attestation_document = data
                    .get("attestation_document")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        Status::internal("Invalid attestation response format")
                    })?
                    .to_string();

                // Extract user_data from attestation document (decode and parse)
                let user_data = Self::extract_user_data(&attestation_document)
                    .unwrap_or_default();

                Ok(Response::new(AttestationResponse {
                    attestation_document,
                    user_data,
                }))
            }
            VsockEnclaveResponse::Error { message } => {
                Err(Status::internal(format!("Enclave error: {}", message)))
            }
        }
    }

    async fn init_wallet(
        &self,
        request: Request<InitWalletRequest>,
    ) -> Result<Response<InitWalletResponse>, Status> {
        // Extract encrypted JWT from metadata before moving request
        let encrypted_jwt = request
            .metadata()
            .get("x-encrypted-jwt")
            .ok_or_else(|| Status::unauthenticated("Missing x-encrypted-jwt metadata"))?
            .to_str()
            .map_err(|_| Status::invalid_argument("Invalid x-encrypted-jwt metadata"))?
            .to_string();

        let req = request.into_inner();

        tracing::info!("gRPC: InitWallet request");

        let vsock_request = VsockEnclaveRequest::InitWallet {
            encrypted_session_key: req.encrypted_session_key,
            encrypted_jwt,
        };

        let vsock_response: VsockEnclaveResponse = self
            .client
            .send_request(&vsock_request)
            .await
            .map_err(|e| {
                tracing::error!("Client error: {}", e);
                Status::internal(format!("Failed to communicate with enclave: {}", e))
            })?;

        match vsock_response {
            VsockEnclaveResponse::Success { data } => {
                let wallet_id = data
                    .get("wallet_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Status::internal("Invalid init wallet response format"))?
                    .to_string();

                let encrypted_seed = data
                    .get("encrypted_seed")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Status::internal("Invalid init wallet response format"))?
                    .to_string();

                let session_id = data
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Status::internal("Invalid init wallet response format"))?
                    .to_string();

                Ok(Response::new(InitWalletResponse {
                    wallet_id,
                    encrypted_seed,
                    session_id,
                }))
            }
            VsockEnclaveResponse::Error { message } => {
                Err(Status::invalid_argument(format!("Enclave error: {}", message)))
            }
        }
    }

    async fn wallet_operation(
        &self,
        request: Request<WalletOperationRequest>,
    ) -> Result<Response<WalletOperationResponse>, Status> {
        // Extract session ID and encrypted JWT from metadata before moving request
        let session_id = request
            .metadata()
            .get("x-session-id")
            .ok_or_else(|| Status::unauthenticated("Missing x-session-id metadata"))?
            .to_str()
            .map_err(|_| Status::invalid_argument("Invalid x-session-id metadata"))?
            .to_string();

        let encrypted_jwt = request
            .metadata()
            .get("x-encrypted-jwt")
            .ok_or_else(|| Status::unauthenticated("Missing x-encrypted-jwt metadata"))?
            .to_str()
            .map_err(|_| Status::invalid_argument("Invalid x-encrypted-jwt metadata"))?
            .to_string();

        let req = request.into_inner();

        tracing::info!("gRPC: WalletOperation request for wallet_id: {}", req.wallet_id);

        let vsock_request = VsockEnclaveRequest::WalletOperation {
            wallet_id: req.wallet_id,
            session_id,
            encrypted_jwt,
            encrypted_request: req.encrypted_request,
        };

        let vsock_response: VsockEnclaveResponse = self
            .client
            .send_request(&vsock_request)
            .await
            .map_err(|e| {
                tracing::error!("Client error: {}", e);
                Status::internal(format!("Failed to communicate with enclave: {}", e))
            })?;

        match vsock_response {
            VsockEnclaveResponse::Success { data } => {
                // Extract encrypted response data
                let encrypted_data = data
                    .get("encrypted_data")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Status::internal("Invalid wallet operation response format"))?
                    .to_string();

                Ok(Response::new(WalletOperationResponse {
                    result: Some(wallet_operation_response::Result::Success(
                        OperationSuccess { data: encrypted_data },
                    )),
                }))
            }
            VsockEnclaveResponse::Error { message } => {
                Ok(Response::new(WalletOperationResponse {
                    result: Some(wallet_operation_response::Result::Error(
                        OperationError {
                            message: message.clone(),
                            code: "ENCLAVE_ERROR".to_string(),
                        },
                    )),
                }))
            }
        }
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: health_check_response::Status::Serving as i32,
        }))
    }
}

impl EnclaveServiceImpl {
    /// Extract user_data from base64-encoded attestation document
    fn extract_user_data(attestation_base64: &str) -> Option<String> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        // Decode attestation document
        let doc_bytes = BASE64.decode(attestation_base64).ok()?;

        // Parse as JSON (local-dev mode format)
        if let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&doc_bytes) {
            if let Some(user_data) = doc.get("user_data").and_then(|v| v.as_str()) {
                return Some(user_data.to_string());
            }
        }

        // For NSM mode, the attestation document is CBOR-encoded
        // We would need to parse it properly, but for now return empty
        // The actual implementation would decode CBOR and extract user_data field
        None
    }
}
