use crate::vsock::VsockClient;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub vsock_client: Arc<VsockClient>,
}

/// Request/Response types matching enclave types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EnclaveRequest {
    GetAttestation,
    InitWallet { encrypted_seed: String },
    WalletOperation {
        wallet_id: String,
        encrypted_jwt: String,
        encrypted_request: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum EnclaveResponse {
    Success { data: serde_json::Value },
    Error { message: String },
}

/// Get attestation document from enclave
pub async fn get_attestation(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Forwarding attestation request to enclave");

    let request = EnclaveRequest::GetAttestation;

    let response: EnclaveResponse = state
        .vsock_client
        .send_request(&request)
        .map_err(|e| {
            tracing::error!("Failed to get attestation: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to communicate with enclave: {}", e),
            )
        })?;

    match response {
        EnclaveResponse::Success { data } => Ok(Json(data)),
        EnclaveResponse::Error { message } => {
            tracing::error!("Enclave returned error: {}", message);
            Err((StatusCode::INTERNAL_SERVER_ERROR, message))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InitWalletRequest {
    pub encrypted_seed: String,
}

/// Initialize wallet with encrypted seed
pub async fn init_wallet(
    State(state): State<AppState>,
    Json(payload): Json<InitWalletRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Forwarding wallet initialization to enclave");

    let request = EnclaveRequest::InitWallet {
        encrypted_seed: payload.encrypted_seed,
    };

    let response: EnclaveResponse = state
        .vsock_client
        .send_request(&request)
        .map_err(|e| {
            tracing::error!("Failed to initialize wallet: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to communicate with enclave: {}", e),
            )
        })?;

    match response {
        EnclaveResponse::Success { data } => Ok(Json(data)),
        EnclaveResponse::Error { message } => {
            tracing::error!("Enclave returned error: {}", message);
            Err((StatusCode::BAD_REQUEST, message))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WalletOperationRequest {
    pub encrypted_jwt: String,
    pub encrypted_request: String,
}

/// Execute wallet operation
pub async fn wallet_operation(
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Json(payload): Json<WalletOperationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Forwarding wallet operation for wallet_id: {}", wallet_id);

    let request = EnclaveRequest::WalletOperation {
        wallet_id,
        encrypted_jwt: payload.encrypted_jwt,
        encrypted_request: payload.encrypted_request,
    };

    let response: EnclaveResponse = state
        .vsock_client
        .send_request(&request)
        .map_err(|e| {
            tracing::error!("Failed to execute wallet operation: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to communicate with enclave: {}", e),
            )
        })?;

    match response {
        EnclaveResponse::Success { data } => Ok(Json(data)),
        EnclaveResponse::Error { message } => {
            tracing::error!("Enclave returned error: {}", message);
            Err((StatusCode::BAD_REQUEST, message))
        }
    }
}

/// Health check endpoint
pub async fn health_check() -> &'static str {
    "OK"
}
