use super::handlers::*;
use axum::{
    routing::{get, post},
    Router,
};

pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Health check
        .route("/health", get(health_check))
        // Attestation
        .route("/attestation", post(get_attestation))
        // Wallet operations
        .route("/wallet/init", post(init_wallet))
        .route("/wallet/:wallet_id/operation", post(wallet_operation))
        .with_state(state)
}
