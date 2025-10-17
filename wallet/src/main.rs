mod attestation;
mod crypto;
mod database;
mod error;
mod network;
mod network_proxy;
mod types;
mod vsock_http;
mod wallet_manager;

use attestation::AttestationService;
use error::Result;
use network::UnixServer;
#[cfg(feature = "nsm")]
use network::VsockServer;
use wallet_manager::WalletManager;
use std::sync::Arc;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS operations
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    tracing::info!("Starting Cashu Enclave Wallet");

    // Log build mode
    #[cfg(feature = "local-dev")]
    tracing::info!("Running in local development mode");
    #[cfg(feature = "nsm")]
    tracing::info!("Running in Nitro Enclave mode");

    // Get JWKS URL from environment (required)
    let jwks_url = std::env::var("JWKS_URL")
        .map_err(|_| error::EnclaveError::Config("JWKS_URL environment variable is required".to_string()))?;
    tracing::info!("JWKS URL: {}", jwks_url);

    // Get database URL from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://cashu:cashu@localhost:5432/cashu_enclave".to_string());

    tracing::info!("Connecting to database");

    // Create database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .map_err(|e| error::EnclaveError::Database(format!("Failed to connect to database: {}", e)))?;

    tracing::info!("Database connected successfully");

    // Create attestation service
    tracing::info!("Initializing attestation service");
    let attestation = Arc::new(AttestationService::new()?);

    // Create wallet manager
    tracing::info!("Initializing wallet manager");
    let wallet_manager = Arc::new(WalletManager::new(attestation.clone(), pool, jwks_url).await?);

    // Start session cleanup task
    let cleanup_manager = wallet_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            cleanup_manager.cleanup_expired_sessions().await;
        }
    });

    // Start server based on compile-time feature
    #[cfg(feature = "local-dev")]
    {
        // Start Unix socket server for local testing
        let socket_path = std::env::var("SOCKET_PATH")
            .unwrap_or_else(|_| "/tmp/enclave.sock".to_string());
        tracing::info!("Starting Unix socket server at {}", socket_path);
        let server = UnixServer::new(wallet_manager, socket_path);
        server.start().await?;
    }

    #[cfg(feature = "nsm")]
    {
        // Start vsock server for Nitro Enclave
        tracing::info!("Starting vsock server");
        let server = VsockServer::new(wallet_manager);
        server.start().await?;
    }

    Ok(())
}
