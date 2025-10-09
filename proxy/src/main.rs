mod client;
mod grpc;
mod unix;
mod vsock;

use client::EnclaveClient;
use proto::enclave_service_server::EnclaveServiceServer;
use grpc::EnclaveServiceImpl;
use std::sync::Arc;
use tonic::transport::Server;
use unix::UnixClient;
use vsock::VsockClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    tracing::info!("Starting Cashu Parent Proxy (gRPC)");

    // Get mode from environment (nitro or local)
    let mode = std::env::var("MODE").unwrap_or_else(|_| "nitro".to_string());
    tracing::info!("Running in {} mode", mode);

    // Get configuration from environment
    let listen_addr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()?;

    tracing::info!("Listening on {}", listen_addr);

    // Create client based on mode
    let enclave_client = match mode.as_str() {
        "local" => {
            let socket_path = std::env::var("SOCKET_PATH")
                .unwrap_or_else(|_| "/tmp/enclave.sock".to_string());
            tracing::info!("Using Unix socket at {}", socket_path);
            Arc::new(EnclaveClient::Unix(UnixClient::new(socket_path)))
        }
        "nitro" | _ => {
            let enclave_cid: u32 = std::env::var("ENCLAVE_CID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(16); // Default CID
            tracing::info!("Using vsock with CID: {}", enclave_cid);
            Arc::new(EnclaveClient::Vsock(VsockClient::with_cid(enclave_cid)))
        }
    };

    // Create gRPC service
    let enclave_service = EnclaveServiceImpl::new(enclave_client);

    // Build reflection service
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    // Build health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<EnclaveServiceServer<EnclaveServiceImpl>>()
        .await;

    // Start gRPC server
    Server::builder()
        .add_service(reflection_service)
        .add_service(health_service)
        .add_service(EnclaveServiceServer::new(enclave_service))
        .serve(listen_addr)
        .await?;

    Ok(())
}
