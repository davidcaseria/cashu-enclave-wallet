mod client;
mod grpc;
mod network_proxy;
mod tcp_proxy;
mod unix;

#[cfg(feature = "vsock")]
mod vsock;

use client::EnclaveClient;
use proto::enclave_service_server::EnclaveServiceServer;
use grpc::EnclaveServiceImpl;
use network_proxy::NetworkProxyServer;
use tcp_proxy::DatabaseProxy;
use std::sync::Arc;
use tonic::transport::Server;
use unix::UnixClient;

#[cfg(feature = "vsock")]
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
    let grpc_listen_addr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()?;

    tracing::info!("gRPC listening on {}", grpc_listen_addr);

    // Get network proxy configuration
    #[cfg(feature = "vsock")]
    let network_proxy_port: u32 = std::env::var("NETWORK_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000);

    #[cfg(not(feature = "vsock"))]
    let network_proxy_socket = std::env::var("NETWORK_PROXY_SOCKET")
        .unwrap_or_else(|_| "/tmp/network-proxy.sock".to_string());

    // Create client based on mode
    #[cfg(feature = "vsock")]
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

    #[cfg(not(feature = "vsock"))]
    let enclave_client = {
        let socket_path = std::env::var("SOCKET_PATH")
            .unwrap_or_else(|_| "/tmp/enclave.sock".to_string());
        tracing::info!("Using Unix socket at {} (vsock feature disabled)", socket_path);
        Arc::new(EnclaveClient::Unix(UnixClient::new(socket_path)))
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

    // Create network proxy server
    #[cfg(feature = "vsock")]
    let network_proxy = NetworkProxyServer::new(network_proxy_port);

    #[cfg(not(feature = "vsock"))]
    let network_proxy = NetworkProxyServer::new(network_proxy_socket.clone());

    #[cfg(feature = "vsock")]
    tracing::info!("Network proxy listening on vsock port {}", network_proxy_port);

    #[cfg(not(feature = "vsock"))]
    tracing::info!("Network proxy listening on unix socket {}", network_proxy_socket);

    // Create database proxy for PostgreSQL connections
    // Listens on Unix socket to simulate network isolation (no TCP access in enclave)
    // In production Nitro Enclaves, this would be vsock; in local-dev it's Unix socket
    let postgres_proxy_socket = std::env::var("POSTGRES_PROXY_SOCKET")
        .unwrap_or_else(|_| "/tmp/postgres-proxy.sock".to_string());
    let postgres_backend = std::env::var("POSTGRES_BACKEND_ADDR")
        .unwrap_or_else(|_| "wallet-postgres:5432".to_string());

    let db_proxy = DatabaseProxy::new(postgres_proxy_socket.clone(), postgres_backend.clone());
    tracing::info!("Database proxy: unix:{} → {}", postgres_proxy_socket, postgres_backend);

    // Run all servers concurrently
    let grpc_server = async {
        Server::builder()
            .add_service(reflection_service)
            .add_service(health_service)
            .add_service(EnclaveServiceServer::new(enclave_service))
            .serve(grpc_listen_addr)
            .await
    };

    let network_proxy_server = async { network_proxy.start().await };
    let db_proxy_server = async { db_proxy.start().await };

    // Run all servers, exit if any fails
    tokio::select! {
        result = grpc_server => {
            tracing::error!("gRPC server exited: {:?}", result);
            result?;
        }
        result = network_proxy_server => {
            tracing::error!("Network proxy server exited: {:?}", result);
            result?;
        }
        result = db_proxy_server => {
            tracing::error!("Database proxy server exited: {:?}", result);
            result?;
        }
    }

    Ok(())
}
