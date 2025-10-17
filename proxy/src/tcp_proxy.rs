//! Database proxy for PostgreSQL
//!
//! Listens on a Unix socket and forwards PostgreSQL protocol traffic to a backend server.
//! Used in local-dev mode to simulate Nitro Enclave network isolation where the wallet
//! has no direct network access.

use tokio::io;
use tokio::net::{TcpStream, UnixListener, UnixStream};

pub struct DatabaseProxy {
    listen_socket: String,
    backend_addr: String,
}

impl DatabaseProxy {
    pub fn new(listen_socket: String, backend_addr: String) -> Self {
        Self {
            listen_socket,
            backend_addr,
        }
    }

    /// Start the database proxy server
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        // Remove existing socket file if it exists
        let _ = std::fs::remove_file(&self.listen_socket);

        let listener = UnixListener::bind(&self.listen_socket)?;
        tracing::info!(
            "Database proxy listening on unix:{} → {}",
            self.listen_socket,
            self.backend_addr
        );

        loop {
            let (inbound, _addr) = listener.accept().await?;
            let backend_addr = self.backend_addr.clone();

            tracing::debug!("Accepted database connection via Unix socket");

            tokio::spawn(async move {
                if let Err(e) = handle_connection(inbound, backend_addr).await {
                    tracing::debug!("Database proxy connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    mut inbound: UnixStream,
    backend_addr: String,
) -> io::Result<()> {
    // Connect to backend database via TCP
    let mut outbound = TcpStream::connect(&backend_addr).await.map_err(|e| {
        tracing::error!("Failed to connect to backend database {}: {}", backend_addr, e);
        e
    })?;

    tracing::debug!("Connected to backend database: {}", backend_addr);

    // Bidirectional forwarding of PostgreSQL protocol
    let (bytes_to_backend, bytes_from_backend) =
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;

    tracing::debug!(
        "Database proxy connection closed for {}: {} bytes →, {} bytes ←",
        backend_addr,
        bytes_to_backend,
        bytes_from_backend
    );

    Ok(())
}
