use super::client::connect_to_parent;
use super::http_connect::{parse_connect_request, send_connect_response};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

/// Network proxy client that runs inside the enclave
///
/// Provides local TCP listeners on 127.0.0.1 that applications can connect to.
/// Forwards all traffic to parent via vsock/unix-socket for actual TCP connections.
///
/// Services:
/// - Port 5432: PostgreSQL proxy → forwards to "wallet-postgres:5432"
/// - Port 8888: HTTP CONNECT proxy → parses destination and forwards
pub struct NetworkProxyClient {
    #[cfg(feature = "nsm")]
    parent_cid: u32,
    #[cfg(feature = "nsm")]
    parent_port: u32,

    #[cfg(feature = "local-dev")]
    parent_socket: String,
}

impl NetworkProxyClient {
    #[cfg(feature = "nsm")]
    pub fn new(parent_cid: u32, parent_port: u32) -> Self {
        Self {
            parent_cid,
            parent_port,
        }
    }

    #[cfg(feature = "local-dev")]
    pub fn new(parent_socket: String) -> Self {
        Self { parent_socket }
    }

    /// Start all local TCP listeners
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        // Start PostgreSQL proxy on port 5432
        let postgres_client = self.clone_config();
        tokio::spawn(async move {
            if let Err(e) = postgres_client.run_postgres_proxy().await {
                tracing::error!("PostgreSQL proxy error: {}", e);
            }
        });

        // Start HTTP CONNECT proxy on port 8888
        let http_client = self.clone_config();
        tokio::spawn(async move {
            if let Err(e) = http_client.run_http_connect_proxy().await {
                tracing::error!("HTTP CONNECT proxy error: {}", e);
            }
        });

        // Keep running indefinitely
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }

    /// Clone configuration for spawning tasks
    fn clone_config(&self) -> Self {
        #[cfg(feature = "nsm")]
        {
            Self {
                parent_cid: self.parent_cid,
                parent_port: self.parent_port,
            }
        }

        #[cfg(feature = "local-dev")]
        {
            Self {
                parent_socket: self.parent_socket.clone(),
            }
        }
    }

    /// Run PostgreSQL proxy on port 5432
    async fn run_postgres_proxy(self) -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:5432").await?;
        tracing::info!("PostgreSQL proxy listening on 127.0.0.1:5432");

        loop {
            let (stream, addr) = listener.accept().await?;
            tracing::debug!("PostgreSQL connection from {}", addr);

            let config = self.clone_config();
            tokio::spawn(async move {
                if let Err(e) = config
                    .forward_to_parent(stream, "wallet-postgres:5432")
                    .await
                {
                    tracing::debug!("PostgreSQL proxy error: {}", e);
                }
            });
        }
    }

    /// Run HTTP CONNECT proxy on port 8888
    async fn run_http_connect_proxy(self) -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:8888").await?;
        tracing::info!("HTTP CONNECT proxy listening on 127.0.0.1:8888");

        loop {
            let (stream, addr) = listener.accept().await?;
            tracing::debug!("HTTP CONNECT connection from {}", addr);

            let config = self.clone_config();
            tokio::spawn(async move {
                if let Err(e) = config.handle_http_connect(stream).await {
                    tracing::debug!("HTTP CONNECT proxy error: {}", e);
                }
            });
        }
    }

    /// Handle HTTP CONNECT request
    async fn handle_http_connect(self, mut client_stream: TcpStream) -> io::Result<()> {
        // Parse CONNECT request to get destination
        let destination = parse_connect_request(&mut client_stream).await?;
        tracing::info!("HTTP CONNECT to: {}", destination);

        // Send 200 Connection Established response
        send_connect_response(&mut client_stream).await?;

        // Forward to parent
        self.forward_to_parent(client_stream, &destination).await
    }

    /// Forward connection to parent network proxy
    async fn forward_to_parent(
        self,
        mut client_stream: TcpStream,
        destination: &str,
    ) -> io::Result<()> {
        // Connect to parent and send destination
        #[cfg(feature = "nsm")]
        let mut parent_stream =
            connect_to_parent(self.parent_cid, self.parent_port, destination).await?;

        #[cfg(feature = "local-dev")]
        let mut parent_stream = connect_to_parent(&self.parent_socket, destination).await?;

        tracing::debug!("Forwarding to parent: {}", destination);

        // Bidirectional forwarding
        let (bytes_to_parent, bytes_from_parent) =
            tokio::io::copy_bidirectional(&mut client_stream, &mut parent_stream).await?;

        tracing::debug!(
            "Connection closed for {}: {} bytes →, {} bytes ←",
            destination,
            bytes_to_parent,
            bytes_from_parent
        );

        Ok(())
    }
}
