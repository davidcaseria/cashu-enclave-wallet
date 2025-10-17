use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::io;

#[cfg(feature = "vsock")]
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

#[cfg(not(feature = "vsock"))]
use tokio::net::{UnixListener, UnixStream};

/// Network proxy server that forwards vsock/unix-socket connections to TCP
///
/// This proxy enables AWS Nitro Enclaves (which have no network access) to make
/// TCP connections by tunneling through the parent EC2 instance via vsock.
///
/// Protocol:
/// 1. Client connects via vsock/unix-socket
/// 2. Client sends: [2 bytes: destination length (u16 big-endian)][N bytes: "host:port"]
/// 3. Server connects to destination via TCP
/// 4. Bidirectional forwarding begins
///
/// Security:
/// - NO allowlist: Enclave (trusted component) decides what to connect to
/// - Server just forwards bytes - cannot decrypt HTTPS or encrypted database traffic
/// - Zero-knowledge properties maintained
pub struct NetworkProxyServer {
    #[cfg(feature = "vsock")]
    port: u32,
    #[cfg(not(feature = "vsock"))]
    socket_path: String,
}

impl NetworkProxyServer {
    #[cfg(feature = "vsock")]
    pub fn new(port: u32) -> Self {
        Self { port }
    }

    #[cfg(not(feature = "vsock"))]
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    /// Start the network proxy server
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(feature = "vsock")]
        {
            let addr = VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, self.port);
            let listener = VsockListener::bind(addr)?;
            tracing::info!("Network proxy listening on vsock port {}", self.port);

            loop {
                let (stream, peer_addr) = listener.accept().await?;
                tracing::debug!("Accepted vsock connection from {:?}", peer_addr);
                tokio::spawn(handle_vsock_connection(stream));
            }
        }

        #[cfg(not(feature = "vsock"))]
        {
            // Remove existing socket file if it exists
            let _ = std::fs::remove_file(&self.socket_path);

            let listener = UnixListener::bind(&self.socket_path)?;
            tracing::info!("Network proxy listening on unix socket {}", self.socket_path);

            loop {
                let (stream, _addr) = listener.accept().await?;
                tracing::debug!("Accepted unix socket connection");
                tokio::spawn(handle_unix_connection(stream));
            }
        }
    }
}

#[cfg(feature = "vsock")]
async fn handle_vsock_connection(mut stream: VsockStream) {
    if let Err(e) = handle_connection(&mut stream).await {
        tracing::debug!("Vsock connection error: {}", e);
    }
}

#[cfg(not(feature = "vsock"))]
async fn handle_unix_connection(mut stream: UnixStream) {
    if let Err(e) = handle_connection(&mut stream).await {
        tracing::debug!("Unix socket connection error: {}", e);
    }
}

/// Handle a single connection: read destination, connect to TCP, forward bidirectionally
async fn handle_connection<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Read destination header: [2 bytes length][N bytes "host:port"]
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let dest_len = u16::from_be_bytes(len_buf) as usize;

    if dest_len == 0 || dest_len > 512 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid destination length: {}", dest_len),
        ));
    }

    let mut dest_buf = vec![0u8; dest_len];
    stream.read_exact(&mut dest_buf).await?;

    let destination = String::from_utf8(dest_buf).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid UTF-8 in destination: {}", e),
        )
    })?;

    tracing::info!("Forwarding connection to: {}", destination);

    // Connect to destination via TCP
    let mut tcp_stream = TcpStream::connect(&destination).await.map_err(|e| {
        tracing::error!("Failed to connect to {}: {}", destination, e);
        e
    })?;

    tracing::debug!("Connected to destination: {}", destination);

    // Bidirectional forwarding
    let (bytes_to_dest, bytes_from_dest) =
        tokio::io::copy_bidirectional(stream, &mut tcp_stream).await?;

    tracing::debug!(
        "Connection closed for {}: {} bytes →, {} bytes ←",
        destination,
        bytes_to_dest,
        bytes_from_dest
    );

    Ok(())
}
