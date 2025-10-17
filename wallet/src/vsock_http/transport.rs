//! Vsock-based HTTP transport with TLS encryption
//!
//! Implements CDK's `Transport` trait using vsock for communication with parent proxy.
//! TLS encryption happens inside the enclave before data goes over vsock.

use async_trait::async_trait;
use cdk_common::error::Error as CdkError;
use cdk_common::AuthToken;
use rustls::pki_types::ServerName;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

#[cfg(feature = "nsm")]
use tokio_vsock::{VsockAddr, VsockStream};

#[cfg(feature = "local-dev")]
use tokio::net::UnixStream;

/// Vsock-based HTTP transport that encrypts with TLS inside the enclave
#[derive(Clone)]
pub struct VsockTransport {
    #[cfg(feature = "nsm")]
    parent_cid: u32,
    #[cfg(feature = "nsm")]
    parent_port: u32,

    #[cfg(feature = "local-dev")]
    parent_socket: String,

    tls_connector: Arc<TlsConnector>,
}

impl std::fmt::Debug for VsockTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("VsockTransport");
        #[cfg(feature = "nsm")]
        {
            d.field("parent_cid", &self.parent_cid);
            d.field("parent_port", &self.parent_port);
        }
        #[cfg(feature = "local-dev")]
        {
            d.field("parent_socket", &self.parent_socket);
        }
        d.field("tls_connector", &"<TlsConnector>").finish()
    }
}

impl VsockTransport {
    /// Create new vsock transport
    #[cfg(feature = "nsm")]
    pub fn new(parent_cid: u32, parent_port: u32) -> Result<Self, CdkError> {
        let tls_connector = Self::create_tls_connector()?;

        Ok(Self {
            parent_cid,
            parent_port,
            tls_connector: Arc::new(tls_connector),
        })
    }

    /// Create new vsock transport (local-dev mode)
    #[cfg(feature = "local-dev")]
    pub fn new(parent_socket: String) -> Result<Self, CdkError> {
        let tls_connector = Self::create_tls_connector()?;

        Ok(Self {
            parent_socket,
            tls_connector: Arc::new(tls_connector),
        })
    }

    /// Create TLS connector with root certificates
    fn create_tls_connector() -> Result<TlsConnector, CdkError> {
        // Load root certificates
        let mut root_store = RootCertStore::empty();

        // Add webpki roots (Mozilla's root certificates)
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// Connect to mint via vsock tunnel, conditionally with TLS
    ///
    /// 1. Connect to parent proxy via vsock
    /// 2. Send destination header (host:port)
    /// 3. Establish TLS connection for HTTPS URLs
    /// 4. Return stream for HTTP communication
    async fn connect(&self, url: &Url) -> Result<HttpStream, CdkError> {
        // Extract host and port from URL
        let host = url
            .host_str()
            .ok_or_else(|| CdkError::Custom("Missing host in URL".to_string()))?;

        let scheme = url.scheme();
        let default_port = match scheme {
            "https" => 443,
            "http" => 80,
            _ => return Err(CdkError::Custom(format!("Unsupported URL scheme: {}", scheme))),
        };
        let port = url.port().unwrap_or(default_port);
        let destination = format!("{}:{}", host, port);

        tracing::debug!("Connecting via vsock: {} ({})", destination, scheme);

        // Connect to parent proxy via vsock
        #[cfg(feature = "nsm")]
        let mut stream = {
            let addr = VsockAddr::new(self.parent_cid, self.parent_port);
            let vsock_stream = VsockStream::connect(addr)
                .await
                .map_err(|e| CdkError::Custom(format!("Vsock connection failed: {}", e)))?;
            TransportStream::Vsock(vsock_stream)
        };

        #[cfg(feature = "local-dev")]
        let mut stream = {
            let unix_stream = UnixStream::connect(&self.parent_socket)
                .await
                .map_err(|e| CdkError::Custom(format!("Unix socket connection failed: {}", e)))?;
            TransportStream::Unix(unix_stream)
        };

        // Send destination header: [2 bytes length][N bytes "host:port"]
        let dest_bytes = destination.as_bytes();
        if dest_bytes.len() > u16::MAX as usize {
            return Err(CdkError::Custom(format!(
                "Destination too long: {} bytes",
                dest_bytes.len()
            )));
        }

        let len = dest_bytes.len() as u16;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| CdkError::Custom(format!("Failed to send destination length: {}", e)))?;
        stream
            .write_all(dest_bytes)
            .await
            .map_err(|e| CdkError::Custom(format!("Failed to send destination: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| CdkError::Custom(format!("Failed to flush destination: {}", e)))?;

        tracing::debug!("Sent destination header to parent proxy");

        // Conditionally establish TLS connection for HTTPS URLs
        if scheme == "https" {
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| CdkError::Custom(format!("Invalid server name: {}", e)))?;

            let tls_stream = self
                .tls_connector
                .connect(server_name, stream)
                .await
                .map_err(|e| CdkError::Custom(format!("TLS handshake failed: {}", e)))?;

            tracing::debug!("TLS connection established with {}", host);
            Ok(HttpStream::Tls(tls_stream))
        } else {
            tracing::debug!("Plain HTTP connection to {}", host);
            Ok(HttpStream::Plain(stream))
        }
    }

    /// Send HTTP request and receive response
    async fn http_request<P, R>(
        &self,
        method: &str,
        url: Url,
        auth_token: Option<AuthToken>,
        payload: Option<&P>,
    ) -> Result<R, CdkError>
    where
        P: Serialize + ?Sized + Send + Sync,
        R: DeserializeOwned,
    {
        // Establish connection (with or without TLS based on URL scheme)
        let mut stream = self.connect(&url).await?;

        // Build HTTP request
        let path = url.path();
        let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let host = url
            .host_str()
            .ok_or_else(|| CdkError::Custom("Missing host".to_string()))?;

        let mut request = format!(
            "{} {}{} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: cashu-enclave-wallet/0.1.0\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n",
            method, path, query, host
        );

        // Add auth header if provided
        if let Some(auth) = auth_token {
            request.push_str(&format!("{}: {}\r\n", auth.header_key(), auth.to_string()));
        }

        // Add body for POST requests
        if let Some(body) = payload {
            let json = serde_json::to_string(body)
                .map_err(|e| CdkError::Custom(format!("JSON serialization failed: {}", e)))?;

            request.push_str(&format!("Content-Type: application/json\r\n"));
            request.push_str(&format!("Content-Length: {}\r\n", json.len()));
            request.push_str("\r\n");
            request.push_str(&json);
        } else {
            request.push_str("\r\n");
        }

        tracing::trace!("Sending HTTP request:\n{}", request);

        // Send request
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| CdkError::Custom(format!("Failed to send HTTP request: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| CdkError::Custom(format!("Failed to flush request: {}", e)))?;

        // Read response
        let mut response_buf = Vec::new();
        stream
            .read_to_end(&mut response_buf)
            .await
            .map_err(|e| CdkError::Custom(format!("Failed to read HTTP response: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response_buf);
        tracing::trace!("Received HTTP response:\n{}", response_str);

        // Parse HTTP response
        let (status_line, body) = Self::parse_http_response(&response_str)?;

        // Check status code
        if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
            let status_code = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok());

            return Err(CdkError::HttpError(
                status_code,
                format!("HTTP error: {}", status_line),
            ));
        }

        // Parse JSON response
        serde_json::from_str::<R>(body).map_err(|e| {
            tracing::warn!("JSON parse error: {} - Response: {}", e, body);
            CdkError::Custom(format!("JSON parse failed: {}", e))
        })
    }

    /// Parse HTTP response into status line and body
    fn parse_http_response(response: &str) -> Result<(&str, &str), CdkError> {
        // Split headers and body
        let parts: Vec<&str> = response.splitn(2, "\r\n\r\n").collect();
        if parts.len() < 2 {
            return Err(CdkError::Custom("Invalid HTTP response format".to_string()));
        }

        let headers = parts[0];
        let body = parts[1];

        // Extract status line (first line of headers)
        let status_line = headers
            .lines()
            .next()
            .ok_or_else(|| CdkError::Custom("Missing status line".to_string()))?;

        Ok((status_line, body))
    }
}

impl Default for VsockTransport {
    fn default() -> Self {
        #[cfg(feature = "nsm")]
        {
            // Default vsock configuration for Nitro Enclaves
            Self::new(3, 9000).expect("Failed to create default VsockTransport")
        }

        #[cfg(feature = "local-dev")]
        {
            // Default Unix socket for local development
            Self::new("/tmp/network-proxy.sock".to_string())
                .expect("Failed to create default VsockTransport")
        }
    }
}

#[async_trait]
impl cdk::wallet::HttpTransport for VsockTransport {
    #[cfg(all(feature = "bip353", not(target_arch = "wasm32")))]
    async fn resolve_dns_txt(&self, _domain: &str) -> Result<Vec<String>, CdkError> {
        // DNS resolution not supported - mints should be accessed by IP or rely on parent proxy DNS
        Err(CdkError::Custom(
            "DNS TXT resolution not supported in vsock transport".to_string(),
        ))
    }

    #[cfg(not(all(feature = "bip353", not(target_arch = "wasm32"))))]
    async fn resolve_dns_txt(&self, _domain: &str) -> Result<Vec<String>, CdkError> {
        // DNS resolution not supported - mints should be accessed by IP or rely on parent proxy DNS
        Err(CdkError::Custom(
            "DNS TXT resolution not supported in vsock transport".to_string(),
        ))
    }

    fn with_proxy(
        &mut self,
        _proxy: Url,
        _host_matcher: Option<&str>,
        _accept_invalid_certs: bool,
    ) -> Result<(), CdkError> {
        // Vsock already acts as a proxy - this is a no-op
        Ok(())
    }

    async fn http_get<R>(&self, url: Url, auth: Option<AuthToken>) -> Result<R, CdkError>
    where
        R: DeserializeOwned,
    {
        self.http_request::<(), R>("GET", url, auth, None).await
    }

    async fn http_post<P, R>(
        &self,
        url: Url,
        auth_token: Option<AuthToken>,
        payload: &P,
    ) -> Result<R, CdkError>
    where
        P: Serialize + ?Sized + Send + Sync,
        R: DeserializeOwned,
    {
        self.http_request("POST", url, auth_token, Some(payload))
            .await
    }
}

/// Enum to support both VsockStream and UnixStream without trait objects
enum TransportStream {
    #[cfg(feature = "nsm")]
    Vsock(VsockStream),
    #[cfg(feature = "local-dev")]
    Unix(UnixStream),
}

impl tokio::io::AsyncRead for TransportStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(feature = "nsm")]
            TransportStream::Vsock(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "local-dev")]
            TransportStream::Unix(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for TransportStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            #[cfg(feature = "nsm")]
            TransportStream::Vsock(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "local-dev")]
            TransportStream::Unix(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(feature = "nsm")]
            TransportStream::Vsock(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "local-dev")]
            TransportStream::Unix(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(feature = "nsm")]
            TransportStream::Vsock(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "local-dev")]
            TransportStream::Unix(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Enum to support both TLS and plain HTTP streams
enum HttpStream {
    Tls(tokio_rustls::client::TlsStream<TransportStream>),
    Plain(TransportStream),
}

impl tokio::io::AsyncRead for HttpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            HttpStream::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            HttpStream::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for HttpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            HttpStream::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            HttpStream::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            HttpStream::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            HttpStream::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            HttpStream::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            HttpStream::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}
