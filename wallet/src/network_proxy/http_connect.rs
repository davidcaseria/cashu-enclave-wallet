use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::io;

/// Parse HTTP CONNECT request and extract destination
///
/// Reads from a TCP stream that contains an HTTP CONNECT request:
/// ```
/// CONNECT mint.example.com:443 HTTP/1.1
/// Host: mint.example.com:443
/// ...
/// ```
///
/// Returns the destination (e.g., "mint.example.com:443")
pub async fn parse_connect_request<S>(stream: &mut S) -> io::Result<String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();

    // Read first line: "CONNECT host:port HTTP/1.1"
    reader.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid CONNECT request: {}", request_line),
        ));
    }

    let destination = parts[1].to_string();

    // Read and discard remaining headers until empty line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
    }

    Ok(destination)
}

/// Send HTTP 200 Connection Established response
pub async fn send_connect_response<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    stream.flush().await?;
    Ok(())
}
