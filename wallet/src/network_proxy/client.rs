use tokio::io::AsyncWriteExt;
use std::io;

#[cfg(feature = "nsm")]
use tokio_vsock::{VsockAddr, VsockStream};

#[cfg(feature = "local-dev")]
use tokio::net::UnixStream;

/// Connect to parent network proxy and send destination header
#[cfg(feature = "nsm")]
pub async fn connect_to_parent(parent_cid: u32, parent_port: u32, destination: &str) -> io::Result<VsockStream> {
    let addr = VsockAddr::new(parent_cid, parent_port);
    let mut stream = VsockStream::connect(addr).await?;

    // Send destination header: [2 bytes length][N bytes "host:port"]
    send_destination_header(&mut stream, destination).await?;

    Ok(stream)
}

/// Connect to parent network proxy and send destination header
#[cfg(feature = "local-dev")]
pub async fn connect_to_parent(socket_path: &str, destination: &str) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket_path).await?;

    // Send destination header: [2 bytes length][N bytes "host:port"]
    send_destination_header(&mut stream, destination).await?;

    Ok(stream)
}

/// Send destination header in the protocol format
async fn send_destination_header<S>(stream: &mut S, destination: &str) -> io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let dest_bytes = destination.as_bytes();
    if dest_bytes.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Destination too long: {} bytes", dest_bytes.len()),
        ));
    }

    let len = dest_bytes.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(dest_bytes).await?;
    stream.flush().await?;

    Ok(())
}
