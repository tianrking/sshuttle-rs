use std::net::SocketAddr;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn establish_tunnel(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let host_port = target.to_string();
    let req = format!(
        "CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );

    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 256];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("HTTP proxy closed connection during CONNECT handshake");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            bail!("HTTP CONNECT response header too large");
        }
    }

    let header = String::from_utf8_lossy(&buf);
    let first_line = header.lines().next().unwrap_or_default();
    let ok = first_line.starts_with("HTTP/1.1 200") || first_line.starts_with("HTTP/1.0 200");
    if !ok {
        bail!("HTTP CONNECT failed: {first_line}");
    }

    Ok(())
}