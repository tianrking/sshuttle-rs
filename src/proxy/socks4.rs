use std::net::SocketAddr;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn establish_tunnel(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => bail!("SOCKS4 does not support IPv6 target destinations"),
    };

    let mut req = Vec::with_capacity(16);
    req.push(0x04); // VN
    req.push(0x01); // CONNECT
    req.extend_from_slice(&target.port().to_be_bytes());
    req.extend_from_slice(&ip.octets());
    req.push(0x00); // empty USERID

    stream.write_all(&req).await?;

    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x5a {
        bail!("SOCKS4 CONNECT rejected with code: {}", resp[1]);
    }

    Ok(())
}