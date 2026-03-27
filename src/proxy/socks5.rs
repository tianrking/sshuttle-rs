use std::net::SocketAddr;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn establish_tunnel(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    if auth_reply != [0x05, 0x00] {
        bail!("SOCKS5 auth negotiation failed: {auth_reply:?}");
    }

    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);

    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        }
    }

    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;

    if head[0] != 0x05 || head[1] != 0x00 {
        bail!("SOCKS5 CONNECT rejected with code: {}", head[1]);
    }

    let atyp = head[3];
    match atyp {
        0x01 => {
            let mut ipv4_and_port = [0u8; 6];
            stream.read_exact(&mut ipv4_and_port).await?;
        }
        0x04 => {
            let mut ipv6_and_port = [0u8; 18];
            stream.read_exact(&mut ipv6_and_port).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut payload = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut payload).await?;
        }
        _ => bail!("SOCKS5 response has unsupported ATYP={atyp}"),
    }

    Ok(())
}