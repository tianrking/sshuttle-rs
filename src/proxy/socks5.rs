use std::net::SocketAddr;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};

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

pub async fn udp_query(
    socks_server: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut ctrl = TcpStream::connect(socks_server).await?;
    ctrl.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut auth_reply = [0u8; 2];
    ctrl.read_exact(&mut auth_reply).await?;
    if auth_reply != [0x05, 0x00] {
        bail!("SOCKS5 auth negotiation failed: {auth_reply:?}");
    }

    let udp_local: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().expect("valid socket")
    } else {
        "0.0.0.0:0".parse().expect("valid socket")
    };
    let udp_socket = UdpSocket::bind(udp_local).await?;
    let udp_bound = udp_socket.local_addr()?;

    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&[0x05, 0x03, 0x00]); // UDP ASSOCIATE
    match udp_bound.ip() {
        std::net::IpAddr::V4(ip) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        }
    }
    req.extend_from_slice(&udp_bound.port().to_be_bytes());
    ctrl.write_all(&req).await?;

    let relay = parse_bind_addr(&mut ctrl).await?;

    let mut udp_pkt = Vec::with_capacity(payload.len() + 64);
    udp_pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            udp_pkt.push(0x01);
            udp_pkt.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            udp_pkt.push(0x04);
            udp_pkt.extend_from_slice(&ip.octets());
        }
    }
    udp_pkt.extend_from_slice(&target.port().to_be_bytes());
    udp_pkt.extend_from_slice(payload);

    udp_socket.send_to(&udp_pkt, relay).await?;

    let mut resp = [0u8; 4096];
    let (size, _) = timeout(Duration::from_secs(5), udp_socket.recv_from(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("socks udp relay timeout"))??;
    if size < 10 {
        bail!("short socks udp response");
    }

    let data_offset = parse_udp_header_len(&resp[..size])?;
    Ok(resp[data_offset..size].to_vec())
}

async fn parse_bind_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        bail!("SOCKS5 UDP ASSOCIATE rejected with code: {}", head[1]);
    }
    match head[3] {
        0x01 => {
            let mut p = [0u8; 6];
            stream.read_exact(&mut p).await?;
            let ip = std::net::Ipv4Addr::new(p[0], p[1], p[2], p[3]);
            let port = u16::from_be_bytes([p[4], p[5]]);
            Ok(SocketAddr::from((ip, port)))
        }
        0x04 => {
            let mut p = [0u8; 18];
            stream.read_exact(&mut p).await?;
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&p[..16]);
            let ip = std::net::Ipv6Addr::from(oct);
            let port = u16::from_be_bytes([p[16], p[17]]);
            Ok(SocketAddr::from((ip, port)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host_and_port = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut host_and_port).await?;
            let host = String::from_utf8_lossy(&host_and_port[..len[0] as usize]).to_string();
            let port = u16::from_be_bytes([
                host_and_port[len[0] as usize],
                host_and_port[len[0] as usize + 1],
            ]);
            let addr = format!("{host}:{port}").parse::<std::net::SocketAddr>();
            if let Ok(a) = addr {
                Ok(a)
            } else {
                bail!("SOCKS5 returned domain relay address that is not directly parseable")
            }
        }
        atyp => bail!("unsupported SOCKS5 ATYP={atyp} in UDP ASSOCIATE response"),
    }
}

fn parse_udp_header_len(buf: &[u8]) -> Result<usize> {
    if buf.len() < 4 {
        bail!("invalid socks udp frame");
    }
    if buf[2] != 0x00 {
        bail!("fragmented socks udp frames are not supported");
    }
    let atyp = buf[3];
    let header_len = match atyp {
        0x01 => 4 + 4 + 2,
        0x04 => 4 + 16 + 2,
        0x03 => {
            if buf.len() < 5 {
                bail!("invalid socks udp domain header");
            }
            4 + 1 + buf[4] as usize + 2
        }
        _ => bail!("unsupported socks udp atyp={atyp}"),
    };
    if buf.len() < header_len {
        bail!("truncated socks udp frame");
    }
    Ok(header_len)
}
