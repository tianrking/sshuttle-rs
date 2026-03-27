mod dns;
mod original_dst;
mod socks5;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};

pub struct TransparentProxy {
    listen: std::net::SocketAddr,
    socks5: std::net::SocketAddr,
}

pub struct DnsProxy {
    listen: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    socks5: std::net::SocketAddr,
    via_socks: bool,
}

impl DnsProxy {
    pub fn new(
        listen: std::net::SocketAddr,
        upstream: std::net::SocketAddr,
        socks5: std::net::SocketAddr,
        via_socks: bool,
    ) -> Self {
        Self {
            listen,
            upstream,
            socks5,
            via_socks,
        }
    }

    pub async fn run(self) -> Result<()> {
        dns::run_dns_proxy(self.listen, self.upstream, self.socks5, self.via_socks).await
    }
}

impl TransparentProxy {
    pub fn new(listen: std::net::SocketAddr, socks5: std::net::SocketAddr) -> Self {
        Self { listen, socks5 }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("failed to bind listener at {}", self.listen))?;

        println!("[info] transparent proxy listening on {}", self.listen);

        loop {
            let (stream, peer) = listener.accept().await?;
            let socks5 = self.socks5;
            tokio::spawn(async move {
                if let Err(err) = handle_client(stream, socks5).await {
                    eprintln!("[warn] client {} failed: {err:#}", peer);
                }
            });
        }
    }
}

async fn handle_client(mut inbound: TcpStream, socks5_upstream: std::net::SocketAddr) -> Result<()> {
    let original = original_dst::resolve_original_dst(&inbound)?;
    let mut upstream = TcpStream::connect(socks5_upstream)
        .await
        .with_context(|| format!("failed to connect socks5 upstream {socks5_upstream}"))?;

    socks5::establish_tunnel(&mut upstream, original).await?;

    tokio::io::copy_bidirectional(&mut inbound, &mut upstream)
        .await
        .context("copy bidirectional failed")?;

    Ok(())
}
