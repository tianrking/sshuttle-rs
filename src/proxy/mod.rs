mod dns;
mod http_connect;
mod original_dst;
mod socks4;
mod socks5;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use crate::config::ProxyTypeArg;

pub struct TransparentProxy {
    listen: std::net::SocketAddr,
    proxy_addr: std::net::SocketAddr,
    proxy_type: ProxyTypeArg,
}

pub struct DnsProxy {
    listen: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    proxy_addr: std::net::SocketAddr,
    via_socks: bool,
}

impl DnsProxy {
    pub fn new(
        listen: std::net::SocketAddr,
        upstream: std::net::SocketAddr,
        proxy_addr: std::net::SocketAddr,
        via_socks: bool,
    ) -> Self {
        Self {
            listen,
            upstream,
            proxy_addr,
            via_socks,
        }
    }

    pub async fn run(self) -> Result<()> {
        dns::run_dns_proxy(self.listen, self.upstream, self.proxy_addr, self.via_socks).await
    }
}

impl TransparentProxy {
    pub fn new(
        listen: std::net::SocketAddr,
        proxy_addr: std::net::SocketAddr,
        proxy_type: ProxyTypeArg,
    ) -> Self {
        Self {
            listen,
            proxy_addr,
            proxy_type,
        }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("failed to bind listener at {}", self.listen))?;

        println!("[info] transparent proxy listening on {}", self.listen);

        loop {
            let (stream, peer) = listener.accept().await?;
            let proxy_addr = self.proxy_addr;
            let proxy_type = self.proxy_type;
            tokio::spawn(async move {
                if let Err(err) = handle_client(stream, proxy_addr, proxy_type).await {
                    eprintln!("[warn] client {} failed: {err:#}", peer);
                }
            });
        }
    }
}

async fn handle_client(
    mut inbound: TcpStream,
    proxy_upstream: std::net::SocketAddr,
    proxy_type: ProxyTypeArg,
) -> Result<()> {
    let original = original_dst::resolve_original_dst(&inbound)?;
    let mut upstream = TcpStream::connect(proxy_upstream)
        .await
        .with_context(|| format!("failed to connect upstream proxy {proxy_upstream}"))?;

    match proxy_type {
        ProxyTypeArg::Socks5 => socks5::establish_tunnel(&mut upstream, original).await?,
        ProxyTypeArg::Socks4 => socks4::establish_tunnel(&mut upstream, original).await?,
        ProxyTypeArg::Http => http_connect::establish_tunnel(&mut upstream, original).await?,
    }

    tokio::io::copy_bidirectional(&mut inbound, &mut upstream)
        .await
        .context("copy bidirectional failed")?;

    Ok(())
}
