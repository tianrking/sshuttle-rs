use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

pub async fn run_dns_proxy(listen: std::net::SocketAddr, upstream: std::net::SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("failed to bind dns listener at {listen}"))?;

    println!("[info] dns proxy listening on {} -> {}", listen, upstream);

    let mut buf = [0u8; 4096];
    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        let req = buf[..size].to_vec();

        let response = query_upstream(&req, upstream).await;
        match response {
            Ok(resp) => {
                let _ = socket.send_to(&resp, src).await;
            }
            Err(err) => {
                eprintln!("[warn] dns query from {} failed: {err:#}", src);
            }
        }
    }
}

async fn query_upstream(payload: &[u8], upstream: std::net::SocketAddr) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind temporary upstream DNS socket")?;

    sock.send_to(payload, upstream)
        .await
        .with_context(|| format!("failed to send DNS packet to {upstream}"))?;

    let mut resp = [0u8; 4096];
    let (size, _) = timeout(Duration::from_secs(5), sock.recv_from(&mut resp))
        .await
        .context("upstream DNS timed out")??;

    Ok(resp[..size].to_vec())
}