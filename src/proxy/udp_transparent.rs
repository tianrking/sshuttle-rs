use anyhow::{Result, bail};

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use tokio::task;
#[cfg(target_os = "linux")]
use super::socks5;

#[cfg(target_os = "linux")]
pub async fn run_udp_proxy(listen: std::net::SocketAddr, socks5_upstream: std::net::SocketAddr) -> Result<()> {
    println!("[info] udp transparent proxy listening on {} via socks5 {}", listen, socks5_upstream);
    task::spawn_blocking(move || blocking_loop(listen, socks5_upstream))
        .await
        .context("udp transparent worker task join failed")??;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn run_udp_proxy(_listen: std::net::SocketAddr, _socks5_upstream: std::net::SocketAddr) -> Result<()> {
    bail!("udp transparent proxy is currently implemented for linux only")
}

#[cfg(target_os = "linux")]
fn blocking_loop(listen: std::net::SocketAddr, socks5_upstream: std::net::SocketAddr) -> Result<()> {
    use std::mem;
    use std::net::{SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;

    const IP_RECVORIGDSTADDR: i32 = 20;

    let sock = UdpSocket::bind(listen)?;
    let fd = sock.as_raw_fd();
    let one: i32 = 1;
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(anyhow::anyhow!("setsockopt(IP_RECVORIGDSTADDR) failed: {}", std::io::Error::last_os_error()));
    }

    loop {
        let mut buf = [0u8; 65535];
        let mut cmsg = [0u8; 128];
        let mut src_addr: libc::sockaddr_storage = unsafe { mem::zeroed() };

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg.len();

        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if n < 0 {
            return Err(anyhow::anyhow!("recvmsg failed: {}", std::io::Error::last_os_error()));
        }
        let n = n as usize;

        let src = sockaddr_storage_to_socket_addr(&src_addr, msg.msg_namelen)
            .ok_or_else(|| anyhow::anyhow!("unsupported source sockaddr"))?;
        let dst = extract_original_dst(&msg)
            .ok_or_else(|| anyhow::anyhow!("failed to get original dst from cmsg"))?;

        let payload = &buf[..n];
        let resp = tokio::runtime::Handle::current().block_on(socks5::udp_query(socks5_upstream, dst, payload));
        match resp {
            Ok(data) => {
                let _ = sock.send_to(&data, src);
            }
            Err(err) => {
                eprintln!("[warn] udp relay {} -> {} failed: {err:#}", src, dst);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_storage_to_socket_addr(ss: &libc::sockaddr_storage, _len: libc::socklen_t) -> Option<std::net::SocketAddr> {
    if ss.ss_family as i32 == libc::AF_INET {
        let sin = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
        let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port = u16::from_be(sin.sin_port);
        return Some(SocketAddr::from((ip, port)));
    }
    None
}

#[cfg(target_os = "linux")]
fn extract_original_dst(msg: &libc::msghdr) -> Option<std::net::SocketAddr> {
    use std::mem;

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg as *const _ as *mut _) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == 20 {
            let sa = unsafe { libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in };
            let sin = unsafe { &*sa };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            return Some(std::net::SocketAddr::from((ip, port)));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg as *const _ as *mut _, cmsg) };
    }

    let _ = mem::size_of::<libc::cmsghdr>();
    None
}
