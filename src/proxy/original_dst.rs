use std::net::SocketAddr;

use anyhow::{Result, anyhow};
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
pub fn resolve_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    use std::mem;
    use std::net::Ipv4Addr;
    use std::os::fd::AsRawFd;

    const SO_ORIGINAL_DST: i32 = 80;

    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut addr_len,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow!("getsockopt(SO_ORIGINAL_DST) failed: {err}"));
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);

    Ok(SocketAddr::from((ip, port)))
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_original_dst(_stream: &TcpStream) -> Result<SocketAddr> {
    Err(anyhow!(
        "original destination resolution is only implemented on Linux"
    ))
}
