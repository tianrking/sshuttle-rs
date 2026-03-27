use anyhow::{Result, bail};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(windows)]
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::config::WinNativeWorkerArgs;
use crate::policy::{FlowContext, PolicyAction, PolicyEvaluator};

#[cfg(windows)]
use serde::Deserialize;
#[cfg(windows)]
use windivert::prelude::*;
#[cfg(windows)]
use windivert_sys::ChecksumFlags;

#[derive(Clone, Debug)]
pub struct PacketDecision {
    pub action: PolicyAction,
    pub flow: FlowContext,
}

pub trait PacketEngine {
    fn process_once(
        &mut self,
        evaluator: Option<&mut PolicyEvaluator>,
        bypass_processes: &[String],
    ) -> Result<Vec<PacketDecision>>;
}

#[cfg(windows)]
pub struct WinDivertPacketEngine {
    divert: WinDivert<NetworkLayer>,
    cfg: NativeRedirectConfig,
    buf: Vec<u8>,
    conn_cache: ConnectionCache,
}

#[derive(Clone)]
pub struct NativeRedirectConfig {
    pub listen_ip: IpAddr,
    pub listen_port: u16,
    pub proxy_addr: SocketAddr,
    pub dns_capture: bool,
    pub dns_listen_port: u16,
    pub udp_capture: bool,
    pub udp_listen_port: u16,
    pub udp_ports: Vec<u16>,
}

impl NativeRedirectConfig {
    pub fn from_args(args: &WinNativeWorkerArgs) -> Self {
        Self {
            listen_ip: args.listen_ip,
            listen_port: args.listen_port,
            proxy_addr: args.proxy_addr,
            dns_capture: args.dns_capture,
            dns_listen_port: args.dns_listen_port,
            udp_capture: args.udp_capture,
            udp_listen_port: args.udp_listen_port,
            udp_ports: args.udp_ports.clone(),
        }
    }
}

#[cfg(windows)]
impl WinDivertPacketEngine {
    pub fn new(cfg: NativeRedirectConfig) -> Result<Self> {
        let filter = format!(
            "outbound and (ip or ipv6) and (tcp or udp) and !loopback and ip.DstAddr != {}",
            cfg.proxy_addr.ip()
        );
        let divert = WinDivert::network(filter, 0, WinDivertFlags::default())?;
        Ok(Self {
            divert,
            cfg,
            buf: vec![0u8; 65535],
            conn_cache: ConnectionCache::default(),
        })
    }
}

#[cfg(windows)]
impl PacketEngine for WinDivertPacketEngine {
    fn process_once(
        &mut self,
        evaluator: Option<&mut PolicyEvaluator>,
        bypass_processes: &[String],
    ) -> Result<Vec<PacketDecision>> {
        let mut out = Vec::new();
        self.conn_cache.maybe_refresh()?;

        let Some(packet) = self.divert.recv_wait(&mut self.buf, 50)? else {
            return Ok(out);
        };

        let mut packet = packet.into_owned();
        let Some(meta) = parse_packet_meta(&packet.data) else {
            let _ = self.divert.send(&packet);
            return Ok(out);
        };

        let proc_info = self.conn_cache.lookup(&meta);
        let flow = FlowContext {
            process_name: proc_info.as_ref().and_then(|p| p.name.clone()),
            process_path: proc_info.as_ref().and_then(|p| p.path.clone()),
            dst: SocketAddr::from((meta.dst_ip, meta.dst_port)),
            proto: match meta.proto {
                Proto::Tcp => crate::policy::FlowProto::Tcp,
                Proto::Udp => crate::policy::FlowProto::Udp,
            },
        };

        let bypass_list_hit = flow.process_name.as_ref().is_some_and(|n| {
            bypass_processes.iter().any(|x| {
                n.eq_ignore_ascii_case(x) || n.eq_ignore_ascii_case(x.trim_end_matches(".exe"))
            })
        }) || flow
            .process_path
            .as_ref()
            .is_some_and(|p| bypass_processes.iter().any(|x| p.eq_ignore_ascii_case(x)));

        let action = if bypass_list_hit {
            PolicyAction::Bypass
        } else if let Some(eval) = evaluator {
            eval.evaluate(&flow).action
        } else {
            PolicyAction::Proxy
        };

        match action {
            PolicyAction::Drop => {
                out.push(PacketDecision { action, flow });
                return Ok(out);
            }
            PolicyAction::Bypass | PolicyAction::Direct => {
                let _ = self.divert.send(&packet);
                out.push(PacketDecision { action, flow });
                return Ok(out);
            }
            PolicyAction::Proxy => {}
        }

        let redirect_port = match meta.proto {
            Proto::Tcp => Some(self.cfg.listen_port),
            Proto::Udp if meta.dst_port == 53 && self.cfg.dns_capture => {
                Some(self.cfg.dns_listen_port)
            }
            Proto::Udp if self.cfg.udp_capture && self.cfg.udp_ports.contains(&meta.dst_port) => {
                Some(self.cfg.udp_listen_port)
            }
            _ => None,
        };

        if let Some(port) = redirect_port {
            if should_skip_redirect(&flow.dst, &self.cfg) {
                let _ = self.divert.send(&packet);
            } else {
                rewrite_destination(packet.data.to_mut(), self.cfg.listen_ip, port)?;
                let _ = packet.recalculate_checksums(ChecksumFlags::new());
                let _ = self.divert.send(&packet);
            }
        } else {
            let _ = self.divert.send(&packet);
        }

        out.push(PacketDecision { action, flow });
        Ok(out)
    }
}

#[cfg(not(windows))]
pub struct WinDivertPacketEngine;

#[cfg(not(windows))]
impl WinDivertPacketEngine {
    pub fn new(_cfg: NativeRedirectConfig) -> Result<Self> {
        bail!("WinDivert native engine is only available on Windows")
    }
}

#[cfg(not(windows))]
impl PacketEngine for WinDivertPacketEngine {
    fn process_once(
        &mut self,
        _evaluator: Option<&mut PolicyEvaluator>,
        _bypass_processes: &[String],
    ) -> Result<Vec<PacketDecision>> {
        Ok(vec![])
    }
}

#[derive(Clone, Copy)]
enum Proto {
    Tcp,
    Udp,
}

struct PacketMeta {
    proto: Proto,
    src_port: u16,
    dst_port: u16,
    dst_ip: IpAddr,
}

fn parse_packet_meta(buf: &[u8]) -> Option<PacketMeta> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] >> 4 {
        4 => parse_ipv4_meta(buf),
        6 => parse_ipv6_meta(buf),
        _ => None,
    }
}

fn parse_ipv4_meta(buf: &[u8]) -> Option<PacketMeta> {
    if buf.len() < 20 || (buf[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    if buf.len() < ihl + 4 {
        return None;
    }
    let proto = match buf[9] {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        _ => return None,
    };
    let dst_ip = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
    let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
    let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
    Some(PacketMeta {
        proto,
        src_port,
        dst_port,
        dst_ip,
    })
}

fn parse_ipv6_meta(buf: &[u8]) -> Option<PacketMeta> {
    if buf.len() < 40 || (buf[0] >> 4) != 6 {
        return None;
    }
    let next = buf[6];
    let proto = match next {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        _ => return None,
    };
    if buf.len() < 44 {
        return None;
    }
    let mut dst_oct = [0u8; 16];
    dst_oct.copy_from_slice(&buf[24..40]);
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_oct));
    let src_port = u16::from_be_bytes([buf[40], buf[41]]);
    let dst_port = u16::from_be_bytes([buf[42], buf[43]]);
    Some(PacketMeta {
        proto,
        src_port,
        dst_port,
        dst_ip,
    })
}

fn rewrite_destination(buf: &mut [u8], ip: IpAddr, port: u16) -> Result<()> {
    if buf.is_empty() {
        bail!("empty packet");
    }
    match buf[0] >> 4 {
        4 => rewrite_ipv4_destination(buf, ip, port),
        6 => rewrite_ipv6_destination(buf, ip, port),
        _ => bail!("unsupported ip version"),
    }
}

fn rewrite_ipv4_destination(buf: &mut [u8], ip: IpAddr, port: u16) -> Result<()> {
    if buf.len() < 20 || (buf[0] >> 4) != 4 {
        bail!("unsupported non-ipv4 packet");
    }
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    if buf.len() < ihl + 4 {
        bail!("short packet");
    }
    let v4 = match ip {
        IpAddr::V4(x) => x,
        IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
    };
    buf[16..20].copy_from_slice(&v4.octets());
    let p = port.to_be_bytes();
    buf[ihl + 2] = p[0];
    buf[ihl + 3] = p[1];
    Ok(())
}

fn rewrite_ipv6_destination(buf: &mut [u8], ip: IpAddr, port: u16) -> Result<()> {
    if buf.len() < 44 || (buf[0] >> 4) != 6 {
        bail!("unsupported non-ipv6 packet");
    }
    let v6 = match ip {
        IpAddr::V6(x) => x,
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
    };
    buf[24..40].copy_from_slice(&v6.octets());
    let p = port.to_be_bytes();
    buf[42] = p[0];
    buf[43] = p[1];
    Ok(())
}

fn should_skip_redirect(dst: &SocketAddr, cfg: &NativeRedirectConfig) -> bool {
    dst.ip().is_loopback()
        || dst.ip() == cfg.proxy_addr.ip()
        || dst.port() == cfg.listen_port
        || dst.port() == cfg.dns_listen_port
        || dst.port() == cfg.udp_listen_port
}

#[derive(Clone)]
struct ProcessInfo {
    name: Option<String>,
    path: Option<String>,
}

type TcpConnMap = HashMap<(u16, IpAddr, u16), ProcessInfo>;
type UdpConnMap = HashMap<u16, ProcessInfo>;

#[derive(Default)]
struct ConnectionCache {
    last_refresh: Option<Instant>,
    tcp: TcpConnMap,
    udp: UdpConnMap,
}

impl ConnectionCache {
    fn maybe_refresh(&mut self) -> Result<()> {
        if self
            .last_refresh
            .is_some_and(|t| t.elapsed() < Duration::from_secs(2))
        {
            return Ok(());
        }
        self.refresh()?;
        self.last_refresh = Some(Instant::now());
        Ok(())
    }

    fn lookup(&self, p: &PacketMeta) -> Option<ProcessInfo> {
        match p.proto {
            Proto::Tcp => self.tcp.get(&(p.src_port, p.dst_ip, p.dst_port)).cloned(),
            Proto::Udp => self.udp.get(&p.src_port).cloned(),
        }
    }

    fn refresh(&mut self) -> Result<()> {
        #[cfg(not(windows))]
        {
            self.tcp.clear();
            self.udp.clear();
            Ok(())
        }
        #[cfg(windows)]
        {
            let (tcp, udp) = load_process_connections()?;
            self.tcp = tcp;
            self.udp = udp;
            Ok(())
        }
    }
}

#[cfg(windows)]
#[derive(Deserialize)]
struct TcpRow {
    #[serde(rename = "LocalPort")]
    local_port: Option<u16>,
    #[serde(rename = "RemoteAddress")]
    remote_address: Option<String>,
    #[serde(rename = "RemotePort")]
    remote_port: Option<u16>,
    #[serde(rename = "ProcessName")]
    process_name: Option<String>,
    #[serde(rename = "ProcessPath")]
    process_path: Option<String>,
}

#[cfg(windows)]
#[derive(Deserialize)]
struct UdpRow {
    #[serde(rename = "LocalPort")]
    local_port: Option<u16>,
    #[serde(rename = "ProcessName")]
    process_name: Option<String>,
    #[serde(rename = "ProcessPath")]
    process_path: Option<String>,
}

#[cfg(windows)]
fn load_process_connections() -> Result<(TcpConnMap, UdpConnMap)> {
    let script = r#"
$tcp = @()
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  if ($null -ne $p) {
    $tcp += [pscustomobject]@{
      LocalPort = $_.LocalPort
      RemoteAddress = $_.RemoteAddress
      RemotePort = $_.RemotePort
      ProcessName = $p.ProcessName
      ProcessPath = $p.Path
    }
  }
}
$udp = @()
Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  if ($null -ne $p) {
    $udp += [pscustomobject]@{
      LocalPort = $_.LocalPort
      ProcessName = $p.ProcessName
      ProcessPath = $p.Path
    }
  }
}
[pscustomobject]@{ tcp = $tcp; udp = $udp } | ConvertTo-Json -Compress
"#;
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .stdin(Stdio::null())
        .output()?;
    if !out.status.success() {
        return Ok((HashMap::new(), HashMap::new()));
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() || text == "null" {
        return Ok((HashMap::new(), HashMap::new()));
    }
    let root: serde_json::Value = serde_json::from_str(&text)?;
    let tcp_rows = parse_maybe_array::<TcpRow>(&root["tcp"])?;
    let udp_rows = parse_maybe_array::<UdpRow>(&root["udp"])?;

    let mut tcp_map = HashMap::new();
    for r in tcp_rows {
        let (Some(lp), Some(ra), Some(rp)) = (r.local_port, r.remote_address, r.remote_port) else {
            continue;
        };
        let Some(ip) = parse_ip_flexible(&ra) else {
            continue;
        };
        tcp_map.insert(
            (lp, ip, rp),
            ProcessInfo {
                name: r.process_name,
                path: r.process_path,
            },
        );
    }

    let mut udp_map = HashMap::new();
    for r in udp_rows {
        let Some(lp) = r.local_port else {
            continue;
        };
        udp_map.insert(
            lp,
            ProcessInfo {
                name: r.process_name,
                path: r.process_path,
            },
        );
    }

    Ok((tcp_map, udp_map))
}

#[cfg(windows)]
fn parse_maybe_array<T: for<'de> Deserialize<'de>>(value: &serde_json::Value) -> Result<Vec<T>> {
    if value.is_null() {
        return Ok(vec![]);
    }
    if value.is_array() {
        Ok(serde_json::from_value::<Vec<T>>(value.clone())?)
    } else {
        Ok(vec![serde_json::from_value::<T>(value.clone())?])
    }
}

#[cfg(windows)]
fn parse_ip_flexible(s: &str) -> Option<IpAddr> {
    let core = s.split('%').next().unwrap_or(s);
    core.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::{parse_packet_meta, rewrite_destination};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_rewrite_works() {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[9] = 6;
        p[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
        p[20] = 0x30;
        p[21] = 0x39;
        p[22] = 0x01;
        p[23] = 0xbb;

        rewrite_destination(&mut p, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18080)
            .expect("rewrite");
        assert_eq!(p[16..20], Ipv4Addr::new(127, 0, 0, 1).octets());
        assert_eq!(u16::from_be_bytes([p[22], p[23]]), 18080);
    }

    #[test]
    fn ipv6_rewrite_works() {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[6] = 17;
        p[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p[40] = 0x30;
        p[41] = 0x39;
        p[42] = 0x00;
        p[43] = 0x35;

        let target = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        rewrite_destination(&mut p, IpAddr::V6(target), 19090).expect("rewrite");
        assert_eq!(&p[24..40], &target.octets());
        assert_eq!(u16::from_be_bytes([p[42], p[43]]), 19090);
    }

    #[test]
    fn parse_meta_ipv6_tcp() {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[6] = 6;
        let dst = Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 1);
        p[24..40].copy_from_slice(&dst.octets());
        p[40] = 0x12;
        p[41] = 0x34;
        p[42] = 0x01;
        p[43] = 0xbb;

        let m = parse_packet_meta(&p).expect("meta");
        assert_eq!(m.dst_ip, IpAddr::V6(dst));
        assert_eq!(m.src_port, 0x1234);
        assert_eq!(m.dst_port, 443);
    }
}
