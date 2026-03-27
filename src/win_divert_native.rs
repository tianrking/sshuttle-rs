use anyhow::{Result, bail};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
            "outbound and ip and (tcp or udp) and ip.DstAddr != 127.0.0.1 and ip.DstAddr != {}",
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
        let Some(meta) = parse_ipv4_meta(&packet.data) else {
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
                rewrite_ipv4_destination(packet.data.to_mut(), self.cfg.listen_ip, port)?;
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
    dst_ip: Ipv4Addr,
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
    let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
    let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
    Some(PacketMeta {
        proto,
        src_port,
        dst_port,
        dst_ip,
    })
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
    let oct = v4.octets();
    buf[16..20].copy_from_slice(&oct);
    let p = port.to_be_bytes();
    buf[ihl + 2] = p[0];
    buf[ihl + 3] = p[1];
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

#[derive(Default)]
struct ConnectionCache {
    last_refresh: Option<Instant>,
    tcp: HashMap<(u16, Ipv4Addr, u16), ProcessInfo>,
    udp: HashMap<u16, ProcessInfo>,
}

type TcpConnMap = HashMap<(u16, Ipv4Addr, u16), ProcessInfo>;
type UdpConnMap = HashMap<u16, ProcessInfo>;

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
            return Ok(());
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
        let Ok(ip) = ra.parse::<Ipv4Addr>() else {
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
