use std::net::{IpAddr, SocketAddr};

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(author, version, about = "Cross-platform transparent proxy core (Rust rewrite draft)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    Run(RunArgs),
    Doctor(DoctorArgs),
    Cleanup(RunArgs),
}

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    #[arg(long, value_enum, default_value_t = ModeArg::Transparent)]
    pub mode: ModeArg,

    #[arg(long, default_value = "127.0.0.1:18080")]
    pub listen: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:1080")]
    pub socks5: SocketAddr,

    #[arg(long)]
    pub ssh_remote: Option<String>,

    #[arg(long, default_value = "ssh")]
    pub ssh_cmd: String,

    #[arg(long)]
    pub win_transparent_cmd: Option<String>,

    #[arg(long)]
    pub win_transparent_stop_cmd: Option<String>,

    #[arg(long = "include", default_value = "0.0.0.0/0")]
    pub include_cidrs: Vec<String>,

    #[arg(long = "exclude")]
    pub exclude_cidrs: Vec<String>,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub no_apply_rules: bool,

    #[arg(long)]
    pub dns_capture: bool,

    #[arg(long, default_value = "127.0.0.1:15353")]
    pub dns_listen: SocketAddr,

    #[arg(long, default_value = "1.1.1.1:53")]
    pub dns_upstream: SocketAddr,

    #[arg(long, default_value_t = true)]
    pub dns_via_socks: bool,

    #[arg(long, value_enum, default_value_t = PlatformArg::Auto)]
    pub platform: PlatformArg,

    #[arg(long, value_enum, default_value_t = LinuxBackendArg::Auto)]
    pub linux_backend: LinuxBackendArg,
}

#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    #[arg(long, value_enum, default_value_t = ModeArg::Transparent)]
    pub mode: ModeArg,

    #[arg(long, value_enum, default_value_t = PlatformArg::Auto)]
    pub platform: PlatformArg,

    #[arg(long, value_enum, default_value_t = LinuxBackendArg::Auto)]
    pub linux_backend: LinuxBackendArg,

    #[arg(long, default_value = "ssh")]
    pub ssh_cmd: String,

    #[arg(long)]
    pub ssh_remote: Option<String>,

    #[arg(long)]
    pub dns_capture: bool,

    #[arg(long, default_value_t = true)]
    pub dns_via_socks: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PlatformArg {
    Auto,
    Linux,
    Windows,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ModeArg {
    Transparent,
    SystemProxy,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LinuxBackendArg {
    Auto,
    Iptables,
    Nft,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub mode: ModeArg,
    pub listen: SocketAddr,
    pub socks5: SocketAddr,
    pub ssh_remote: Option<String>,
    pub ssh_cmd: String,
    pub win_transparent_cmd: Option<String>,
    pub win_transparent_stop_cmd: Option<String>,
    pub include_cidrs: Vec<String>,
    pub exclude_cidrs: Vec<String>,
    pub dry_run: bool,
    pub no_apply_rules: bool,
    pub dns_capture: bool,
    pub dns_listen: SocketAddr,
    pub dns_upstream: SocketAddr,
    pub dns_via_socks: bool,
    pub requested_platform: PlatformArg,
    pub linux_backend: LinuxBackendArg,
}

impl From<RunArgs> for RuntimeConfig {
    fn from(value: RunArgs) -> Self {
        Self {
            mode: value.mode,
            listen: value.listen,
            socks5: value.socks5,
            ssh_remote: value.ssh_remote,
            ssh_cmd: value.ssh_cmd,
            win_transparent_cmd: value.win_transparent_cmd,
            win_transparent_stop_cmd: value.win_transparent_stop_cmd,
            include_cidrs: value.include_cidrs,
            exclude_cidrs: value.exclude_cidrs,
            dry_run: value.dry_run,
            no_apply_rules: value.no_apply_rules,
            dns_capture: value.dns_capture,
            dns_listen: value.dns_listen,
            dns_upstream: value.dns_upstream,
            dns_via_socks: value.dns_via_socks,
            requested_platform: value.platform,
            linux_backend: value.linux_backend,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DoctorConfig {
    pub mode: ModeArg,
    pub requested_platform: PlatformArg,
    pub linux_backend: LinuxBackendArg,
    pub ssh_cmd: String,
    pub ssh_remote: Option<String>,
    pub dns_capture: bool,
    pub dns_via_socks: bool,
}

impl From<DoctorArgs> for DoctorConfig {
    fn from(value: DoctorArgs) -> Self {
        Self {
            mode: value.mode,
            requested_platform: value.platform,
            linux_backend: value.linux_backend,
            ssh_cmd: value.ssh_cmd,
            ssh_remote: value.ssh_remote,
            dns_capture: value.dns_capture,
            dns_via_socks: value.dns_via_socks,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RulePlan {
    pub mode: ModeArg,
    pub listen_ip: IpAddr,
    pub listen_port: u16,
    pub socks_upstream: SocketAddr,
    pub include_cidrs: Vec<String>,
    pub exclude_cidrs: Vec<String>,
    pub dns_capture: bool,
    pub dns_listen_ip: IpAddr,
    pub dns_listen_port: u16,
    pub win_transparent_cmd: Option<String>,
    pub win_transparent_stop_cmd: Option<String>,
    pub linux_backend: LinuxBackendArg,
}

impl RuntimeConfig {
    pub fn to_rule_plan(&self) -> RulePlan {
        let mut excludes = self.exclude_cidrs.clone();
        excludes.push(loopback_exclusion(self.listen.ip()));
        excludes.push(single_host_cidr(self.socks5.ip()));
        if self.dns_capture {
            excludes.push(single_host_cidr(self.dns_upstream.ip()));
        }

        RulePlan {
            mode: self.mode,
            listen_ip: self.listen.ip(),
            listen_port: self.listen.port(),
            socks_upstream: self.socks5,
            include_cidrs: self.include_cidrs.clone(),
            exclude_cidrs: excludes,
            dns_capture: self.dns_capture,
            dns_listen_ip: self.dns_listen.ip(),
            dns_listen_port: self.dns_listen.port(),
            win_transparent_cmd: self.win_transparent_cmd.clone(),
            win_transparent_stop_cmd: self.win_transparent_stop_cmd.clone(),
            linux_backend: self.linux_backend,
        }
    }
}

fn loopback_exclusion(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => "127.0.0.0/8".to_string(),
        IpAddr::V6(_) => "::1/128".to_string(),
    }
}

fn single_host_cidr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    }
}

#[cfg(test)]
mod tests {
    use super::{LinuxBackendArg, ModeArg, PlatformArg, RunArgs, RuntimeConfig};
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn to_rule_plan_adds_loopback_and_socks_excludes() {
        let args = RunArgs {
            mode: ModeArg::Transparent,
            listen: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 18080)),
            socks5: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 1080)),
            ssh_remote: None,
            ssh_cmd: "ssh".to_string(),
            win_transparent_cmd: None,
            win_transparent_stop_cmd: None,
            include_cidrs: vec!["0.0.0.0/0".to_string()],
            exclude_cidrs: vec![],
            dry_run: true,
            no_apply_rules: true,
            dns_capture: false,
            dns_listen: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 15353)),
            dns_upstream: SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
            dns_via_socks: true,
            platform: PlatformArg::Auto,
            linux_backend: LinuxBackendArg::Auto,
        };
        let cfg: RuntimeConfig = args.into();
        let plan = cfg.to_rule_plan();
        assert!(plan.exclude_cidrs.iter().any(|c| c == "127.0.0.0/8"));
        assert!(plan.exclude_cidrs.iter().any(|c| c == "127.0.0.1/32"));
    }
}
