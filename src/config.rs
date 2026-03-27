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

    #[arg(long, value_enum, default_value_t = PlatformArg::Auto)]
    pub platform: PlatformArg,
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
    pub requested_platform: PlatformArg,
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
            requested_platform: value.platform,
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
