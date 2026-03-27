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

    #[arg(long = "include", default_value = "0.0.0.0/0")]
    pub include_cidrs: Vec<String>,

    #[arg(long = "exclude")]
    pub exclude_cidrs: Vec<String>,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub no_apply_rules: bool,

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
    pub include_cidrs: Vec<String>,
    pub exclude_cidrs: Vec<String>,
    pub dry_run: bool,
    pub no_apply_rules: bool,
    pub requested_platform: PlatformArg,
}

impl From<RunArgs> for RuntimeConfig {
    fn from(value: RunArgs) -> Self {
        Self {
            mode: value.mode,
            listen: value.listen,
            socks5: value.socks5,
            include_cidrs: value.include_cidrs,
            exclude_cidrs: value.exclude_cidrs,
            dry_run: value.dry_run,
            no_apply_rules: value.no_apply_rules,
            requested_platform: value.platform,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RulePlan {
    pub mode: ModeArg,
    pub listen_port: u16,
    pub socks_upstream: SocketAddr,
    pub include_cidrs: Vec<String>,
    pub exclude_cidrs: Vec<String>,
}

impl RuntimeConfig {
    pub fn to_rule_plan(&self) -> RulePlan {
        let mut excludes = self.exclude_cidrs.clone();
        excludes.push(loopback_exclusion(self.listen.ip()));
        excludes.push(format!("{}/32", self.socks5.ip()));

        RulePlan {
            mode: self.mode,
            listen_port: self.listen.port(),
            socks_upstream: self.socks5,
            include_cidrs: self.include_cidrs.clone(),
            exclude_cidrs: excludes,
        }
    }
}

fn loopback_exclusion(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => "127.0.0.0/8".to_string(),
        IpAddr::V6(_) => "::1/128".to_string(),
    }
}
