use anyhow::Result;
use async_trait::async_trait;

use crate::config::{ModeArg, RulePlan};

use super::{CommandExecutor, Platform};

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Platform for LinuxPlatform {
    fn name(&self) -> &'static str {
        "linux/iptables+ip6tables"
    }

    async fn apply_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
        if matches!(plan.mode, ModeArg::SystemProxy) {
            println!("[info] linux backend: system-proxy mode is a no-op.");
            return Ok(());
        }

        let (include_v4, include_v6): (Vec<String>, Vec<String>) =
            plan.include_cidrs.iter().cloned().partition(|c| !is_ipv6_cidr(c));
        let (exclude_v4, exclude_v6): (Vec<String>, Vec<String>) =
            plan.exclude_cidrs.iter().cloned().partition(|c| !is_ipv6_cidr(c));

        if !include_v4.is_empty() {
            apply_family_rules(
                exec,
                "iptables",
                &chain_name_v4(plan.listen_port),
                plan.listen_port,
                plan.socks_upstream,
                &include_v4,
                &exclude_v4,
                plan.dns_capture,
                plan.dns_listen_port,
            )
            .await?;
        }

        if !include_v6.is_empty() {
            if !plan.listen_ip.is_ipv6() {
                println!(
                    "[warn] IPv6 include CIDRs are configured but transparent listener is not IPv6; skipping ip6tables rules"
                );
            } else {
                let dns_capture_v6 = plan.dns_capture && plan.dns_listen_ip.is_ipv6();
                apply_family_rules(
                    exec,
                    "ip6tables",
                    &chain_name_v6(plan.listen_port),
                    plan.listen_port,
                    plan.socks_upstream,
                    &include_v6,
                    &exclude_v6,
                    dns_capture_v6,
                    plan.dns_listen_port,
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn cleanup_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
        if matches!(plan.mode, ModeArg::SystemProxy) {
            return Ok(());
        }

        cleanup_family_rules(
            exec,
            "iptables",
            &chain_name_v4(plan.listen_port),
            plan.dns_capture,
        )
        .await?;

        let dns_capture_v6 = plan.dns_capture && plan.dns_listen_ip.is_ipv6();
        cleanup_family_rules(
            exec,
            "ip6tables",
            &chain_name_v6(plan.listen_port),
            dns_capture_v6,
        )
        .await?;

        Ok(())
    }
}

async fn apply_family_rules(
    exec: &CommandExecutor,
    cmd: &str,
    chain: &str,
    listen_port: u16,
    socks_upstream: std::net::SocketAddr,
    include_cidrs: &[String],
    exclude_cidrs: &[String],
    dns_capture: bool,
    dns_listen_port: u16,
) -> Result<()> {
    exec.run(cmd, ["-t", "nat", "-N", chain]).await.ok();
    exec.run(cmd, ["-t", "nat", "-F", chain]).await?;

    for cidr in exclude_cidrs {
        exec.run(cmd, ["-t", "nat", "-A", chain, "-d", cidr, "-j", "RETURN"])
            .await?;
    }

    exec.run(
        cmd,
        [
            "-t",
            "nat",
            "-A",
            chain,
            "-d",
            &single_host_cidr(socks_upstream.ip()),
            "-p",
            "tcp",
            "--dport",
            &socks_upstream.port().to_string(),
            "-j",
            "RETURN",
        ],
    )
    .await?;

    for cidr in include_cidrs {
        exec.run(
            cmd,
            [
                "-t",
                "nat",
                "-A",
                chain,
                "-p",
                "tcp",
                "-d",
                cidr,
                "-j",
                "REDIRECT",
                "--to-ports",
                &listen_port.to_string(),
            ],
        )
        .await?;

        if dns_capture {
            exec.run(
                cmd,
                [
                    "-t",
                    "nat",
                    "-A",
                    chain,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-d",
                    cidr,
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &dns_listen_port.to_string(),
                ],
            )
            .await?;
        }
    }

    exec.run(cmd, ["-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-j", chain])
        .await
        .ok();
    exec.run(cmd, ["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", chain])
        .await
        .ok();

    if dns_capture {
        exec.run(
            cmd,
            ["-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", chain],
        )
        .await
        .ok();
    }

    Ok(())
}

async fn cleanup_family_rules(
    exec: &CommandExecutor,
    cmd: &str,
    chain: &str,
    dns_capture: bool,
) -> Result<()> {
    exec.run(cmd, ["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", chain])
        .await
        .ok();

    if dns_capture {
        exec.run(
            cmd,
            ["-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", chain],
        )
        .await
        .ok();
    }

    exec.run(cmd, ["-t", "nat", "-F", chain]).await.ok();
    exec.run(cmd, ["-t", "nat", "-X", chain]).await.ok();

    Ok(())
}

fn chain_name_v4(port: u16) -> String {
    format!("SSHUTTLE_RS_{}", port)
}

fn chain_name_v6(port: u16) -> String {
    format!("SSHUTTLE_RS6_{}", port)
}

fn is_ipv6_cidr(cidr: &str) -> bool {
    cidr.contains(':')
}

fn single_host_cidr(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}/32"),
        std::net::IpAddr::V6(v6) => format!("{v6}/128"),
    }
}