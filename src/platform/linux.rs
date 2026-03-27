use anyhow::Result;
use async_trait::async_trait;
use tokio::process::Command;

use crate::config::{LinuxBackendArg, ModeArg, RulePlan};

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

        let backend = detect_backend(plan.linux_backend).await;
        println!("[info] linux transparent backend: {:?}", backend);
        if matches!(backend, LinuxBackendArg::Nft) {
            return apply_nft_rules(plan, exec).await;
        }

        let (include_v4, include_v6): (Vec<String>, Vec<String>) =
            plan.include_cidrs.iter().cloned().partition(|c| !is_ipv6_cidr(c));
        let (exclude_v4, exclude_v6): (Vec<String>, Vec<String>) =
            plan.exclude_cidrs.iter().cloned().partition(|c| !is_ipv6_cidr(c));

        if !include_v4.is_empty() {
            let chain_v4 = chain_name_v4(plan.listen_port);
            apply_family_rules(
                exec,
                FamilyRules {
                    cmd: "iptables",
                    chain: &chain_v4,
                    listen_port: plan.listen_port,
                    socks_upstream: plan.socks_upstream,
                    include_cidrs: &include_v4,
                    exclude_cidrs: &exclude_v4,
                    dns_capture: plan.dns_capture,
                    dns_listen_port: plan.dns_listen_port,
                },
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
                let chain_v6 = chain_name_v6(plan.listen_port);
                apply_family_rules(
                    exec,
                    FamilyRules {
                        cmd: "ip6tables",
                        chain: &chain_v6,
                        listen_port: plan.listen_port,
                        socks_upstream: plan.socks_upstream,
                        include_cidrs: &include_v6,
                        exclude_cidrs: &exclude_v6,
                        dns_capture: dns_capture_v6,
                        dns_listen_port: plan.dns_listen_port,
                    },
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

        let backend = detect_backend(plan.linux_backend).await;
        if matches!(backend, LinuxBackendArg::Nft) {
            return cleanup_nft_rules(exec).await;
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

async fn detect_backend(selected: LinuxBackendArg) -> LinuxBackendArg {
    match selected {
        LinuxBackendArg::Auto => {
            if has_nft().await {
                LinuxBackendArg::Nft
            } else {
                LinuxBackendArg::Iptables
            }
        }
        b => b,
    }
}

async fn has_nft() -> bool {
    Command::new("nft")
        .arg("--version")
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn apply_nft_rules(plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
    let table = "sshuttle_rs";
    exec.run("nft", ["delete", "table", "inet", table]).await.ok();
    exec.run("nft", ["add", "table", "inet", table]).await?;
    exec.run(
        "nft",
        [
            "add",
            "chain",
            "inet",
            table,
            "output",
            "{",
            "type",
            "nat",
            "hook",
            "output",
            "priority",
            "-100",
            ";",
            "}",
        ],
    )
    .await?;

    for cidr in &plan.exclude_cidrs {
        let fam = if is_ipv6_cidr(cidr) { "ip6" } else { "ip" };
        exec.run(
            "nft",
            [
                "add", "rule", "inet", table, "output", fam, "daddr", cidr, "return",
            ],
        )
        .await?;
    }

    for cidr in &plan.include_cidrs {
        let fam = if is_ipv6_cidr(cidr) { "ip6" } else { "ip" };
        exec.run(
            "nft",
            [
                "add",
                "rule",
                "inet",
                table,
                "output",
                fam,
                "daddr",
                cidr,
                "tcp",
                "redirect",
                "to",
                &plan.listen_port.to_string(),
            ],
        )
        .await?;
        if plan.dns_capture {
            exec.run(
                "nft",
                [
                    "add",
                    "rule",
                    "inet",
                    table,
                    "output",
                    fam,
                    "daddr",
                    cidr,
                    "udp",
                    "dport",
                    "53",
                    "redirect",
                    "to",
                    &plan.dns_listen_port.to_string(),
                ],
            )
            .await?;
        }
    }
    Ok(())
}

async fn cleanup_nft_rules(exec: &CommandExecutor) -> Result<()> {
    exec.run("nft", ["delete", "table", "inet", "sshuttle_rs"])
        .await
        .ok();
    Ok(())
}

struct FamilyRules<'a> {
    cmd: &'a str,
    chain: &'a str,
    listen_port: u16,
    socks_upstream: std::net::SocketAddr,
    include_cidrs: &'a [String],
    exclude_cidrs: &'a [String],
    dns_capture: bool,
    dns_listen_port: u16,
}

async fn apply_family_rules(
    exec: &CommandExecutor,
    cfg: FamilyRules<'_>,
) -> Result<()> {
    exec.run(cfg.cmd, ["-t", "nat", "-N", cfg.chain]).await.ok();
    exec.run(cfg.cmd, ["-t", "nat", "-F", cfg.chain]).await?;

    for cidr in cfg.exclude_cidrs {
        exec.run(cfg.cmd, ["-t", "nat", "-A", cfg.chain, "-d", cidr, "-j", "RETURN"])
            .await?;
    }

    exec.run(
        cfg.cmd,
        [
            "-t",
            "nat",
            "-A",
            cfg.chain,
            "-d",
            &single_host_cidr(cfg.socks_upstream.ip()),
            "-p",
            "tcp",
            "--dport",
            &cfg.socks_upstream.port().to_string(),
            "-j",
            "RETURN",
        ],
    )
    .await?;

    for cidr in cfg.include_cidrs {
        exec.run(
            cfg.cmd,
            [
                "-t",
                "nat",
                "-A",
                cfg.chain,
                "-p",
                "tcp",
                "-d",
                cidr,
                "-j",
                "REDIRECT",
                "--to-ports",
                &cfg.listen_port.to_string(),
            ],
        )
        .await?;

        if cfg.dns_capture {
            exec.run(
                cfg.cmd,
                [
                    "-t",
                    "nat",
                    "-A",
                    cfg.chain,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-d",
                    cidr,
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &cfg.dns_listen_port.to_string(),
                ],
            )
            .await?;
        }
    }

    exec.run(cfg.cmd, ["-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-j", cfg.chain])
        .await
        .ok();
    exec.run(cfg.cmd, ["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", cfg.chain])
        .await
        .ok();

    if cfg.dns_capture {
        exec.run(
            cfg.cmd,
            ["-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", cfg.chain],
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
