use anyhow::Result;
use async_trait::async_trait;

use crate::config::RulePlan;

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
        "linux/iptables"
    }

    async fn apply_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
        let chain = chain_name(plan.listen_port);

        exec.run("iptables", ["-t", "nat", "-N", &chain]).await.ok();
        exec.run("iptables", ["-t", "nat", "-F", &chain]).await?;

        for cidr in &plan.exclude_cidrs {
            exec.run(
                "iptables",
                ["-t", "nat", "-A", &chain, "-d", cidr, "-j", "RETURN"],
            )
            .await?;
        }

        exec.run(
            "iptables",
            [
                "-t",
                "nat",
                "-A",
                &chain,
                "-d",
                &format!("{}/32", plan.socks_upstream.ip()),
                "-p",
                "tcp",
                "--dport",
                &plan.socks_upstream.port().to_string(),
                "-j",
                "RETURN",
            ],
        )
        .await?;

        for cidr in &plan.include_cidrs {
            exec.run(
                "iptables",
                [
                    "-t",
                    "nat",
                    "-A",
                    &chain,
                    "-p",
                    "tcp",
                    "-d",
                    cidr,
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &plan.listen_port.to_string(),
                ],
            )
            .await?;
        }

        exec.run(
            "iptables",
            ["-t", "nat", "-C", "OUTPUT", "-j", &chain],
        )
        .await
        .ok();

        exec.run(
            "iptables",
            ["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", &chain],
        )
        .await
        .ok();

        Ok(())
    }

    async fn cleanup_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
        let chain = chain_name(plan.listen_port);

        exec.run(
            "iptables",
            ["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", &chain],
        )
        .await
        .ok();

        exec.run("iptables", ["-t", "nat", "-F", &chain]).await.ok();
        exec.run("iptables", ["-t", "nat", "-X", &chain]).await.ok();

        Ok(())
    }
}

fn chain_name(port: u16) -> String {
    format!("SSHUTTLE_RS_{}", port)
}