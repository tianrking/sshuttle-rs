use anyhow::{Result, bail};
use async_trait::async_trait;

use crate::config::ModeArg;
use crate::config::RulePlan;

use super::{CommandExecutor, Platform};

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Platform for WindowsPlatform {
    fn name(&self) -> &'static str {
        "windows/system-proxy+transparent-planned"
    }

    async fn apply_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
        match plan.mode {
            ModeArg::Transparent => {
                bail!(
                    "Windows transparent redirect backend is not implemented yet (planned: WinDivert/WFP)"
                )
            }
            ModeArg::SystemProxy => {
                let proxy = format!("socks={}:{}", plan.socks_upstream.ip(), plan.socks_upstream.port());
                let key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

                exec.run(
                    "reg",
                    [
                        "add",
                        key,
                        "/v",
                        "ProxyEnable",
                        "/t",
                        "REG_DWORD",
                        "/d",
                        "1",
                        "/f",
                    ],
                )
                .await?;

                exec.run(
                    "reg",
                    [
                        "add",
                        key,
                        "/v",
                        "ProxyServer",
                        "/t",
                        "REG_SZ",
                        "/d",
                        &proxy,
                        "/f",
                    ],
                )
                .await?;

                println!("[info] windows system proxy applied: {}", proxy);
                Ok(())
            }
        }
    }

    async fn cleanup_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
        if matches!(plan.mode, ModeArg::Transparent) {
            return Ok(());
        }

        let key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

        exec.run(
            "reg",
            [
                "add",
                key,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ],
        )
        .await
        .ok();

        exec.run("reg", ["delete", key, "/v", "ProxyServer", "/f"])
            .await
            .ok();

        println!("[info] windows system proxy restored");
        Ok(())
    }
}
