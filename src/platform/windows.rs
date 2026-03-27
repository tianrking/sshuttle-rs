use anyhow::{Result, bail};
use async_trait::async_trait;
use std::path::PathBuf;

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
                persist_previous_proxy_state(exec, key).await?;

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

                exec.run("RUNDLL32.EXE", ["USER32.DLL,UpdatePerUserSystemParameters"])
                    .await
                    .ok();

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
        if restore_previous_proxy_state(exec, key).await? {
            exec.run("RUNDLL32.EXE", ["USER32.DLL,UpdatePerUserSystemParameters"])
                .await
                .ok();
            println!("[info] windows system proxy restored from saved state");
            return Ok(());
        }

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

        exec.run("RUNDLL32.EXE", ["USER32.DLL,UpdatePerUserSystemParameters"])
            .await
            .ok();

        println!("[info] windows system proxy restored");
        Ok(())
    }
}

async fn persist_previous_proxy_state(exec: &CommandExecutor, key: &str) -> Result<()> {
    let enable_raw = exec
        .capture("reg", ["query", key, "/v", "ProxyEnable"])
        .await
        .unwrap_or_default();
    let server_raw = exec
        .capture("reg", ["query", key, "/v", "ProxyServer"])
        .await
        .unwrap_or_default();

    let enable = parse_reg_value(&enable_raw, "ProxyEnable").unwrap_or_else(|| "0x0".to_string());
    let server = parse_reg_value(&server_raw, "ProxyServer").unwrap_or_default();
    let payload = format!("{}\n{}", enable, server);

    if exec
        .capture(
            "powershell",
            [
                "-NoProfile",
                "-Command",
                &format!(
                    "Set-Content -Encoding UTF8 -Path '{}' -Value @'\n{}\n'@",
                    state_file_path().display(),
                    payload
                ),
            ],
        )
        .await
        .is_err()
    {
        // best effort only
    }

    Ok(())
}

async fn restore_previous_proxy_state(exec: &CommandExecutor, key: &str) -> Result<bool> {
    let script = format!(
        "if (Test-Path '{}') {{ Get-Content '{}' -Raw }}",
        state_file_path().display(),
        state_file_path().display()
    );
    let raw = exec
        .capture("powershell", ["-NoProfile", "-Command", &script])
        .await
        .unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(false);
    }

    let mut lines = raw.lines();
    let enable = lines.next().unwrap_or("0x0").trim();
    let server = lines.next().unwrap_or("").trim();

    let enable_decimal = if enable.eq_ignore_ascii_case("0x1") || enable == "1" {
        "1"
    } else {
        "0"
    };

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
            enable_decimal,
            "/f",
        ],
    )
    .await
    .ok();

    if server.is_empty() {
        exec.run("reg", ["delete", key, "/v", "ProxyServer", "/f"])
            .await
            .ok();
    } else {
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
                server,
                "/f",
            ],
        )
        .await
        .ok();
    }

    exec.run(
        "powershell",
        [
            "-NoProfile",
            "-Command",
            &format!("Remove-Item -Force '{}' -ErrorAction SilentlyContinue", state_file_path().display()),
        ],
    )
    .await
    .ok();

    Ok(true)
}

fn parse_reg_value(raw: &str, name: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        if !line.contains(name) {
            return None;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        parts.last().map(|s| s.to_string())
    })
}

fn state_file_path() -> PathBuf {
    std::env::temp_dir().join("sshuttle-rs-proxy-state.txt")
}
