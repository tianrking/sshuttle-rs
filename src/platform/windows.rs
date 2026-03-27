use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use crate::config::RulePlan;
use crate::config::{ModeArg, ProxyTypeArg};

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
        "windows/system-proxy+transparent-worker"
    }

    async fn apply_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
        match plan.mode {
            ModeArg::Transparent => apply_transparent_worker(plan, exec).await,
            ModeArg::SystemProxy => {
                if !plan.bypass_processes.is_empty() {
                    println!(
                        "[warn] windows system-proxy mode cannot enforce per-process bypass list; use transparent mode worker/native backend"
                    );
                }
                let proxy = match plan.proxy_type {
                    ProxyTypeArg::Socks5 | ProxyTypeArg::Socks4 => {
                        format!(
                            "socks={}:{}",
                            plan.proxy_upstream.ip(),
                            plan.proxy_upstream.port()
                        )
                    }
                    ProxyTypeArg::Http => {
                        format!(
                            "http={}:{}",
                            plan.proxy_upstream.ip(),
                            plan.proxy_upstream.port()
                        )
                    }
                };
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
            return cleanup_transparent_worker(plan, exec).await;
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

async fn apply_transparent_worker(plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
    let rendered = if let Some(cmd_tpl) = &plan.win_transparent_cmd {
        render_transparent_cmd(cmd_tpl, plan)
    } else {
        built_in_worker_cmd(plan)?
    };
    let with_env = if plan.bypass_processes.is_empty() {
        rendered.clone()
    } else {
        let env_value = plan.bypass_processes.join(";");
        format!("set SSHUTTLE_RS_BYPASS_PROCESSES={env_value}&& {rendered}")
    };
    let ps_script = format!(
        "$p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/C {}' -PassThru -WindowStyle Hidden; \
Set-Content -Path '{}' -Value $p.Id; \
Write-Output $p.Id",
        escape_for_single_quote(&with_env),
        worker_pid_file_path().display()
    );
    let pid = exec
        .capture("powershell", ["-NoProfile", "-Command", &ps_script])
        .await?;
    println!(
        "[info] windows transparent worker started (pid={}) with command: {}",
        pid.trim(),
        with_env
    );
    Ok(())
}

async fn cleanup_transparent_worker(plan: &RulePlan, exec: &CommandExecutor) -> Result<()> {
    if let Some(stop_tpl) = &plan.win_transparent_stop_cmd {
        let rendered = render_transparent_cmd(stop_tpl, plan);
        exec.run("cmd.exe", ["/C", &rendered]).await.ok();
        println!(
            "[info] windows transparent worker stop command executed: {}",
            rendered
        );
        return Ok(());
    }

    let pid_script = format!(
        "if (Test-Path '{}') {{ Get-Content '{}' -Raw }}",
        worker_pid_file_path().display(),
        worker_pid_file_path().display()
    );
    let pid_raw = exec
        .capture("powershell", ["-NoProfile", "-Command", &pid_script])
        .await
        .unwrap_or_default();
    let pid = pid_raw.trim();
    if !pid.is_empty() {
        exec.run("taskkill", ["/PID", pid, "/T", "/F"]).await.ok();
    }
    exec.run(
        "powershell",
        [
            "-NoProfile",
            "-Command",
            &format!(
                "Remove-Item -Force '{}' -ErrorAction SilentlyContinue",
                worker_pid_file_path().display()
            ),
        ],
    )
    .await
    .ok();
    println!("[info] windows transparent worker stopped");
    Ok(())
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
            &format!(
                "Remove-Item -Force '{}' -ErrorAction SilentlyContinue",
                state_file_path().display()
            ),
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

fn worker_pid_file_path() -> PathBuf {
    std::env::temp_dir().join("sshuttle-rs-win-transparent.pid")
}

fn render_transparent_cmd(tpl: &str, plan: &RulePlan) -> String {
    let bypass_csv = plan.bypass_processes.join(",");
    let bypass_semicolon = plan.bypass_processes.join(";");
    let policy_file = plan
        .policy_file
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    tpl.replace("{listen_port}", &plan.listen_port.to_string())
        .replace("{proxy_host}", &plan.proxy_upstream.ip().to_string())
        .replace("{proxy_port}", &plan.proxy_upstream.port().to_string())
        .replace("{proxy_addr}", &plan.proxy_upstream.to_string())
        .replace("{policy_file}", &policy_file)
        .replace("{bypass_processes_csv}", &bypass_csv)
        .replace("{bypass_processes_semicolon}", &bypass_semicolon)
        .replace("{socks_host}", &plan.proxy_upstream.ip().to_string())
        .replace("{socks_port}", &plan.proxy_upstream.port().to_string())
        .replace("{socks_addr}", &plan.proxy_upstream.to_string())
}

fn escape_for_single_quote(s: &str) -> String {
    s.replace('\'', "''")
}

fn built_in_worker_cmd(plan: &RulePlan) -> Result<String> {
    let exe = std::env::current_exe()?;
    let mut parts = vec![
        quote_cmd_arg(exe.to_string_lossy().as_ref()),
        "win-native-worker".to_string(),
        "--listen-ip".to_string(),
        plan.listen_ip.to_string(),
        "--listen-port".to_string(),
        plan.listen_port.to_string(),
        "--proxy-addr".to_string(),
        quote_cmd_arg(&plan.proxy_upstream.to_string()),
    ];
    for p in &plan.bypass_processes {
        parts.push("--bypass-process".to_string());
        parts.push(quote_cmd_arg(p));
    }
    if let Some(path) = &plan.policy_file {
        parts.push("--policy-file".to_string());
        parts.push(quote_cmd_arg(path.to_string_lossy().as_ref()));
    }
    if plan.dns_capture {
        parts.push("--dns-capture".to_string());
        parts.push("true".to_string());
    }
    parts.push("--dns-listen-port".to_string());
    parts.push(plan.dns_listen_port.to_string());
    if plan.udp_capture {
        parts.push("--udp-capture".to_string());
        parts.push("true".to_string());
    }
    parts.push("--udp-listen-port".to_string());
    parts.push(plan.udp_listen_port.to_string());
    for p in &plan.udp_ports {
        parts.push("--udp-port".to_string());
        parts.push(p.to_string());
    }
    Ok(parts.join(" "))
}

fn quote_cmd_arg(s: &str) -> String {
    if s.contains(' ') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::render_transparent_cmd;
    use crate::config::{LinuxBackendArg, ModeArg, ProxyTypeArg, RulePlan};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sample_plan() -> RulePlan {
        RulePlan {
            mode: ModeArg::Transparent,
            listen_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            listen_port: 18080,
            proxy_upstream: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 1080)),
            proxy_type: ProxyTypeArg::Socks5,
            include_cidrs: vec!["0.0.0.0/0".to_string()],
            exclude_cidrs: vec![],
            bypass_uids: vec![],
            bypass_gids: vec![],
            bypass_processes: vec!["foo.exe".to_string(), "bar.exe".to_string()],
            dns_capture: false,
            dns_listen_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dns_listen_port: 15353,
            win_transparent_cmd: None,
            win_transparent_stop_cmd: None,
            policy_file: None,
            linux_backend: LinuxBackendArg::Auto,
            udp_capture: false,
            udp_listen_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            udp_listen_port: 19090,
            udp_ports: vec![],
        }
    }

    #[test]
    fn render_cmd_replaces_placeholders() {
        let p = sample_plan();
        let out = render_transparent_cmd(
            "worker --listen {listen_port} --proxy {proxy_addr} --bypass {bypass_processes_csv}",
            &p,
        );
        assert!(out.contains("18080"));
        assert!(out.contains("127.0.0.1:1080"));
        assert!(out.contains("foo.exe,bar.exe"));
    }
}
