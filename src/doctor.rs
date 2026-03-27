use anyhow::Result;
use tokio::process::Command;

use crate::config::{DoctorConfig, LinuxBackendArg, ModeArg, PlatformArg, ProxyTypeArg};

pub async fn run(cfg: DoctorConfig) -> Result<()> {
    let platform = resolved_platform(cfg.requested_platform);
    println!("[doctor] target platform: {}", platform);
    println!("[doctor] mode: {:?}", cfg.mode);

    let mut missing = 0usize;

    if cfg.ssh_remote.is_some() {
        missing += check_cmd(&cfg.ssh_cmd, &["-V"], "ssh command").await as usize;
    }

    match platform.as_str() {
        "linux" => {
            let backend = resolved_linux_backend(cfg.linux_backend).await;
            println!("[doctor] linux backend: {:?}", backend);
            match backend {
                LinuxBackendArg::Nft => {
                    missing += check_cmd("nft", &["--version"], "nftables userspace").await as usize;
                }
                LinuxBackendArg::Iptables | LinuxBackendArg::Auto => {
                    missing += check_cmd("iptables", &["--version"], "iptables").await as usize;
                    missing += check_cmd("ip6tables", &["--version"], "ip6tables").await as usize;
                }
            }
        }
        "windows" => {
            missing += check_cmd("reg", &["/?"], "registry tool").await as usize;
            missing += check_cmd("powershell", &["-NoProfile", "-Command", "$PSVersionTable.PSVersion"], "powershell").await as usize;
            if matches!(cfg.mode, ModeArg::Transparent) {
                println!("[doctor] transparent mode on windows currently requires --win-transparent-cmd runtime input");
                missing += check_cmd("taskkill", &["/?"], "taskkill").await as usize;
            }
        }
        _ => {
            println!("[doctor] unsupported auto-detected platform");
            missing += 1;
        }
    }

    if cfg.dns_capture && cfg.dns_via_socks {
        if cfg.proxy_type == ProxyTypeArg::Socks5 {
            println!("[doctor] DNS over SOCKS UDP associate is enabled");
        } else {
            println!(
                "[doctor][warn] --dns-via-socks requires --proxy-type socks5, current={:?}",
                cfg.proxy_type
            );
        }
    }

    if missing == 0 {
        println!("[doctor] result: OK");
    } else {
        println!("[doctor] result: MISSING ({missing} checks failed)");
    }

    Ok(())
}

async fn check_cmd(cmd: &str, args: &[&str], label: &str) -> bool {
    let ok = Command::new(cmd)
        .args(args)
        .status()
        .await
        .map(|s| s.success() || s.code().is_some())
        .unwrap_or(false);

    if ok {
        println!("[doctor][ok] {} ({})", label, cmd);
        false
    } else {
        println!("[doctor][missing] {} ({})", label, cmd);
        true
    }
}

fn resolved_platform(p: PlatformArg) -> String {
    match p {
        PlatformArg::Linux => "linux".to_string(),
        PlatformArg::Windows => "windows".to_string(),
        PlatformArg::Auto => {
            if cfg!(target_os = "linux") {
                "linux".to_string()
            } else if cfg!(target_os = "windows") {
                "windows".to_string()
            } else {
                "unknown".to_string()
            }
        }
    }
}

async fn resolved_linux_backend(b: LinuxBackendArg) -> LinuxBackendArg {
    match b {
        LinuxBackendArg::Auto => {
            let has_nft = Command::new("nft")
                .arg("--version")
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if has_nft {
                LinuxBackendArg::Nft
            } else {
                LinuxBackendArg::Iptables
            }
        }
        other => other,
    }
}
