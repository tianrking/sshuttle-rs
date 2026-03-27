use anyhow::Result;
use tokio::process::Command;

use crate::config::{DoctorConfig, LinuxBackendArg, ModeArg, PlatformArg, ProxyTypeArg};
use crate::policy::{FlowContext, PolicyAction, PolicyFile};

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
                    missing +=
                        check_cmd("nft", &["--version"], "nftables userspace").await as usize;
                }
                LinuxBackendArg::Iptables | LinuxBackendArg::Auto => {
                    missing += check_cmd("iptables", &["--version"], "iptables").await as usize;
                    missing += check_cmd("ip6tables", &["--version"], "ip6tables").await as usize;
                }
            }
        }
        "windows" => {
            missing += check_cmd("reg", &["/?"], "registry tool").await as usize;
            missing += check_cmd(
                "powershell",
                &["-NoProfile", "-Command", "$PSVersionTable.PSVersion"],
                "powershell",
            )
            .await as usize;
            if matches!(cfg.mode, ModeArg::Transparent) {
                println!(
                    "[doctor] transparent mode on windows uses built-in native worker (external worker override optional)"
                );
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

    if let Some(path) = &cfg.policy_file {
        let policy = PolicyFile::load(path)?;
        println!(
            "[doctor] policy: {} (rules={})",
            path.display(),
            policy.rules.len()
        );
        if cfg.bypass_check_processes.is_empty() {
            let inferred = policy.static_bypass_processes();
            if inferred.is_empty() {
                println!("[doctor] bypass-check: no static bypass process inferred from policy");
            } else {
                println!(
                    "[doctor] bypass-check: inferred static process entries = {}",
                    inferred.join(", ")
                );
            }
        } else {
            for p in &cfg.bypass_check_processes {
                let flow = FlowContext {
                    process_name: Some(p.clone()),
                    process_path: Some(p.clone()),
                    dst: cfg.bypass_check_dst,
                    proto: cfg.bypass_check_proto,
                };
                let decision = policy.explain(&flow);
                if decision.action == PolicyAction::Bypass {
                    println!(
                        "[doctor][ok] bypass-check process={} dst={} -> BYPASS ({})",
                        p,
                        cfg.bypass_check_dst,
                        decision.matched_rule.as_deref().unwrap_or("default"),
                    );
                } else {
                    println!(
                        "[doctor][warn] bypass-check process={} dst={} -> {:?} ({})",
                        p,
                        cfg.bypass_check_dst,
                        decision.action,
                        decision.matched_rule.as_deref().unwrap_or("default"),
                    );
                }
            }
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
