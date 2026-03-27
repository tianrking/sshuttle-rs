use anyhow::Result;
use std::process::Stdio;
use tokio::task::JoinHandle;
use tokio::{process::Child, process::Command as TokioCommand, time::Duration};

use crate::config::{Cli, Command, ExplainConfig, ModeArg, ProxyTypeArg, RuntimeConfig};
use crate::doctor;
use crate::platform::{CommandExecutor, build_platform};
use crate::policy::{FlowContext, PolicyFile};
use crate::proxy::{DnsProxy, TransparentProxy, UdpTransparentProxy};
use crate::win_native;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(args) => run_mode(args.into()).await,
        Command::Doctor(args) => doctor::run(args.into()).await,
        Command::Cleanup(args) => cleanup_mode(args.into()).await,
        Command::Explain(args) => explain_mode(args.into()).await,
        Command::WinNativeWorker(args) => win_native::run(args).await,
    }
}

async fn run_mode(mut cfg: RuntimeConfig) -> Result<()> {
    if let Some(path) = cfg.policy_file.clone() {
        let policy = PolicyFile::load(path.as_path())?;
        let validation = policy.validate();
        if !validation.errors.is_empty() {
            for e in validation.errors {
                eprintln!("[error][policy] {e}");
            }
            anyhow::bail!("policy validation failed");
        }
        for w in validation.warnings {
            println!("[warn][policy] {w}");
        }
        let inferred_bypass = policy.static_bypass_processes();
        if !inferred_bypass.is_empty() {
            let mut added = 0usize;
            for p in inferred_bypass {
                if !cfg
                    .bypass_processes
                    .iter()
                    .any(|x| x.eq_ignore_ascii_case(&p))
                {
                    cfg.bypass_processes.push(p);
                    added += 1;
                }
            }
            if added > 0 {
                println!("[info] policy preloaded: added {added} static bypass process entries");
            }
        }
    }

    let platform = build_platform(cfg.requested_platform)?;
    let exec = CommandExecutor::new(cfg.dry_run);
    let rules = cfg.to_rule_plan();

    println!("[info] selected platform backend: {}", platform.name());
    println!(
        "[info] upstream proxy: {} ({:?})",
        cfg.proxy, cfg.proxy_type
    );
    println!("[info] transparent listen: {}", cfg.listen);
    println!(
        "[info] dns capture: {}",
        if cfg.dns_capture { "on" } else { "off" }
    );

    let mut ssh_tunnel = start_ssh_dynamic_tunnel(&cfg).await?;

    if !cfg.no_apply_rules {
        platform.apply_rules(&rules, &exec).await?;
    }

    let mut run_tasks: Vec<JoinHandle<anyhow::Result<()>>> = Vec::new();

    match cfg.mode {
        ModeArg::Transparent => {
            println!("[info] run mode: transparent");
            if platform.name().starts_with("linux/") {
                let proxy = TransparentProxy::new(cfg.listen, cfg.proxy, cfg.proxy_type);
                run_tasks.push(tokio::spawn(async move { proxy.run().await }));
            } else {
                println!(
                    "[info] transparent runtime is delegated to platform backend worker/native engine"
                );
            }

            if cfg.dns_capture {
                let via_socks = cfg.dns_via_socks && cfg.proxy_type == ProxyTypeArg::Socks5;
                if cfg.dns_via_socks && !via_socks {
                    println!(
                        "[warn] DNS via proxy is only supported with socks5; fallback to direct DNS upstream"
                    );
                }
                let dns = DnsProxy::new(cfg.dns_listen, cfg.dns_upstream, cfg.proxy, via_socks);
                run_tasks.push(tokio::spawn(async move { dns.run().await }));
            }

            if cfg.udp_capture {
                if cfg.proxy_type != ProxyTypeArg::Socks5 {
                    println!(
                        "[warn] udp capture currently requires socks5 upstream; skip udp capture"
                    );
                } else if platform.name().starts_with("linux/") {
                    let udp = UdpTransparentProxy::new(cfg.udp_listen, cfg.proxy);
                    run_tasks.push(tokio::spawn(async move { udp.run().await }));
                } else {
                    println!("[warn] udp capture runtime currently implemented for linux only");
                }
            }
        }
        ModeArg::SystemProxy => {
            println!("[info] run mode: system-proxy");
            println!("[info] system proxy is active; press Ctrl+C to restore settings");
        }
    }

    tokio::signal::ctrl_c().await?;
    println!("[info] received Ctrl+C, shutting down...");

    for run_task in run_tasks {
        run_task.abort();
        let _ = run_task.await;
    }

    if !cfg.no_apply_rules {
        platform.cleanup_rules(&rules, &exec).await?;
    }

    if let Some(mut child) = ssh_tunnel.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    Ok(())
}

async fn start_ssh_dynamic_tunnel(cfg: &RuntimeConfig) -> Result<Option<Child>> {
    let Some(remote) = &cfg.ssh_remote else {
        return Ok(None);
    };
    if cfg.proxy_type != ProxyTypeArg::Socks5 {
        anyhow::bail!("--ssh-remote is only supported with --proxy-type socks5");
    }

    println!(
        "[info] starting ssh dynamic tunnel: {} -N -D {} {}",
        cfg.ssh_cmd, cfg.proxy, remote
    );

    let mut child = TokioCommand::new(&cfg.ssh_cmd)
        .arg("-N")
        .arg("-D")
        .arg(cfg.proxy.to_string())
        .arg(remote)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(600)).await;
    if let Some(status) = child.try_wait()? {
        anyhow::bail!("ssh dynamic tunnel exited early with status: {status}");
    }

    Ok(Some(child))
}

async fn cleanup_mode(cfg: RuntimeConfig) -> Result<()> {
    let platform = build_platform(cfg.requested_platform)?;
    let exec = CommandExecutor::new(cfg.dry_run);
    let rules = cfg.to_rule_plan();
    println!(
        "[info] running cleanup for platform backend: {}",
        platform.name()
    );
    platform.cleanup_rules(&rules, &exec).await
}

async fn explain_mode(cfg: ExplainConfig) -> Result<()> {
    let policy = PolicyFile::load(cfg.policy_file.as_path())?;
    let flow = FlowContext {
        process_name: cfg.process_name,
        process_path: cfg.process_path,
        dst: cfg.dst,
        proto: cfg.proto,
    };
    let decision = policy.explain(&flow);
    println!("[explain] action={:?}", decision.action);
    match decision.matched_rule {
        Some(rule) => println!(
            "[explain] matched_rule={} index={} priority={}",
            rule,
            decision.matched_index.unwrap_or(0),
            decision.matched_priority.unwrap_or(0)
        ),
        None => println!("[explain] matched_rule=<default>"),
    }
    Ok(())
}
