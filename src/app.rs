use anyhow::Result;
use std::process::Stdio;
use tokio::task::JoinHandle;
use tokio::{process::Child, process::Command as TokioCommand, time::Duration};

use crate::config::{Cli, Command, ModeArg, RuntimeConfig};
use crate::doctor;
use crate::platform::{build_platform, CommandExecutor};
use crate::proxy::{DnsProxy, TransparentProxy};

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(args) => run_mode(args.into()).await,
        Command::Doctor(args) => doctor::run(args.into()).await,
        Command::Cleanup(args) => cleanup_mode(args.into()).await,
    }
}

async fn run_mode(cfg: RuntimeConfig) -> Result<()> {
    let platform = build_platform(cfg.requested_platform)?;
    let exec = CommandExecutor::new(cfg.dry_run);
    let rules = cfg.to_rule_plan();

    println!("[info] selected platform backend: {}", platform.name());
    println!("[info] socks5 upstream: {}", cfg.socks5);
    println!("[info] transparent listen: {}", cfg.listen);
    println!("[info] dns capture: {}", if cfg.dns_capture { "on" } else { "off" });

    let mut ssh_tunnel = start_ssh_dynamic_tunnel(&cfg).await?;

    if !cfg.no_apply_rules {
        platform.apply_rules(&rules, &exec).await?;
    }

    let mut run_tasks: Vec<JoinHandle<anyhow::Result<()>>> = Vec::new();

    match cfg.mode {
        ModeArg::Transparent => {
            println!("[info] run mode: transparent");
            if platform.name().starts_with("linux/") {
                let proxy = TransparentProxy::new(cfg.listen, cfg.socks5);
                run_tasks.push(tokio::spawn(async move { proxy.run().await }));
            } else {
                println!(
                    "[info] transparent runtime is delegated to platform backend worker/native engine"
                );
            }

            if cfg.dns_capture {
                let dns = DnsProxy::new(cfg.dns_listen, cfg.dns_upstream, cfg.socks5, cfg.dns_via_socks);
                run_tasks.push(tokio::spawn(async move { dns.run().await }));
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

    println!(
        "[info] starting ssh dynamic tunnel: {} -N -D {} {}",
        cfg.ssh_cmd, cfg.socks5, remote
    );

    let mut child = TokioCommand::new(&cfg.ssh_cmd)
        .arg("-N")
        .arg("-D")
        .arg(cfg.socks5.to_string())
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
    println!("[info] running cleanup for platform backend: {}", platform.name());
    platform.cleanup_rules(&rules, &exec).await
}
