use anyhow::Result;
use tokio::task::JoinHandle;

use crate::config::{Cli, Command, ModeArg, RuntimeConfig};
use crate::platform::{build_platform, CommandExecutor};
use crate::proxy::{DnsProxy, TransparentProxy};

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(args) => run_mode(args.into()).await,
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

    if !cfg.no_apply_rules {
        platform.apply_rules(&rules, &exec).await?;
    }

    let mut run_tasks: Vec<JoinHandle<anyhow::Result<()>>> = Vec::new();

    match cfg.mode {
        ModeArg::Transparent => {
            let proxy = TransparentProxy::new(cfg.listen, cfg.socks5);
            println!("[info] run mode: transparent");
            run_tasks.push(tokio::spawn(async move { proxy.run().await }));

            if cfg.dns_capture {
                let dns = DnsProxy::new(cfg.dns_listen, cfg.dns_upstream);
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

    Ok(())
}
