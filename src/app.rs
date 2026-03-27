use anyhow::Result;

use crate::config::{Cli, Command, ModeArg, RuntimeConfig};
use crate::platform::{build_platform, CommandExecutor};
use crate::proxy::TransparentProxy;

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

    if !cfg.no_apply_rules {
        platform.apply_rules(&rules, &exec).await?;
    }

    let run_task = match cfg.mode {
        ModeArg::Transparent => {
            let proxy = TransparentProxy::new(cfg.listen, cfg.socks5);
            println!("[info] run mode: transparent");
            Some(tokio::spawn(async move { proxy.run().await }))
        }
        ModeArg::SystemProxy => {
            println!("[info] run mode: system-proxy");
            println!("[info] system proxy is active; press Ctrl+C to restore settings");
            None
        }
    };

    tokio::signal::ctrl_c().await?;
    println!("[info] received Ctrl+C, shutting down...");

    if let Some(run_task) = run_task {
        run_task.abort();
        let _ = run_task.await;
    }

    if !cfg.no_apply_rules {
        platform.cleanup_rules(&rules, &exec).await?;
    }

    Ok(())
}
