use anyhow::Result;
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{Duration, sleep};

use crate::config::WinNativeWorkerArgs;

pub async fn run(args: WinNativeWorkerArgs) -> Result<()> {
    println!(
        "[win-native-worker] started: listen_port={} proxy={} bypass_processes={} ",
        args.listen_port,
        args.proxy_addr,
        args.bypass_processes.join(",")
    );
    println!("[win-native-worker] trying WinDivert engine handoff...");

    if let Some(mut child) = try_start_external_engine(&args).await? {
        println!("[win-native-worker] external engine started, supervising");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("[win-native-worker] stop signal received");
            }
            r = child.wait() => {
                println!("[win-native-worker] external engine exited: {:?}", r);
            }
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Ok(());
    }

    println!("[win-native-worker] no external WinDivert engine found; running minimal fallback loop");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("[win-native-worker] stop signal received, exiting");
                break;
            }
            _ = sleep(Duration::from_secs(3)) => {
                println!("[win-native-worker] heartbeat: fallback mode active");
            }
        }
    }
    Ok(())
}

async fn try_start_external_engine(
    args: &WinNativeWorkerArgs,
) -> Result<Option<tokio::process::Child>> {
    let mut cmd_candidates = vec!["sshuttle-rs-windivert.exe".to_string()];
    if let Ok(env_cmd) = std::env::var("SSHUTTLE_RS_WINDIVERT_ENGINE")
        && !env_cmd.trim().is_empty()
    {
        cmd_candidates.insert(0, env_cmd);
    }

    for bin in cmd_candidates {
        let mut cmd = Command::new(&bin);
        cmd.arg("--listen-port")
            .arg(args.listen_port.to_string())
            .arg("--proxy-addr")
            .arg(args.proxy_addr.to_string());
        for p in &args.bypass_processes {
            cmd.arg("--bypass-process").arg(p);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        match cmd.spawn() {
            Ok(child) => {
                println!("[win-native-worker] using external engine binary: {}", bin);
                return Ok(Some(child));
            }
            Err(_) => continue,
        }
    }

    Ok(None)
}
