use anyhow::Result;
use serde::Deserialize;
use std::collections::HashSet;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::time::{Duration, sleep};

use crate::config::WinNativeWorkerArgs;
use crate::policy::{FlowContext, FlowProto, PolicyFile};

pub async fn run(args: WinNativeWorkerArgs) -> Result<()> {
    let policy = if let Some(path) = args.policy_file.as_ref() {
        let p = PolicyFile::load(path.as_path())?;
        println!(
            "[win-native-worker] loaded policy: {} (rules={})",
            path.display(),
            p.rules.len()
        );
        Some(Arc::new(p))
    } else {
        None
    };

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

    println!(
        "[win-native-worker] no external WinDivert engine found; running minimal fallback loop"
    );
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("[win-native-worker] stop signal received, exiting");
                break;
            }
            _ = sleep(Duration::from_secs(3)) => {
                if let Some(policy) = policy.clone()
                    && let Err(err) = classify_live_tcp_flows(policy, &args.bypass_processes, &mut seen).await
                {
                    eprintln!("[win-native-worker][warn] policy classification failed: {err:#}");
                }
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
        if let Some(path) = &args.policy_file {
            cmd.arg("--policy-file").arg(path);
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

#[derive(Debug, Deserialize)]
struct WinConnRow {
    #[serde(rename = "ProcessName")]
    process_name: Option<String>,
    #[serde(rename = "ProcessPath")]
    process_path: Option<String>,
    #[serde(rename = "RemoteAddress")]
    remote_address: Option<String>,
    #[serde(rename = "RemotePort")]
    remote_port: Option<u16>,
}

async fn classify_live_tcp_flows(
    policy: Arc<PolicyFile>,
    bypass_processes: &[String],
    seen: &mut HashSet<String>,
) -> Result<()> {
    let rows = sample_windows_tcp_rows().await?;
    for row in rows {
        let Some(addr) = row.remote_address else {
            continue;
        };
        let Some(port) = row.remote_port else {
            continue;
        };
        if addr == "127.0.0.1" || addr == "::1" || addr == "0.0.0.0" || addr == "::" {
            continue;
        }
        let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
            continue;
        };
        let flow = FlowContext {
            process_name: row.process_name.clone(),
            process_path: row.process_path.clone(),
            dst: std::net::SocketAddr::from((ip, port)),
            proto: FlowProto::Tcp,
        };
        let decision = policy.explain(&flow);
        let key = format!(
            "{}|{}|{}|{:?}",
            flow.process_name.as_deref().unwrap_or("-"),
            flow.process_path.as_deref().unwrap_or("-"),
            flow.dst,
            decision.action
        );
        if seen.insert(key) {
            println!(
                "[win-native-worker][policy] {:?} proc={} path={} dst={} rule={}",
                decision.action,
                flow.process_name.as_deref().unwrap_or("-"),
                flow.process_path.as_deref().unwrap_or("-"),
                flow.dst,
                decision.matched_rule.as_deref().unwrap_or("default")
            );
        }
    }

    for p in bypass_processes {
        if seen.insert(format!("bypass-list:{p}")) {
            println!("[win-native-worker][policy] bypass-list contains: {p}");
        }
    }

    Ok(())
}

async fn sample_windows_tcp_rows() -> Result<Vec<WinConnRow>> {
    let script = r#"
$rows = @()
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  if ($null -ne $proc) {
    $rows += [pscustomobject]@{
      ProcessName = $proc.ProcessName
      ProcessPath = $proc.Path
      RemoteAddress = $_.RemoteAddress
      RemotePort = $_.RemotePort
    }
  }
}
$rows | ConvertTo-Json -Compress
"#;
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .stdin(Stdio::null())
        .output()
        .await?;
    if !out.status.success() {
        return Ok(vec![]);
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() || text == "null" {
        return Ok(vec![]);
    }
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let rows = if value.is_array() {
        serde_json::from_value::<Vec<WinConnRow>>(value)?
    } else {
        vec![serde_json::from_value::<WinConnRow>(value)?]
    };
    Ok(rows)
}
