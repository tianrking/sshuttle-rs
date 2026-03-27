use anyhow::Result;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::SystemTime;
use tokio::process::Command;
use tokio::time::{Duration, sleep};

use crate::config::WinNativeWorkerArgs;
use crate::policy::{FlowContext, FlowProto, PolicyEvaluator, PolicyFile};

pub async fn run(args: WinNativeWorkerArgs) -> Result<()> {
    println!(
        "[win-native-worker] started: listen_port={} proxy={} bypass_processes={} ",
        args.listen_port,
        args.proxy_addr,
        args.bypass_processes.join(",")
    );

    let mut runtime = WorkerRuntime::new(args)?;
    runtime.run().await
}

struct WorkerRuntime {
    args: WinNativeWorkerArgs,
    engine: Box<dyn DataplaneEngine>,
    policy_file: Option<PathBuf>,
    policy_last_modified: Option<SystemTime>,
    policy_eval: Option<PolicyEvaluator>,
    decision_counts: BTreeMap<String, u64>,
    seen: HashSet<String>,
}

impl WorkerRuntime {
    fn new(args: WinNativeWorkerArgs) -> Result<Self> {
        let (policy_eval, modified) = load_policy(args.policy_file.as_deref())?;
        let engine: Box<dyn DataplaneEngine> = Box::new(AutoEngine::new());
        Ok(Self {
            policy_file: args.policy_file.clone(),
            policy_last_modified: modified,
            policy_eval,
            engine,
            args,
            decision_counts: BTreeMap::new(),
            seen: HashSet::new(),
        })
    }

    async fn run(&mut self) -> Result<()> {
        self.engine.start(&self.args).await?;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("[win-native-worker] stop signal received, exiting");
                    break;
                }
                _ = sleep(Duration::from_secs(3)) => {
                    self.reload_policy_if_needed()?;
                    if let Err(err) = self.tick().await {
                        eprintln!("[win-native-worker][warn] tick failed: {err:#}");
                    }
                }
            }
        }
        self.engine.stop().await;
        Ok(())
    }

    fn reload_policy_if_needed(&mut self) -> Result<()> {
        let Some(path) = self.policy_file.as_deref() else {
            return Ok(());
        };
        let Ok(meta) = std::fs::metadata(path) else {
            return Ok(());
        };
        let Ok(modified) = meta.modified() else {
            return Ok(());
        };

        let changed = self
            .policy_last_modified
            .map(|m| m != modified)
            .unwrap_or(true);
        if changed {
            let loaded = PolicyFile::load(path)?;
            let validation = loaded.validate();
            if !validation.errors.is_empty() {
                eprintln!(
                    "[win-native-worker][warn] policy reload has {} errors, keep old policy",
                    validation.errors.len()
                );
                return Ok(());
            }
            println!(
                "[win-native-worker] policy reloaded: {} (rules={})",
                path.display(),
                loaded.rules.len()
            );
            for w in validation.warnings {
                println!("[win-native-worker][policy][warn] {w}");
            }
            self.policy_eval = Some(loaded.evaluator());
            self.policy_last_modified = Some(modified);
            self.seen.clear();
        }

        Ok(())
    }

    async fn tick(&mut self) -> Result<()> {
        let flows = self.engine.sample_flows().await?;
        if let Some(eval) = self.policy_eval.as_mut() {
            for flow in flows {
                let decision = eval.evaluate(&flow);
                let key = format!(
                    "{:?}|{}|{}|{}",
                    decision.action,
                    flow.process_name.as_deref().unwrap_or("-"),
                    flow.process_path.as_deref().unwrap_or("-"),
                    flow.dst
                );
                let dkey = format!("{:?}", decision.action);
                *self.decision_counts.entry(dkey).or_insert(0) += 1;
                if self.seen.insert(key) {
                    println!(
                        "[win-native-worker][policy] {:?} proc={} path={} dst={} rule={} prio={}",
                        decision.action,
                        flow.process_name.as_deref().unwrap_or("-"),
                        flow.process_path.as_deref().unwrap_or("-"),
                        flow.dst,
                        decision.matched_rule.as_deref().unwrap_or("default"),
                        decision.matched_priority.unwrap_or(0)
                    );
                }
            }

            let stats = eval.stats();
            let decision_summary = self
                .decision_counts
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<String>>()
                .join(", ");
            println!(
                "[win-native-worker][stats] rules_hit={} default_hit={} decisions={}",
                stats.rule_hits.values().sum::<u64>(),
                stats.default_hits,
                if decision_summary.is_empty() {
                    "<none>"
                } else {
                    &decision_summary
                }
            );
        }

        println!("[win-native-worker] heartbeat: active");
        Ok(())
    }
}

fn load_policy(path: Option<&Path>) -> Result<(Option<PolicyEvaluator>, Option<SystemTime>)> {
    let Some(path) = path else {
        return Ok((None, None));
    };
    let policy = PolicyFile::load(path)?;
    let validation = policy.validate();
    if !validation.errors.is_empty() {
        for e in validation.errors {
            eprintln!("[win-native-worker][policy][error] {e}");
        }
        anyhow::bail!("policy validation failed");
    }
    for w in validation.warnings {
        println!("[win-native-worker][policy][warn] {w}");
    }
    println!(
        "[win-native-worker] loaded policy: {} (rules={})",
        path.display(),
        policy.rules.len()
    );
    let modified = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
    Ok((Some(policy.evaluator()), modified))
}

#[async_trait::async_trait]
trait DataplaneEngine: Send {
    async fn start(&mut self, args: &WinNativeWorkerArgs) -> Result<()>;
    async fn stop(&mut self);
    async fn sample_flows(&mut self) -> Result<Vec<FlowContext>>;
}

struct AutoEngine {
    inner: Option<Box<dyn DataplaneEngine>>,
}

impl AutoEngine {
    fn new() -> Self {
        Self { inner: None }
    }
}

#[async_trait::async_trait]
impl DataplaneEngine for AutoEngine {
    async fn start(&mut self, args: &WinNativeWorkerArgs) -> Result<()> {
        println!("[win-native-worker] trying WinDivert engine handoff...");
        if let Some(engine) = ExternalEngine::spawn(args).await? {
            self.inner = Some(Box::new(engine));
            println!("[win-native-worker] external engine active");
            return Ok(());
        }
        println!(
            "[win-native-worker] external engine unavailable, fallback to built-in minimal engine"
        );
        self.inner = Some(Box::new(BuiltinProbeEngine));
        Ok(())
    }

    async fn stop(&mut self) {
        if let Some(engine) = self.inner.as_mut() {
            engine.stop().await;
        }
    }

    async fn sample_flows(&mut self) -> Result<Vec<FlowContext>> {
        if let Some(engine) = self.inner.as_mut() {
            return engine.sample_flows().await;
        }
        Ok(vec![])
    }
}

struct ExternalEngine {
    child: tokio::process::Child,
}

impl ExternalEngine {
    async fn spawn(args: &WinNativeWorkerArgs) -> Result<Option<Self>> {
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
                    return Ok(Some(Self { child }));
                }
                Err(_) => continue,
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl DataplaneEngine for ExternalEngine {
    async fn start(&mut self, _args: &WinNativeWorkerArgs) -> Result<()> {
        Ok(())
    }

    async fn stop(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }

    async fn sample_flows(&mut self) -> Result<Vec<FlowContext>> {
        if let Some(status) = self.child.try_wait()? {
            anyhow::bail!("external engine exited unexpectedly: {status}");
        }
        Ok(vec![])
    }
}

struct BuiltinProbeEngine;

#[async_trait::async_trait]
impl DataplaneEngine for BuiltinProbeEngine {
    async fn start(&mut self, _args: &WinNativeWorkerArgs) -> Result<()> {
        Ok(())
    }

    async fn stop(&mut self) {}

    async fn sample_flows(&mut self) -> Result<Vec<FlowContext>> {
        sample_windows_tcp_flows().await
    }
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

async fn sample_windows_tcp_flows() -> Result<Vec<FlowContext>> {
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

    let mut flows = Vec::new();
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
        flows.push(FlowContext {
            process_name: row.process_name,
            process_path: row.process_path,
            dst: std::net::SocketAddr::from((ip, port)),
            proto: FlowProto::Tcp,
        });
    }

    Ok(flows)
}
