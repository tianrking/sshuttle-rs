use anyhow::Result;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::SystemTime;
use tokio::time::{Duration, sleep};

use crate::config::WinNativeWorkerArgs;
use crate::policy::{PolicyEvaluator, PolicyFile};
use crate::win_divert_native::{
    NativeRedirectConfig, PacketDecision, PacketEngine, WinDivertPacketEngine,
};

pub async fn run(args: WinNativeWorkerArgs) -> Result<()> {
    println!(
        "[win-native-worker] started: listen_ip={} listen_port={} proxy={} bypass_processes={} ",
        args.listen_ip,
        args.listen_port,
        args.proxy_addr,
        args.bypass_processes.join(",")
    );

    let mut runtime = WorkerRuntime::new(args)?;
    runtime.run().await
}

struct WorkerRuntime {
    args: WinNativeWorkerArgs,
    engine: Box<dyn RuntimeEngine>,
    policy_file: Option<PathBuf>,
    policy_last_modified: Option<SystemTime>,
    policy_eval: Option<PolicyEvaluator>,
    decision_counts: BTreeMap<String, u64>,
    seen: HashSet<String>,
}

impl WorkerRuntime {
    fn new(args: WinNativeWorkerArgs) -> Result<Self> {
        let (policy_eval, modified) = load_policy(args.policy_file.as_deref())?;
        let engine: Box<dyn RuntimeEngine> = match NativeEngine::new(&args) {
            Ok(native) => {
                println!("[win-native-worker] native WinDivert engine active");
                Box::new(native)
            }
            Err(err) => {
                eprintln!("[win-native-worker][warn] native WinDivert init failed: {err:#}");
                println!("[win-native-worker] trying external WinDivert engine handoff...");
                Box::new(ExternalEngine::new())
            }
        };

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
                _ = sleep(Duration::from_millis(250)) => {
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
        let decisions = self
            .engine
            .tick(self.policy_eval.as_mut(), &self.args.bypass_processes)
            .await?;

        for d in decisions {
            self.observe_decision(d);
        }

        if let Some(eval) = self.policy_eval.as_ref() {
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

        Ok(())
    }

    fn observe_decision(&mut self, d: PacketDecision) {
        let dkey = format!("{:?}", d.action);
        *self.decision_counts.entry(dkey).or_insert(0) += 1;
        let key = format!(
            "{:?}|{}|{}|{}",
            d.action,
            d.flow.process_name.as_deref().unwrap_or("-"),
            d.flow.process_path.as_deref().unwrap_or("-"),
            d.flow.dst
        );
        if self.seen.insert(key) {
            println!(
                "[win-native-worker][policy] {:?} proc={} path={} dst={}",
                d.action,
                d.flow.process_name.as_deref().unwrap_or("-"),
                d.flow.process_path.as_deref().unwrap_or("-"),
                d.flow.dst,
            );
        }
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
trait RuntimeEngine: Send {
    async fn start(&mut self, args: &WinNativeWorkerArgs) -> Result<()>;
    async fn tick(
        &mut self,
        evaluator: Option<&mut PolicyEvaluator>,
        bypass_processes: &[String],
    ) -> Result<Vec<PacketDecision>>;
    async fn stop(&mut self);
}

struct NativeEngine {
    inner: WinDivertPacketEngine,
}

impl NativeEngine {
    fn new(args: &WinNativeWorkerArgs) -> Result<Self> {
        let cfg = NativeRedirectConfig::from_args(args);
        let inner = WinDivertPacketEngine::new(cfg)?;
        Ok(Self { inner })
    }
}

#[async_trait::async_trait]
impl RuntimeEngine for NativeEngine {
    async fn start(&mut self, _args: &WinNativeWorkerArgs) -> Result<()> {
        Ok(())
    }

    async fn tick(
        &mut self,
        evaluator: Option<&mut PolicyEvaluator>,
        bypass_processes: &[String],
    ) -> Result<Vec<PacketDecision>> {
        self.inner.process_once(evaluator, bypass_processes)
    }

    async fn stop(&mut self) {}
}

struct ExternalEngine {
    child: Option<tokio::process::Child>,
}

impl ExternalEngine {
    fn new() -> Self {
        Self { child: None }
    }

    fn build_cmd_candidates() -> Vec<String> {
        let mut cmd_candidates = vec!["sshuttle-rs-windivert.exe".to_string()];
        if let Ok(env_cmd) = std::env::var("SSHUTTLE_RS_WINDIVERT_ENGINE")
            && !env_cmd.trim().is_empty()
        {
            cmd_candidates.insert(0, env_cmd);
        }
        cmd_candidates
    }
}

#[async_trait::async_trait]
impl RuntimeEngine for ExternalEngine {
    async fn start(&mut self, args: &WinNativeWorkerArgs) -> Result<()> {
        for bin in Self::build_cmd_candidates() {
            let mut cmd = tokio::process::Command::new(&bin);
            cmd.arg("--listen-ip")
                .arg(args.listen_ip.to_string())
                .arg("--listen-port")
                .arg(args.listen_port.to_string())
                .arg("--proxy-addr")
                .arg(args.proxy_addr.to_string());
            for p in &args.bypass_processes {
                cmd.arg("--bypass-process").arg(p);
            }
            if let Some(path) = &args.policy_file {
                cmd.arg("--policy-file").arg(path);
            }
            if args.dns_capture {
                cmd.arg("--dns-capture").arg("true");
            }
            cmd.arg("--dns-listen-port")
                .arg(args.dns_listen_port.to_string());
            if args.udp_capture {
                cmd.arg("--udp-capture").arg("true");
            }
            cmd.arg("--udp-listen-port")
                .arg(args.udp_listen_port.to_string());
            for p in &args.udp_ports {
                cmd.arg("--udp-port").arg(p.to_string());
            }
            cmd.stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            if let Ok(child) = cmd.spawn() {
                println!("[win-native-worker] using external engine binary: {}", bin);
                self.child = Some(child);
                return Ok(());
            }
        }
        anyhow::bail!("no external windivert engine available")
    }

    async fn tick(
        &mut self,
        _evaluator: Option<&mut PolicyEvaluator>,
        _bypass_processes: &[String],
    ) -> Result<Vec<PacketDecision>> {
        if let Some(child) = self.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            anyhow::bail!("external engine exited unexpectedly: {status}");
        }
        Ok(vec![])
    }

    async fn stop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
}
