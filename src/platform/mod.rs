use std::ffi::OsStr;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;

use crate::config::{PlatformArg, RulePlan};

mod linux;
mod windows;

pub struct CommandExecutor {
    dry_run: bool,
}

impl CommandExecutor {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    pub async fn run<I, S>(&self, program: &str, args: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args_vec: Vec<String> = args
            .into_iter()
            .map(|s| s.as_ref().to_string_lossy().to_string())
            .collect();

        if self.dry_run {
            println!("[dry-run] {} {}", program, args_vec.join(" "));
            return Ok(());
        }

        let status = tokio::process::Command::new(program)
            .args(&args_vec)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .with_context(|| format!("failed to run command: {}", program))?;

        if !status.success() {
            bail!("command failed: {} {}", program, args_vec.join(" "));
        }

        Ok(())
    }
}

#[async_trait]
pub trait Platform: Send + Sync {
    fn name(&self) -> &'static str;
    async fn apply_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()>;
    async fn cleanup_rules(&self, plan: &RulePlan, exec: &CommandExecutor) -> Result<()>;
}

pub fn build_platform(arg: PlatformArg) -> Result<Box<dyn Platform>> {
    match arg {
        PlatformArg::Linux => Ok(Box::new(linux::LinuxPlatform::new())),
        PlatformArg::Windows => Ok(Box::new(windows::WindowsPlatform::new())),
        PlatformArg::Auto => {
            if cfg!(target_os = "linux") {
                return Ok(Box::new(linux::LinuxPlatform::new()));
            }
            if cfg!(target_os = "windows") {
                return Ok(Box::new(windows::WindowsPlatform::new()));
            }
            anyhow::bail!("auto platform is not supported on this OS yet")
        }
    }
}
