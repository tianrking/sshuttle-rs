use anyhow::{Result, bail};
use async_trait::async_trait;

use crate::config::RulePlan;

use super::{CommandExecutor, Platform};

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Platform for WindowsPlatform {
    fn name(&self) -> &'static str {
        "windows/wfp-planned"
    }

    async fn apply_rules(&self, _plan: &RulePlan, _exec: &CommandExecutor) -> Result<()> {
        bail!("Windows transparent redirect backend is not implemented yet (planned: WinDivert/WFP)")
    }

    async fn cleanup_rules(&self, _plan: &RulePlan, _exec: &CommandExecutor) -> Result<()> {
        Ok(())
    }
}