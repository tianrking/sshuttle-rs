use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub _version: Option<u32>,
    #[serde(default)]
    pub defaults: PolicyDefaults,
    #[serde(default, alias = "default_action")]
    pub default_action: Option<PolicyAction>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PolicyDefaults {
    #[serde(default)]
    pub action: Option<PolicyAction>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PolicyRule {
    #[serde(default)]
    pub name: Option<String>,
    pub action: PolicyAction,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub process: ProcessSelector,
    #[serde(default, alias = "destination")]
    pub dst: DestinationSelector,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Proxy,
    Bypass,
    Direct,
    Drop,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FlowProto {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProcessSelector {
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        alias = "names"
    )]
    pub name: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        alias = "paths"
    )]
    pub path: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct DestinationSelector {
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        alias = "cidr"
    )]
    pub cidrs: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_u16_or_vec", alias = "port")]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub proto: Option<FlowProto>,
}

#[derive(Clone, Debug)]
pub struct FlowContext {
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub dst: SocketAddr,
    pub proto: FlowProto,
}

#[derive(Clone, Debug)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub matched_rule: Option<String>,
}

impl PolicyFile {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path.display()))?;
        let ext = path
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or_default();
        let mut p = match ext {
            "yaml" | "yml" => serde_yaml::from_str::<PolicyFile>(&content)
                .with_context(|| format!("invalid YAML policy: {}", path.display()))?,
            _ => serde_json::from_str::<PolicyFile>(&content)
                .or_else(|_| serde_yaml::from_str::<PolicyFile>(&content))
                .with_context(|| format!("invalid JSON/YAML policy: {}", path.display()))?,
        };
        if p.defaults.action.is_none() && p.default_action.is_some() {
            p.defaults.action = p.default_action;
        }
        Ok(p)
    }

    pub fn default_action(&self) -> PolicyAction {
        self.defaults.action.unwrap_or(PolicyAction::Proxy)
    }

    pub fn explain(&self, flow: &FlowContext) -> PolicyDecision {
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.enabled == Some(false) {
                continue;
            }
            if !matches_process(&rule.process, flow) {
                continue;
            }
            if !matches_destination(&rule.dst, flow) {
                continue;
            }
            return PolicyDecision {
                action: rule.action,
                matched_rule: Some(rule.name.clone().unwrap_or_else(|| format!("rule#{idx}"))),
            };
        }
        PolicyDecision {
            action: self.default_action(),
            matched_rule: None,
        }
    }

    pub fn static_bypass_processes(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for rule in &self.rules {
            if rule.enabled == Some(false) || rule.action != PolicyAction::Bypass {
                continue;
            }
            if !rule.dst.cidrs.is_empty() || !rule.dst.ports.is_empty() || rule.dst.proto.is_some()
            {
                continue;
            }
            for p in &rule.process.name {
                if !out.iter().any(|v| v.eq_ignore_ascii_case(p)) {
                    out.push(p.clone());
                }
            }
            for p in &rule.process.path {
                if !out.iter().any(|v| v.eq_ignore_ascii_case(p)) {
                    out.push(p.clone());
                }
            }
        }
        out
    }
}

fn matches_process(sel: &ProcessSelector, flow: &FlowContext) -> bool {
    let mut hit = true;
    if !sel.name.is_empty() {
        hit = flow.process_name.as_ref().is_some_and(|n| {
            sel.name
                .iter()
                .any(|x| n.eq_ignore_ascii_case(x) || n.eq_ignore_ascii_case(strip_exe(x)))
        });
    }
    if !hit {
        return false;
    }
    if !sel.path.is_empty() {
        return flow
            .process_path
            .as_ref()
            .is_some_and(|p| sel.path.iter().any(|x| p.eq_ignore_ascii_case(x)));
    }
    true
}

fn matches_destination(sel: &DestinationSelector, flow: &FlowContext) -> bool {
    if let Some(proto) = sel.proto
        && proto != flow.proto
    {
        return false;
    }
    if !sel.ports.is_empty() && !sel.ports.contains(&flow.dst.port()) {
        return false;
    }
    if !sel.cidrs.is_empty() {
        let ip = flow.dst.ip();
        let cidr_hit = sel
            .cidrs
            .iter()
            .filter_map(|x| x.parse::<IpNet>().ok())
            .any(|net| net.contains(&ip));
        if !cidr_hit {
            return false;
        }
    }
    true
}

fn strip_exe(s: &str) -> &str {
    s.strip_suffix(".exe").unwrap_or(s)
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        One(String),
        Many(Vec<String>),
    }
    let v = Option::<StringOrVec>::deserialize(deserializer)?;
    Ok(match v {
        None => vec![],
        Some(StringOrVec::One(x)) => vec![x],
        Some(StringOrVec::Many(xs)) => xs,
    })
}

fn deserialize_u16_or_vec<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum U16OrVec {
        One(u16),
        Many(Vec<u16>),
    }
    let v = Option::<U16OrVec>::deserialize(deserializer)?;
    Ok(match v {
        None => vec![],
        Some(U16OrVec::One(x)) => vec![x],
        Some(U16OrVec::Many(xs)) => xs,
    })
}
