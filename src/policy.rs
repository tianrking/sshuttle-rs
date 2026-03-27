use std::collections::{BTreeMap, HashMap};
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
    pub priority: i32,
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
    pub matched_index: Option<usize>,
    pub matched_priority: Option<i32>,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyValidation {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyStats {
    pub default_hits: u64,
    pub rule_hits: BTreeMap<String, u64>,
}

pub struct PolicyEvaluator {
    policy: PolicyFile,
    stats: PolicyStats,
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

    pub fn evaluator(self) -> PolicyEvaluator {
        PolicyEvaluator {
            policy: self,
            stats: PolicyStats::default(),
        }
    }

    pub fn explain(&self, flow: &FlowContext) -> PolicyDecision {
        for (idx, rule) in self.ordered_rules() {
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
                matched_index: Some(idx),
                matched_priority: Some(rule.priority),
            };
        }
        PolicyDecision {
            action: self.default_action(),
            matched_rule: None,
            matched_index: None,
            matched_priority: None,
        }
    }

    pub fn validate(&self) -> PolicyValidation {
        let mut out = PolicyValidation::default();
        let mut seen_name = HashMap::<String, usize>::new();

        for (i, r) in self.rules.iter().enumerate() {
            if let Some(name) = &r.name {
                let key = name.to_ascii_lowercase();
                if let Some(prev) = seen_name.insert(key, i) {
                    out.errors.push(format!(
                        "duplicate rule name '{}' at indexes {} and {}",
                        name, prev, i
                    ));
                }
            }
            for cidr in &r.dst.cidrs {
                if cidr.parse::<IpNet>().is_err() {
                    out.errors
                        .push(format!("rule#{} has invalid CIDR: {}", i, cidr));
                }
            }
        }

        for i in 0..self.rules.len() {
            for j in (i + 1)..self.rules.len() {
                let a = &self.rules[i];
                let b = &self.rules[j];
                if a.enabled == Some(false) || b.enabled == Some(false) {
                    continue;
                }
                if a.priority != b.priority {
                    continue;
                }
                if a.action == b.action {
                    continue;
                }
                if selectors_overlap(a, b) {
                    out.warnings.push(format!(
                        "potential conflict between rule#{} and rule#{}: same priority {} with different actions",
                        i, j, a.priority
                    ));
                }
            }
        }

        out
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

    fn ordered_rules(&self) -> Vec<(usize, &PolicyRule)> {
        let mut idx: Vec<usize> = (0..self.rules.len()).collect();
        idx.sort_by(|a, b| {
            self.rules[*b]
                .priority
                .cmp(&self.rules[*a].priority)
                .then_with(|| a.cmp(b))
        });
        idx.into_iter().map(|i| (i, &self.rules[i])).collect()
    }
}

impl PolicyEvaluator {
    pub fn evaluate(&mut self, flow: &FlowContext) -> PolicyDecision {
        let d = self.policy.explain(flow);
        if let Some(rule) = &d.matched_rule {
            let c = self.stats.rule_hits.entry(rule.clone()).or_insert(0);
            *c += 1;
        } else {
            self.stats.default_hits += 1;
        }
        d
    }

    pub fn stats(&self) -> &PolicyStats {
        &self.stats
    }
}

fn selectors_overlap(a: &PolicyRule, b: &PolicyRule) -> bool {
    process_overlap(&a.process, &b.process) && destination_overlap(&a.dst, &b.dst)
}

fn process_overlap(a: &ProcessSelector, b: &ProcessSelector) -> bool {
    let names_overlap = if a.name.is_empty() || b.name.is_empty() {
        true
    } else {
        a.name
            .iter()
            .any(|x| b.name.iter().any(|y| x.eq_ignore_ascii_case(y)))
    };
    if !names_overlap {
        return false;
    }

    if a.path.is_empty() || b.path.is_empty() {
        return true;
    }
    a.path
        .iter()
        .any(|x| b.path.iter().any(|y| x.eq_ignore_ascii_case(y)))
}

fn destination_overlap(a: &DestinationSelector, b: &DestinationSelector) -> bool {
    if let (Some(pa), Some(pb)) = (a.proto, b.proto)
        && pa != pb
    {
        return false;
    }

    if !a.ports.is_empty() && !b.ports.is_empty() && !a.ports.iter().any(|p| b.ports.contains(p)) {
        return false;
    }

    if a.cidrs.is_empty() || b.cidrs.is_empty() {
        return true;
    }

    let a_nets: Vec<IpNet> = a
        .cidrs
        .iter()
        .filter_map(|x| x.parse::<IpNet>().ok())
        .collect();
    let b_nets: Vec<IpNet> = b
        .cidrs
        .iter()
        .filter_map(|x| x.parse::<IpNet>().ok())
        .collect();
    if a_nets.is_empty() || b_nets.is_empty() {
        return true;
    }
    a_nets.iter().any(|x| {
        b_nets
            .iter()
            .any(|y| x.contains(&y.network()) || y.contains(&x.network()))
    })
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

#[cfg(test)]
mod tests {
    use super::{FlowContext, FlowProto, PolicyAction, PolicyFile};
    use std::net::{Ipv4Addr, SocketAddr};

    fn flow(proc_name: &str, ip: [u8; 4], port: u16) -> FlowContext {
        FlowContext {
            process_name: Some(proc_name.to_string()),
            process_path: None,
            dst: SocketAddr::from((Ipv4Addr::from(ip), port)),
            proto: FlowProto::Tcp,
        }
    }

    #[test]
    fn higher_priority_rule_wins() {
        let p: PolicyFile = serde_yaml::from_str(
            r#"
defaults:
  action: proxy
rules:
  - name: low
    action: bypass
    priority: 0
    process:
      name: ["a.exe"]
  - name: high
    action: drop
    priority: 10
    process:
      name: ["a.exe"]
"#,
        )
        .expect("valid policy");

        let d = p.explain(&flow("a.exe", [1, 1, 1, 1], 443));
        assert_eq!(d.action, PolicyAction::Drop);
        assert_eq!(d.matched_rule.as_deref(), Some("high"));
    }

    #[test]
    fn validate_reports_duplicate_and_invalid_cidr() {
        let p: PolicyFile = serde_yaml::from_str(
            r#"
rules:
  - name: dup
    action: bypass
    destination:
      cidrs: ["not-cidr"]
  - name: dup
    action: proxy
"#,
        )
        .expect("valid yaml shape");

        let v = p.validate();
        assert!(!v.errors.is_empty());
    }

    #[test]
    fn validate_reports_conflict_same_priority() {
        let p: PolicyFile = serde_yaml::from_str(
            r#"
rules:
  - action: bypass
    priority: 5
    process:
      name: ["x.exe"]
  - action: proxy
    priority: 5
    process:
      name: ["x.exe"]
"#,
        )
        .expect("valid policy");

        let v = p.validate();
        assert!(!v.warnings.is_empty());
    }

    #[test]
    fn evaluator_collects_stats() {
        let p: PolicyFile = serde_yaml::from_str(
            r#"
defaults:
  action: proxy
rules:
  - name: bypass-a
    action: bypass
    process:
      name: ["a.exe"]
"#,
        )
        .expect("valid policy");

        let mut e = p.evaluator();
        let _ = e.evaluate(&flow("a.exe", [8, 8, 8, 8], 443));
        let _ = e.evaluate(&flow("b.exe", [8, 8, 8, 8], 443));

        assert_eq!(*e.stats().rule_hits.get("bypass-a").unwrap_or(&0), 1);
        assert_eq!(e.stats().default_hits, 1);
    }
}
