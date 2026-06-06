use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

pub type SharedFirewallConfig = Arc<RwLock<FirewallConfig>>;

const CONFIG_PATH: &str = "firewall.json";

/// Default policy when no rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    /// Default ALLOW — explicit DROP rules.
    #[default]
    Blacklist,
    /// Default DROP — explicit ACCEPT rules.
    Whitelist,
}

/// Which netfilter chain(s) the rule goes into.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Agent → internet (OUTPUT chain).
    #[default]
    Out,
    /// Internet → agent (INPUT chain).
    In,
    /// Both chains.
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    #[default]
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallRule {
    pub id: u64,
    /// Rule is active; if false it is stored but not applied.
    pub enabled: bool,
    pub name: String,
    pub direction: Direction,
    pub protocol: Protocol,
    /// CIDR notation — empty string means "any".
    pub remote_cidr: String,
    /// 0 = any port. For a single port set port_min = port_max.
    pub port_min: u16,
    pub port_max: u16,
    pub action: RuleAction,
}

impl Default for FirewallRule {
    fn default() -> Self {
        Self {
            id: 0,
            enabled: true,
            name: String::new(),
            direction: Direction::Out,
            protocol: Protocol::Tcp,
            remote_cidr: String::new(),
            port_min: 0,
            port_max: 0,
            action: RuleAction::Block,
        }
    }
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub mode: FirewallMode,
    pub rules: Vec<FirewallRule>,
    /// Monotonic counter — incremented by the UI each time a rule is added.
    pub next_id: u64,
    /// Hostnames allowlisted for egress in whitelist mode. Their **currently
    /// resolved** IPs are kept in an ipset and refreshed on a timer, so CDN
    /// backends with rotating IPs (e.g. `api.anthropic.com`) keep working.
    pub allow_hosts: Vec<String>,
    /// Allow outbound DNS (port 53) in whitelist mode so the agent can resolve
    /// `allow_hosts`. Note: DNS is itself a (low-bandwidth) exfil channel.
    #[serde(default = "default_true")]
    pub allow_dns: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: FirewallMode::Blacklist,
            rules: Vec::new(),
            next_id: 1,
            allow_hosts: Vec::new(),
            allow_dns: true,
        }
    }
}

impl FirewallConfig {
    /// A ready-to-use default-deny egress policy: drop everything outbound from
    /// the agent except DNS, loopback, established replies, and the resolved IPs
    /// of `hosts` (defaults to the Anthropic API). IPv6 egress is dropped wholesale.
    pub fn egress_deny(hosts: Vec<String>) -> Self {
        Self {
            enabled: true,
            mode: FirewallMode::Whitelist,
            rules: Vec::new(),
            next_id: 1,
            allow_hosts: if hosts.is_empty() {
                vec!["api.anthropic.com".to_string()]
            } else {
                hosts
            },
            allow_dns: true,
        }
    }
}

impl FirewallConfig {
    pub fn load_or_default() -> Self {
        std::fs::read_to_string(CONFIG_PATH)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        std::fs::write(CONFIG_PATH, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

pub fn new_shared(config: FirewallConfig) -> SharedFirewallConfig {
    Arc::new(RwLock::new(config))
}
