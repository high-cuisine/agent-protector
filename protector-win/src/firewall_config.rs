//! Firewall config stub for Windows — compiles but provides no iptables rules.
//! The web dashboard's /api/firewall endpoint is available but non-functional.
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};

pub type SharedFirewallConfig = Arc<RwLock<FirewallConfig>>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub mode: String,
    pub rules: Vec<serde_json::Value>,
}

impl FirewallConfig {
    pub fn load_or_default() -> Self {
        Self { enabled: false, mode: "blacklist".into(), rules: vec![] }
    }

    /// No-op on Windows (WFP not yet implemented); always succeeds.
    pub fn save(&self) -> anyhow::Result<()> { Ok(()) }
}

pub fn new_shared(cfg: FirewallConfig) -> SharedFirewallConfig {
    Arc::new(RwLock::new(cfg))
}
