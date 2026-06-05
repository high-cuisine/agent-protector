//! Network firewall stub for Windows.
//! WFP (Windows Filtering Platform) integration is a future milestone.
use crate::firewall_config::FirewallConfig;

pub struct NetworkFirewall;

impl NetworkFirewall {
    pub fn new() -> anyhow::Result<Self> {
        anyhow::bail!("Network firewall (WFP) is not yet implemented on Windows")
    }

    pub fn apply(&self, _cfg: &FirewallConfig) -> anyhow::Result<()> { Ok(()) }
    pub fn track_pids(&self, _pids: &[u32]) {}
}
