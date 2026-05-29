use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub type SharedSiemConfig = Arc<std::sync::RwLock<SiemConfig>>;

const CONFIG_PATH: &str = "siem.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SiemConfig {
    pub enabled:     bool,
    pub host:        String,
    pub port:        u16,
    pub protocol:    SiemProtocol,
    /// Syslog facility number (0-23). 16 = local0, common default for custom apps.
    pub facility:    u8,
    pub min_outcome: MinOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SiemProtocol { #[default] Udp, Tcp }

/// Which outcome levels to forward. Events below the threshold are silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MinOutcome {
    All,
    WarnAndAbove,
    #[default] AlertAndAbove,
    BlockOnly,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled:     false,
            host:        String::new(),
            port:        514,
            protocol:    SiemProtocol::Udp,
            facility:    16,
            min_outcome: MinOutcome::AlertAndAbove,
        }
    }
}

impl SiemConfig {
    pub fn load_or_default() -> Self {
        std::fs::read_to_string(CONFIG_PATH)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(CONFIG_PATH, json)?;
        Ok(())
    }
}

pub fn new_shared(cfg: SiemConfig) -> SharedSiemConfig {
    Arc::new(std::sync::RwLock::new(cfg))
}
