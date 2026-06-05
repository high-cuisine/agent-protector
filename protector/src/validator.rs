use crate::errors::ThreatError;
use std::path::PathBuf;

pub struct ValidationContext {
    pub pid: u32,
    pub filename: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
}

pub enum ValidationResult {
    Allow,
    /// The action is blocked and the agent receives a typed threat description.
    Block(ThreatError),
    /// The action is allowed but the agent is warned about the threat.
    Warn(ThreatError),
    /// The action is allowed; threat is logged to the web alert panel.
    Alert { threat: ThreatError, rule: String },
    /// Shim-based masking (Windows): block original command, deliver synthetic
    /// output back to the shim over the named-pipe IPC channel.
    /// Never returned by Linux validators — exists so both crates share the type.
    MaskedOutput { content: String, threat: ThreatError },
}

pub trait Validator: Send + Sync {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult;
}
