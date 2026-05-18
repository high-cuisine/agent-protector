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
}

pub trait Validator: Send + Sync {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult;
}
