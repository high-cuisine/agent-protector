use std::path::PathBuf;

pub struct ValidationContext {
    pub pid: u32,
    pub filename: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
}

pub enum ValidationResult {
    Allow,
    Block { reason: String },
    Warn { reason: String },
}

pub trait Validator: Send + Sync {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult;
}
