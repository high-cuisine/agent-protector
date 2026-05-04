use crate::validator::{ValidationContext, ValidationResult, Validator};
use crate::validators::{git_commit::GitCommitValidator, secret::SecretScanner};

/// A single tool action: which command + sub-args trigger it, and how to validate it.
pub struct ToolAction {
    pub name: &'static str,
    /// Suffix match on the executable path (e.g. "git", "/usr/bin/git")
    command_suffix: &'static str,
    /// All of these must appear somewhere in argv to trigger this action
    required_args: &'static [&'static str],
    /// Any of these args causes the action to be skipped (e.g. read-only git sub-commands)
    excluded_args: &'static [&'static str],
    validator: Box<dyn Validator>,
}

impl ToolAction {
    pub fn matches(&self, filename: &str, args: &[String]) -> bool {
        if !filename.ends_with(self.command_suffix) {
            return false;
        }
        let has_required = self
            .required_args
            .iter()
            .all(|req| args.iter().any(|a| a == *req));
        let has_excluded = self
            .excluded_args
            .iter()
            .any(|ex| args.iter().any(|a| a == *ex));
        has_required && !has_excluded
    }

    pub fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        self.validator.validate(ctx)
    }
}

pub struct ToolDb {
    actions: Vec<ToolAction>,
}

impl Default for ToolDb {
    fn default() -> Self {
        Self {
            actions: vec![
                // git commit — scan staged files for secrets
                ToolAction {
                    name: "git-commit",
                    command_suffix: "git",
                    required_args: &["commit"],
                    excluded_args: &["--dry-run"],
                    validator: Box::new(GitCommitValidator::new(SecretScanner::default())),
                },
                // TODO: npm publish, pip install --index-url, curl <unknown-host>, etc.
            ],
        }
    }
}

impl ToolDb {
    pub fn find_action(&self, filename: &str, args: &[String]) -> Option<&ToolAction> {
        self.actions.iter().find(|a| a.matches(filename, args))
    }
}
