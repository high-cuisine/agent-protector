use crate::validator::{ValidationContext, ValidationResult, Validator};
use crate::validators::secret::SecretScanner;
use log::{info, warn};
use std::path::Path;
use std::process::Command;

pub struct GitCommitValidator {
    scanner: SecretScanner,
}

impl GitCommitValidator {
    pub fn new(scanner: SecretScanner) -> Self {
        Self { scanner }
    }

    /// Returns the list of file paths staged for commit.
    fn staged_files(cwd: &Path) -> Vec<String> {
        let out = Command::new("git")
            .args(["-C", &cwd.to_string_lossy(), "diff", "--cached", "--name-only"])
            .output();

        match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            _ => vec![],
        }
    }

    /// Returns staged content of a file (from the index, not the working tree).
    fn staged_content(cwd: &Path, file: &str) -> Option<String> {
        let out = Command::new("git")
            .args(["-C", &cwd.to_string_lossy(), "show", &format!(":{}", file)])
            .output()
            .ok()?;

        if out.status.success() {
            String::from_utf8(out.stdout).ok()
        } else {
            None
        }
    }
}

impl Validator for GitCommitValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        let cwd = match &ctx.working_dir {
            Some(d) => d.clone(),
            None => return ValidationResult::Allow,
        };

        let files = Self::staged_files(&cwd);
        if files.is_empty() {
            return ValidationResult::Allow;
        }

        info!(
            "[git-commit] pid={} staged {} file(s) in {:?}",
            ctx.pid,
            files.len(),
            cwd
        );

        let mut violations: Vec<String> = Vec::new();

        for file in &files {
            // Use staged index content so we scan exactly what's going in
            if let Some(content) = Self::staged_content(&cwd, file) {
                for m in self.scanner.scan_content(&content) {
                    let msg = format!(
                        "{}:{} [{}] — {}",
                        file, m.line_number, m.pattern_name, m.snippet
                    );
                    warn!("[git-commit] secret detected: {}", msg);
                    violations.push(msg);
                }
            }
        }

        if violations.is_empty() {
            info!("[git-commit] validation passed");
            ValidationResult::Allow
        } else {
            ValidationResult::Block {
                reason: format!(
                    "Potential secrets detected in staged files ({} hit(s)):\n  {}",
                    violations.len(),
                    violations.join("\n  ")
                ),
            }
        }
    }
}
