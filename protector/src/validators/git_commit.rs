use crate::errors::{SecretHit, ThreatError};
use crate::validator::{ValidationContext, ValidationResult, Validator};
use crate::validators::secret::SecretScanner;
use log::info;
use std::path::Path;
use std::process::Command;

pub struct GitCommitValidator {
    scanner: SecretScanner,
}

impl GitCommitValidator {
    pub fn new(scanner: SecretScanner) -> Self {
        Self { scanner }
    }

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

        let mut hits: Vec<SecretHit> = Vec::new();

        for file in &files {
            if let Some(content) = Self::staged_content(&cwd, file) {
                for m in self.scanner.scan_content(&content) {
                    hits.push(SecretHit {
                        file: file.clone(),
                        line: m.line_number,
                        kind: m.pattern_name,
                        snippet: m.snippet,
                    });
                }
            }
        }

        if hits.is_empty() {
            info!("[git-commit] validation passed");
            ValidationResult::Allow
        } else {
            ValidationResult::Block(ThreatError::SecretLeak { hits })
        }
    }
}
