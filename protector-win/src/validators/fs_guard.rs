//! Windows-adapted filesystem access guard.
//!
//! Runs the original command, masks secrets in its stdout, then returns
//! `ValidationResult::MaskedOutput` so the daemon can forward it to the shim.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use regex::Regex;

use crate::data_policy::{DataPolicy, PolicyMode};
use crate::errors::ThreatError;
use crate::validator::{ValidationContext, ValidationResult, Validator};

#[derive(Clone, Copy)]
pub enum PathStrategy {
    AllPositional,
    SkipFirstPositional,
    FirstPositional,
    FirstPositional2,
}

pub struct FsGuardValidator {
    policy:   Arc<DataPolicy>,
    tool:     &'static str,
    strategy: PathStrategy,
    masker:   ContentMasker,
}

impl FsGuardValidator {
    pub fn new(policy: Arc<DataPolicy>, tool: &'static str, strategy: PathStrategy) -> Self {
        Self { policy, tool, strategy, masker: ContentMasker::new() }
    }
}

impl Validator for FsGuardValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        if self.policy.is_empty() { return ValidationResult::Allow; }

        let paths = self.extract_paths(&ctx.args, ctx.working_dir.as_deref());
        if paths.is_empty() { return ValidationResult::Allow; }

        let hit = paths.iter().find_map(|p| {
            self.policy.find_fs_rule(p).map(|r| (p.clone(), r))
        });
        let (matched_path, rule) = match hit {
            Some(h) => h,
            None    => return ValidationResult::Allow,
        };

        let path_str = matched_path.to_string_lossy().into_owned();
        log::info!(
            "[{}] fs_guard: access to protected path '{}' (mode={:?})",
            self.tool, path_str, rule.mode
        );

        match rule.mode {
            PolicyMode::Block => {
                ValidationResult::Block(ThreatError::FsPolicyBlock {
                    tool:    self.tool,
                    path:    path_str,
                    pattern: rule.raw.clone(),
                })
            }
            PolicyMode::Mask => {
                // cp/mv/find don't produce file content on stdout → fall back to block.
                if matches!(self.strategy,
                    PathStrategy::FirstPositional | PathStrategy::FirstPositional2)
                {
                    return ValidationResult::Block(ThreatError::FsPolicyBlock {
                        tool:    self.tool,
                        path:    path_str,
                        pattern: rule.raw.clone(),
                    });
                }

                match self.capture_and_mask(ctx, &path_str) {
                    Ok(content) => ValidationResult::MaskedOutput {
                        content,
                        threat: ThreatError::FsPolicyMasked {
                            tool:    self.tool,
                            path:    path_str,
                            pattern: rule.raw.clone(),
                        },
                    },
                    Err(e) => {
                        log::error!("[{}] fs_guard: capture failed: {e}", self.tool);
                        ValidationResult::Block(ThreatError::FsPolicyBlock {
                            tool:    self.tool,
                            path:    path_str,
                            pattern: rule.raw.clone(),
                        })
                    }
                }
            }
        }
    }
}

impl FsGuardValidator {
    fn extract_paths(&self, args: &[String], cwd: Option<&Path>) -> Vec<PathBuf> {
        let positional: Vec<&str> = args.iter()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .map(String::as_str)
            .collect();

        let range: &[&str] = match self.strategy {
            PathStrategy::AllPositional       => &positional,
            PathStrategy::SkipFirstPositional => positional.get(1..).unwrap_or(&[]),
            PathStrategy::FirstPositional     => positional.get(..1).unwrap_or(&[]),
            PathStrategy::FirstPositional2    => positional.get(..1).unwrap_or(&[]),
        };

        range.iter().map(|s| resolve_path(s, cwd)).collect()
    }

    fn capture_and_mask(&self, ctx: &ValidationContext, matched_path: &str) -> anyhow::Result<String> {
        // Run the original command and capture stdout.
        // On Windows we run as the current user (no setuid).
        let output = std::process::Command::new(&ctx.args[0])
            .args(&ctx.args[1..])
            .output()?;

        let raw    = String::from_utf8_lossy(&output.stdout);
        let masked = self.masker.mask(&raw);

        Ok(format!(
            "\n[FS_POLICY: output masked — '{}' matched protected pattern]\n{}",
            matched_path, masked
        ))
    }
}

fn resolve_path(s: &str, cwd: Option<&Path>) -> PathBuf {
    let p = PathBuf::from(s);
    if p.is_absolute() { return p; }
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
            return PathBuf::from(home).join(rest);
        }
    }
    if let Some(base) = cwd { return base.join(&p); }
    p
}

// ── Content masker (same patterns as Linux version) ───────────────────────────

struct ContentMasker { rules: Vec<(Regex, &'static str)> }

impl ContentMasker {
    fn new() -> Self {
        let defs: &[(&str, &'static str)] = &[
            (r"AKIA[0-9A-Z]{16}",                              "[AWS_KEY]"),
            (r"ghp_[A-Za-z0-9]{36}",                          "[GITHUB_TOKEN]"),
            (r"github_pat_[A-Za-z0-9_]{82}",                  "[GITHUB_PAT]"),
            (r"ghs_[A-Za-z0-9]{36}",                          "[GITHUB_SECRET]"),
            (r"xox[baprs]-[0-9A-Za-z\-]{10,}",               "[SLACK_TOKEN]"),
            (r"AIza[0-9A-Za-z_\-]{35}",                       "[GOOGLE_KEY]"),
            (r"sk_(live|test)_[0-9a-zA-Z]{24,}",             "[STRIPE_KEY]"),
            (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                                                               "[JWT]"),
            (r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----",
                                                               "[PRIVATE_KEY_BLOCK]"),
            (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                                                               "[EMAIL]"),
            (r#"(?i)(password|passwd|secret|token|api[_\-]?key|access[_\-]?key)\s*[=:]\s*['"]?\S{8,}['"]?"#,
                                                               "[SECRET=REDACTED]"),
            (r"\b[0-9a-f]{32,64}\b",                          "[HEX_TOKEN]"),
        ];

        let rules = defs.iter()
            .filter_map(|(pat, label)| Regex::new(pat).ok().map(|re| (re, *label)))
            .collect();

        Self { rules }
    }

    fn mask(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (re, label) in &self.rules {
            out = re.replace_all(&out, *label).into_owned();
        }
        out
    }
}
