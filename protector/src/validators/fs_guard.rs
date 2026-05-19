/// Filesystem access guard.
///
/// Intercepts file-reading and file-management commands (cat, head, tail,
/// grep, find, cp, mv, diff) when they touch paths listed in the data policy.
///
/// Two enforcement modes (same as data_guard):
///
/// - **fblock**: deny the command; agent receives [FS_POLICY_BLOCK].
/// - **fmask**: let the command run but replace secrets in its stdout before
///              the agent reads it; agent receives masked content plus
///              [FS_POLICY_MASKED] on stderr.
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use regex::Regex;

use crate::data_policy::{DataPolicy, PolicyMode};
use crate::errors::ThreatError;
use crate::validator::{ValidationContext, ValidationResult, Validator};

// ── Path-extraction strategy ──────────────────────────────────────────────────

/// Describes how to pull file-path arguments out of a specific command's argv.
#[derive(Clone, Copy)]
pub enum PathStrategy {
    /// All non-flag positional args are file paths: cat, head, tail, diff, wc
    AllPositional,
    /// First non-flag positional is a regex pattern; the rest are paths: grep
    SkipFirstPositional,
    /// Only the first non-flag positional (the start directory): find
    FirstPositional,
    /// First non-flag positional is source, second is destination (ignore dest): cp, mv
    FirstPositional2,
}

// ── Validator ─────────────────────────────────────────────────────────────────

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
        if self.policy.is_empty() {
            return ValidationResult::Allow;
        }

        let paths = self.extract_paths(&ctx.args, ctx.working_dir.as_deref());
        if paths.is_empty() {
            return ValidationResult::Allow;
        }

        // Find the first path that matches a policy rule.
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
                // For commands that don't produce readable file content as
                // stdout (cp, mv, find) — fall back to block.
                if matches!(self.strategy,
                    PathStrategy::FirstPositional | PathStrategy::FirstPositional2)
                {
                    return ValidationResult::Block(ThreatError::FsPolicyBlock {
                        tool:    self.tool,
                        path:    path_str,
                        pattern: rule.raw.clone(),
                    });
                }

                match self.substitute_output(ctx, &path_str) {
                    Ok(()) => ValidationResult::Block(ThreatError::FsPolicyMasked {
                        tool:    self.tool,
                        path:    path_str,
                        pattern: rule.raw.clone(),
                    }),
                    Err(e) => {
                        log::error!("[{}] fs_guard: mask substitution failed: {e}", self.tool);
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

// ── Path extraction ───────────────────────────────────────────────────────────

impl FsGuardValidator {
    fn extract_paths(&self, args: &[String], cwd: Option<&Path>) -> Vec<PathBuf> {
        let positional: Vec<&str> = args.iter()
            .skip(1) // skip argv[0]
            .filter(|a| !a.starts_with('-'))
            .map(String::as_str)
            .collect();

        let range: &[&str] = match self.strategy {
            PathStrategy::AllPositional       => &positional,
            PathStrategy::SkipFirstPositional => positional.get(1..).unwrap_or(&[]),
            PathStrategy::FirstPositional     => positional.get(..1).unwrap_or(&[]),
            PathStrategy::FirstPositional2    => positional.get(..1).unwrap_or(&[]),
        };

        range.iter()
            .map(|s| resolve_path(s, cwd))
            .collect()
    }
}

fn resolve_path(s: &str, cwd: Option<&Path>) -> PathBuf {
    let p = PathBuf::from(s);
    if p.is_absolute() {
        return p;
    }
    // Expand ~
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    // Relative to cwd
    if let Some(base) = cwd {
        return base.join(&p);
    }
    p
}

// ── Mask substitution ─────────────────────────────────────────────────────────

impl FsGuardValidator {
    /// Run the original command (as the original user), mask its stdout, then
    /// write the masked output into the stopped process's stdout pipe.
    fn substitute_output(&self, ctx: &ValidationContext, matched_path: &str) -> anyhow::Result<()> {
        let uid = proc_uid(ctx.pid)?;
        let gid = proc_gid(ctx.pid)?;

        // Re-run the exact same command under the original user's identity.
        let output = unsafe {
            std::process::Command::new(&ctx.args[0])
                .args(&ctx.args[1..])
                .pre_exec(move || {
                    libc::setgid(gid);
                    libc::setuid(uid);
                    Ok(())
                })
                .output()?
        };

        // Mask secret patterns in the captured stdout.
        let raw = String::from_utf8_lossy(&output.stdout);
        let masked = self.masker.mask(&raw);

        let header = format!(
            "\n[FS_POLICY: output masked — '{}' matched protected pattern]\n",
            matched_path
        );

        // Write into the stopped process's stdout pipe.
        let stdout_link = format!("/proc/{}/fd/1", ctx.pid);
        let mut pipe = std::fs::OpenOptions::new().write(true).open(&stdout_link)?;
        pipe.write_all(header.as_bytes())?;
        pipe.write_all(masked.as_bytes())?;

        Ok(())
    }
}

// ── Content masker ────────────────────────────────────────────────────────────

/// Replaces known secret patterns in plain text with labelled placeholders.
/// Patterns are built from the same definitions used by SecretScanner, but
/// here we do in-place replacement rather than detection.
struct ContentMasker {
    rules: Vec<(Regex, &'static str)>,
}

impl ContentMasker {
    fn new() -> Self {
        let defs: &[(&str, &'static str)] = &[
            // Specific API key formats first (most precise)
            (r"AKIA[0-9A-Z]{16}",                              "[AWS_KEY]"),
            (r"ghp_[A-Za-z0-9]{36}",                          "[GITHUB_TOKEN]"),
            (r"github_pat_[A-Za-z0-9_]{82}",                  "[GITHUB_PAT]"),
            (r"ghs_[A-Za-z0-9]{36}",                          "[GITHUB_SECRET]"),
            (r"xox[baprs]-[0-9A-Za-z\-]{10,}",               "[SLACK_TOKEN]"),
            (r"AIza[0-9A-Za-z_\-]{35}",                       "[GOOGLE_KEY]"),
            (r"sk_(live|test)_[0-9a-zA-Z]{24,}",             "[STRIPE_KEY]"),
            (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                                                               "[JWT]"),
            // Private key blocks
            (r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----",
                                                               "[PRIVATE_KEY_BLOCK]"),
            // Email addresses
            (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                                                               "[EMAIL]"),
            // Generic key=value or key: value patterns
            (r#"(?i)(password|passwd|secret|token|api[_\-]?key|access[_\-]?key)\s*[=:]\s*['"]?\S{8,}['"]?"#,
                                                               "[SECRET=REDACTED]"),
            // High-entropy hex strings (32+ hex chars — looks like tokens/hashes)
            (r"\b[0-9a-f]{32,64}\b",                          "[HEX_TOKEN]"),
        ];

        let rules = defs.iter().filter_map(|(pat, label)| {
            Regex::new(pat).ok().map(|re| (re, *label))
        }).collect();

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

// ── /proc helpers ─────────────────────────────────────────────────────────────

fn proc_uid(pid: u32) -> anyhow::Result<libc::uid_t> { proc_id_field(pid, "Uid:") }
fn proc_gid(pid: u32) -> anyhow::Result<libc::gid_t> { proc_id_field(pid, "Gid:") }

fn proc_id_field(pid: u32, field: &str) -> anyhow::Result<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(val) = rest.split_whitespace().next() {
                return val.parse().map_err(Into::into);
            }
        }
    }
    anyhow::bail!("field '{}' not found in /proc/{}/status", field, pid)
}
