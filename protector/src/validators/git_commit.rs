use crate::errors::{SecretHit, ThreatError};
use crate::validator::{ValidationContext, ValidationResult, Validator};
use crate::validators::secret::SecretScanner;
use log::{debug, info, warn};
use std::path::Path;
use std::process::Command;

pub struct GitCommitValidator {
    scanner: SecretScanner,
}

impl GitCommitValidator {
    pub fn new(scanner: SecretScanner) -> Self {
        Self { scanner }
    }

    fn git(cwd: &Path, args: &[&str]) -> std::process::Output {
        // -c safe.directory=* lets root read repos owned by other users
        // (git 2.35.2+ rejects cross-owner repos by default)
        let mut cmd = Command::new("git");
        cmd.args(["-C", &cwd.to_string_lossy(), "-c", "safe.directory=*"]);
        cmd.args(args);
        // Suppress interactive prompts and locale noise
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        cmd.env("LANG", "C");
        cmd.output().unwrap_or_else(|e| {
            warn!("[git-commit] failed to spawn git: {e}");
            std::process::Output {
                status: std::process::ExitStatus::default(),
                stdout: vec![],
                stderr: vec![],
            }
        })
    }

    fn staged_diff(cwd: &Path) -> Result<String, String> {
        // Use the full diff rather than file-by-file show, so we get only
        // the lines actually being added (+ lines), not the whole file.
        // This avoids false positives from pre-existing secrets in unchanged hunks.
        let out = Self::git(cwd, &["diff", "--cached", "--unified=0", "--no-ext-diff"]);
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(format!(
                "`git diff --cached` exited {:?}: {}",
                out.status.code(),
                err.trim()
            ))
        }
    }

    fn staged_filenames(cwd: &Path) -> Result<Vec<String>, String> {
        let out = Self::git(cwd, &["diff", "--cached", "--name-only"]);
        if out.status.success() {
            Ok(
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect(),
            )
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(format!(
                "`git diff --cached --name-only` exited {:?}: {}",
                out.status.code(),
                err.trim()
            ))
        }
    }
}

impl Validator for GitCommitValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        let cwd = match &ctx.working_dir {
            Some(d) => d.clone(),
            None => {
                warn!("[git-commit] pid={} — cannot read cwd from /proc, skipping scan", ctx.pid);
                return ValidationResult::Allow;
            }
        };

        // Listing staged paths must succeed; otherwise we previously returned Allow without
        // scanning ("dubious ownership" / permission errors → silent bypass).
        let filenames = match Self::staged_filenames(&cwd) {
            Ok(names) => names,
            Err(e) => {
                warn!("[git-commit] pid={} cannot list staged files: {e}", ctx.pid);
                return ValidationResult::Block(ThreatError::GitCommitInspectionFailed {
                    detail: e,
                });
            }
        };
        if filenames.is_empty() {
            debug!("[git-commit] pid={} — no staged files found in {:?}", ctx.pid, cwd);
            return ValidationResult::Allow;
        }

        info!(
            "[git-commit] pid={} scanning {} staged file(s) in {:?}: {:?}",
            ctx.pid,
            filenames.len(),
            cwd,
            filenames,
        );

        let diff = match Self::staged_diff(&cwd) {
            Ok(d) => d,
            Err(e) => {
                warn!("[git-commit] pid={} cannot build staged diff: {e}", ctx.pid);
                return ValidationResult::Block(ThreatError::GitCommitInspectionFailed {
                    detail: e,
                });
            }
        };
        // Textual diff empty with non-empty staged names → usually binaries or non-text deltas.
        if diff.is_empty() {
            debug!(
                "[git-commit] pid={} — textual staged diff empty (binary-only?), allowing",
                ctx.pid
            );
            return ValidationResult::Allow;
        }

        let hits = scan_diff(&self.scanner, &diff);

        if hits.is_empty() {
            info!("[git-commit] pid={} — no secrets found, allowing", ctx.pid);
            ValidationResult::Allow
        } else {
            ValidationResult::Block(ThreatError::SecretLeak { hits })
        }
    }
}

// ── Diff parser ───────────────────────────────────────────────────────────────

/// Parse a unified diff and run the secret scanner only on added (+) lines.
/// Returns one SecretHit per match, attributed to the correct file and line.
fn scan_diff(scanner: &SecretScanner, diff: &str) -> Vec<SecretHit> {
    let mut hits   = Vec::new();
    let mut file   = String::new();
    let mut lineno = 0u32; // line number in the new file

    for raw in diff.lines() {
        if let Some(f) = raw.strip_prefix("+++ b/") {
            file   = f.to_string();
            lineno = 0;
            continue;
        }
        // Hunk header: @@ -old_start,old_count +new_start,new_count @@
        if raw.starts_with("@@") {
            if let Some(n) = parse_new_start(raw) {
                lineno = n.saturating_sub(1); // will be incremented on first '+' line
            }
            continue;
        }
        if raw.starts_with('+') && !raw.starts_with("+++") {
            lineno += 1;
            let line = &raw[1..]; // strip leading '+'
            for m in scanner.scan_content(line) {
                hits.push(SecretHit {
                    file:    file.clone(),
                    line:    lineno as usize,
                    kind:    m.pattern_name,
                    snippet: m.snippet,
                });
            }
        } else if !raw.starts_with('-') {
            // Context line — counts toward new-file line numbers
            lineno += 1;
        }
    }

    hits
}

/// Extract the new-file start line from a hunk header like `@@ -3,4 +7,2 @@`.
fn parse_new_start(hunk: &str) -> Option<u32> {
    let (_, rhs) = hunk.split_once('+')?;
    let end = rhs
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rhs.len());
    rhs[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_start_basic() {
        assert_eq!(parse_new_start("@@ -1,3 +7,2 @@ foo"), Some(7));
        assert_eq!(parse_new_start("@@ -0,0 +1,10 @@"), Some(1));
        assert_eq!(parse_new_start("@@ -42 +43 @@ hook"), Some(43));
    }

    #[test]
    fn scan_diff_finds_added_secret() {
        let scanner = SecretScanner::default();
        let diff = "\
diff --git a/secrets.env b/secrets.env
--- a/secrets.env
+++ b/secrets.env
@@ -0,0 +1,2 @@
+GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
+FOO=bar
";
        let hits = scan_diff(&scanner, diff);
        assert!(
            hits.iter().any(|h| h.kind.contains("GitHub")),
            "expected a GitHub PAT hit in added line, got {hits:?}"
        );
    }

    #[test]
    fn scan_diff_only_hits_added_lines_not_deletions() {
        let scanner = SecretScanner::default();
        let tok = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let diff = format!(
            "+++ b/x\n@@ -1,2 +1,2 @@\n-{tok}\n+replacement clean\n",
        );
        let hits_min = scan_diff(&scanner, &diff);
        assert!(
            hits_min.is_empty(),
            "deleted line carries token but must not be scanned; got {:?}",
            hits_min
        );

        let diff_plus = format!("+++ b/x\n@@ -1,1 +1,2 @@\n+OTHER=1\n+{tok}\n",);
        let hits_plus = scan_diff(&scanner, &diff_plus);
        assert!(
            hits_plus.iter().any(|h| h.snippet.contains("ghp_")),
            "added line must match; got {:?}",
            hits_plus
        );
    }
}
