use crate::errors::{SecretHit, ThreatError};
use crate::validator::{ValidationContext, ValidationResult, Validator};
use crate::validators::secret::SecretScanner;
use log::{debug, info, warn};
use std::path::Path;
use std::process::Command;

// ── Sensitive filename patterns ────────────────────────────────────────────────
// A commit that adds any of these files is blocked regardless of content.
// Patterns support '*' (glob) and exact match; checked against the basename.

const SENSITIVE_FILENAME_SUFFIXES: &[&str] = &[
    // Private keys and certificates
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".pkcs12",
    // SSH private keys (no extension)
    "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk",
    // Legacy net credentials
    ".netrc",
    // Terraform secret values
    ".tfvars",
];

const SENSITIVE_FILENAME_EXACT: &[&str] = &[
    // AWS credential store
    "credentials",
    // Kubernetes config
    "kubeconfig",
    // GCP service account
    "service_account.json",
    // Docker Hub auth
    "config.json",  // inside .docker/ — caught by path check below
];

const SENSITIVE_PATH_SEGMENTS: &[&str] = &[
    ".ssh/",
    ".aws/",
    ".kube/",
    ".docker/",
    ".gnupg/",
    "secrets/",
    "private/",
];

// ── Validator ─────────────────────────────────────────────────────────────────

pub struct GitCommitValidator {
    scanner: SecretScanner,
}

impl GitCommitValidator {
    pub fn new(scanner: SecretScanner) -> Self {
        Self { scanner }
    }

    fn git(cwd: &Path, args: &[&str]) -> std::process::Output {
        // -c safe.directory=* lets root read repos owned by other users
        let mut cmd = Command::new("git");
        cmd.args(["-C", &cwd.to_string_lossy(), "-c", "safe.directory=*"]);
        cmd.args(args);
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
            Ok(String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect())
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

        let filenames = match Self::staged_filenames(&cwd) {
            Ok(names) => names,
            Err(e) => {
                warn!("[git-commit] pid={} cannot list staged files: {e}", ctx.pid);
                return ValidationResult::Block(ThreatError::GitCommitInspectionFailed { detail: e });
            }
        };

        if filenames.is_empty() {
            debug!("[git-commit] pid={} — no staged files in {:?}", ctx.pid, cwd);
            return ValidationResult::Allow;
        }

        info!(
            "[git-commit] pid={} scanning {} staged file(s) in {:?}: {:?}",
            ctx.pid,
            filenames.len(),
            cwd,
            filenames,
        );

        // ── Phase 1: block by filename ────────────────────────────────────────────
        let filename_hits = check_sensitive_filenames(&filenames);
        if !filename_hits.is_empty() {
            for h in &filename_hits {
                warn!(
                    "[git-commit] pid={} blocked sensitive file: {} ({})",
                    ctx.pid, h.file, h.kind
                );
            }
            return ValidationResult::Block(ThreatError::SecretLeak { hits: filename_hits });
        }

        // ── Phase 2: scan diff content ────────────────────────────────────────────
        let diff = match Self::staged_diff(&cwd) {
            Ok(d) => d,
            Err(e) => {
                warn!("[git-commit] pid={} cannot build staged diff: {e}", ctx.pid);
                return ValidationResult::Block(ThreatError::GitCommitInspectionFailed { detail: e });
            }
        };

        if diff.is_empty() {
            debug!("[git-commit] pid={} — textual diff empty (binary only?), allowing", ctx.pid);
            return ValidationResult::Allow;
        }

        let hits = scan_diff(&self.scanner, &diff);

        if hits.is_empty() {
            info!(
                "[git-commit] pid={} — {} pattern(s) checked, no secrets found — allowing",
                ctx.pid,
                self.scanner.pattern_count()
            );
            ValidationResult::Allow
        } else {
            ValidationResult::Block(ThreatError::SecretLeak { hits })
        }
    }
}

// ── Sensitive filename check ──────────────────────────────────────────────────

fn check_sensitive_filenames(filenames: &[String]) -> Vec<SecretHit> {
    let mut hits = Vec::new();

    for path in filenames {
        let lower = path.to_ascii_lowercase();
        let basename = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();

        // Check path segments
        for &seg in SENSITIVE_PATH_SEGMENTS {
            if lower.contains(seg) {
                hits.push(SecretHit {
                    file: path.clone(),
                    line: 0,
                    kind: format!("File in sensitive directory ({})", seg.trim_end_matches('/')),
                    snippet: path.clone(),
                });
                break;
            }
        }

        if hits.last().map(|h| &h.file) == Some(path) {
            // Already flagged by path segment check
            continue;
        }

        // Check exact filenames
        for &exact in SENSITIVE_FILENAME_EXACT {
            if basename == exact {
                hits.push(SecretHit {
                    file: path.clone(),
                    line: 0,
                    kind: format!("Sensitive filename: {}", exact),
                    snippet: path.clone(),
                });
                break;
            }
        }

        if hits.last().map(|h| &h.file) == Some(path) {
            continue;
        }

        // Check file extension / suffix
        for &suffix in SENSITIVE_FILENAME_SUFFIXES {
            if suffix.starts_with('.') {
                if lower.ends_with(suffix) {
                    hits.push(SecretHit {
                        file: path.clone(),
                        line: 0,
                        kind: format!("Sensitive file type ({})", suffix),
                        snippet: path.clone(),
                    });
                    break;
                }
            } else if basename == suffix {
                hits.push(SecretHit {
                    file: path.clone(),
                    line: 0,
                    kind: format!("Sensitive filename: {}", suffix),
                    snippet: path.clone(),
                });
                break;
            }
        }
    }

    hits
}

// ── Diff parser ───────────────────────────────────────────────────────────────

/// Parse a unified diff and run the secret scanner on added (+) lines only.
/// Returns one SecretHit per pattern match, attributed to the correct file and line.
fn scan_diff(scanner: &SecretScanner, diff: &str) -> Vec<SecretHit> {
    let mut hits   = Vec::new();
    let mut file   = String::new();
    let mut lineno = 0u32;

    for raw in diff.lines() {
        if let Some(f) = raw.strip_prefix("+++ b/") {
            file   = f.to_string();
            lineno = 0;
            continue;
        }
        if raw.starts_with("@@") {
            if let Some(n) = parse_new_start(raw) {
                lineno = n.saturating_sub(1);
            }
            continue;
        }
        if raw.starts_with('+') && !raw.starts_with("+++") {
            lineno += 1;
            let line = &raw[1..];
            for m in scanner.scan_content(line) {
                hits.push(SecretHit {
                    file:    file.clone(),
                    line:    lineno as usize,
                    kind:    m.pattern_name,
                    snippet: m.snippet,
                });
            }
        } else if !raw.starts_with('-') {
            lineno += 1;
        }
    }

    // Deduplicate: same file + line + kind (multiple patterns can fire on one spot)
    hits.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.kind == b.kind);
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

// ── Tests ─────────────────────────────────────────────────────────────────────

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
    fn scan_diff_finds_github_pat() {
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
            "expected GitHub PAT hit, got {hits:?}"
        );
    }

    #[test]
    fn scan_diff_only_hits_added_lines() {
        let scanner = SecretScanner::default();
        let tok = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let diff = format!("+++ b/x\n@@ -1,2 +1,2 @@\n-{tok}\n+replacement clean\n");
        let hits = scan_diff(&scanner, &diff);
        assert!(
            hits.is_empty(),
            "deleted line must not be scanned; got {hits:?}"
        );

        let diff_plus = format!("+++ b/x\n@@ -1,1 +1,2 @@\n+OTHER=1\n+{tok}\n");
        let hits_plus = scan_diff(&scanner, &diff_plus);
        assert!(
            hits_plus.iter().any(|h| h.snippet.contains("ghp_")),
            "added line must match; got {hits_plus:?}"
        );
    }

    #[test]
    fn blocks_pem_file() {
        let hits = check_sensitive_filenames(&["certs/server.pem".to_string()]);
        assert!(!hits.is_empty(), "expected .pem to be blocked");
        assert!(hits[0].kind.contains("pem"), "{:?}", hits[0].kind);
    }

    #[test]
    fn blocks_ssh_private_key() {
        let hits = check_sensitive_filenames(&["~/.ssh/id_rsa".to_string()]);
        assert!(!hits.is_empty(), "expected id_rsa to be blocked");
    }

    #[test]
    fn blocks_aws_credentials() {
        let hits = check_sensitive_filenames(&[".aws/credentials".to_string()]);
        assert!(!hits.is_empty(), "expected .aws/credentials to be blocked");
    }

    #[test]
    fn allows_normal_files() {
        let hits = check_sensitive_filenames(&[
            "src/main.rs".to_string(),
            "README.md".to_string(),
            "config/settings.toml".to_string(),
        ]);
        assert!(hits.is_empty(), "normal files should not be blocked, got {hits:?}");
    }

    #[test]
    fn scan_diff_detects_stripe_key() {
        let scanner = SecretScanner::default();
        // Built at runtime so push scanners don't flag test fixtures as real secrets.
        let stripe_key = format!("sk_live_{}", "A".repeat(24));
        let diff = format!(
            "+++ b/.env\n@@ -0,0 +1 @@\n+STRIPE_SECRET_KEY={stripe_key}\n"
        );
        let hits = scan_diff(&scanner, &diff);
        assert!(
            hits.iter().any(|h| h.kind.contains("Stripe")),
            "expected Stripe key hit, got {hits:?}"
        );
    }

    #[test]
    fn scan_diff_detects_private_key_header() {
        let scanner = SecretScanner::default();
        let diff = "+++ b/key.txt\n@@ -0,0 +1 @@\n+-----BEGIN RSA PRIVATE KEY-----\n";
        let hits = scan_diff(&scanner, diff);
        assert!(
            hits.iter().any(|h| h.kind.contains("Private Key")),
            "expected private key hit, got {hits:?}"
        );
    }
}
