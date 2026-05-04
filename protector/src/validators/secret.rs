use regex::Regex;
use std::path::Path;

pub struct SecretMatch {
    pub pattern_name: String,
    pub line_number: usize,
    /// Truncated snippet of the offending line
    pub snippet: String,
}

struct SecretPattern {
    name: &'static str,
    regex: Regex,
}

pub struct SecretScanner {
    patterns: Vec<SecretPattern>,
}

impl Default for SecretScanner {
    fn default() -> Self {
        let defs: &[(&'static str, &str)] = &[
            ("AWS Access Key ID",         r"AKIA[0-9A-Z]{16}"),
            ("AWS Secret Access Key",     r"(?i)aws.{0,20}secret.{0,20}[A-Za-z0-9/+]{40}"),
            ("GitHub Token (classic)",    r"ghp_[A-Za-z0-9]{36}"),
            ("GitHub Token (fine-grained)", r"github_pat_[A-Za-z0-9_]{82}"),
            ("GitHub Actions secret",     r"ghs_[A-Za-z0-9]{36}"),
            ("Private Key Header",        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            ("Slack Token",               r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
            ("Google API Key",            r"AIza[0-9A-Za-z_\-]{35}"),
            ("Stripe Secret Key",         r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
            ("SendGrid API Key",          r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
            ("JWT Token",                 r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
            ("Generic API Key",           r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9/_\-]{20,}"),
            ("Generic Secret/Password",   r#"(?i)(secret|password|passwd|pwd|token)\s*[=:]\s*['"]\S{8,}['"]"#),
            ("High-entropy hex string",   r"\b[0-9a-f]{32,}\b"),
        ];

        let patterns = defs
            .iter()
            .filter_map(|(name, pattern)| {
                Regex::new(pattern)
                    .ok()
                    .map(|regex| SecretPattern { name, regex })
            })
            .collect();

        Self { patterns }
    }
}

impl SecretScanner {
    /// Scan string content line by line, returning all matches.
    pub fn scan_content(&self, content: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();
        for (line_idx, line) in content.lines().enumerate() {
            for pat in &self.patterns {
                if pat.regex.is_match(line) {
                    matches.push(SecretMatch {
                        pattern_name: pat.name.to_string(),
                        line_number: line_idx + 1,
                        snippet: line.trim().chars().take(120).collect(),
                    });
                    break; // one hit per line is enough
                }
            }
        }
        matches
    }

    /// Scan a file. Skips binaries and files larger than 2 MB.
    pub fn scan_file(&self, path: &Path) -> Vec<SecretMatch> {
        let Ok(meta) = std::fs::metadata(path) else {
            return vec![];
        };
        if meta.len() > 2_000_000 {
            return vec![];
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            return vec![];
        };
        self.scan_content(&content)
    }
}
