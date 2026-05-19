/// Sensitive-data policy: database tables and filesystem paths.
///
/// Config is a plain text file — one directive per line:
///
///   # comment
///   block  <table>                       — deny all SQL access
///   mask   <table>  <col>:<kind> ...     — mask sensitive columns in output
///   fblock <path_pattern>                — deny any read of matching paths
///   fmask  <path_pattern>                — allow read but mask secrets in output
///
/// Column mask kinds: redact | email | phone | partial:<n>
/// Path patterns support `*` (segment wildcard) and `~` (home dir expansion).
///
/// Example:
///   block  payment_cards
///   mask   users  email:email  phone:phone  ssn:redact  password_hash:redact
///   fblock /etc/shadow
///   fblock ~/.ssh/id_*
///   fmask  ~/.aws/credentials
///   fmask  /var/log/*.log
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ── SQL column mask types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PolicyMode { Block, Mask }

#[derive(Debug, Clone, Copy)]
pub enum MaskKind {
    Redact,
    Email,
    Phone,
    Partial(u8),
}

impl MaskKind {
    pub fn sql_expr(self, col: &str, dialect: SqlDialect) -> String {
        match (self, dialect) {
            (MaskKind::Redact, _) => format!("'[REDACTED]' AS {col}"),
            (MaskKind::Email, SqlDialect::Postgres) => {
                format!("(left({col}::text, 1) || '***@***.***') AS {col}")
            }
            (MaskKind::Email, _) => {
                format!("CONCAT(LEFT({col}, 1), '***@***.***') AS {col}")
            }
            (MaskKind::Phone, SqlDialect::Postgres) => {
                format!("('***-**-' || right({col}::text, 4)) AS {col}")
            }
            (MaskKind::Phone, _) => {
                format!("CONCAT('***-**-', RIGHT({col}, 4)) AS {col}")
            }
            (MaskKind::Partial(n), SqlDialect::Postgres) => {
                format!("(left({col}::text, {n}) || '***') AS {col}")
            }
            (MaskKind::Partial(n), _) => {
                format!("CONCAT(LEFT({col}, {n}), '***') AS {col}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SqlDialect { Postgres, Mysql, Sqlite }

#[derive(Debug, Clone)]
pub struct ColumnPolicy { pub name: String, pub mask: MaskKind }

#[derive(Debug, Clone)]
pub struct TablePolicy {
    pub name:    String,
    pub mode:    PolicyMode,
    pub columns: Vec<ColumnPolicy>,
}

// ── Filesystem path policy ────────────────────────────────────────────────────

/// A rule that protects a path (or glob of paths) on the filesystem.
#[derive(Debug, Clone)]
pub struct FsRule {
    /// Original pattern string (for display).
    pub raw: String,
    /// Expanded pattern (~ replaced with $HOME).
    expanded: String,
    pub mode: PolicyMode,
}

impl FsRule {
    fn new(raw: &str, mode: PolicyMode) -> Self {
        let expanded = expand_home(raw);
        Self { raw: raw.to_string(), expanded, mode }
    }

    /// True if `path` is covered by this rule.
    pub fn matches(&self, path: &Path) -> bool {
        let p = path.to_string_lossy();
        glob_match(&self.expanded, &p)
    }
}

// ── DataPolicy ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DataPolicy {
    tables:   HashMap<String, TablePolicy>,
    fs_rules: Vec<FsRule>,
}

impl DataPolicy {
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty() && self.fs_rules.is_empty()
    }

    pub fn find_table(&self, name: &str) -> Option<&TablePolicy> {
        self.tables.get(&name.to_ascii_lowercase())
    }

    /// Return the first filesystem rule that covers `path`, if any.
    pub fn find_fs_rule(&self, path: &Path) -> Option<&FsRule> {
        self.fs_rules.iter().find(|r| r.matches(path))
    }

    pub fn load(path: &Path) -> anyhow::Result<Arc<Self>> {
        let content = fs::read_to_string(path)?;
        Self::parse(&content).map(Arc::new)
    }

    pub fn load_default() -> Arc<Self> {
        let candidates = [
            std::env::var("PROTECTOR_POLICY").ok().map(PathBuf::from),
            Some(PathBuf::from("/etc/protector/policy.conf")),
            Some(PathBuf::from("policy.conf")),
        ];
        for path in candidates.into_iter().flatten() {
            if path.exists() {
                match Self::load(&path) {
                    Ok(p) => {
                        log::info!(
                            "Data policy loaded from {:?} ({} table(s), {} path rule(s))",
                            path, p.tables.len(), p.fs_rules.len()
                        );
                        return p;
                    }
                    Err(e) => log::warn!("Ignoring malformed policy file {:?}: {e}", path),
                }
            }
        }
        log::debug!("No data policy file found — sensitive-data protection inactive");
        Arc::new(Self::default())
    }

    fn parse(input: &str) -> anyhow::Result<Self> {
        let mut policy = DataPolicy::default();

        for (lineno, raw_line) in input.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 2 {
                anyhow::bail!(
                    "policy line {}: expected '<directive> <target> [...]', got {:?}",
                    lineno + 1, line
                );
            }

            match tokens[0] {
                // ── Filesystem rules ────────────────────────────────────────
                "fblock" => {
                    policy.fs_rules.push(FsRule::new(tokens[1], PolicyMode::Block));
                }
                "fmask" => {
                    policy.fs_rules.push(FsRule::new(tokens[1], PolicyMode::Mask));
                }

                // ── Database table rules ────────────────────────────────────
                "block" | "mask" => {
                    let mode = if tokens[0] == "block" { PolicyMode::Block } else { PolicyMode::Mask };
                    let table_name = tokens[1].to_ascii_lowercase();

                    let mut columns = Vec::new();
                    for token in &tokens[2..] {
                        let (col, kind_str) = token.split_once(':').ok_or_else(|| {
                            anyhow::anyhow!(
                                "policy line {}: bad column spec '{}' — expected col:kind",
                                lineno + 1, token
                            )
                        })?;
                        let mask = parse_mask_kind(kind_str).ok_or_else(|| {
                            anyhow::anyhow!(
                                "policy line {}: unknown mask kind '{}' (redact|email|phone|partial:N)",
                                lineno + 1, kind_str
                            )
                        })?;
                        columns.push(ColumnPolicy { name: col.to_ascii_lowercase(), mask });
                    }

                    policy.tables.insert(table_name.clone(), TablePolicy {
                        name: table_name,
                        mode,
                        columns,
                    });
                }

                other => anyhow::bail!(
                    "policy line {}: unknown directive '{}' (block|mask|fblock|fmask)",
                    lineno + 1, other
                ),
            }
        }

        Ok(policy)
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn expand_home(s: &str) -> String {
    if s.starts_with("~/") || s == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}{}", home, &s[1..]);
        }
    }
    s.to_string()
}

/// Simple glob matcher.  Supports `*` (matches any chars except `/`) and
/// `**` (matches any chars including `/`).  Directory prefix match: if the
/// pattern ends with `/`, any path that starts with the prefix matches.
fn glob_match(pattern: &str, text: &str) -> bool {
    // Directory prefix: "fblock /etc/ssh/" matches "/etc/ssh/known_hosts"
    if pattern.ends_with('/') {
        return text.starts_with(pattern) || text == pattern.trim_end_matches('/');
    }

    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_inner(pat: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == text[ti] || pat[pi] == b'?') {
            pi += 1;
            ti += 1;
        } else if pi + 1 < pat.len() && pat[pi] == b'*' && pat[pi + 1] == b'*' {
            // ** — match anything including /
            star_pi = Some(pi);
            star_ti = ti;
            pi += 2;
        } else if pi < pat.len() && pat[pi] == b'*' {
            // * — match anything except /
            if text[ti] == b'/' {
                // * does not cross directory boundaries
                if let Some(sp) = star_pi {
                    pi = sp;
                } else {
                    return false;
                }
            } else {
                star_pi = Some(pi);
                star_ti = ti;
                pi += 1;
            }
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }

    pi == pat.len()
}

// ── Parsers ───────────────────────────────────────────────────────────────────

fn parse_mask_kind(s: &str) -> Option<MaskKind> {
    match s {
        "redact" => Some(MaskKind::Redact),
        "email"  => Some(MaskKind::Email),
        "phone"  => Some(MaskKind::Phone),
        other if other.starts_with("partial:") => {
            let n: u8 = other["partial:".len()..].parse().ok()?;
            Some(MaskKind::Partial(n))
        }
        _ => None,
    }
}
