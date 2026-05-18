use crate::errors::ThreatError;
use crate::validator::{ValidationContext, ValidationResult, Validator};
use log::{debug, info, warn};
use regex::Regex;
use std::path::PathBuf;

// -- SQL source ---------------------------------------------------------------

enum SqlSource {
    Inline(String),
    File(PathBuf),
}

// -- Threat category for block-level patterns ---------------------------------

#[derive(Copy, Clone)]
pub(crate) enum SqlCategory {
    Destructive,
    PrivilegeEscalation,
    FilesystemAccess,
    RemoteExec,
    Injection,
}

// -- Pattern engine -----------------------------------------------------------

struct NamedPattern {
    name: &'static str,
    re: Regex,
    /// true = Block (with category), false = Warn
    block: bool,
    category: SqlCategory,
}

pub struct SqlAnalyzer {
    patterns: Vec<NamedPattern>,
    re_where: Regex,
    re_delete_from: Regex,
    re_update_set: Regex,
    re_comment_line: Regex,
    re_comment_block: Regex,
}

impl Default for SqlAnalyzer {
    fn default() -> Self {
        fn re(s: &str) -> Regex {
            Regex::new(s).unwrap_or_else(|e| panic!("bad SQL guard regex `{s}`: {e}"))
        }

        macro_rules! block {
            ($cat:expr, $name:expr, $pat:expr) => {
                NamedPattern { name: $name, re: re($pat), block: true, category: $cat }
            };
        }
        macro_rules! warn_pat {
            ($name:expr, $pat:expr) => {
                NamedPattern {
                    name: $name,
                    re: re($pat),
                    block: false,
                    category: SqlCategory::Injection,
                }
            };
        }

        use SqlCategory::*;
        let patterns = vec![
            // BLOCK: DDL - object destruction
            block!(Destructive, "DROP TABLE",
                r"(?i)\bDROP\s+TABLE\b"),
            block!(Destructive, "DROP DATABASE / SCHEMA",
                r"(?i)\bDROP\s+(DATABASE|SCHEMA)\b"),
            block!(Destructive, "DROP USER / ROLE",
                r"(?i)\bDROP\s+(USER|ROLE)\b"),
            block!(Destructive, "TRUNCATE TABLE",
                r"(?i)\bTRUNCATE(\s+TABLE)?\b"),
            block!(Destructive, "ALTER TABLE DROP COLUMN",
                r"(?i)\bALTER\s+TABLE\b.{0,500}\bDROP\s+COLUMN\b"),

            // BLOCK: Privilege escalation
            block!(PrivilegeEscalation, "GRANT privileges",
                r"(?i)\bGRANT\s+\w"),
            block!(PrivilegeEscalation, "REVOKE privileges",
                r"(?i)\bREVOKE\s+\w"),
            block!(PrivilegeEscalation, "CREATE / ALTER USER or ROLE",
                r"(?i)\b(CREATE|ALTER)\s+(USER|ROLE)\b"),

            // BLOCK: Filesystem access via SQL
            block!(FilesystemAccess, "MySQL SELECT INTO OUTFILE",
                r"(?i)\bINTO\s+OUTFILE\b"),
            block!(FilesystemAccess, "MySQL LOAD DATA INFILE",
                r"(?i)\bLOAD\s+DATA\s+(LOCAL\s+)?INFILE\b"),
            block!(FilesystemAccess, "PostgreSQL COPY TO/FROM filesystem",
                r"(?i)\bCOPY\b[^;]{0,400}\b(TO|FROM)\s+['\"/]"),
            block!(FilesystemAccess, "PostgreSQL pg_read_file / pg_ls_dir / pg_stat_file",
                r"(?i)\bPG_(READ_FILE|LS_DIR|STAT_FILE)\s*\("),
            block!(FilesystemAccess, "PostgreSQL pg_execute_server_program",
                r"(?i)\bPG_EXECUTE_SERVER_PROGRAM\s*\("),
            block!(FilesystemAccess, "PostgreSQL lo_export / lo_import",
                r"(?i)\bLO_(EXPORT|IMPORT)\s*\("),

            // BLOCK: Remote code / OS command execution
            block!(RemoteExec, "MSSQL xp_cmdshell",
                r"(?i)\bXP_CMDSHELL\s*\("),
            block!(RemoteExec, "MSSQL OPENROWSET / OPENDATASOURCE",
                r"(?i)\b(OPENROWSET|OPENDATASOURCE)\s*\("),
            block!(RemoteExec, "MSSQL sp_configure",
                r"(?i)\bSP_CONFIGURE\b"),
            block!(RemoteExec, "MSSQL sp_addlogin / sp_addsrvrolemember",
                r"(?i)\bSP_(ADDLOGIN|ADDSRVROLEMEMBER|GRANTDBACCESS)\b"),

            // BLOCK: SQL injection signatures
            block!(Injection, "UNION SELECT",
                r"(?i)\bUNION\s+(ALL\s+)?SELECT\b"),
            block!(Injection, "Stacked query - DDL/DML after semicolon",
                r"(?i);\s*(DROP|TRUNCATE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w[\w.]*\s+SET|CREATE\s+(TABLE|DATABASE|USER)|ALTER\s+(TABLE|USER)|GRANT|EXEC(UTE)?)\b"),
            block!(Injection, "Dynamic EXEC with variable",
                r"(?i)\bEXEC(UTE)?\s*\(\s*@"),

            // WARN: Schema reconnaissance
            warn_pat!("System schema access (information_schema / pg_catalog)",
                r"(?i)\b(INFORMATION_SCHEMA|PG_CATALOG)\b|(?i)\bSYS\."),
            warn_pat!("SHOW DATABASES / TABLES / GRANTS / PROCESSLIST",
                r"(?i)\bSHOW\s+(DATABASES|TABLES|GRANTS|USERS|PROCESSLIST|VARIABLES|STATUS)\b"),
            warn_pat!("psql schema introspection meta-command",
                r"(?i)\\d[tfvisScCnpuFDE]?\b"),
            warn_pat!("MySQL / MariaDB DESCRIBE / EXPLAIN",
                r"(?i)\b(DESCRIBE|EXPLAIN)\s+\w"),

            // WARN: Risky schema modification
            warn_pat!("ALTER TABLE - schema modification",
                r"(?i)\bALTER\s+TABLE\b"),
            warn_pat!("DROP INDEX / VIEW / SEQUENCE / FUNCTION / PROCEDURE / TRIGGER",
                r"(?i)\bDROP\s+(INDEX|VIEW|SEQUENCE|FUNCTION|PROCEDURE|TRIGGER)\b"),

            // WARN: Bulk data operations
            warn_pat!("INSERT ... SELECT - mass data copy",
                r"(?i)\bINSERT\s+(INTO\s+)?\w[\w.]*\s+SELECT\b"),
            warn_pat!("SELECT * from sensitive-sounding table",
                r"(?i)\bSELECT\s+\*\s+FROM\s+\w*(user|account|cred|token|secret|password|auth|api_?key|session)\w*\b"),

            // WARN: Time-based injection indicators
            warn_pat!("Time-based injection (pg_sleep / SLEEP / BENCHMARK)",
                r"(?i)\b(PG_SLEEP|SLEEP|BENCHMARK)\s*\("),
            warn_pat!("WAITFOR DELAY - MSSQL time-based injection",
                r"(?i)\bWAITFOR\s+DELAY\b"),

            // WARN: Classic injection tautologies
            warn_pat!("OR 1=1 tautology",
                r#"(?i)\bOR\s+(\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*')"#),
            warn_pat!("Comment-based injection",
                r"(?i)'.{0,60}(--|/\*)"),
        ];

        Self {
            patterns,
            re_where:         re(r"(?i)\bWHERE\b"),
            re_delete_from:   re(r"(?i)\bDELETE\s+FROM\b"),
            re_update_set:    re(r"(?i)\bUPDATE\s+\w[\w.]*\s+SET\b"),
            re_comment_line:  re(r"--[^\n]*"),
            re_comment_block: re(r"/\*[\s\S]*?\*/"),
        }
    }
}

// -- Classified finding -------------------------------------------------------

pub(crate) struct CategorizedFinding {
    pub(crate) category: SqlCategory,
    pub(crate) detail: String,
}

impl SqlAnalyzer {
    fn normalize(&self, sql: &str) -> String {
        let s = self.re_comment_block.replace_all(sql, " ");
        let s = self.re_comment_line.replace_all(&s, " ");
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn analyze_statement(
        &self,
        stmt: &str,
        blocks: &mut Vec<CategorizedFinding>,
        warns: &mut Vec<String>,
    ) {
        let stmt = stmt.trim();
        if stmt.is_empty() { return; }

        for pat in &self.patterns {
            if pat.re.is_match(stmt) {
                let detail = format!("{} -- `{}`", pat.name, snippet(stmt, 100));
                if pat.block {
                    blocks.push(CategorizedFinding { category: pat.category, detail });
                } else {
                    warns.push(detail);
                }
            }
        }

        if self.re_delete_from.is_match(stmt) && !self.re_where.is_match(stmt) {
            blocks.push(CategorizedFinding {
                category: SqlCategory::Destructive,
                detail: format!(
                    "DELETE FROM without WHERE (would delete every row) -- `{}`",
                    snippet(stmt, 100)
                ),
            });
        }

        if self.re_update_set.is_match(stmt) && !self.re_where.is_match(stmt) {
            blocks.push(CategorizedFinding {
                category: SqlCategory::Destructive,
                detail: format!(
                    "UPDATE without WHERE (would update every row) -- `{}`",
                    snippet(stmt, 100)
                ),
            });
        }
    }

    pub fn analyze(&self, sql: &str) -> SqlAnalysis {
        let normalized = self.normalize(sql);
        let mut block_findings: Vec<CategorizedFinding> = Vec::new();
        let mut warn_findings: Vec<String> = Vec::new();

        for stmt in normalized.split(';') {
            self.analyze_statement(stmt, &mut block_findings, &mut warn_findings);
        }

        warn_findings.dedup();

        if !block_findings.is_empty() {
            SqlAnalysis::Dangerous(block_findings)
        } else if !warn_findings.is_empty() {
            SqlAnalysis::Suspicious(warn_findings)
        } else {
            SqlAnalysis::Clean
        }
    }
}

pub enum SqlAnalysis {
    Clean,
    Suspicious(Vec<String>),
    Dangerous(Vec<CategorizedFinding>),
}

// -- Validator ----------------------------------------------------------------

pub struct SqlGuardValidator {
    tool_label: &'static str,
    sql_flags: &'static [&'static str],
    file_flags: &'static [&'static str],
    positional_sql: bool,
    analyzer: SqlAnalyzer,
}

impl SqlGuardValidator {
    pub fn psql() -> Self {
        Self {
            tool_label: "psql",
            sql_flags: &["-c", "--command"],
            file_flags: &["-f", "--file"],
            positional_sql: false,
            analyzer: SqlAnalyzer::default(),
        }
    }

    pub fn mysql() -> Self {
        Self {
            tool_label: "mysql",
            sql_flags: &["-e", "--execute"],
            file_flags: &["-f", "--file"],
            positional_sql: false,
            analyzer: SqlAnalyzer::default(),
        }
    }

    pub fn sqlite3() -> Self {
        Self {
            tool_label: "sqlite3",
            sql_flags: &[],
            file_flags: &[],
            positional_sql: true,
            analyzer: SqlAnalyzer::default(),
        }
    }

    fn extract_sql(&self, args: &[String]) -> Option<SqlSource> {
        let find_flag = |flags: &[&str]| -> Option<String> {
            let mut iter = args.iter().peekable();
            while let Some(arg) = iter.next() {
                for flag in flags {
                    if arg == flag {
                        return iter.next().cloned();
                    }
                    let prefix = format!("{}=", flag);
                    if let Some(val) = arg.strip_prefix(&prefix) {
                        return Some(val.to_string());
                    }
                }
            }
            None
        };

        if let Some(sql) = find_flag(self.sql_flags) {
            return Some(SqlSource::Inline(sql));
        }
        if let Some(path) = find_flag(self.file_flags) {
            return Some(SqlSource::File(PathBuf::from(path)));
        }
        if self.positional_sql {
            let bare: Vec<&str> = args.iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .map(String::as_str)
                .collect();
            if bare.len() >= 2 {
                return Some(SqlSource::Inline(bare[bare.len() - 1].to_string()));
            }
        }
        None
    }
}

impl Validator for SqlGuardValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        let source = match self.extract_sql(&ctx.args) {
            Some(s) => s,
            None => {
                debug!(
                    "[{}] pid={} no inline SQL in args",
                    self.tool_label, ctx.pid
                );
                return ValidationResult::Allow;
            }
        };

        let sql = match source {
            SqlSource::Inline(s) => s,
            SqlSource::File(path) => match std::fs::read_to_string(&path) {
                Ok(content) => {
                    info!(
                        "[{}] pid={} scanning SQL file {:?} ({} bytes)",
                        self.tool_label, ctx.pid, path, content.len()
                    );
                    content
                }
                Err(e) => {
                    warn!(
                        "[{}] pid={} cannot read SQL file {:?}: {}",
                        self.tool_label, ctx.pid, path, e
                    );
                    return ValidationResult::Allow;
                }
            },
        };

        info!(
            "[{}] pid={} analyzing SQL ({} chars)",
            self.tool_label, ctx.pid, sql.len()
        );

        match self.analyzer.analyze(&sql) {
            SqlAnalysis::Clean => {
                info!("[{}] SQL analysis passed", self.tool_label);
                ValidationResult::Allow
            }
            SqlAnalysis::Suspicious(findings) => {
                ValidationResult::Warn(ThreatError::SqlSuspicious {
                    tool: self.tool_label,
                    findings,
                })
            }
            SqlAnalysis::Dangerous(categorized) => {
                ValidationResult::Block(build_sql_threat(self.tool_label, categorized))
            }
        }
    }
}

// -- pub(crate) helper for kubectl_guard --------------------------------------

pub(crate) fn build_sql_threat_pub(
    tool: &'static str,
    findings: Vec<CategorizedFinding>,
) -> ThreatError {
    build_sql_threat(tool, findings)
}

/// Group categorized findings into the most specific ThreatError variant.
/// Priority: RemoteExec > Injection > PrivilegeEscalation > FilesystemAccess > Destructive.
fn build_sql_threat(tool: &'static str, findings: Vec<CategorizedFinding>) -> ThreatError {
    let mut destructive: Vec<String> = vec![];
    let mut priv_esc: Vec<String> = vec![];
    let mut filesystem: Vec<String> = vec![];
    let mut remote_exec: Vec<String> = vec![];
    let mut injection: Vec<String> = vec![];

    for f in findings {
        match f.category {
            SqlCategory::Destructive         => destructive.push(f.detail),
            SqlCategory::PrivilegeEscalation => priv_esc.push(f.detail),
            SqlCategory::FilesystemAccess    => filesystem.push(f.detail),
            SqlCategory::RemoteExec          => remote_exec.push(f.detail),
            SqlCategory::Injection           => injection.push(f.detail),
        }
    }

    if !remote_exec.is_empty() {
        ThreatError::SqlRemoteExec { tool, operations: remote_exec }
    } else if !injection.is_empty() {
        ThreatError::SqlInjection { tool, patterns: injection }
    } else if !priv_esc.is_empty() {
        ThreatError::SqlPrivilegeEscalation { tool, operations: priv_esc }
    } else if !filesystem.is_empty() {
        ThreatError::SqlFilesystemAccess { tool, operations: filesystem }
    } else {
        ThreatError::SqlDestructive { tool, operations: destructive }
    }
}

// -- Helpers used by kubectl_guard --------------------------------------------

pub(crate) fn extract_sql_for_tool(tool: &str, args: &[String]) -> Option<String> {
    let validator = match tool {
        "psql"              => SqlGuardValidator::psql(),
        "mysql" | "mariadb" => SqlGuardValidator::mysql(),
        "sqlite3"           => SqlGuardValidator::sqlite3(),
        _                   => return None,
    };
    match validator.extract_sql(args)? {
        SqlSource::Inline(s)  => Some(s),
        SqlSource::File(path) => std::fs::read_to_string(&path).ok(),
    }
}

fn snippet(s: &str, max_chars: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_chars).collect::<String>())
    }
}

