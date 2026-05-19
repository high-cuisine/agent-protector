/// Sensitive-table access guard.
///
/// Intercepts SQL queries against tables listed in the data policy.
/// Two enforcement modes:
///
/// - **block**: deny the query outright (agent gets [DATA_POLICY_BLOCK]).
/// - **mask**: rewrite the query to replace sensitive column expressions,
///             run the rewritten query as a subprocess, pipe its output into
///             the stopped process's stdout so the agent receives masked data,
///             then SIGKILL the original process (agent gets [DATA_POLICY_MASKED]).
use std::collections::HashSet;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::sync::Arc;

use regex::Regex;

use crate::data_policy::{DataPolicy, PolicyMode, SqlDialect, TablePolicy};
use crate::errors::ThreatError;
use crate::validator::{ValidationContext, ValidationResult, Validator};

// ── Validator ─────────────────────────────────────────────────────────────────

pub struct DataGuardValidator {
    policy:     Arc<DataPolicy>,
    dialect:    SqlDialect,
    tool_label: &'static str,
    sql_flags:  &'static [&'static str],
    file_flags: &'static [&'static str],
    /// Regex that finds bare table names after FROM / JOIN / UPDATE / INTO.
    re_table_refs: Vec<Regex>,
    re_select_star: Regex,
}

impl DataGuardValidator {
    pub fn psql(policy: Arc<DataPolicy>) -> Self {
        Self::new(policy, SqlDialect::Postgres, "psql", &["-c", "--command"], &["-f", "--file"])
    }

    pub fn mysql(policy: Arc<DataPolicy>) -> Self {
        Self::new(policy, SqlDialect::Mysql, "mysql", &["-e", "--execute"], &["-f", "--file"])
    }

    pub fn sqlite3(policy: Arc<DataPolicy>) -> Self {
        Self::new(policy, SqlDialect::Sqlite, "sqlite3", &[], &[])
    }

    fn new(
        policy:     Arc<DataPolicy>,
        dialect:    SqlDialect,
        tool_label: &'static str,
        sql_flags:  &'static [&'static str],
        file_flags: &'static [&'static str],
    ) -> Self {
        let re = |s: &str| Regex::new(s).expect("data_guard: bad regex");
        Self {
            policy,
            dialect,
            tool_label,
            sql_flags,
            file_flags,
            re_table_refs: vec![
                re(r"(?i)\bFROM\s+([a-zA-Z_][a-zA-Z0-9_]*)"),
                re(r"(?i)\bJOIN\s+([a-zA-Z_][a-zA-Z0-9_]*)"),
                re(r"(?i)\bUPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*)"),
                re(r"(?i)\bINTO\s+([a-zA-Z_][a-zA-Z0-9_]*)"),
            ],
            re_select_star: re(r"(?i)\bSELECT\s+\*"),
        }
    }
}

impl Validator for DataGuardValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        if self.policy.is_empty() {
            return ValidationResult::Allow;
        }

        let sql = match self.extract_sql(&ctx.args) {
            Some(s) => s,
            None    => return ValidationResult::Allow,
        };

        let touched = self.table_refs(&sql);
        if touched.is_empty() {
            return ValidationResult::Allow;
        }

        // Find the first protected table hit in this query.
        let hit = touched.iter().find_map(|t| {
            self.policy.find_table(t).map(|p| (t.as_str(), p))
        });
        let (table_name, table_policy) = match hit {
            Some(h) => h,
            None    => return ValidationResult::Allow,
        };

        log::info!(
            "[{}] data_guard: query touches protected table '{}' (mode={:?})",
            self.tool_label, table_name, table_policy.mode
        );

        match table_policy.mode {
            PolicyMode::Block => {
                ValidationResult::Block(ThreatError::DataPolicyBlock {
                    tool:    self.tool_label,
                    table:   table_name.to_string(),
                    columns: table_policy.columns.iter().map(|c| c.name.clone()).collect(),
                })
            }

            PolicyMode::Mask => {
                // SELECT * cannot be masked without querying the schema first.
                if self.re_select_star.is_match(&sql) {
                    return ValidationResult::Block(ThreatError::DataPolicyBlock {
                        tool:    self.tool_label,
                        table:   table_name.to_string(),
                        columns: table_policy.columns.iter().map(|c| c.name.clone()).collect(),
                    });
                }

                let masked_sql  = self.rewrite_sql(&sql, table_policy);
                let masked_cols = table_policy.columns.iter().map(|c| c.name.clone()).collect();

                match self.substitute_output(ctx, &masked_sql) {
                    Ok(()) => {
                        ValidationResult::Block(ThreatError::DataPolicyMasked {
                            tool:           self.tool_label,
                            table:          table_name.to_string(),
                            masked_columns: masked_cols,
                        })
                    }
                    Err(e) => {
                        log::error!("[{}] data_guard: mask substitution failed: {e}", self.tool_label);
                        // Fall back to block so nothing leaks.
                        ValidationResult::Block(ThreatError::DataPolicyBlock {
                            tool:    self.tool_label,
                            table:   table_name.to_string(),
                            columns: masked_cols,
                        })
                    }
                }
            }
        }
    }
}

// ── SQL helpers ───────────────────────────────────────────────────────────────

impl DataGuardValidator {
    /// Extract the SQL text from the command arguments.
    fn extract_sql(&self, args: &[String]) -> Option<String> {
        // Flag-value pairs: -c "SQL" or -c=SQL
        for flag in self.sql_flags {
            let mut iter = args.iter().peekable();
            while let Some(arg) = iter.next() {
                if arg == flag {
                    return iter.next().cloned();
                }
                let prefix = format!("{flag}=");
                if let Some(val) = arg.strip_prefix(&prefix) {
                    return Some(val.to_string());
                }
            }
        }

        // File-based SQL (read the file)
        for flag in self.file_flags {
            let mut iter = args.iter().peekable();
            while let Some(arg) = iter.next() {
                if arg == flag {
                    if let Some(path) = iter.next() {
                        return std::fs::read_to_string(path).ok();
                    }
                }
            }
        }

        // sqlite3: last positional arg after the db filename
        if self.dialect == SqlDialect::Sqlite {
            let positional: Vec<&str> = args.iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .map(String::as_str)
                .collect();
            if positional.len() >= 2 {
                return Some(positional[positional.len() - 1].to_string());
            }
        }

        None
    }

    /// Collect table names referenced in the SQL (lowercase).
    fn table_refs(&self, sql: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        for re in &self.re_table_refs {
            for cap in re.captures_iter(sql) {
                if let Some(m) = cap.get(1) {
                    out.insert(m.as_str().to_ascii_lowercase());
                }
            }
        }
        out
    }

    /// Rewrite SELECT-list column references to their masking SQL expressions.
    /// Only replaces occurrences BEFORE the first FROM keyword, so WHERE / JOIN
    /// conditions keep the original column names for correct filtering.
    fn rewrite_sql(&self, sql: &str, policy: &TablePolicy) -> String {
        // Split at the first FROM boundary (case-insensitive).
        let upper = sql.to_ascii_uppercase();
        let from_pos = upper
            .find(" FROM ")
            .or_else(|| upper.find("\nFROM "))
            .or_else(|| upper.find("\tFROM "));

        let (select_part, rest) = match from_pos {
            Some(idx) => (&sql[..idx], &sql[idx..]),
            None      => return sql.to_string(), // no FROM — can't rewrite safely
        };

        let mut rewritten = select_part.to_string();
        for col in &policy.columns {
            let escaped = regex::escape(&col.name);
            // Match the column name as a standalone word (not part of another identifier).
            let re = match Regex::new(&format!(r"(?i)\b{escaped}\b")) {
                Ok(r)  => r,
                Err(_) => continue,
            };
            let expr = col.mask.sql_expr(&col.name, self.dialect);
            rewritten = re.replace_all(&rewritten, expr.as_str()).into_owned();
        }

        format!("{rewritten}{rest}")
    }
}

// ── Mask substitution ─────────────────────────────────────────────────────────

impl DataGuardValidator {
    /// Run the masked query as a subprocess, then write its output into the
    /// stopped process's stdout pipe so the agent receives masked data.
    ///
    /// After this call, the caller MUST SIGKILL + SIGCONT the original process.
    /// The masked output is already in the pipe buffer; the agent reads it
    /// once the original process terminates (closing its end of the pipe).
    fn substitute_output(&self, ctx: &ValidationContext, masked_sql: &str) -> anyhow::Result<()> {
        let uid = proc_uid(ctx.pid)?;
        let gid = proc_gid(ctx.pid)?;

        // Rebuild the argv with the SQL replaced.
        let new_args = self.replace_sql_arg(&ctx.args, masked_sql);
        let binary   = PathBuf::from(&new_args[0]);

        let header = format!(
            "\n[DATA_POLICY: masked output — sensitive columns replaced in '{}']\n",
            ctx.filename.split('/').next_back().unwrap_or(&ctx.filename)
        );

        // Spawn the masked query.  Drop privileges to the original user so
        // peer-auth and row-security policies stay correct.
        let output = unsafe {
            std::process::Command::new(&binary)
                .args(&new_args[1..])
                // Safety: we call setuid/setgid from the child before exec.
                .pre_exec(move || {
                    libc::setgid(gid);
                    libc::setuid(uid);
                    Ok(())
                })
                .output()?
        };

        // Write masked output to the stopped process's stdout pipe.
        // Opening /proc/<pid>/fd/1 gives us our own fd to the same pipe
        // write-end that psql holds, so the agent's read side receives it.
        let stdout_link = format!("/proc/{}/fd/1", ctx.pid);
        let mut pipe = std::fs::OpenOptions::new().write(true).open(&stdout_link)?;

        pipe.write_all(header.as_bytes())?;
        pipe.write_all(&output.stdout)?;

        if !output.stderr.is_empty() {
            let stderr_link = format!("/proc/{}/fd/2", ctx.pid);
            if let Ok(mut ep) = std::fs::OpenOptions::new().write(true).open(&stderr_link) {
                let _ = ep.write_all(&output.stderr);
            }
        }

        Ok(())
    }

    /// Return a new argv with the SQL flag value replaced by `new_sql`.
    fn replace_sql_arg(&self, args: &[String], new_sql: &str) -> Vec<String> {
        let mut out = args.to_vec();
        for i in 0..out.len() {
            for flag in self.sql_flags {
                if out[i] == *flag && i + 1 < out.len() {
                    out[i + 1] = new_sql.to_string();
                    return out;
                }
                let prefix = format!("{flag}=");
                if out[i].starts_with(&prefix) {
                    out[i] = format!("{flag}={new_sql}");
                    return out;
                }
            }
        }
        out
    }
}

// ── /proc helpers ─────────────────────────────────────────────────────────────

fn proc_uid(pid: u32) -> anyhow::Result<libc::uid_t> {
    proc_id_field(pid, "Uid:")
}

fn proc_gid(pid: u32) -> anyhow::Result<libc::gid_t> {
    proc_id_field(pid, "Gid:")
}

fn proc_id_field(pid: u32, field: &str) -> anyhow::Result<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            // "Uid:\t1000\t1000\t1000\t1000" — first value is real UID
            if let Some(val) = rest.split_whitespace().next() {
                return val.parse().map_err(Into::into);
            }
        }
    }
    anyhow::bail!("field '{}' not found in /proc/{}/status", field, pid)
}
