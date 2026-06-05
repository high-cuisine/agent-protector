//! Windows-adapted sensitive-table guard.
//!
//! Identical logic to the Linux version except that instead of writing
//! masked output to /proc/<pid>/fd/1, it returns `ValidationResult::MaskedOutput`
//! so the daemon can forward the content to the shim over the named-pipe IPC.
use std::collections::HashSet;
use std::sync::Arc;

use regex::Regex;

use crate::data_policy::{DataPolicy, PolicyMode, SqlDialect, TablePolicy};
use crate::errors::ThreatError;
use crate::validator::{ValidationContext, ValidationResult, Validator};

pub struct DataGuardValidator {
    policy:        Arc<DataPolicy>,
    dialect:       SqlDialect,
    tool_label:    &'static str,
    sql_flags:     &'static [&'static str],
    file_flags:    &'static [&'static str],
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
            policy, dialect, tool_label, sql_flags, file_flags,
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
        if self.policy.is_empty() { return ValidationResult::Allow; }

        let sql = match self.extract_sql(&ctx.args) {
            Some(s) => s,
            None    => return ValidationResult::Allow,
        };

        let touched = self.table_refs(&sql);
        if touched.is_empty() { return ValidationResult::Allow; }

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
                if self.re_select_star.is_match(&sql) {
                    return ValidationResult::Block(ThreatError::DataPolicyBlock {
                        tool:    self.tool_label,
                        table:   table_name.to_string(),
                        columns: table_policy.columns.iter().map(|c| c.name.clone()).collect(),
                    });
                }

                let masked_sql  = self.rewrite_sql(&sql, table_policy);
                let masked_cols = table_policy.columns.iter().map(|c| c.name.clone()).collect();

                match self.run_masked_query(ctx, &masked_sql) {
                    Ok(output) => {
                        let content = format!(
                            "\n[DATA_POLICY: masked output — sensitive columns replaced in '{}']\n{}",
                            ctx.filename.split(['/', '\\']).next_back().unwrap_or(&ctx.filename),
                            output
                        );
                        ValidationResult::MaskedOutput {
                            content,
                            threat: ThreatError::DataPolicyMasked {
                                tool:           self.tool_label,
                                table:          table_name.to_string(),
                                masked_columns: masked_cols,
                            },
                        }
                    }
                    Err(e) => {
                        log::error!("[{}] data_guard: masked query failed: {e}", self.tool_label);
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

impl DataGuardValidator {
    fn extract_sql(&self, args: &[String]) -> Option<String> {
        for flag in self.sql_flags {
            let mut iter = args.iter().peekable();
            while let Some(arg) = iter.next() {
                if arg == flag { return iter.next().cloned(); }
                let prefix = format!("{flag}=");
                if let Some(val) = arg.strip_prefix(&prefix) { return Some(val.to_string()); }
            }
        }
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
        if self.dialect == SqlDialect::Sqlite {
            let positional: Vec<&str> = args.iter()
                .skip(1).filter(|a| !a.starts_with('-')).map(String::as_str).collect();
            if positional.len() >= 2 {
                return Some(positional[positional.len() - 1].to_string());
            }
        }
        None
    }

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

    fn rewrite_sql(&self, sql: &str, policy: &TablePolicy) -> String {
        let upper = sql.to_ascii_uppercase();
        let from_pos = upper.find(" FROM ")
            .or_else(|| upper.find("\nFROM "))
            .or_else(|| upper.find("\tFROM "));
        let (select_part, rest) = match from_pos {
            Some(idx) => (&sql[..idx], &sql[idx..]),
            None      => return sql.to_string(),
        };
        let mut rewritten = select_part.to_string();
        for col in &policy.columns {
            let escaped = regex::escape(&col.name);
            if let Ok(re) = Regex::new(&format!(r"(?i)\b{escaped}\b")) {
                let expr = col.mask.sql_expr(&col.name, self.dialect);
                rewritten = re.replace_all(&rewritten, expr.as_str()).into_owned();
            }
        }
        format!("{rewritten}{rest}")
    }

    fn replace_sql_arg(&self, args: &[String], new_sql: &str) -> Vec<String> {
        let mut out = args.to_vec();
        for i in 0..out.len() {
            for flag in self.sql_flags {
                if out[i] == *flag && i + 1 < out.len() {
                    out[i + 1] = new_sql.to_string(); return out;
                }
                let prefix = format!("{flag}=");
                if out[i].starts_with(&prefix) {
                    out[i] = format!("{flag}={new_sql}"); return out;
                }
            }
        }
        out
    }

    /// Run the masked query as a subprocess and return its stdout.
    /// On Windows we run as the current user (no setuid available).
    fn run_masked_query(&self, ctx: &ValidationContext, masked_sql: &str) -> anyhow::Result<String> {
        let new_args = self.replace_sql_arg(&ctx.args, masked_sql);
        let output = std::process::Command::new(&new_args[0])
            .args(&new_args[1..])
            .output()?;
        let mut result = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.stderr.is_empty() {
            result.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        Ok(result)
    }
}
