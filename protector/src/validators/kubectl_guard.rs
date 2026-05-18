use crate::errors::ThreatError;
use crate::validator::{ValidationContext, ValidationResult, Validator};
use crate::validators::sql_guard::{
    build_sql_threat_pub, extract_sql_for_tool, SqlAnalysis, SqlAnalyzer,
};
use log::{debug, info, warn};

const SQL_TOOLS: &[&str] = &["psql", "mysql", "mariadb", "sqlite3"];

pub struct KubectlSqlGuardValidator {
    analyzer: SqlAnalyzer,
}

impl KubectlSqlGuardValidator {
    pub fn new() -> Self {
        Self { analyzer: SqlAnalyzer::default() }
    }

    fn pod_name(args: &[String]) -> String {
        // First non-flag arg after "exec" is the pod name
        let mut after_exec = false;
        for arg in args.iter().skip(1) {
            if arg == "exec" {
                after_exec = true;
                continue;
            }
            if after_exec && !arg.starts_with('-') {
                return arg.clone();
            }
        }
        "<unknown-pod>".into()
    }
}

impl Validator for KubectlSqlGuardValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        if !ctx.args.iter().skip(1).any(|a| a == "exec") {
            return ValidationResult::Allow;
        }

        let sep_pos = match ctx.args.iter().position(|a| a == "--") {
            Some(p) => p,
            None => {
                debug!("[kubectl] pid={} no '--' separator — Allow", ctx.pid);
                return ValidationResult::Allow;
            }
        };

        let sub_args = &ctx.args[sep_pos + 1..];
        let sub_tool = match sub_args.first() {
            Some(t) => t.as_str(),
            None => return ValidationResult::Allow,
        };

        let tool_name = SQL_TOOLS
            .iter()
            .find(|&&t| sub_tool == t || sub_tool.ends_with(&format!("/{t}")))
            .copied();

        let tool_name = match tool_name {
            Some(t) => t,
            None => {
                debug!("[kubectl] pid={} sub-tool '{}' is not a SQL CLI — Allow", ctx.pid, sub_tool);
                return ValidationResult::Allow;
            }
        };

        let pod = Self::pod_name(&ctx.args);

        let sql = match extract_sql_for_tool(tool_name, sub_args) {
            Some(s) => s,
            None => {
                warn!(
                    "[kubectl] pid={} '{}' exec'd without explicit SQL arg — stdin not inspectable — BLOCK",
                    ctx.pid, tool_name
                );
                // Treat uninspectable stdin as a destructive threat
                return ValidationResult::Block(ThreatError::KubectlSqlThreat {
                    pod,
                    inner: Box::new(ThreatError::SqlDestructive {
                        tool: tool_name,
                        operations: vec![format!(
                            "SQL tool '{tool_name}' launched without an explicit SQL argument (-c/-e/positional) \
                             — stdin SQL cannot be inspected and is always blocked"
                        )],
                    }),
                });
            }
        };

        info!(
            "[kubectl] pid={} analyzing SQL via '{}' ({} chars)",
            ctx.pid, tool_name, sql.len()
        );

        match self.analyzer.analyze(&sql) {
            SqlAnalysis::Clean => {
                info!("[kubectl] SQL analysis passed — Allow");
                ValidationResult::Allow
            }
            // Maximum restriction: Suspicious is upgraded to Block inside kubectl
            SqlAnalysis::Suspicious(findings) => {
                ValidationResult::Block(ThreatError::KubectlSqlThreat {
                    pod,
                    inner: Box::new(ThreatError::SqlSuspicious {
                        tool: tool_name,
                        findings,
                    }),
                })
            }
            SqlAnalysis::Dangerous(categorized) => {
                ValidationResult::Block(ThreatError::KubectlSqlThreat {
                    pod,
                    inner: Box::new(build_sql_threat_pub(tool_name, categorized)),
                })
            }
        }
    }
}
