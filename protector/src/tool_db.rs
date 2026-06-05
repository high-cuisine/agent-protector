use std::sync::Arc;

use crate::data_policy::DataPolicy;
use crate::errors::ThreatError;
use crate::rules_config::{RuleAction, SharedRulesConfig};
use crate::validator::{ValidationContext, ValidationResult, Validator};
use crate::validators::{
    data_guard::DataGuardValidator,
    docker_guard::DockerGuardValidator,
    fs_guard::{FsGuardValidator, PathStrategy},
    git_commit::GitCommitValidator,
    kubectl_guard::KubectlSqlGuardValidator,
    redis_guard::RedisGuardValidator,
    secret::SecretScanner,
    sql_guard::SqlGuardValidator,
};

// ── Configured validator wrapper ──────────────────────────────────────────────

/// Wraps any validator with enable/disable/alert logic from the shared rules config.
struct ConfiguredValidator {
    tool_name: &'static str,
    inner:     Box<dyn Validator>,
    config:    SharedRulesConfig,
}

impl ConfiguredValidator {
    fn new(
        tool_name: &'static str,
        inner:     Box<dyn Validator>,
        config:    SharedRulesConfig,
    ) -> Self {
        Self { tool_name, inner, config }
    }
}

impl Validator for ConfiguredValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        {
            let cfg = self.config.read().unwrap();
            if !cfg.is_tool_enabled(self.tool_name) {
                return ValidationResult::Allow;
            }
        }
        let result = self.inner.validate(ctx);
        self.apply_action(result, ctx)
    }
}

impl ConfiguredValidator {
    fn rule_for_threat(threat: &ThreatError) -> &'static str {
        match threat {
            ThreatError::SecretLeak { .. }
            | ThreatError::GitCommitInspectionFailed { .. }   => "secret_scan",
            ThreatError::SqlDestructive { .. }                => "destructive",
            ThreatError::SqlPrivilegeEscalation { .. }        => "privilege_escalation",
            ThreatError::SqlFilesystemAccess { .. }           => "filesystem_access",
            ThreatError::SqlRemoteExec { .. }                 => "remote_exec",
            ThreatError::SqlInjection { .. }                  => "injection",
            ThreatError::SqlSuspicious { .. }                 => "suspicious",
            ThreatError::DockerUnsafeRun { .. }               => "unsafe_run",
            ThreatError::DockerVolumeDestroy { .. }           => "volume_destroy",
            ThreatError::DockerForceRemove { .. }             => "force_remove",
            ThreatError::DockerExec { .. }                    => "exec_warn",
            ThreatError::DockerPush { .. }                    => "push_warn",
            ThreatError::DockerLogin                          => "login_warn",
            ThreatError::DockerCommit                        => "commit_warn",
            ThreatError::DockerCp                            => "cp_warn",
            ThreatError::RedisDestructive { command, .. } => {
                let cmd = command.as_str();
                if cmd.starts_with("CLUSTER") { "cluster_ops" }
                else if cmd.starts_with("ACL")     { "acl_changes"  }
                else                               { "destructive"   }
            }
            ThreatError::RedisConfigChange { .. }             => "config_change",
            ThreatError::KubectlSqlThreat { .. }              => "sql_threat",
            ThreatError::FsPolicyBlock { .. }                 => "path_block",
            ThreatError::FsPolicyMasked { .. }                => "path_mask",
            // Data policy is always enforced — not user-configurable
            ThreatError::DataPolicyBlock { .. }
            | ThreatError::DataPolicyMasked { .. }            => "",
        }
    }

    fn apply_action(&self, result: ValidationResult, _ctx: &ValidationContext) -> ValidationResult {
        let threat = match &result {
            ValidationResult::Allow => return result,
            ValidationResult::Block(t) | ValidationResult::Warn(t) => t.clone(),
            ValidationResult::Alert { .. } => return result,
            ValidationResult::MaskedOutput { .. } => return result,
        };

        let rule = Self::rule_for_threat(&threat);
        if rule.is_empty() {
            return result; // data-policy: always enforce
        }

        let action = {
            let cfg = self.config.read().unwrap();
            cfg.rule_action(self.tool_name, rule)
        };

        match action {
            RuleAction::Pass  => ValidationResult::Allow,
            RuleAction::Block => result,
            RuleAction::Alert => ValidationResult::Alert {
                threat,
                rule: rule.to_string(),
            },
        }
    }
}

// ── Composite validator ───────────────────────────────────────────────────────

/// Runs `first`; if it returns Allow, runs `second`.
/// Use it to layer DataGuard in front of the existing SQL guards.
struct ChainedValidator {
    first:  Box<dyn Validator>,
    second: Box<dyn Validator>,
}

impl Validator for ChainedValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        match self.first.validate(ctx) {
            ValidationResult::Allow => self.second.validate(ctx),
            other                   => other,
        }
    }
}

/// One watchable tool action: which binary + which args trigger it, and the validator to run.
pub struct ToolAction {
    pub name: &'static str,
    /// Bare binary name that the executable path must equal or end with "/<name>".
    command: &'static str,
    /// ALL of these must appear somewhere in argv (empty = match any invocation).
    required_args: &'static [&'static str],
    /// ANY of these causes the action to be skipped (help / version / read-only sub-commands).
    excluded_args: &'static [&'static str],
    validator: Box<dyn Validator>,
}

impl ToolAction {
    pub fn matches(&self, filename: &str, args: &[String]) -> bool {
        // Exact match OR path-component match (/usr/bin/git → "git")
        // Using ends_with("/<name>") avoids matching "not-git" on suffix "git".
        if filename != self.command && !filename.ends_with(&format!("/{}", self.command)) {
            return false;
        }
        let has_required = self
            .required_args
            .iter()
            .all(|req| args.iter().any(|a| a == *req));
        let has_excluded = self
            .excluded_args
            .iter()
            .any(|ex| args.iter().any(|a| a == *ex));
        has_required && !has_excluded
    }

    pub fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        self.validator.validate(ctx)
    }
}

pub struct ToolDb {
    actions: Vec<ToolAction>,
}

impl ToolDb {
    /// Build the tool registry, optionally wrapping SQL validators with a
    /// DataGuard that enforces the sensitive-table policy before sql_guard runs.
    pub fn new(policy: Arc<DataPolicy>, rules: SharedRulesConfig) -> Self {
        let has_policy = !policy.is_empty();

        // Helper: wrap a SQL validator with DataGuard when a policy is active.
        macro_rules! sql_validator {
            ($guard:expr, $data:expr) => {
                if has_policy {
                    Box::new(ChainedValidator {
                        first:  Box::new($data),
                        second: Box::new($guard),
                    }) as Box<dyn Validator>
                } else {
                    Box::new($guard) as Box<dyn Validator>
                }
            };
        }

        macro_rules! configured {
            ($name:expr, $v:expr) => {
                Box::new(ConfiguredValidator::new(
                    $name, $v, Arc::clone(&rules),
                )) as Box<dyn Validator>
            };
        }

        Self {
            actions: vec![
                // ── Git ──────────────────────────────────────────────────────
                ToolAction {
                    name: "git-commit",
                    command: "git",
                    required_args: &["commit"],
                    excluded_args: &["--dry-run"],
                    validator: configured!("git-commit",
                        Box::new(GitCommitValidator::new(SecretScanner::default()))),
                },

                // ── PostgreSQL ───────────────────────────────────────────────
                ToolAction {
                    name: "psql",
                    command: "psql",
                    required_args: &[],
                    excluded_args: &["--help", "-?", "--version", "-V", "-l", "--list"],
                    validator: configured!("psql", sql_validator!(
                        SqlGuardValidator::psql(),
                        DataGuardValidator::psql(Arc::clone(&policy))
                    )),
                },

                // ── MySQL / MariaDB ──────────────────────────────────────────
                ToolAction {
                    name: "mysql",
                    command: "mysql",
                    required_args: &[],
                    excluded_args: &["--help", "--version", "--print-defaults"],
                    validator: configured!("mysql", sql_validator!(
                        SqlGuardValidator::mysql(),
                        DataGuardValidator::mysql(Arc::clone(&policy))
                    )),
                },
                ToolAction {
                    name: "mariadb",
                    command: "mariadb",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("mariadb", sql_validator!(
                        SqlGuardValidator::mysql(),
                        DataGuardValidator::mysql(Arc::clone(&policy))
                    )),
                },

                // ── SQLite ───────────────────────────────────────────────────
                ToolAction {
                    name: "sqlite3",
                    command: "sqlite3",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("sqlite3", sql_validator!(
                        SqlGuardValidator::sqlite3(),
                        DataGuardValidator::sqlite3(Arc::clone(&policy))
                    )),
                },

                // ── Redis ────────────────────────────────────────────────────
                ToolAction {
                    name: "redis-cli",
                    command: "redis-cli",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("redis-cli",
                        Box::new(RedisGuardValidator::new())),
                },

                // ── kubectl exec (max-restriction SQL guard) ─────────────────
                ToolAction {
                    name: "kubectl-exec-sql",
                    command: "kubectl",
                    required_args: &["exec"],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("kubectl-exec-sql",
                        Box::new(KubectlSqlGuardValidator::new())),
                },

                // ── Docker ───────────────────────────────────────────────────
                ToolAction {
                    name: "docker",
                    command: "docker",
                    required_args: &[],
                    excluded_args: &["--help", "-h", "--version"],
                    validator: configured!("docker",
                        Box::new(DockerGuardValidator::new())),
                },

                // ── Filesystem readers (cat / head / tail / diff / wc) ────────
                ToolAction {
                    name: "cat",
                    command: "cat",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("cat", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "cat", PathStrategy::AllPositional,
                    ))),
                },
                ToolAction {
                    name: "head",
                    command: "head",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("head", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "head", PathStrategy::AllPositional,
                    ))),
                },
                ToolAction {
                    name: "tail",
                    command: "tail",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("tail", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "tail", PathStrategy::AllPositional,
                    ))),
                },
                ToolAction {
                    name: "diff",
                    command: "diff",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("diff", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "diff", PathStrategy::AllPositional,
                    ))),
                },

                // ── grep / egrep / fgrep ─────────────────────────────────────
                ToolAction {
                    name: "grep",
                    command: "grep",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("grep", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "grep", PathStrategy::SkipFirstPositional,
                    ))),
                },
                ToolAction {
                    name: "egrep",
                    command: "egrep",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("egrep", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "egrep", PathStrategy::SkipFirstPositional,
                    ))),
                },

                // ── find ──────────────────────────────────────────────────────
                ToolAction {
                    name: "find",
                    command: "find",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("find", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "find", PathStrategy::FirstPositional,
                    ))),
                },

                // ── cp / mv ───────────────────────────────────────────────────
                ToolAction {
                    name: "cp",
                    command: "cp",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("cp", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "cp", PathStrategy::FirstPositional2,
                    ))),
                },
                ToolAction {
                    name: "mv",
                    command: "mv",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("mv", Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "mv", PathStrategy::FirstPositional2,
                    ))),
                },

                // ── curl / wget (secret proxy intercepts before validation) ─────
                ToolAction {
                    name: "curl",
                    command: "curl",
                    required_args: &[],
                    excluded_args: &["--help", "--version", "-V"],
                    validator: configured!("curl", Box::new(AllowAllValidator)),
                },
                ToolAction {
                    name: "wget",
                    command: "wget",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: configured!("wget", Box::new(AllowAllValidator)),
                },
            ],
        }
    }
}

/// Passthrough validator — used for tools where all enforcement happens
/// before validation (e.g. secret proxy relay for curl/wget).
struct AllowAllValidator;

impl crate::validator::Validator for AllowAllValidator {
    fn validate(&self, _ctx: &crate::validator::ValidationContext) -> crate::validator::ValidationResult {
        crate::validator::ValidationResult::Allow
    }
}

impl ToolDb {
    pub fn find_action(&self, filename: &str, args: &[String]) -> Option<&ToolAction> {
        self.actions.iter().find(|a| a.matches(filename, args))
    }
}
