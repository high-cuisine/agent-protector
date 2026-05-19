use std::sync::Arc;

use crate::data_policy::DataPolicy;
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
    pub fn new(policy: Arc<DataPolicy>) -> Self {
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

        Self {
            actions: vec![
                // ── Git ──────────────────────────────────────────────────────
                ToolAction {
                    name: "git-commit",
                    command: "git",
                    required_args: &["commit"],
                    excluded_args: &["--dry-run"],
                    validator: Box::new(GitCommitValidator::new(SecretScanner::default())),
                },

                // ── PostgreSQL ───────────────────────────────────────────────
                ToolAction {
                    name: "psql",
                    command: "psql",
                    required_args: &[],
                    excluded_args: &["--help", "-?", "--version", "-V", "-l", "--list"],
                    validator: sql_validator!(
                        SqlGuardValidator::psql(),
                        DataGuardValidator::psql(Arc::clone(&policy))
                    ),
                },

                // ── MySQL / MariaDB ──────────────────────────────────────────
                ToolAction {
                    name: "mysql",
                    command: "mysql",
                    required_args: &[],
                    excluded_args: &["--help", "--version", "--print-defaults"],
                    validator: sql_validator!(
                        SqlGuardValidator::mysql(),
                        DataGuardValidator::mysql(Arc::clone(&policy))
                    ),
                },
                ToolAction {
                    name: "mariadb",
                    command: "mariadb",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: sql_validator!(
                        SqlGuardValidator::mysql(),
                        DataGuardValidator::mysql(Arc::clone(&policy))
                    ),
                },

                // ── SQLite ───────────────────────────────────────────────────
                ToolAction {
                    name: "sqlite3",
                    command: "sqlite3",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: sql_validator!(
                        SqlGuardValidator::sqlite3(),
                        DataGuardValidator::sqlite3(Arc::clone(&policy))
                    ),
                },

                // ── Redis ────────────────────────────────────────────────────
                ToolAction {
                    name: "redis-cli",
                    command: "redis-cli",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(RedisGuardValidator::new()),
                },

                // ── kubectl exec (max-restriction SQL guard) ─────────────────
                ToolAction {
                    name: "kubectl-exec-sql",
                    command: "kubectl",
                    required_args: &["exec"],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(KubectlSqlGuardValidator::new()),
                },

                // ── Docker ───────────────────────────────────────────────────
                ToolAction {
                    name: "docker",
                    command: "docker",
                    required_args: &[],
                    excluded_args: &["--help", "-h", "--version"],
                    validator: Box::new(DockerGuardValidator::new()),
                },

                // ── Filesystem readers (cat / head / tail / diff / wc) ────────
                ToolAction {
                    name: "cat",
                    command: "cat",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "cat", PathStrategy::AllPositional,
                    )),
                },
                ToolAction {
                    name: "head",
                    command: "head",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "head", PathStrategy::AllPositional,
                    )),
                },
                ToolAction {
                    name: "tail",
                    command: "tail",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "tail", PathStrategy::AllPositional,
                    )),
                },
                ToolAction {
                    name: "diff",
                    command: "diff",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "diff", PathStrategy::AllPositional,
                    )),
                },

                // ── grep / egrep / fgrep ─────────────────────────────────────
                ToolAction {
                    name: "grep",
                    command: "grep",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "grep", PathStrategy::SkipFirstPositional,
                    )),
                },
                ToolAction {
                    name: "egrep",
                    command: "egrep",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "egrep", PathStrategy::SkipFirstPositional,
                    )),
                },

                // ── find ──────────────────────────────────────────────────────
                ToolAction {
                    name: "find",
                    command: "find",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "find", PathStrategy::FirstPositional,
                    )),
                },

                // ── cp / mv ───────────────────────────────────────────────────
                ToolAction {
                    name: "cp",
                    command: "cp",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "cp", PathStrategy::FirstPositional2,
                    )),
                },
                ToolAction {
                    name: "mv",
                    command: "mv",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(FsGuardValidator::new(
                        Arc::clone(&policy), "mv", PathStrategy::FirstPositional2,
                    )),
                },
            ],
        }
    }
}

impl ToolDb {
    pub fn find_action(&self, filename: &str, args: &[String]) -> Option<&ToolAction> {
        self.actions.iter().find(|a| a.matches(filename, args))
    }
}
