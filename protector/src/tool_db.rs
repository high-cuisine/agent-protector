use crate::validator::{ValidationContext, ValidationResult, Validator};
use crate::validators::{
    docker_guard::DockerGuardValidator,
    git_commit::GitCommitValidator,
    kubectl_guard::KubectlSqlGuardValidator,
    redis_guard::RedisGuardValidator,
    secret::SecretScanner,
    sql_guard::SqlGuardValidator,
};

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

impl Default for ToolDb {
    fn default() -> Self {
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
                    validator: Box::new(SqlGuardValidator::psql()),
                },

                // ── MySQL / MariaDB ──────────────────────────────────────────
                ToolAction {
                    name: "mysql",
                    command: "mysql",
                    required_args: &[],
                    excluded_args: &["--help", "--version", "--print-defaults"],
                    validator: Box::new(SqlGuardValidator::mysql()),
                },
                ToolAction {
                    name: "mariadb",
                    command: "mariadb",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(SqlGuardValidator::mysql()),
                },

                // ── SQLite ───────────────────────────────────────────────────
                ToolAction {
                    name: "sqlite3",
                    command: "sqlite3",
                    required_args: &[],
                    excluded_args: &["--help", "--version"],
                    validator: Box::new(SqlGuardValidator::sqlite3()),
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
            ],
        }
    }
}

impl ToolDb {
    pub fn find_action(&self, filename: &str, args: &[String]) -> Option<&ToolAction> {
        self.actions.iter().find(|a| a.matches(filename, args))
    }
}
