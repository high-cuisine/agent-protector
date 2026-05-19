use std::fmt;

/// Structured threat returned to the agent instead of a raw OS error string.
/// Every variant carries the data relevant to its category so the agent can
/// understand exactly what was detected and why the action was blocked.
#[derive(Debug, Clone)]
pub enum ThreatError {
    // ── Secrets ───────────────────────────────────────────────────────────────
    /// Credentials / API keys found in files about to be committed.
    SecretLeak {
        hits: Vec<SecretHit>,
    },

    // ── SQL: destructive DDL / DML ────────────────────────────────────────────
    /// DROP, TRUNCATE, DELETE/UPDATE without WHERE, ALTER TABLE DROP COLUMN.
    SqlDestructive {
        tool: &'static str,
        operations: Vec<String>,
    },

    // ── SQL: privilege escalation ─────────────────────────────────────────────
    /// GRANT, REVOKE, CREATE/ALTER USER or ROLE.
    SqlPrivilegeEscalation {
        tool: &'static str,
        operations: Vec<String>,
    },

    // ── SQL: filesystem access via DB engine ──────────────────────────────────
    /// INTO OUTFILE, LOAD DATA INFILE, COPY TO/FROM file, pg_read_file, etc.
    SqlFilesystemAccess {
        tool: &'static str,
        operations: Vec<String>,
    },

    // ── SQL: OS command execution via DB ──────────────────────────────────────
    /// xp_cmdshell, OPENROWSET, sp_configure, lo_export / lo_import.
    SqlRemoteExec {
        tool: &'static str,
        operations: Vec<String>,
    },

    // ── SQL: injection patterns ───────────────────────────────────────────────
    /// UNION SELECT, stacked queries, dynamic EXEC, tautologies, time-based.
    SqlInjection {
        tool: &'static str,
        patterns: Vec<String>,
    },

    // ── SQL: suspicious reconnaissance (warn-level) ───────────────────────────
    /// information_schema reads, SHOW DATABASES, DESCRIBE, etc.
    SqlSuspicious {
        tool: &'static str,
        findings: Vec<String>,
    },

    // ── Docker ────────────────────────────────────────────────────────────────
    /// --privileged, dangerous --cap-add, --pid=host, docker.sock mount, etc.
    DockerUnsafeRun {
        issues: Vec<String>,
    },

    /// docker volume rm — permanent named-volume deletion.
    DockerVolumeDestroy {
        name: String,
    },

    /// docker exec into a running container (warn).
    DockerExec {
        privileged: bool,
    },

    /// docker push to an external registry (warn).
    DockerPush {
        image: String,
    },

    /// docker login — credentials stored locally (warn).
    DockerLogin,

    /// docker commit — may bake secrets into the image (warn).
    DockerCommit,

    /// docker cp — host/container filesystem data exchange (warn).
    DockerCp,

    /// docker rm/rmi -f — forcible removal without graceful shutdown (warn).
    DockerForceRemove {
        subject: String,
    },

    // ── Redis ─────────────────────────────────────────────────────────────────
    /// Commands that irrecoverably wipe data or stop the server.
    RedisDestructive {
        command: String,
        detail: String,
    },

    /// Commands that change live server configuration or topology.
    RedisConfigChange {
        command: String,
        detail: String,
    },

    // ── kubectl ───────────────────────────────────────────────────────────────
    /// kubectl exec into a pod that ran a dangerous SQL sub-command.
    KubectlSqlThreat {
        pod: String,
        inner: Box<ThreatError>,
    },

    // ── Data policy ───────────────────────────────────────────────────────────
    /// Query against a table marked `block` in the data policy.
    DataPolicyBlock {
        tool: &'static str,
        table: String,
        columns: Vec<String>,
    },

    /// Query against a table marked `mask` — original process killed, masked
    /// output already written to the agent's pipe.
    DataPolicyMasked {
        tool: &'static str,
        table: String,
        masked_columns: Vec<String>,
    },

    // ── Filesystem policy ─────────────────────────────────────────────────────
    /// Access to a path marked `fblock` in the data policy.
    FsPolicyBlock {
        tool:    &'static str,
        path:    String,
        pattern: String,
    },

    /// Access to a path marked `fmask` — masked output already written to pipe.
    FsPolicyMasked {
        tool:    &'static str,
        path:    String,
        pattern: String,
    },
}

/// A single credential / secret match inside a file.
#[derive(Debug, Clone)]
pub struct SecretHit {
    pub file: String,
    pub line: usize,
    pub kind: String,
    /// Truncated line content (safe snippet, not the full secret value).
    pub snippet: String,
}

impl ThreatError {
    /// Short machine-readable code for log prefixes and future serialisation.
    pub fn code(&self) -> &'static str {
        match self {
            Self::SecretLeak { .. }             => "SECRET_LEAK",
            Self::SqlDestructive { .. }         => "SQL_DESTRUCTIVE",
            Self::SqlPrivilegeEscalation { .. } => "SQL_PRIV_ESCALATION",
            Self::SqlFilesystemAccess { .. }    => "SQL_FILESYSTEM",
            Self::SqlRemoteExec { .. }          => "SQL_REMOTE_EXEC",
            Self::SqlInjection { .. }           => "SQL_INJECTION",
            Self::SqlSuspicious { .. }          => "SQL_SUSPICIOUS",
            Self::DockerUnsafeRun { .. }        => "DOCKER_UNSAFE_RUN",
            Self::DockerVolumeDestroy { .. }    => "DOCKER_VOLUME_DESTROY",
            Self::DockerExec { .. }             => "DOCKER_EXEC",
            Self::DockerPush { .. }             => "DOCKER_PUSH",
            Self::DockerLogin                   => "DOCKER_LOGIN",
            Self::DockerCommit                  => "DOCKER_COMMIT",
            Self::DockerCp                      => "DOCKER_CP",
            Self::DockerForceRemove { .. }      => "DOCKER_FORCE_REMOVE",
            Self::RedisDestructive { .. }       => "REDIS_DESTRUCTIVE",
            Self::RedisConfigChange { .. }      => "REDIS_CONFIG_CHANGE",
            Self::KubectlSqlThreat { .. }       => "KUBECTL_SQL_THREAT",
            Self::DataPolicyBlock { .. }         => "DATA_POLICY_BLOCK",
            Self::DataPolicyMasked { .. }        => "DATA_POLICY_MASKED",
            Self::FsPolicyBlock { .. }           => "FS_POLICY_BLOCK",
            Self::FsPolicyMasked { .. }          => "FS_POLICY_MASKED",
        }
    }
}

// ── Display ────────────────────────────────────────────────────────────────────
// The output is what gets logged/sent back to the agent.
// Format: [CODE] human-readable summary, then indented details.

impl fmt::Display for ThreatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // ── Secrets ───────────────────────────────────────────────────────
            Self::SecretLeak { hits } => {
                writeln!(
                    f,
                    "[{}] {} credential(s) detected in staged file(s) — commit blocked:",
                    self.code(), hits.len()
                )?;
                for h in hits {
                    writeln!(
                        f,
                        "  {}:{} · {} → {}",
                        h.file, h.line, h.kind, h.snippet
                    )?;
                }
                write!(
                    f,
                    "  Remove or rotate the credentials before committing."
                )
            }

            // ── SQL ───────────────────────────────────────────────────────────
            Self::SqlDestructive { tool, operations } => {
                writeln!(
                    f,
                    "[{}] {}: {} irreversible operation(s) blocked:",
                    self.code(), tool, operations.len()
                )?;
                for op in operations {
                    writeln!(f, "  • {}", op)?;
                }
                write!(f, "  Use a targeted WHERE clause or coordinate with the DBA.")
            }

            Self::SqlPrivilegeEscalation { tool, operations } => {
                writeln!(
                    f,
                    "[{}] {}: {} privilege-escalation statement(s) blocked:",
                    self.code(), tool, operations.len()
                )?;
                for op in operations {
                    writeln!(f, "  • {}", op)?;
                }
                write!(f, "  Permission changes must be reviewed by an administrator.")
            }

            Self::SqlFilesystemAccess { tool, operations } => {
                writeln!(
                    f,
                    "[{}] {}: {} filesystem-access statement(s) blocked:",
                    self.code(), tool, operations.len()
                )?;
                for op in operations {
                    writeln!(f, "  • {}", op)?;
                }
                write!(
                    f,
                    "  Filesystem access via the DB engine is not allowed."
                )
            }

            Self::SqlRemoteExec { tool, operations } => {
                writeln!(
                    f,
                    "[{}] {}: {} OS-command-execution statement(s) blocked:",
                    self.code(), tool, operations.len()
                )?;
                for op in operations {
                    writeln!(f, "  • {}", op)?;
                }
                write!(
                    f,
                    "  Running OS commands through the database engine is forbidden."
                )
            }

            Self::SqlInjection { tool, patterns } => {
                writeln!(
                    f,
                    "[{}] {}: {} injection pattern(s) detected — blocked:",
                    self.code(), tool, patterns.len()
                )?;
                for p in patterns {
                    writeln!(f, "  • {}", p)?;
                }
                write!(f, "  Use parameterised queries instead of interpolated SQL.")
            }

            Self::SqlSuspicious { tool, findings } => {
                writeln!(
                    f,
                    "[{}] {}: {} suspicious pattern(s) — proceeding with warning:",
                    self.code(), tool, findings.len()
                )?;
                for find in findings {
                    writeln!(f, "  ⚠ {}", find)?;
                }
                write!(f, "  Review the query intent before continuing.")
            }

            // ── Docker ────────────────────────────────────────────────────────
            Self::DockerUnsafeRun { issues } => {
                writeln!(
                    f,
                    "[{}] docker run: {} dangerous configuration issue(s) — blocked:",
                    self.code(), issues.len()
                )?;
                for issue in issues {
                    writeln!(f, "  • {}", issue)?;
                }
                write!(
                    f,
                    "  Remove the unsafe flags or switch to a least-privilege configuration."
                )
            }

            Self::DockerVolumeDestroy { name } => {
                write!(
                    f,
                    "[{}] docker volume rm \"{}\": permanently destroys the named volume — blocked.",
                    self.code(), name
                )
            }

            Self::DockerExec { privileged } => {
                if *privileged {
                    write!(
                        f,
                        "[{}] docker exec --privileged: elevates the session to full host capabilities — blocked.",
                        self.code()
                    )
                } else {
                    write!(
                        f,
                        "[{}] docker exec: executing a command inside a running container — verify this is intentional.",
                        self.code()
                    )
                }
            }

            Self::DockerPush { image } => {
                write!(
                    f,
                    "[{}] docker push \"{}\": publishes the image to an external registry — verify the target.",
                    self.code(), image
                )
            }

            Self::DockerLogin => {
                write!(
                    f,
                    "[{}] docker login: credentials will be stored on disk — ensure this is an authorised registry.",
                    self.code()
                )
            }

            Self::DockerCommit => {
                write!(
                    f,
                    "[{}] docker commit: snapshot of a running container — may capture secrets from runtime state.",
                    self.code()
                )
            }

            Self::DockerCp => {
                write!(
                    f,
                    "[{}] docker cp: copies files between the host and a container filesystem.",
                    self.code()
                )
            }

            Self::DockerForceRemove { subject } => {
                write!(
                    f,
                    "[{}] docker rm/rmi -f \"{}\": forcible removal without graceful shutdown.",
                    self.code(), subject
                )
            }

            // ── Redis ─────────────────────────────────────────────────────────
            Self::RedisDestructive { command, detail } => {
                write!(
                    f,
                    "[{}] redis-cli {}: {} — blocked.",
                    self.code(), command, detail
                )
            }

            Self::RedisConfigChange { command, detail } => {
                write!(
                    f,
                    "[{}] redis-cli {}: {} — proceeding with warning.",
                    self.code(), command, detail
                )
            }

            // ── Data policy ───────────────────────────────────────────────────
            Self::DataPolicyBlock { tool, table, columns } => {
                writeln!(
                    f,
                    "[{}] {}: access to protected table '{}' is blocked.",
                    self.code(), tool, table
                )?;
                if !columns.is_empty() {
                    writeln!(f, "  Protected columns: {}", columns.join(", "))?;
                }
                write!(
                    f,
                    "  Use explicit non-sensitive columns or request access through a data steward."
                )
            }

            Self::DataPolicyMasked { tool, table, masked_columns } => {
                writeln!(
                    f,
                    "[{}] {}: query against protected table '{}' — sensitive columns masked.",
                    self.code(), tool, table
                )?;
                write!(f, "  Masked columns: {}", masked_columns.join(", "))
            }

            // ── Filesystem policy ─────────────────────────────────────────────
            Self::FsPolicyBlock { tool, path, pattern } => {
                write!(
                    f,
                    "[{}] {}: access to '{}' is blocked (matches protected pattern '{}').",
                    self.code(), tool, path, pattern
                )
            }

            Self::FsPolicyMasked { tool, path, pattern } => {
                write!(
                    f,
                    "[{}] {}: content of '{}' was masked (matched protected pattern '{}').",
                    self.code(), tool, path, pattern
                )
            }

            // ── kubectl ───────────────────────────────────────────────────────
            Self::KubectlSqlThreat { pod, inner } => {
                writeln!(
                    f,
                    "[{}] kubectl exec into pod \"{}\": SQL threat detected inside the exec command:",
                    self.code(), pod
                )?;
                write!(f, "  {}", inner)
            }
        }
    }
}

impl std::error::Error for ThreatError {}
