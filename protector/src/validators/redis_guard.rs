use crate::errors::ThreatError;
use crate::validator::{ValidationContext, ValidationResult, Validator};
use log::info;

pub struct RedisGuardValidator;

impl RedisGuardValidator {
    pub fn new() -> Self { Self }

    fn positional_args(args: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let mut skip_next = false;
        for arg in args.iter().skip(1) {
            if skip_next {
                skip_next = false;
                continue;
            }
            if arg.starts_with('-') {
                const VALUE_FLAGS: &[&str] = &[
                    "-h", "--host", "-p", "--port", "-a", "--auth",
                    "-n", "--db", "-u", "--uri", "--pass", "--user",
                    "--cert", "--key", "--cacert", "--sni", "--tls",
                    "--resp2", "--resp3", "-c",
                ];
                if VALUE_FLAGS.iter().any(|f| *f == arg.as_str()) && !arg.contains('=') {
                    skip_next = true;
                }
                continue;
            }
            out.push(arg.to_uppercase());
        }
        out
    }

    fn block(command: impl Into<String>, detail: impl Into<String>) -> ValidationResult {
        ValidationResult::Block(ThreatError::RedisDestructive {
            command: command.into(),
            detail: detail.into(),
        })
    }

    fn warn_cfg(command: impl Into<String>, detail: impl Into<String>) -> ValidationResult {
        ValidationResult::Warn(ThreatError::RedisConfigChange {
            command: command.into(),
            detail: detail.into(),
        })
    }
}

impl Validator for RedisGuardValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        let positional = Self::positional_args(&ctx.args);

        let Some(command) = positional.first() else {
            info!("[redis] pid={} no command in argv — allowing", ctx.pid);
            return ValidationResult::Allow;
        };

        info!(
            "[redis] pid={} command={} args={:?}",
            ctx.pid, command, &positional[1..]
        );

        let sub = positional.get(1).map(String::as_str);

        match command.as_str() {
            // ── BLOCK: full-database wipe ─────────────────────────────────────
            "FLUSHALL" => Self::block(
                "FLUSHALL",
                format!("deletes ALL data across EVERY Redis database (modifier: {})",
                    sub.unwrap_or("none")),
            ),
            "FLUSHDB" => Self::block(
                "FLUSHDB",
                "deletes ALL keys in the current Redis database",
            ),

            // ── BLOCK: server shutdown ────────────────────────────────────────
            "SHUTDOWN" => Self::block(
                "SHUTDOWN",
                format!("stops the Redis server process (modifier: {})",
                    sub.unwrap_or("none")),
            ),

            // ── BLOCK: replication topology change ───────────────────────────
            "SLAVEOF" | "REPLICAOF" => Self::block(
                command.as_str(),
                format!("changes Redis replication — target: {:?}", &positional[1..]),
            ),

            // ── BLOCK: dangerous DEBUG subcommands ────────────────────────────
            "DEBUG" => match sub {
                Some("SLEEP")          => Self::block("DEBUG SLEEP",
                    "blocks the Redis event loop (DoS risk)"),
                Some("SEGFAULT")       => Self::block("DEBUG SEGFAULT",
                    "crashes the Redis server intentionally"),
                Some("RELOAD")         => Self::block("DEBUG RELOAD",
                    "force-reloads the dataset (data loss risk)"),
                Some("FLUSHALL")       => Self::block("DEBUG FLUSHALL",
                    "bypasses persistence and wipes all data"),
                Some("CHANGE-REPL-ID") => Self::block("DEBUG CHANGE-REPL-ID",
                    "disrupts replication"),
                other => Self::warn_cfg(
                    format!("DEBUG {}", other.unwrap_or("(no subcommand)")),
                    "can be destructive — verify this subcommand is intentional",
                ),
            },

            // ── BLOCK: Lua script cache wipe ──────────────────────────────────
            "SCRIPT" if sub == Some("FLUSH") => Self::block(
                "SCRIPT FLUSH",
                "removes ALL cached Lua scripts from the server",
            ),

            // ── BLOCK: cluster topology reset ────────────────────────────────
            "CLUSTER" => match sub {
                Some("RESET")      => Self::block("CLUSTER RESET",
                    "resets node state and removes all cluster data"),
                Some("FAILOVER")   => Self::block("CLUSTER FAILOVER",
                    "triggers a manual replication failover"),
                Some("FLUSHSLOTS") => Self::block("CLUSTER FLUSHSLOTS",
                    "removes all hash slot assignments from this node"),
                other => Self::warn_cfg(
                    format!("CLUSTER {}", other.unwrap_or("")),
                    "modifies cluster topology — verify intent",
                ),
            },

            // ── BLOCK: ACL / permission changes ──────────────────────────────
            "ACL" => match sub {
                Some("SETUSER") => Self::block(
                    "ACL SETUSER",
                    format!("modifies permissions for user {:?}", positional.get(2)),
                ),
                Some("DELUSER") => Self::block(
                    "ACL DELUSER",
                    format!("removes user {:?}", positional.get(2)),
                ),
                _ => ValidationResult::Allow,
            },

            // ── WARN: live server configuration change ────────────────────────
            "CONFIG" => match sub {
                Some("SET") => Self::warn_cfg(
                    "CONFIG SET",
                    format!("modifies a live Redis parameter: {:?}", &positional[2..]),
                ),
                Some("REWRITE") => Self::warn_cfg(
                    "CONFIG REWRITE",
                    "overwrites the redis.conf file on disk",
                ),
                Some("RESETSTAT") => Self::warn_cfg(
                    "CONFIG RESETSTAT",
                    "clears all server statistics",
                ),
                _ => ValidationResult::Allow,
            },

            // ── WARN: persistence / snapshot control ──────────────────────────
            "BGREWRITEAOF" => Self::warn_cfg(
                "BGREWRITEAOF",
                "rewrites the AOF file — may cause brief I/O spike",
            ),

            // ── WARN: key migration ───────────────────────────────────────────
            "MIGRATE" => Self::warn_cfg(
                "MIGRATE",
                format!(
                    "transfers keys to {}:{} — verify the target is correct",
                    positional.get(1).map(String::as_str).unwrap_or("?"),
                    positional.get(2).map(String::as_str).unwrap_or("?"),
                ),
            ),

            // ── WARN: mass key deletion ───────────────────────────────────────
            "DEL" | "UNLINK" if positional.len() > 10 => Self::warn_cfg(
                command.as_str(),
                format!("deleting {} keys at once — verify this is intentional",
                    positional.len() - 1),
            ),

            _ => ValidationResult::Allow,
        }
    }
}
