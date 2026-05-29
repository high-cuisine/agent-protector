/// L3/L4 network firewall for Claude Code agent traffic.
///
/// Piggybacks on the cgroup v2 path `/sys/fs/cgroup/claude-protector` that
/// TrafficRedirector also uses.  Claude PIDs are written into the cgroup, so
/// all their descendants are automatically covered.
///
/// Creates two dedicated chains in the filter table:
///   PROTECTOR-FW-OUT  — jumped from OUTPUT for agent egress
///   PROTECTOR-FW-IN   — jumped from INPUT  for agent ingress
///
/// Requires: root, iptables with xt_cgroup and xt_conntrack modules, cgroup v2.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use log::{info, warn};

use crate::firewall_config::{Direction, FirewallConfig, FirewallMode, Protocol, RuleAction};

const CGROUP_NAME: &str = "claude-protector";
const CHAIN_OUT: &str   = "PROTECTOR-FW-OUT";
const CHAIN_IN: &str    = "PROTECTOR-FW-IN";

pub struct NetworkFirewall {
    cgroup_dir: PathBuf,
}

impl NetworkFirewall {
    /// Creates the cgroup directory and the two netfilter chains.
    /// Returns an error only if cgroup creation fails; missing iptables is
    /// reported as a warning at `apply()` time.
    pub fn new() -> anyhow::Result<Self> {
        let cgroup_dir = PathBuf::from(format!("/sys/fs/cgroup/{CGROUP_NAME}"));
        fs::create_dir_all(&cgroup_dir)?;

        // Create chains — ignore "already exists" errors
        let _ = ipt(&["-t", "filter", "-N", CHAIN_OUT]);
        let _ = ipt(&["-t", "filter", "-N", CHAIN_IN]);

        Ok(Self { cgroup_dir })
    }

    /// Write PIDs into the cgroup so iptables cgroup-match covers them.
    /// Idempotent — re-writing an already-present PID is harmless.
    pub fn track_pids(&self, pids: &[u32]) {
        let procs = self.cgroup_dir.join("cgroup.procs");
        for &pid in pids {
            if let Err(e) = fs::write(&procs, pid.to_string()) {
                log::debug!("[firewall] cgroup track pid={pid}: {e}");
            }
        }
    }

    /// Flush and re-install all iptables rules according to `config`.
    /// Calling with `enabled = false` removes all rules without touching the chains.
    pub fn apply(&self, config: &FirewallConfig) -> anyhow::Result<()> {
        // Remove existing jump rules (best-effort — they may not exist yet)
        let cg_path = format!("/{CGROUP_NAME}");
        let _ = ipt(&["-t", "filter", "-D", "OUTPUT",
            "-m", "cgroup", "--path", &cg_path, "-j", CHAIN_OUT]);
        let _ = ipt(&["-t", "filter", "-D", "INPUT",
            "-m", "cgroup", "--path", &cg_path, "-j", CHAIN_IN]);

        // Flush both chains
        ipt(&["-t", "filter", "-F", CHAIN_OUT])?;
        ipt(&["-t", "filter", "-F", CHAIN_IN])?;

        if !config.enabled {
            info!("[firewall] disabled — all rules removed");
            return Ok(());
        }

        // Re-insert jump rules at the top of the system chains
        ipt(&["-t", "filter", "-I", "OUTPUT", "1",
            "-m", "cgroup", "--path", &cg_path, "-j", CHAIN_OUT])?;
        ipt(&["-t", "filter", "-I", "INPUT", "1",
            "-m", "cgroup", "--path", &cg_path, "-j", CHAIN_IN])?;

        // In whitelist mode, the INPUT chain must allow established/related packets
        // first so that responses to Claude's outgoing connections are not dropped.
        if matches!(config.mode, FirewallMode::Whitelist) {
            ipt(&["-t", "filter", "-A", CHAIN_IN,
                  "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                  "-j", "ACCEPT"])?;
        }

        let mut applied = 0usize;
        for rule in config.rules.iter().filter(|r| r.enabled) {
            let action = match rule.action {
                RuleAction::Allow => "ACCEPT",
                RuleAction::Block => "DROP",
            };

            let want_out = matches!(rule.direction, Direction::Out | Direction::Both);
            let want_in  = matches!(rule.direction, Direction::In  | Direction::Both);

            for &chain in [
                want_out.then_some(CHAIN_OUT),
                want_in.then_some(CHAIN_IN),
            ]
            .iter()
            .filter_map(|x| x.as_ref())
            {
                let mut args: Vec<String> = vec![
                    "-t".into(), "filter".into(), "-A".into(), chain.to_string(),
                ];

                match rule.protocol {
                    Protocol::Tcp => { args.push("-p".into()); args.push("tcp".into()); }
                    Protocol::Udp => { args.push("-p".into()); args.push("udp".into()); }
                    Protocol::Any => {}
                }

                // CIDR — remote endpoint address
                if let Some(cidr) = sanitize_cidr(&rule.remote_cidr) {
                    // OUT → destination address; IN → source address
                    let flag = if *chain == *CHAIN_OUT { "-d" } else { "-s" };
                    args.push(flag.into());
                    args.push(cidr.into());
                }

                // Port — remote endpoint port
                if rule.port_min > 0 && !matches!(rule.protocol, Protocol::Any) {
                    // OUT → --dport; IN → --sport (remote source)
                    let flag = if *chain == *CHAIN_OUT { "--dport" } else { "--sport" };
                    args.push(flag.into());
                    if rule.port_max > rule.port_min {
                        args.push(format!("{}:{}", rule.port_min, rule.port_max));
                    } else {
                        args.push(rule.port_min.to_string());
                    }
                }

                args.push("-j".into());
                args.push(action.to_string());

                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                match ipt(&refs) {
                    Ok(()) => { applied += 1; }
                    Err(e) => warn!("[firewall] rule '{}' ({chain}): {e}", rule.name),
                }
            }
        }

        // Default policy — appended last so explicit rules above take priority
        let default = match config.mode {
            FirewallMode::Whitelist => "DROP",
            FirewallMode::Blacklist => "ACCEPT",
        };
        ipt(&["-t", "filter", "-A", CHAIN_OUT, "-j", default])?;
        ipt(&["-t", "filter", "-A", CHAIN_IN,  "-j", default])?;

        let total = config.rules.iter().filter(|r| r.enabled).count();
        info!(
            "[firewall] applied {applied}/{total} rules  mode={:?}  default={}",
            config.mode, default
        );
        Ok(())
    }
}

impl Drop for NetworkFirewall {
    fn drop(&mut self) {
        let cg_path = format!("/{CGROUP_NAME}");
        let _ = ipt(&["-t", "filter", "-D", "OUTPUT",
            "-m", "cgroup", "--path", &cg_path, "-j", CHAIN_OUT]);
        let _ = ipt(&["-t", "filter", "-D", "INPUT",
            "-m", "cgroup", "--path", &cg_path, "-j", CHAIN_IN]);
        let _ = ipt(&["-t", "filter", "-F", CHAIN_OUT]);
        let _ = ipt(&["-t", "filter", "-F", CHAIN_IN]);
        let _ = ipt(&["-t", "filter", "-X", CHAIN_OUT]);
        let _ = ipt(&["-t", "filter", "-X", CHAIN_IN]);
        info!("[firewall] rules removed");
    }
}

/// Validate a CIDR string to prevent command injection.
/// Returns `None` if the value means "any" or is invalid.
fn sanitize_cidr(raw: &str) -> Option<&str> {
    let cidr = raw.trim();
    if cidr.is_empty() || cidr.eq_ignore_ascii_case("any") || cidr == "0.0.0.0/0" {
        return None;
    }
    // Allow only digits, dots, colons (IPv6), and slash
    if cidr.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | '/' | ':')) {
        Some(cidr)
    } else {
        warn!("[firewall] rejected CIDR '{}' — invalid characters", cidr);
        None
    }
}

fn ipt(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("iptables").args(args).status()?;
    if !status.success() {
        anyhow::bail!(
            "iptables {} → exit {}",
            args.join(" "),
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}
