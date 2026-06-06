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
/// ipset holding the currently-resolved IPs of `allow_hosts` (egress allowlist).
const IPSET_ALLOW: &str = "protector-allow";
const IPSET_TMP: &str   = "protector-allow-tmp";

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

        // Create the egress-allowlist ipset (best-effort — needs the `ipset`
        // tool + xt_set module; the host allowlist is inactive without it).
        let _ = ipset_cmd(&["create", IPSET_ALLOW, "hash:ip", "-exist"]);

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
        // Remove any prior blanket IPv6-egress drop for the agent cgroup.
        let _ = ip6t(&["-D", "OUTPUT",
            "-m", "cgroup", "--path", &cg_path, "-j", "DROP"]);

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

        // In whitelist mode (default-deny egress), install the baseline allows
        // that keep the agent functional without opening an exfil path:
        //   IN : established/related replies + loopback
        //   OUT: loopback, established/related, DNS (optional), and the dynamic
        //        host allowlist (ipset). Everything else hits the trailing DROP.
        //   IPv6: dropped wholesale (the ipset path is IPv4-only) to avoid a v6
        //        bypass of the allowlist.
        if matches!(config.mode, FirewallMode::Whitelist) {
            ipt(&["-t", "filter", "-A", CHAIN_IN,
                  "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
            ipt(&["-t", "filter", "-A", CHAIN_IN, "-i", "lo", "-j", "ACCEPT"])?;

            ipt(&["-t", "filter", "-A", CHAIN_OUT, "-o", "lo", "-j", "ACCEPT"])?;
            ipt(&["-t", "filter", "-A", CHAIN_OUT,
                  "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
            if config.allow_dns {
                ipt(&["-t", "filter", "-A", CHAIN_OUT, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])?;
                ipt(&["-t", "filter", "-A", CHAIN_OUT, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])?;
            }
            // Resolved allowlist IPs live in the ipset (maintained out-of-band by
            // the resolver). Best-effort: without xt_set this rule is skipped and
            // only DNS/loopback/established are allowed.
            match ipt(&["-t", "filter", "-A", CHAIN_OUT,
                  "-m", "set", "--match-set", IPSET_ALLOW, "dst", "-j", "ACCEPT"]) {
                Ok(()) => {}
                Err(e) => warn!("[firewall] ipset match rule not installed ({e}); \
                                 host allowlist inactive — install `ipset` + xt_set"),
            }

            // Block all IPv6 egress for the agent (allowlist is IPv4-only).
            let _ = ip6t(&["-I", "OUTPUT", "1",
                "-m", "cgroup", "--path", &cg_path, "-j", "DROP"]);
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

        // Populate the allowlist ipset now so the agent can reach its hosts
        // immediately; the resolver thread keeps it fresh afterwards.
        if matches!(config.mode, FirewallMode::Whitelist) && !config.allow_hosts.is_empty() {
            self.refresh_allowlist(&config.allow_hosts);
        }

        let total = config.rules.iter().filter(|r| r.enabled).count();
        info!(
            "[firewall] applied {applied}/{total} rules  mode={:?}  default={}",
            config.mode, default
        );
        Ok(())
    }

    /// Resolve `hosts` to their current IPv4 addresses and atomically swap them
    /// into the allowlist ipset (no window where the set is empty). Called once
    /// at apply() and periodically by the resolver thread so rotating CDN IPs
    /// (e.g. `api.anthropic.com`) stay reachable under default-deny.
    pub fn refresh_allowlist(&self, hosts: &[String]) {
        use std::net::ToSocketAddrs;

        let mut ips: Vec<String> = Vec::new();
        for host in hosts {
            let h = host.trim();
            if h.is_empty() {
                continue;
            }
            // Port is irrelevant to the resolved address; 443 is just a hint.
            match (h, 443u16).to_socket_addrs() {
                Ok(addrs) => {
                    for a in addrs {
                        // IPv4 only — the ipset is hash:ip (inet) and IPv6 egress
                        // is dropped wholesale.
                        if a.is_ipv4() {
                            ips.push(a.ip().to_string());
                        }
                    }
                }
                Err(e) => warn!("[firewall] cannot resolve allow_host '{h}': {e}"),
            }
        }
        ips.sort();
        ips.dedup();

        // Build a temp set and swap it in atomically.
        let _ = ipset_cmd(&["create", IPSET_TMP, "hash:ip", "-exist"]);
        let _ = ipset_cmd(&["flush", IPSET_TMP]);
        for ip in &ips {
            let _ = ipset_cmd(&["add", IPSET_TMP, ip, "-exist"]);
        }
        if ipset_cmd(&["swap", IPSET_TMP, IPSET_ALLOW]).is_err() {
            // ipset unavailable — nothing to do (host allowlist already warned).
            let _ = ipset_cmd(&["destroy", IPSET_TMP]);
            return;
        }
        let _ = ipset_cmd(&["destroy", IPSET_TMP]);
        info!(
            "[firewall] egress allowlist refreshed: {} IPv4(s) for {} host(s)",
            ips.len(),
            hosts.len()
        );
    }
}

impl Drop for NetworkFirewall {
    fn drop(&mut self) {
        let cg_path = format!("/{CGROUP_NAME}");
        let _ = ipt(&["-t", "filter", "-D", "OUTPUT",
            "-m", "cgroup", "--path", &cg_path, "-j", CHAIN_OUT]);
        let _ = ipt(&["-t", "filter", "-D", "INPUT",
            "-m", "cgroup", "--path", &cg_path, "-j", CHAIN_IN]);
        let _ = ip6t(&["-D", "OUTPUT",
            "-m", "cgroup", "--path", &cg_path, "-j", "DROP"]);
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

/// ip6tables wrapper (used only for the blanket IPv6-egress drop). Best-effort:
/// callers ignore the result so a missing ip6tables doesn't break IPv4 rules.
fn ip6t(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("ip6tables").args(args).status()?;
    if !status.success() {
        anyhow::bail!("ip6tables {} → exit {}", args.join(" "), status.code().unwrap_or(-1));
    }
    Ok(())
}

/// ipset wrapper for maintaining the egress allowlist set.
fn ipset_cmd(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("ipset").args(args).status()?;
    if !status.success() {
        anyhow::bail!("ipset {} → exit {}", args.join(" "), status.code().unwrap_or(-1));
    }
    Ok(())
}
