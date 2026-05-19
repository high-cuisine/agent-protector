/// Transparent traffic redirection for Claude Code processes.
///
/// Creates a dedicated cgroup v2 (`/sys/fs/cgroup/claude-protector`) and installs
/// iptables NAT rules so that any TCP port-80/443 traffic from processes in that
/// cgroup is transparently redirected to a local proxy.  Child processes inherit
/// the cgroup automatically, so new Claude sub-processes are covered without
/// additional rule updates.
///
/// Requires: root, iptables with `xt_cgroup` module, cgroup v2 mounted at
/// `/sys/fs/cgroup` (standard on all modern distros).
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const CGROUP_NAME: &str = "claude-protector";
const REDIRECT_PORTS: [u16; 2] = [80, 443];

pub struct TrafficRedirector {
    proxy_port: u16,
    cgroup_dir: PathBuf,
}

impl TrafficRedirector {
    /// Set up the cgroup and install iptables rules.
    /// Returns an error if iptables or the cgroup hierarchy is unavailable.
    pub fn new(proxy_port: u16) -> anyhow::Result<Self> {
        let cgroup_dir = PathBuf::from(format!("/sys/fs/cgroup/{CGROUP_NAME}"));
        fs::create_dir_all(&cgroup_dir)?;

        for &port in &REDIRECT_PORTS {
            iptables("-A", port, proxy_port)?;
        }

        log::info!(
            "Traffic redirect active: Claude HTTP/HTTPS → 127.0.0.1:{proxy_port} \
             (cgroup /{CGROUP_NAME})"
        );

        Ok(Self { proxy_port, cgroup_dir })
    }

    /// Move PIDs into the cgroup so their outgoing traffic is redirected.
    /// New child processes they spawn will inherit membership automatically.
    pub fn track_pids(&self, pids: &[u32]) {
        let procs = self.cgroup_dir.join("cgroup.procs");
        for &pid in pids {
            match fs::write(&procs, pid.to_string()) {
                Ok(()) => log::debug!("redirect: tracking pid={pid}"),
                Err(e) => log::warn!("redirect: cannot add pid={pid} to cgroup: {e}"),
            }
        }
    }
}

impl Drop for TrafficRedirector {
    fn drop(&mut self) {
        for &port in &REDIRECT_PORTS {
            // Ignore errors — rules may have already been cleaned up externally.
            let _ = iptables("-D", port, self.proxy_port);
        }
        if let Err(e) = fs::remove_dir(&self.cgroup_dir) {
            log::debug!("redirect: removing cgroup dir: {e}");
        }
        log::info!("Traffic redirect rules removed");
    }
}

fn iptables(action: &str, dport: u16, to_port: u16) -> anyhow::Result<()> {
    let status = Command::new("iptables")
        .args([
            "-t", "nat",
            action, "OUTPUT",
            "-m", "cgroup",
            "--path", &format!("/{CGROUP_NAME}"),
            "-p", "tcp",
            "--dport", &dport.to_string(),
            "-j", "REDIRECT",
            "--to-port", &to_port.to_string(),
        ])
        .status()?;

    if !status.success() && action == "-A" {
        anyhow::bail!("iptables {action} OUTPUT failed for dport={dport}");
    }
    Ok(())
}
