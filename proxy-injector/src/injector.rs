/// Core injector: kills a Claude instance and relaunches it with proxy env vars.
use crate::discovery::ClaudeInstance;
use std::path::PathBuf;
use std::process::{Child, Command};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Proxy settings to inject into Claude Code's environment.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Proxy host (default: 127.0.0.1).
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// Path to a PEM CA certificate for HTTPS MITM.
    /// Claude Code (Bun) reads NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, CURL_CA_BUNDLE.
    pub ca_cert: Option<PathBuf>,
    /// Set NODE_TLS_REJECT_UNAUTHORIZED=0 — skip all TLS verification.
    /// Simpler than a CA cert, but less safe; use only in dev.
    pub no_tls_verify: bool,
}

impl ProxyConfig {
    pub fn new(port: u16) -> Self {
        Self {
            host: "127.0.0.1".into(),
            port,
            ca_cert: None,
            no_tls_verify: false,
        }
    }

    pub fn with_ca(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert = Some(path.into());
        self
    }

    pub fn insecure(mut self) -> Self {
        self.no_tls_verify = true;
        self
    }

    fn proxy_url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

// ─── Injector ─────────────────────────────────────────────────────────────────

pub struct ProxyInjector {
    pub config: ProxyConfig,
}

impl ProxyInjector {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Inject proxy into every running Claude Code instance.
    /// Returns one `InjectionResult` per discovered process.
    pub fn inject_all(&self) -> Vec<InjectionResult> {
        let instances = crate::discovery::scan();
        if instances.is_empty() {
            log::warn!("[proxy-injector] no running Claude Code instances found");
        }
        instances.iter().map(|inst| self.inject_one(inst)).collect()
    }

    /// Kill one instance and restart it with proxy env.
    pub fn inject_one(&self, inst: &ClaudeInstance) -> InjectionResult {
        log::info!(
            "[proxy-injector] targeting pid={} exe={} cwd={}",
            inst.pid,
            inst.exe.display(),
            inst.cwd.display(),
        );

        if let Err(e) = kill_gracefully(inst.pid) {
            return InjectionResult::KillFailed { pid: inst.pid, error: e.to_string() };
        }
        log::info!("[proxy-injector] pid={} terminated", inst.pid);

        match self.relaunch(inst) {
            Ok(child) => {
                log::info!(
                    "[proxy-injector] relaunched as pid={} with proxy {}",
                    child.id(),
                    self.config.proxy_url(),
                );
                InjectionResult::Relaunched {
                    old_pid: inst.pid,
                    new_pid: child.id(),
                    proxy: self.config.proxy_url(),
                }
            }
            Err(e) => InjectionResult::LaunchFailed {
                old_pid: inst.pid,
                error: e.to_string(),
            },
        }
    }

    /// Spawn a new Claude process in the same directory with proxy env vars injected.
    /// Inherits the rest of the parent environment so the user's PATH/HOME etc. are preserved.
    fn relaunch(&self, inst: &ClaudeInstance) -> std::io::Result<Child> {
        let proxy_url = self.config.proxy_url();

        let mut cmd = Command::new(&inst.exe);
        cmd.current_dir(&inst.cwd);

        // ── proxy settings ────────────────────────────────────────────────────
        // Claude Code (Bun runtime) reads both lowercase and uppercase forms.
        cmd.env("HTTP_PROXY",  &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);
        cmd.env("http_proxy",  &proxy_url);
        cmd.env("https_proxy", &proxy_url);
        // no_proxy ensures localhost/internal don't get routed through the proxy.
        cmd.env("NO_PROXY",  "localhost,127.0.0.1,::1");
        cmd.env("no_proxy",  "localhost,127.0.0.1,::1");

        // ── TLS options ───────────────────────────────────────────────────────
        if self.config.no_tls_verify {
            // Bun respects NODE_TLS_REJECT_UNAUTHORIZED (confirmed in binary).
            cmd.env("NODE_TLS_REJECT_UNAUTHORIZED", "0");
        }
        if let Some(ca) = &self.config.ca_cert {
            let ca_str = ca.to_string_lossy();
            // All three names are read by Bun/Node.js (confirmed in binary).
            cmd.env("NODE_EXTRA_CA_CERTS", ca_str.as_ref());
            cmd.env("SSL_CERT_FILE",       ca_str.as_ref());
            cmd.env("CURL_CA_BUNDLE",      ca_str.as_ref());
        }

        cmd.spawn()
    }
}

// ─── Result ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum InjectionResult {
    Relaunched { old_pid: u32, new_pid: u32, proxy: String },
    KillFailed  { pid: u32, error: String },
    LaunchFailed { old_pid: u32, error: String },
}

impl std::fmt::Display for InjectionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relaunched { old_pid, new_pid, proxy } =>
                write!(f, "✓ pid={old_pid} → pid={new_pid}  proxy={proxy}"),
            Self::KillFailed { pid, error } =>
                write!(f, "✗ kill pid={pid} failed: {error}"),
            Self::LaunchFailed { old_pid, error } =>
                write!(f, "✗ relaunch (after killing {old_pid}) failed: {error}"),
        }
    }
}

// ─── Kill helpers ─────────────────────────────────────────────────────────────

fn kill_gracefully(pid: u32) -> anyhow::Result<()> {
    // SIGTERM first, then SIGKILL after 2 s if still alive.
    send_signal(pid, libc::SIGTERM);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if !process_exists(pid) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Still alive → force kill.
    send_signal(pid, libc::SIGKILL);
    // Give the OS a moment to clean up.
    std::thread::sleep(std::time::Duration::from_millis(200));

    if process_exists(pid) {
        anyhow::bail!("process {pid} did not exit after SIGKILL");
    }
    Ok(())
}

fn send_signal(pid: u32, sig: libc::c_int) {
    unsafe { libc::kill(pid as libc::pid_t, sig) };
}

fn process_exists(pid: u32) -> bool {
    // kill(pid, 0) checks existence without sending a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}
