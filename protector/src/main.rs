use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Ebpf};
use log::{debug, info, warn};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tokio::signal;

mod alert_store;
mod auth;
mod banner;
mod budget;
mod data_policy;
mod errors;
mod event_bus;
mod firewall_config;
mod inspect;
mod network_firewall;
mod read_guard;
mod reporter;
mod run;
mod seccomp_notify;
mod rules_config;
mod secret_proxy;
mod setup;
mod siem;
mod siem_config;
mod token_proxy;
mod tool_db;
mod tracker;
mod traffic_redirect;
mod validator;
mod validators;
mod web_ui;

use protector_common::ExecEvent;
use alert_store::SharedAlertStore;
use data_policy::DataPolicy;
use event_bus::{EventSender, InspectOutcome, SharedHistory};
use reporter::Reporter;
use secret_proxy::SharedSecretStore;
use siem::SiemSender;
use tool_db::ToolDb;
use tracker::ProcessTracker;
use traffic_redirect::TrafficRedirector;
use validator::{ValidationContext, ValidationResult};

fn parse_config_port() -> u16 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == "--config-port" {
            return args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(7878);
        }
        if let Some(v) = arg.strip_prefix("--config-port=") {
            return v.parse().unwrap_or(7878);
        }
    }
    7878
}

fn parse_proxy_port() -> Option<u16> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == "--proxy-port" {
            return args.get(i + 1).and_then(|v| v.parse().ok());
        }
        if let Some(v) = arg.strip_prefix("--proxy-port=") {
            return v.parse().ok();
        }
    }
    None
}

fn parse_budget_port() -> Option<u16> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == "--budget-port" {
            return args.get(i + 1).and_then(|v| v.parse().ok());
        }
        if let Some(v) = arg.strip_prefix("--budget-port=") {
            return v.parse().ok();
        }
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // --hash-password <pass>: print bcrypt hash and exit
    if let Some(pos) = args.iter().position(|a| a == "--hash-password") {
        match args.get(pos + 1) {
            Some(pass) => {
                println!("{}", auth::hash_password(pass));
                std::process::exit(0);
            }
            None => {
                eprintln!("Usage: protector --hash-password <password>");
                std::process::exit(1);
            }
        }
    }

    // Subcommand dispatch (no async runtime needed for these)
    match args.get(1).map(String::as_str) {
        Some("inspect") => {
            let socket = event_bus::socket_path();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime")
                .block_on(inspect::run(&socket))
                .unwrap_or_else(|e| {
                    eprintln!("inspect: {e:#}");
                    std::process::exit(1);
                });
            return;
        }
        Some("setup") => {
            if let Err(e) = setup::run() {
                eprintln!("setup: {e:#}");
                std::process::exit(1);
            }
            return;
        }
        Some("run") => {
            // Everything after `run` (skipping an optional `--`) is the command.
            let mut rest: Vec<String> = args.iter().skip(2).cloned().collect();
            if rest.first().map(String::as_str) == Some("--") {
                rest.remove(0);
            }
            run::exec(&rest); // installs seccomp on self, then execve — never returns
        }
        _ => {}
    }

    banner::print_banner();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async_main())
        .unwrap_or_else(|e| {
            eprintln!("fatal: {e:#}");
            std::process::exit(1);
        });
}

/// Switch to a stable config directory so relative-path config files
/// (rules.json, admin.passwd, policy.conf, …) are found regardless of the
/// daemon's launch CWD (systemd units often start at `/`).
fn enter_config_dir() {
    if let Ok(custom) = std::env::var("PROTECTOR_CONFIG_DIR") {
        if !custom.is_empty() && std::env::set_current_dir(&custom).is_ok() {
            info!("Config directory: {custom}");
            return;
        }
    }
    let etc = std::path::Path::new("/etc/protector");
    if etc.is_dir() && std::env::set_current_dir(etc).is_ok() {
        info!("Config directory: /etc/protector");
    }
    // Otherwise keep the existing CWD (developer/local runs).
}

async fn async_main() -> anyhow::Result<()> {
    env_logger::init();
    enter_config_dir();

    // Required for older kernels without memcg-based eBPF memory accounting
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("setrlimit RLIMIT_MEMLOCK failed (may be OK on newer kernels): {ret}");
    }

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/protector")))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("eBPF logger unavailable: {e}");
    }

    let program: &mut TracePoint = ebpf.program_mut("protector").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let ring_buf = RingBuf::try_from(
        ebpf.map_mut("RING_BUF")
            .ok_or_else(|| anyhow::anyhow!("RING_BUF map not found in eBPF object"))?,
    )?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    let policy       = DataPolicy::load_default();
    // Kept for the fanotify read-guard before `policy` is moved into ToolDb.
    let guard_policy = Arc::clone(&policy);
    let rules_config = Arc::new(std::sync::RwLock::new(
        rules_config::RulesConfig::load_or_default("rules.json"),
    ));
    let alert_store  = Arc::new(std::sync::Mutex::new(alert_store::AlertStore::new()));
    let tool_db  = Arc::new(ToolDb::new(
        policy,
        Arc::clone(&rules_config),
    ));
    let tracker  = Arc::new(Mutex::new(ProcessTracker::new()));
    let reporter = Arc::new(Reporter::new());

    let siem_config  = siem_config::new_shared(siem_config::SiemConfig::load_or_default());
    let siem_sender  = Arc::new(Mutex::new(SiemSender::new(Arc::clone(&siem_config))));
    let secret_store = secret_proxy::new_store();
    let shared_budget = budget::new_shared(budget::BudgetConfig::load_or_default());

    // L3/L4 network firewall
    let fw_config = firewall_config::new_shared(firewall_config::FirewallConfig::load_or_default());
    let network_fw = match network_firewall::NetworkFirewall::new() {
        Ok(fw) => {
            {
                let cfg = fw_config.read().unwrap();
                if let Err(e) = fw.apply(&cfg) {
                    warn!("Firewall initial apply failed (iptables unavailable?): {e}");
                }
            }
            let fw = std::sync::Arc::new(fw);
            // Track existing Claude PIDs into the cgroup
            {
                let t = tracker.lock().unwrap();
                fw.track_pids(&t.claude_root_pids());
            }
            // Keep cgroup up-to-date (runs in parallel with TrafficRedirector's own loop)
            let fw_task   = std::sync::Arc::clone(&fw);
            let trkr_task = Arc::clone(&tracker);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    let pids = { trkr_task.lock().unwrap().claude_root_pids() };
                    if !pids.is_empty() { fw_task.track_pids(&pids); }
                }
            });
            Some(fw)
        }
        Err(e) => {
            warn!("Network firewall unavailable: {e}");
            None
        }
    };

    // Event bus: broadcast + ring-buffer history for `protector inspect`
    let event_tx  = event_bus::new_sender();
    let history   = event_bus::new_history();
    {
        let tx   = event_tx.clone();
        let hist = Arc::clone(&history);
        tokio::spawn(async move {
            if let Err(e) = event_bus::start_unix_server(tx, hist).await {
                log::warn!("inspect socket: {e}");
            }
        });
    }

    // Fanotify read-guard: deny in-process reads (python/node/custom binaries)
    // of policy-protected files by Claude descendants — closes the secret-proxy
    // bypass that tool-level masking can't cover.
    read_guard::start(
        Arc::clone(&guard_policy),
        Arc::clone(&tracker),
        event_tx.clone(),
        Arc::clone(&history),
        Arc::clone(&alert_store),
        Arc::clone(&siem_sender),
    );

    // Seccomp user-notif supervisor: substitute masked content for in-process
    // secret reads by agents launched through proxy-injector (which installs the
    // filter and hands us the listener fd).  Complements read_guard's deny path.
    #[cfg(target_os = "linux")]
    seccomp_notify::start(
        Arc::clone(&guard_policy),
        Arc::clone(&secret_store),
        event_tx.clone(),
        Arc::clone(&history),
        Arc::clone(&alert_store),
        Arc::clone(&siem_sender),
    );

    let config_port  = parse_config_port();
    let auth_state   = Arc::new(auth::AuthState::load());
    {
        let cfg_clone    = Arc::clone(&rules_config);
        let auth_clone   = Arc::clone(&auth_state);
        let alerts_clone = Arc::clone(&alert_store);
        let siem_clone    = Arc::clone(&siem_config);
        let sender_clone  = Arc::clone(&siem_sender);
        let secrets_clone = Arc::clone(&secret_store);
        let budget_clone  = Arc::clone(&shared_budget);
        let fw_cfg_clone  = Arc::clone(&fw_config);
        let fw_clone      = network_fw.as_ref().map(Arc::clone);
        tokio::spawn(async move {
            if let Err(e) = web_ui::start(cfg_clone, auth_clone, alerts_clone, siem_clone, sender_clone, secrets_clone, budget_clone, fw_cfg_clone, fw_clone, config_port).await {
                log::warn!("Config UI failed: {e}");
            }
        });
    }

    // Optional token-budget proxy (intercepts Anthropic API calls)
    if let Some(bp) = parse_budget_port() {
        let budget_proxy = Arc::clone(&shared_budget);
        tokio::spawn(async move {
            if let Err(e) = token_proxy::start(budget_proxy, bp).await {
                log::warn!("Token proxy failed: {e}");
            }
        });
    }

    // Optional transparent proxy redirect
    if let Some(proxy_port) = parse_proxy_port() {
        match TrafficRedirector::new(proxy_port) {
            Ok(redirector) => {
                {
                    let t = tracker.lock().unwrap();
                    redirector.track_pids(&t.claude_root_pids());
                }
                let redirector = Arc::new(redirector);
                let tracker_task = Arc::clone(&tracker);
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(
                        std::time::Duration::from_secs(5),
                    );
                    loop {
                        interval.tick().await;
                        let added = {
                            let mut t = tracker_task.lock().unwrap();
                            t.refresh_and_diff().0
                        };
                        if !added.is_empty() {
                            redirector.track_pids(&added);
                        }
                    }
                });
            }
            Err(e) => {
                warn!("Traffic redirect disabled (requires root + iptables): {e}");
            }
        }
    }

    info!("Protector started — monitoring Claude Code agent actions (RUST_LOG=debug for skip reasons)");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Shutting down protector");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    if item.len() < std::mem::size_of::<ExecEvent>() {
                        continue;
                    }
                    // SAFETY: eBPF program writes a well-formed ExecEvent into the ring buf
                    let event = unsafe { (item.as_ptr() as *const ExecEvent).read_unaligned() };
                    handle_event(event, &tool_db, &tracker, &reporter, &alert_store, &event_tx, &history, &siem_sender, &secret_store);
                }

                guard.clear_ready();
            }
        }
    }

    Ok(())
}

fn handle_event(
    event:    ExecEvent,
    tool_db:  &ToolDb,
    tracker:  &Mutex<ProcessTracker>,
    reporter: &Reporter,
    alerts:   &SharedAlertStore,
    events:   &EventSender,
    history:  &SharedHistory,
    siem:     &Mutex<SiemSender>,
    secrets:  &SharedSecretStore,
) {
    let filename = c_str(&event.filename);
    let comm = c_str(&event.comm);

    debug!("execve pid={} comm={} file={}", event.pid, comm, filename);

    if !looks_interesting(filename) {
        debug!(
            "skip pid={} file={} comm={} reason=not_in_tool_watchlist",
            event.pid, filename, comm
        );
        return;
    }

    let is_agent_child = {
        let mut t = tracker.lock().unwrap();
        t.is_claude_descendant(event.pid)
    };

    if !is_agent_child {
        debug!(
            "skip pid={} file={} comm={} reason=not_descendant_of_claude_roots",
            event.pid, filename, comm
        );
        return;
    }

    let Some(args) = read_cmdline(event.pid) else {
        debug!(
            "skip pid={} file={} comm={} reason=no_cmdline_in_proc",
            event.pid, filename, comm
        );
        return;
    };
    let cwd = read_cwd(event.pid);

    let Some(action) = tool_db.find_action(filename, &args) else {
        debug!(
            "skip pid={} file={} comm={} args={:?} reason=no_matching_tool_rule (argv does not match any ToolDb action)",
            event.pid, filename, comm, args
        );
        return;
    };

    info!(
        "Agent action intercepted: pid={} tool={} args={:?}",
        event.pid, action.name, args
    );

    send_signal(event.pid, libc::SIGSTOP);

    let ctx = ValidationContext {
        pid: event.pid,
        filename: filename.to_string(),
        args,
        working_dir: cwd,
    };

    // ── Secret Proxy phase 1: file masking ─────────────────────────────────────
    // File-reading commands on sensitive paths → inject masked content + kill.
    if matches!(action.name, "cat"|"head"|"tail"|"grep"|"egrep"|"diff"|"cp"|"mv") {
        let paths = secret_proxy::all_file_args(&ctx.args, ctx.working_dir.as_deref());
        let secret_path = paths.iter().find(|p| secret_proxy::is_secret_path(p)).cloned();

        if let Some(ref spath) = secret_path {
            let mask_result = {
                let mut store = secrets.lock().unwrap();
                secret_proxy::mask_file(spath, &mut store)
            };
            match mask_result {
                Ok((masked, count)) => {
                    info!("[secret-proxy] Masking {count} secret(s) from {}", spath.display());
                    let outcome = match secret_proxy::inject_and_terminate(event.pid, masked.as_bytes()) {
                        Ok(()) => InspectOutcome::Alerted {
                            threat_code: "SECRET_MASKED".to_string(),
                            message: format!(
                                "Masked {count} secret(s) from {} before delivering to agent",
                                spath.display()
                            ),
                        },
                        Err(e) => {
                            warn!("[secret-proxy] inject failed ({e}), releasing process");
                            send_signal(event.pid, libc::SIGCONT);
                            InspectOutcome::Allowed
                        }
                    };
                    emit_event(event.pid, action.name, &ctx.args, outcome, events, history);
                    return;
                }
                Err(e) => {
                    debug!("[secret-proxy] mask_file error for {}: {e}", spath.display());
                    // fall through to normal validation
                }
            }
        }
    }

    // ── Secret Proxy phase 2: outgoing request relay ───────────────────────────
    // curl/wget with token args → re-run with real credentials, relay output.
    if matches!(action.name, "curl" | "wget") {
        if secret_proxy::args_have_tokens(&ctx.args) {
            // SECURITY: only substitute real credentials for allowlisted hosts,
            // otherwise an agent could exfiltrate secrets to an attacker URL.
            if !relay_allowed(&ctx.args) {
                warn!("[secret-proxy] relay denied for {} — destination not in PROTECTOR_RELAY_ALLOWLIST", action.name);
                send_signal(event.pid, libc::SIGCONT);
                emit_event(event.pid, action.name, &ctx.args, InspectOutcome::Warned {
                    threat_code: "SECRET_RELAY_DENIED".to_string(),
                    message: "Outbound destination not allowlisted; real credentials NOT substituted".to_string(),
                }, events, history);
                return;
            }
            info!("[secret-proxy] Relaying {} with real credentials", action.name);
            let outcome = {
                let store = secrets.lock().unwrap();
                match secret_proxy::relay_with_real_creds(event.pid, &ctx.args, &store) {
                    Ok(()) => InspectOutcome::Alerted {
                        threat_code: "SECRET_RELAYED".to_string(),
                        message: format!(
                            "Token credentials transparently substituted for {} request",
                            action.name
                        ),
                    },
                    Err(e) => {
                        warn!("[secret-proxy] relay failed ({e}), releasing process");
                        send_signal(event.pid, libc::SIGCONT);
                        InspectOutcome::Allowed
                    }
                }
            };
            emit_event(event.pid, action.name, &ctx.args, outcome, events, history);
            return;
        }
    }

    let outcome = match action.validate(&ctx) {
        ValidationResult::Allow => {
            info!("[{}] ALLOWED — resuming pid={}", action.name, event.pid);
            send_signal(event.pid, libc::SIGCONT);
            InspectOutcome::Allowed
        }
        ValidationResult::Warn(threat) => {
            reporter.warn(action.name, event.pid, &ctx.args, &threat);
            siem.lock().unwrap().send_warn(
                action.name, event.pid, &ctx.args, threat.code(), &threat.to_string());
            send_signal(event.pid, libc::SIGCONT);
            InspectOutcome::Warned {
                threat_code: threat.code().to_string(),
                message:     threat.to_string(),
            }
        }
        ValidationResult::Block(threat) => {
            reporter.block(action.name, event.pid, &ctx.args, &threat);
            siem.lock().unwrap().send_block(
                action.name, event.pid, &ctx.args, threat.code(), &threat.to_string());
            send_signal(event.pid, libc::SIGKILL);
            send_signal(event.pid, libc::SIGCONT);
            InspectOutcome::Blocked {
                threat_code: threat.code().to_string(),
                message:     threat.to_string(),
            }
        }
        ValidationResult::Alert { threat, rule } => {
            alerts.lock().unwrap().push(
                action.name.to_string(),
                rule.clone(),
                threat.code().to_string(),
                threat.to_string(),
                ctx.args.clone(),
                ctx.pid,
            );
            reporter.warn(action.name, event.pid, &ctx.args, &threat);
            siem.lock().unwrap().send_alert(
                action.name, event.pid, &ctx.args, threat.code(), &threat.to_string());
            send_signal(event.pid, libc::SIGCONT);
            InspectOutcome::Alerted {
                threat_code: threat.code().to_string(),
                message:     threat.to_string(),
            }
        }
        // MaskedOutput is only returned by protector-win's validators (shim-based).
        // On Linux, treat it as Block to be safe (should never fire in practice).
        ValidationResult::MaskedOutput { threat, .. } => {
            reporter.block(action.name, event.pid, &ctx.args, &threat);
            send_signal(event.pid, libc::SIGKILL);
            send_signal(event.pid, libc::SIGCONT);
            InspectOutcome::Blocked {
                threat_code: threat.code().to_string(),
                message:     threat.to_string(),
            }
        }
    };

    emit_event(event.pid, action.name, &ctx.args, outcome, events, history);
}

fn emit_event(
    pid:     u32,
    tool:    &str,
    args:    &[String],
    outcome: InspectOutcome,
    events:  &EventSender,
    history: &SharedHistory,
) {
    let ev = event_bus::InspectEvent {
        ts_ms:   event_bus::now_ms(),
        pid,
        tool:    tool.to_string(),
        args:    args.to_vec(),
        outcome,
    };
    event_bus::record(history, &ev);
    let _ = events.send(ev);
}

/// Returns true only if real credentials may be substituted into this outbound
/// request, i.e. every URL host in `args` matches `PROTECTOR_RELAY_ALLOWLIST`
/// (comma-separated host suffixes).  Empty/unset allowlist ⇒ deny (fail safe).
fn relay_allowed(args: &[String]) -> bool {
    let allow_raw = std::env::var("PROTECTOR_RELAY_ALLOWLIST").unwrap_or_default();
    let allow: Vec<String> = allow_raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if allow.is_empty() {
        return false;
    }
    let hosts = extract_hosts(args);
    if hosts.is_empty() {
        return false;
    }
    hosts.iter().all(|h| {
        allow.iter().any(|a| h == a || h.ends_with(&format!(".{a}")))
    })
}

/// Extract lowercased host names from any URL-looking arguments.
fn extract_hosts(args: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    for a in args {
        for scheme in ["http://", "https://"] {
            if let Some(rest) = a.find(scheme).map(|i| &a[i + scheme.len()..]) {
                let after_at = rest.rsplit('@').next().unwrap_or(rest);
                let host: String = after_at
                    .chars()
                    .take_while(|&c| c != '/' && c != ':' && c != '?' && c != '#')
                    .collect();
                let host = host.trim().to_ascii_lowercase();
                if !host.is_empty() {
                    hosts.push(host);
                }
            }
        }
    }
    hosts
}

/// Quick pre-filter: only pass events that could match something in ToolDb.
fn looks_interesting(filename: &str) -> bool {
    const WATCHED: &[&str] = &[
        // VCS
        "git",
        // SQL databases
        "psql", "mysql", "mariadb", "sqlite3",
        // Key-value / cache
        "redis-cli",
        // Package managers (future rules)
        "npm", "pip", "pip3",
        // Network / container
        "curl", "wget", "docker", "kubectl",
        // Filesystem readers — watched when data policy has fblock/fmask rules
        "cat", "head", "tail", "grep", "egrep", "fgrep",
        "diff", "find", "cp", "mv",
    ];
    WATCHED
        .iter()
        .any(|w| filename == *w || filename.ends_with(&format!("/{}", w)))
}

fn send_signal(pid: u32, sig: libc::c_int) {
    let ret = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if ret != 0 {
        // ESRCH (no such process) is normal if the process exited before we got here
        debug!("kill(pid={pid}, sig={sig}) returned {ret}");
    }
}

fn read_cmdline(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    let args: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if args.is_empty() { None } else { Some(args) }
}

fn read_cwd(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{}/cwd", pid)).ok()
}

/// Interpret a fixed-size byte buffer as a null-terminated C string.
fn c_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}
