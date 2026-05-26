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
mod data_policy;
mod errors;
mod event_bus;
mod inspect;
mod reporter;
mod rules_config;
mod setup;
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

async fn async_main() -> anyhow::Result<()> {
    env_logger::init();

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

    let config_port  = parse_config_port();
    let auth_state   = Arc::new(auth::AuthState::load());
    {
        let cfg_clone    = Arc::clone(&rules_config);
        let auth_clone   = Arc::clone(&auth_state);
        let alerts_clone = Arc::clone(&alert_store);
        tokio::spawn(async move {
            if let Err(e) = web_ui::start(cfg_clone, auth_clone, alerts_clone, config_port).await {
                log::warn!("Config UI failed: {e}");
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
                    handle_event(event, &tool_db, &tracker, &reporter, &alert_store, &event_tx, &history);
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

    let outcome = match action.validate(&ctx) {
        ValidationResult::Allow => {
            info!("[{}] ALLOWED — resuming pid={}", action.name, event.pid);
            send_signal(event.pid, libc::SIGCONT);
            InspectOutcome::Allowed
        }
        ValidationResult::Warn(threat) => {
            reporter.warn(action.name, event.pid, &ctx.args, &threat);
            send_signal(event.pid, libc::SIGCONT);
            InspectOutcome::Warned {
                threat_code: threat.code().to_string(),
                message:     threat.to_string(),
            }
        }
        ValidationResult::Block(threat) => {
            reporter.block(action.name, event.pid, &ctx.args, &threat);
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
            send_signal(event.pid, libc::SIGCONT);
            InspectOutcome::Alerted {
                threat_code: threat.code().to_string(),
                message:     threat.to_string(),
            }
        }
    };

    let ev = event_bus::InspectEvent {
        ts_ms:   event_bus::now_ms(),
        pid:     event.pid,
        tool:    action.name.to_string(),
        args:    ctx.args.clone(),
        outcome,
    };
    event_bus::record(history, &ev);
    let _ = events.send(ev);
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
        // Network / container (future rules)
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
