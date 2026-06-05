//! protector-win — Windows security daemon for Claude Code agent monitoring.
//!
//! Architecture:
//!   Shim wrappers (git.exe, psql.exe, …) intercept tool invocations and
//!   communicate with this daemon over a Windows named pipe.  The daemon
//!   validates each request, then tells the shim to run/block/output.
//!
//! Platform-independent modules are referenced via #[path] from protector/src/
//! to avoid code duplication.  Windows-specific modules live in this crate.

// This crate targets Windows.  When type-checked on another host (CI cross-check)
// the cfg(windows) code paths are excluded, leaving many items technically
// unused — silence that noise off-Windows only.
#![cfg_attr(not(windows), allow(dead_code, unused_imports, unused_variables, unreachable_code))]

// ── Platform-independent modules (shared with Linux protector) ────────────────

#[path = "../../protector/src/errors.rs"]
mod errors;

#[path = "../../protector/src/validator.rs"]
mod validator;

#[path = "../../protector/src/data_policy.rs"]
mod data_policy;

#[path = "../../protector/src/rules_config.rs"]
mod rules_config;

#[path = "../../protector/src/alert_store.rs"]
mod alert_store;

#[path = "../../protector/src/reporter.rs"]
mod reporter;

#[path = "../../protector/src/siem.rs"]
mod siem;

#[path = "../../protector/src/siem_config.rs"]
mod siem_config;

#[path = "../../protector/src/auth.rs"]
mod auth;

#[path = "../../protector/src/budget.rs"]
mod budget;

#[path = "../../protector/src/token_proxy.rs"]
mod token_proxy;

#[path = "../../protector/src/banner.rs"]
mod banner;

#[path = "../../protector/src/tool_db.rs"]
mod tool_db;

// ── Windows-specific modules ──────────────────────────────────────────────────

mod event_bus;
mod firewall_config;
mod ipc;
mod network_firewall;
mod secret_proxy;
mod setup;
mod tracker;
mod validators;
mod win_util;

// web_ui references firewall_config and network_firewall — load it AFTER stubs.
#[path = "../../protector/src/web_ui.rs"]
mod web_ui;

// ── Imports ───────────────────────────────────────────────────────────────────

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use log::{debug, info, warn};

use alert_store::SharedAlertStore;
use data_policy::DataPolicy;
use event_bus::{EventSender, InspectOutcome, SharedHistory};
use ipc::{ShimRequest, ShimResponse, PIPE_NAME};
use reporter::Reporter;
use secret_proxy::SharedSecretStore;
use siem::SiemSender;
use tool_db::ToolDb;
use tracker::ProcessTracker;
use validator::{ValidationContext, ValidationResult};

// ── Arg parsing ───────────────────────────────────────────────────────────────

fn parse_port(flag: &str, default: u16) -> u16 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(default);
        }
        if let Some(v) = arg.strip_prefix(&format!("{flag}=")) {
            return v.parse().unwrap_or(default);
        }
    }
    default
}

fn parse_opt_port(flag: &str) -> Option<u16> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == flag { return args.get(i + 1).and_then(|v| v.parse().ok()); }
        if let Some(v) = arg.strip_prefix(&format!("{flag}=")) { return v.parse().ok(); }
    }
    None
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if let Some(pos) = args.iter().position(|a| a == "--hash-password") {
        match args.get(pos + 1) {
            Some(pass) => { println!("{}", auth::hash_password(pass)); std::process::exit(0); }
            None => { eprintln!("Usage: protector-win --hash-password <password>"); std::process::exit(1); }
        }
    }

    match args.get(1).map(String::as_str) {
        Some("setup") => {
            // setup writes HKLM PATH + registers a service — needs admin.
            win_util::ensure_elevated();
            if let Err(e) = setup::run() {
                eprintln!("setup: {e:#}");
                std::process::exit(1);
            }
            return;
        }
        Some("inspect") => {
            // Connect to the inspect named pipe and stream events.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_inspect())
                .unwrap_or_else(|e| { eprintln!("inspect: {e:#}"); std::process::exit(1); });
            return;
        }
        _ => {}
    }

    // Running the daemon needs admin: process enumeration across sessions,
    // reading other processes' command lines, and named-pipe enforcement.
    // When launched as a Windows service (LocalSystem) this is already true and
    // ensure_elevated() is a no-op.
    win_util::ensure_elevated();

    banner::print_banner();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async_main())
        .unwrap_or_else(|e| { eprintln!("fatal: {e:#}"); std::process::exit(1); });
}

// ── Async daemon ──────────────────────────────────────────────────────────────

/// Switch to a stable config directory so relative-path config files
/// (rules.json, admin.passwd, policy.conf, …) are found regardless of how the
/// service was launched (a Windows service starts in C:\Windows\System32).
fn enter_config_dir() {
    if let Ok(custom) = std::env::var("PROTECTOR_CONFIG_DIR") {
        if !custom.is_empty() && std::env::set_current_dir(&custom).is_ok() {
            info!("Config directory: {custom}");
            return;
        }
    }
    if let Ok(program_data) = std::env::var("ProgramData") {
        let dir = std::path::Path::new(&program_data).join("Protector");
        if std::fs::create_dir_all(&dir).is_ok() && std::env::set_current_dir(&dir).is_ok() {
            info!("Config directory: {}", dir.display());
            return;
        }
    }
    warn!("Falling back to current working directory for config files");
}

async fn async_main() -> anyhow::Result<()> {
    env_logger::init();
    enter_config_dir();

    let policy       = DataPolicy::load_default();
    let rules_config = Arc::new(std::sync::RwLock::new(
        rules_config::RulesConfig::load_or_default("rules.json"),
    ));
    let alert_store  = Arc::new(Mutex::new(alert_store::AlertStore::new()));
    let tool_db      = Arc::new(ToolDb::new(policy, Arc::clone(&rules_config)));
    let tracker      = Arc::new(Mutex::new(ProcessTracker::new()));
    let reporter     = Arc::new(Reporter::new());
    let siem_config  = siem_config::new_shared(siem_config::SiemConfig::load_or_default());
    let siem_sender  = Arc::new(Mutex::new(SiemSender::new(Arc::clone(&siem_config))));
    let secret_store = secret_proxy::new_store();
    let shared_budget = budget::new_shared(budget::BudgetConfig::load_or_default());
    let fw_config    = firewall_config::new_shared(firewall_config::FirewallConfig::load_or_default());

    // Event bus (broadcast + named-pipe inspect server)
    let event_tx  = event_bus::new_sender();
    let history   = event_bus::new_history();
    {
        let tx   = event_tx.clone();
        let hist = Arc::clone(&history);
        tokio::spawn(async move {
            if let Err(e) = event_bus::start_inspect_server(tx, hist).await {
                warn!("inspect pipe: {e}");
            }
        });
    }

    // Web dashboard
    let config_port = parse_port("--config-port", 7878);
    let auth_state  = Arc::new(auth::AuthState::load());
    {
        let r = Arc::clone(&rules_config);
        let a = Arc::clone(&auth_state);
        let al = Arc::clone(&alert_store);
        let sc = Arc::clone(&siem_config);
        let ss = Arc::clone(&siem_sender);
        let se = Arc::clone(&secret_store);
        let bu = Arc::clone(&shared_budget);
        let fw = Arc::clone(&fw_config);
        tokio::spawn(async move {
            if let Err(e) = web_ui::start(r, a, al, sc, ss, se, bu, fw, None, config_port).await {
                warn!("Web UI: {e}");
            }
        });
    }

    // Optional token-budget proxy
    if let Some(bp) = parse_opt_port("--budget-port") {
        let b = Arc::clone(&shared_budget);
        tokio::spawn(async move {
            if let Err(e) = token_proxy::start(b, bp).await {
                warn!("Token proxy: {e}");
            }
        });
    }

    info!("protector-win started — listening on {PIPE_NAME}");
    info!("Web dashboard → http://127.0.0.1:{config_port}");

    // Named-pipe IPC server.
    //
    // To avoid a race where no instance is listening between accepting one
    // connection and creating the next (which makes concurrent shims get
    // ERROR_PIPE_BUSY and silently bypass enforcement), we create the *next*
    // listening instance immediately after a connection is accepted, before
    // handing the connected instance off to a task.
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;

        let make_server = || {
            ServerOptions::new()
                .access_inbound(true)
                .access_outbound(true)
                .create(PIPE_NAME)
        };

        let mut server = match make_server() {
            Ok(s) => s,
            Err(e) => anyhow::bail!("cannot create IPC pipe {PIPE_NAME}: {e}"),
        };

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutting down protector-win");
                    break;
                }
                res = server.connect() => {
                    if let Err(e) = res { warn!("pipe connect: {e}"); continue; }

                    // Hand off the connected instance; spin up the next listener
                    // right away so there is no unserved window.
                    let connected = std::mem::replace(&mut server, match make_server() {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("pipe re-create: {e}");
                            // Recreate after a short delay to avoid a tight loop.
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            match make_server() {
                                Ok(s) => s,
                                Err(e2) => anyhow::bail!("cannot recreate IPC pipe: {e2}"),
                            }
                        }
                    });

                    let td  = Arc::clone(&tool_db);
                    let tr  = Arc::clone(&tracker);
                    let rp  = Arc::clone(&reporter);
                    let al  = Arc::clone(&alert_store);
                    let tx  = event_tx.clone();
                    let hi  = Arc::clone(&history);
                    let si  = Arc::clone(&siem_sender);
                    let sec = Arc::clone(&secret_store);
                    tokio::spawn(handle_client(connected, td, tr, rp, al, tx, hi, si, sec));
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}

// ── Per-client handler ────────────────────────────────────────────────────────

#[cfg(windows)]
async fn handle_client(
    conn:     tokio::net::windows::named_pipe::NamedPipeServer,
    tool_db:  Arc<ToolDb>,
    tracker:  Arc<Mutex<ProcessTracker>>,
    reporter: Arc<Reporter>,
    alerts:   SharedAlertStore,
    events:   EventSender,
    history:  SharedHistory,
    siem:     Arc<Mutex<SiemSender>>,
    secrets:  SharedSecretStore,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

    // Trustworthy client PID from the kernel — NOT from the request payload.
    let client_pid = win_util::pipe_client_pid(&conn);

    let (reader, mut writer) = tokio::io::split(conn);
    let mut lines = TokioBufReader::new(reader).lines();

    // Read one JSON line = one ShimRequest
    let line = match lines.next_line().await {
        Ok(Some(l)) => l,
        _ => return,
    };

    let request: ShimRequest = match serde_json::from_str(&line) {
        Ok(r)  => r,
        Err(e) => {
            warn!("bad shim request: {e}");
            return;
        }
    };

    let response = process_request(
        &request, client_pid, &tool_db, &tracker, &reporter, &alerts, &events, &history, &siem, &secrets,
    );

    let json = serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"action":"exec_real"}"#.to_string()
    });
    let _ = writer.write_all(json.as_bytes()).await;
    let _ = writer.write_all(b"\n").await;
    let _ = writer.flush().await;
}

// ── Request processing (sync, called from async handler) ─────────────────────

fn process_request(
    req:        &ShimRequest,
    client_pid: Option<u32>,
    tool_db:    &ToolDb,
    tracker:    &Mutex<ProcessTracker>,
    reporter:   &Reporter,
    alerts:     &SharedAlertStore,
    events:     &EventSender,
    history:    &SharedHistory,
    siem:       &Mutex<SiemSender>,
    secrets:    &SharedSecretStore,
) -> ShimResponse {
    // SECURITY: use the kernel-provided client PID, never req.pid (which the
    // caller could forge to impersonate a Claude descendant).
    let pid = match client_pid {
        Some(p) => p,
        None => {
            // Cannot establish who is calling → do not run anything in the
            // daemon (no exec → no privilege escalation), just let the shim run
            // the tool unmonitored.  This should be vanishingly rare.
            warn!("cannot determine client PID for tool={} — passing through unmonitored", req.tool);
            return ShimResponse::ExecReal;
        }
    };

    debug!("shim request: tool={} client_pid={} (claimed={}) args={:?}",
        req.tool, pid, req.pid, req.args);

    // Check if caller is a Claude Code descendant.
    let is_agent_child = {
        let mut t = tracker.lock().unwrap();
        t.is_claude_descendant(pid)
    };
    if !is_agent_child {
        debug!("skip pid={} tool={} reason=not_descendant_of_claude", pid, req.tool);
        return ShimResponse::ExecReal;
    }

    // SECURITY: resolve the genuine tool binary ourselves (excluding the shim
    // dir).  We must never execute the argv[0] supplied over the pipe, and never
    // resolve through the shim dir (which would recurse).
    //
    // If the tool isn't present anywhere outside the shim dir, there's nothing
    // to monitor or run safely (the shim can't find it either) — pass through.
    let real_tool = match win_util::resolve_real_tool(&req.tool) {
        Some(p) => p,
        None => {
            debug!("no real binary for tool={} outside shim dir — passing through", req.tool);
            return ShimResponse::ExecReal;
        }
    };

    // The argv the daemon executes: argv[0] forced to the resolved real binary
    // so a poisoned argv[0] from the pipe can never be run.
    let exec_args: Vec<String> = {
        let mut a = req.args.clone();
        if a.is_empty() {
            a.push(real_tool.to_string_lossy().into_owned());
        } else {
            a[0] = real_tool.to_string_lossy().into_owned();
        }
        a
    };

    let cwd = if req.cwd.is_empty() { None } else { Some(PathBuf::from(&req.cwd)) };

    // ── Secret Proxy phase 1: file masking ────────────────────────────────────
    if matches!(req.tool.as_str(), "cat"|"head"|"tail"|"grep"|"egrep"|"diff"|"cp"|"mv") {
        let paths = secret_proxy::all_file_args(&req.args, cwd.as_deref());
        if let Some(spath) = paths.iter().find(|p| secret_proxy::is_secret_path(p)).cloned() {
            let mask_result = {
                let mut store = secrets.lock().unwrap();
                secret_proxy::mask_file(&spath, &mut store)
            };
            match mask_result {
                Ok((masked, count)) => {
                    info!("[secret-proxy] Masked {count} secret(s) from {}", spath.display());
                    let outcome = InspectOutcome::Alerted {
                        threat_code: "SECRET_MASKED".to_string(),
                        message: format!("Masked {count} secret(s) from {}", spath.display()),
                    };
                    emit_event(pid, &req.tool, &req.args, outcome, events, history);
                    return ShimResponse::Output { content: masked, exit_code: 0 };
                }
                Err(e) => {
                    debug!("[secret-proxy] mask_file error: {e}");
                    // Fall through to normal validation
                }
            }
        }
    }

    // ── Secret Proxy phase 2: curl/wget relay ─────────────────────────────────
    if matches!(req.tool.as_str(), "curl"|"wget") {
        if secret_proxy::args_have_tokens(&req.args) {
            // SECURITY: substituting REAL credentials into an outbound request
            // is an exfiltration risk if the destination is attacker-controlled.
            // Only do it for hosts on the explicit allowlist; otherwise pass the
            // request through unchanged (tokens, not real secrets, go out).
            if !relay_allowed(&req.args) {
                warn!("[secret-proxy] relay denied for {} — destination not in PROTECTOR_RELAY_ALLOWLIST", req.tool);
                emit_event(pid, &req.tool, &req.args,
                    InspectOutcome::Warned {
                        threat_code: "SECRET_RELAY_DENIED".to_string(),
                        message: "Outbound destination not allowlisted; real credentials NOT substituted".to_string(),
                    },
                    events, history);
                return ShimResponse::ExecReal;
            }

            info!("[secret-proxy] Relaying {} with real credentials", req.tool);
            let result = {
                let store = secrets.lock().unwrap();
                // Use exec_args so argv[0] is the resolved real binary, never the shim.
                secret_proxy::relay_to_output(&exec_args, &store)
            };
            let outcome = match &result {
                Ok(_)  => InspectOutcome::Alerted {
                    threat_code: "SECRET_RELAYED".to_string(),
                    message: format!("Token credentials substituted for {} request", req.tool),
                },
                Err(e) => {
                    warn!("[secret-proxy] relay failed: {e}");
                    InspectOutcome::Allowed
                }
            };
            emit_event(pid, &req.tool, &req.args, outcome, events, history);
            return match result {
                Ok(content) => ShimResponse::Output { content, exit_code: 0 },
                Err(_)      => ShimResponse::ExecReal,
            };
        }
    }

    // ── Normal validation ─────────────────────────────────────────────────────
    // Build a synthetic filename so ToolDb's ends_with("/<cmd>") check works.
    let fake_filename = format!("/{}", req.tool);
    let Some(action) = tool_db.find_action(&fake_filename, &req.args) else {
        debug!("skip tool={} args={:?} reason=no_matching_tool_rule", req.tool, req.args);
        return ShimResponse::ExecReal;
    };

    info!("Agent action intercepted: pid={} tool={} args={:?}", pid, action.name, req.args);

    // ctx.args uses exec_args so any daemon-side execution (mask/relay guards)
    // runs the resolved real binary, never the shim or a poisoned argv[0].
    let ctx = ValidationContext {
        pid,
        filename:    req.tool.clone(),
        args:        exec_args.clone(),
        working_dir: cwd,
    };

    match action.validate(&ctx) {
        ValidationResult::Allow => {
            info!("[{}] ALLOWED pid={}", action.name, pid);
            emit_event(pid, action.name, &req.args, InspectOutcome::Allowed, events, history);
            ShimResponse::ExecReal
        }
        ValidationResult::Warn(threat) => {
            reporter.warn(action.name, pid, &req.args, &threat);
            siem.lock().unwrap().send_warn(
                action.name, pid, &req.args, threat.code(), &threat.to_string());
            emit_event(pid, action.name, &req.args,
                InspectOutcome::Warned { threat_code: threat.code().to_string(), message: threat.to_string() },
                events, history);
            ShimResponse::ExecReal
        }
        ValidationResult::Block(threat) => {
            reporter.block(action.name, pid, &req.args, &threat);
            siem.lock().unwrap().send_block(
                action.name, pid, &req.args, threat.code(), &threat.to_string());
            emit_event(pid, action.name, &req.args,
                InspectOutcome::Blocked { threat_code: threat.code().to_string(), message: threat.to_string() },
                events, history);
            ShimResponse::Block { message: threat.to_string() }
        }
        ValidationResult::Alert { threat, rule } => {
            alerts.lock().unwrap().push(
                action.name.to_string(), rule.clone(),
                threat.code().to_string(), threat.to_string(),
                req.args.clone(), pid,
            );
            reporter.warn(action.name, pid, &req.args, &threat);
            siem.lock().unwrap().send_alert(
                action.name, pid, &req.args, threat.code(), &threat.to_string());
            emit_event(pid, action.name, &req.args,
                InspectOutcome::Alerted { threat_code: threat.code().to_string(), message: threat.to_string() },
                events, history);
            ShimResponse::ExecReal
        }
        ValidationResult::MaskedOutput { content, threat } => {
            reporter.warn(action.name, pid, &req.args, &threat);
            siem.lock().unwrap().send_alert(
                action.name, pid, &req.args, threat.code(), &threat.to_string());
            emit_event(pid, action.name, &req.args,
                InspectOutcome::Alerted {
                    threat_code: threat.code().to_string(),
                    message: threat.to_string(),
                },
                events, history);
            ShimResponse::Output { content, exit_code: 0 }
        }
    }
}

// ── Relay allowlist (anti-exfiltration) ───────────────────────────────────────

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
        return false; // no recognizable destination → don't risk substitution
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
                // host = up to the first '/', ':', '?', or '@' (strip userinfo)
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

// ── inspect subcommand ────────────────────────────────────────────────────────

async fn run_inspect() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe_name = event_bus::pipe_path();
        let conn = ClientOptions::new().open(&pipe_name)
            .map_err(|e| anyhow::anyhow!("Cannot connect to inspect pipe {pipe_name}: {e}\nIs protector-win running?"))?;

        let mut lines = BufReader::new(conn).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            println!("{line}");
        }
    }
    #[cfg(not(windows))]
    { anyhow::bail!("inspect subcommand is only supported on Windows in this binary"); }
    Ok(())
}
