//! read_guard.rs — kernel-enforced read denial for sensitive files (Linux).
//!
//! The secret-masking proxy (`secret_proxy.rs`) only intercepts *known tools*
//! (cat/head/tail/…) by rewriting their stdout.  An agent that reads a secret
//! **in-process** — `python -c "open('.env').read()"`, `node -e "..."`, or any
//! custom binary — bypasses it entirely.  That makes tokenisation a defence
//! with a false sense of safety.
//!
//! This module closes that hole with fanotify `FAN_OPEN_PERM`: every `open()`
//! of a policy-protected path is gated by the kernel.  If the opener is a
//! Claude descendant, the open is **DENIED** (EPERM) regardless of which
//! program issues it.  The daemon's own reads (for the secret relay) are always
//! allowed, so legitimate masked viewing still works.
//!
//! It is **deny-only**: fanotify cannot substitute file contents.  Masked
//! `cat`/`head` output keeps coming from the tool-interception path (which
//! SIGKILLs the tool before it ever calls `open()`), while anything the agent
//! runs itself simply cannot read the raw bytes.
//!
//! Safety: a permission event MUST be answered or the opening process hangs
//! forever.  The event loop therefore never `unwrap()`s in the hot path and
//! **fails open** (ALLOW) on any uncertainty — it only ever DENIES when it has
//! positively identified a Claude descendant touching a marked file.

use std::sync::{Arc, Mutex};

use crate::data_policy::DataPolicy;
use crate::event_bus::{EventSender, SharedHistory};
use crate::tracker::ProcessTracker;

#[cfg(target_os = "linux")]
use crate::alert_store::SharedAlertStore;
#[cfg(target_os = "linux")]
use crate::siem::SiemSender;

/// Start the fanotify read-guard.  No-op (with a log line) when there are no
/// filesystem rules to protect, when fanotify is unavailable, or off Linux.
#[cfg(target_os = "linux")]
pub fn start(
    policy:  Arc<DataPolicy>,
    tracker: Arc<Mutex<ProcessTracker>>,
    events:  EventSender,
    history: SharedHistory,
    alerts:  SharedAlertStore,
    siem:    Arc<Mutex<SiemSender>>,
) {
    use std::ffi::CString;

    if policy.fs_rules().is_empty() {
        log::info!("[read-guard] no fblock/fmask paths in policy — read-guard disabled");
        return;
    }

    // FAN_CLASS_CONTENT is required for permission (allow/deny) decisions.
    let fan_fd = unsafe {
        libc::fanotify_init(
            (libc::FAN_CLOEXEC | libc::FAN_CLASS_CONTENT) as libc::c_uint,
            (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE) as libc::c_uint,
        )
    };
    if fan_fd < 0 {
        let e = std::io::Error::last_os_error();
        log::warn!(
            "[read-guard] fanotify_init failed ({e}); in-process secret reads are NOT blocked. \
             Needs root + CONFIG_FANOTIFY_ACCESS_PERMISSIONS."
        );
        return;
    }

    log::info!(
        "[read-guard] active — denying agent reads of {} protected path rule(s) via fanotify",
        policy.fs_rules().len()
    );

    // ── Marker thread: (re)mark concrete files to watch. ──────────────────────
    // fanotify marks are per-inode, so globs/new files are picked up on a timer.
    // Two sources:
    //   1. Absolute/home-anchored paths from policy fblock/fmask rules.
    //   2. Sensitive files (.env, *.pem, kubeconfig, …) inside each agent's
    //      working directory — this is what catches a project-local `.env`
    //      that a relative or `**/` policy pattern can't be marked from.
    {
        let policy  = Arc::clone(&policy);
        let tracker = Arc::clone(&tracker);
        std::thread::Builder::new()
            .name("read-guard-mark".into())
            .spawn(move || {
                let mut marked: std::collections::HashSet<std::path::PathBuf> =
                    std::collections::HashSet::new();
                loop {
                    let mut targets = concrete_protected_files(&policy);
                    targets.extend(sensitive_files_in_agent_cwds(&tracker));
                    targets.sort();
                    targets.dedup();

                    for path in targets {
                        if marked.contains(&path) {
                            continue;
                        }
                        let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else {
                            continue;
                        };
                        let rc = unsafe {
                            libc::fanotify_mark(
                                fan_fd,
                                libc::FAN_MARK_ADD,
                                libc::FAN_OPEN_PERM,
                                libc::AT_FDCWD,
                                c.as_ptr(),
                            )
                        };
                        if rc == 0 {
                            log::debug!("[read-guard] watching {}", path.display());
                            marked.insert(path);
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_secs(10));
                }
            })
            .ok();
    }

    // ── Event thread: answer every FAN_OPEN_PERM request. ─────────────────────
    std::thread::Builder::new()
        .name("read-guard-perm".into())
        .spawn(move || {
            event_loop(fan_fd, policy, tracker, events, history, alerts, siem);
        })
        .ok();
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn event_loop(
    fan_fd:  libc::c_int,
    _policy: Arc<DataPolicy>,
    tracker: Arc<Mutex<ProcessTracker>>,
    events:  EventSender,
    history: SharedHistory,
    alerts:  SharedAlertStore,
    siem:    Arc<Mutex<SiemSender>>,
) {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::time::{Duration, Instant};

    let daemon_pid = std::process::id();
    let meta_size = size_of::<libc::fanotify_event_metadata>();
    let mut buf = vec![0u8; 16 * 1024];

    // Coarse per-(pid,path) dedupe so a tight read loop doesn't flood alerts.
    let mut recent: HashMap<(u32, String), Instant> = HashMap::new();

    loop {
        let n = unsafe {
            libc::read(fan_fd, buf.as_mut_ptr() as *mut c_void, buf.len())
        };
        if n <= 0 {
            // EINTR/EAGAIN → retry; hard error → stop (marks remain, but no one
            // would answer perm events, so bail rather than hang the system).
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::warn!("[read-guard] fanotify read ended ({e}); read-guard stopping");
            return;
        }

        let mut offset = 0usize;
        while offset + meta_size <= n as usize {
            // SAFETY: bounds-checked above; metadata is POD.
            let meta = unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata,
                )
            };

            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                // ABI mismatch — can't safely walk the rest of the buffer.
                log::warn!("[read-guard] fanotify metadata version mismatch; stopping");
                return;
            }
            let event_len = meta.event_len as usize;
            if event_len < meta_size {
                break;
            }

            if meta.mask & libc::FAN_OPEN_PERM != 0 && meta.fd >= 0 {
                let pid = meta.pid as u32;

                // DENY only for a positively-identified Claude descendant.
                // Marks are placed solely on sensitive files, so any perm event
                // here is already about a protected path.
                let deny = pid != daemon_pid && {
                    let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
                    t.is_claude_descendant(pid)
                };

                respond(fan_fd, meta.fd, if deny { libc::FAN_DENY } else { libc::FAN_ALLOW });
                unsafe { libc::close(meta.fd) };

                if deny {
                    let path = std::fs::read_link(format!("/proc/self/fd/{}", meta.fd))
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "<unknown>".to_string());
                    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|_| "?".to_string());

                    let key = (pid, path.clone());
                    let now = Instant::now();
                    let fresh = recent
                        .get(&key)
                        .map(|t| now.duration_since(*t) > Duration::from_secs(3))
                        .unwrap_or(true);
                    if fresh {
                        recent.insert(key, now);
                        report_denied(&comm, pid, &path, &events, &history, &alerts, &siem);
                    }
                }
            } else if meta.fd >= 0 {
                // An event we didn't request: release the fd, no response needed.
                unsafe { libc::close(meta.fd) };
            }

            offset += event_len;
        }

        // Bound the dedupe map.
        if recent.len() > 4096 {
            recent.clear();
        }
    }
}

#[cfg(target_os = "linux")]
fn respond(fan_fd: libc::c_int, fd: libc::c_int, response: u32) {
    use std::ffi::c_void;
    let resp = libc::fanotify_response { fd, response };
    unsafe {
        libc::write(
            fan_fd,
            &resp as *const _ as *const c_void,
            std::mem::size_of::<libc::fanotify_response>(),
        );
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn report_denied(
    comm:    &str,
    pid:     u32,
    path:    &str,
    events:  &EventSender,
    history: &SharedHistory,
    alerts:  &SharedAlertStore,
    siem:    &Arc<Mutex<SiemSender>>,
) {
    use crate::event_bus::{record, now_ms, InspectEvent, InspectOutcome};

    const CODE: &str = "FS_READ_DENIED";
    let message = format!("Blocked read of {path} by {comm} (pid {pid}) — sensitive file");
    log::warn!("[read-guard] {message}");

    let ev = InspectEvent {
        ts_ms: now_ms(),
        pid,
        tool: comm.to_string(),
        args: vec![path.to_string()],
        outcome: InspectOutcome::Blocked {
            threat_code: CODE.to_string(),
            message: message.clone(),
        },
    };
    record(history, &ev);
    let _ = events.send(ev);

    if let Ok(mut a) = alerts.lock() {
        a.push(
            comm.to_string(),
            "read-guard".to_string(),
            CODE.to_string(),
            message.clone(),
            vec![path.to_string()],
            pid,
        );
    }
    if let Ok(mut s) = siem.lock() {
        s.send_block(comm, pid, &[path.to_string()], CODE, &message);
    }
}

/// Scan the working directory of every live Claude descendant for files that
/// `secret_proxy` treats as sensitive (`.env`, `*.pem`, kubeconfig, …) and
/// return them for marking.  This is how a project-local `.env` gets kernel
/// read-protection even though its policy pattern is relative / `**`-globbed.
/// Bounded in depth and count; skips heavy build/vendor dirs.
#[cfg(target_os = "linux")]
fn sensitive_files_in_agent_cwds(tracker: &Arc<Mutex<ProcessTracker>>) -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;

    const MAX_FILES: usize = 10_000;
    const MAX_DEPTH: usize = 6;
    const SKIP_DIRS: &[&str] =
        &[".git", "node_modules", "target", "vendor", "dist", "build", ".venv", "__pycache__"];

    let pids = {
        let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
        let _ = t.refresh_and_diff();
        t.claude_root_pids()
    };

    // Resolve each agent's cwd, de-duplicated.
    let mut roots: Vec<PathBuf> = pids
        .into_iter()
        .filter_map(|pid| std::fs::read_link(format!("/proc/{pid}/cwd")).ok())
        .collect();
    roots.sort();
    roots.dedup();

    let mut out: Vec<PathBuf> = Vec::new();
    for root in roots {
        let mut stack: Vec<(PathBuf, usize)> = vec![(root, 0)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > MAX_DEPTH || out.len() >= MAX_FILES {
                break;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else { continue };
                if ft.is_symlink() {
                    continue;
                }
                let p = entry.path();
                if ft.is_dir() {
                    let skip = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| SKIP_DIRS.contains(&n))
                        .unwrap_or(false);
                    if !skip {
                        stack.push((p, depth + 1));
                    }
                } else if ft.is_file() && crate::secret_proxy::is_secret_path(&p) {
                    out.push(p);
                    if out.len() >= MAX_FILES {
                        break;
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Expand every fs-rule glob to the concrete, existing **files** it currently
/// matches, so each can get a per-inode fanotify mark.  Bounded so a broad
/// pattern can never trigger a filesystem-wide walk.
#[cfg(target_os = "linux")]
fn concrete_protected_files(policy: &DataPolicy) -> Vec<std::path::PathBuf> {
    use std::path::{Path, PathBuf};

    const MAX_FILES: usize = 50_000;
    const MAX_DEPTH: usize = 12;

    let mut out: Vec<PathBuf> = Vec::new();

    for rule in policy.fs_rules() {
        let pattern = rule.expanded();

        // Base = longest prefix with no wildcard, trimmed to a directory.
        let first_glob = pattern.find('*').unwrap_or(pattern.len());
        let base = match pattern[..first_glob].rfind('/') {
            Some(i) if i > 0 => &pattern[..i],
            _ => pattern[..first_glob].trim_end_matches('/'),
        };

        // Refuse a root / empty base — that would walk the whole filesystem.
        if base.is_empty() || base == "/" {
            log::warn!("[read-guard] skipping over-broad rule '{}' (no bounded base dir)", rule.raw);
            continue;
        }

        let base = Path::new(base);

        // Literal file (no wildcard): mark it directly if it exists.
        if !pattern.contains('*') {
            if base.is_file() {
                out.push(base.to_path_buf());
            }
            continue;
        }

        // Otherwise walk the bounded base directory, matching the full rule.
        let mut stack: Vec<(PathBuf, usize)> = vec![(base.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > MAX_DEPTH || out.len() >= MAX_FILES {
                break;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let p = entry.path();
                // Don't follow symlinks (avoids loops and escaping the base).
                let Ok(ft) = entry.file_type() else { continue };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    stack.push((p, depth + 1));
                } else if ft.is_file() && rule.matches(&p) {
                    out.push(p);
                    if out.len() >= MAX_FILES {
                        break;
                    }
                }
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

// ── Non-Linux stub (the daemon is Linux-only; this keeps host checks happy) ──

#[cfg(not(target_os = "linux"))]
pub fn start(
    _policy:  Arc<DataPolicy>,
    _tracker: Arc<Mutex<ProcessTracker>>,
    _events:  EventSender,
    _history: SharedHistory,
    _alerts:  Arc<Mutex<crate::alert_store::AlertStore>>,
    _siem:    Arc<Mutex<crate::siem::SiemSender>>,
) {
}
