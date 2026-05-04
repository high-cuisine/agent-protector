use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Ebpf};
use log::{debug, info, warn};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tokio::signal;

mod tool_db;
mod tracker;
mod validator;
mod validators;

use protector_common::ExecEvent;
use tool_db::ToolDb;
use tracker::ProcessTracker;
use validator::{ValidationContext, ValidationResult};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let tool_db = Arc::new(ToolDb::default());
    let tracker = Arc::new(Mutex::new(ProcessTracker::new()));

    info!("Protector started — monitoring Claude Code agent actions");

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
                    handle_event(event, &tool_db, &tracker);
                }

                guard.clear_ready();
            }
        }
    }

    Ok(())
}

fn handle_event(event: ExecEvent, tool_db: &ToolDb, tracker: &Mutex<ProcessTracker>) {
    let filename = c_str(&event.filename);
    let comm = c_str(&event.comm);

    debug!("execve pid={} comm={} file={}", event.pid, comm, filename);

    // Fast pre-filter: skip binaries we'd never watch
    if !looks_interesting(filename) {
        return;
    }

    let is_agent_child = {
        let mut t = tracker.lock().unwrap();
        t.is_claude_descendant(event.pid)
    };

    if !is_agent_child {
        return;
    }

    // Read full argv from /proc before the process disappears
    let Some(args) = read_cmdline(event.pid) else {
        return;
    };
    let cwd = read_cwd(event.pid);

    let Some(action) = tool_db.find_action(filename, &args) else {
        return;
    };

    info!(
        "Agent action intercepted: pid={} tool={} args={:?}",
        event.pid, action.name, args
    );

    // Freeze the process during validation to eliminate the race window
    send_signal(event.pid, libc::SIGSTOP);

    let ctx = ValidationContext {
        pid: event.pid,
        filename: filename.to_string(),
        args,
        working_dir: cwd,
    };

    match action.validate(&ctx) {
        ValidationResult::Allow => {
            info!("[{}] ALLOWED — resuming pid={}", action.name, event.pid);
            send_signal(event.pid, libc::SIGCONT);
        }
        ValidationResult::Warn { reason } => {
            warn!(
                "[{}] WARNING pid={} — {}\nResuming.",
                action.name, event.pid, reason
            );
            send_signal(event.pid, libc::SIGCONT);
        }
        ValidationResult::Block { reason } => {
            warn!(
                "[{}] BLOCKED pid={} — {}",
                action.name, event.pid, reason
            );
            // SIGKILL first, SIGCONT so the process can actually receive SIGKILL
            send_signal(event.pid, libc::SIGKILL);
            send_signal(event.pid, libc::SIGCONT);
        }
    }
}

/// Quick pre-filter: only pass events that could match something in ToolDb.
fn looks_interesting(filename: &str) -> bool {
    const WATCHED: &[&str] = &["git", "npm", "pip3", "pip", "curl", "wget", "docker", "kubectl"];
    WATCHED.iter().any(|w| {
        filename == *w
            || filename.ends_with(&format!("/{}", w))
    })
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
