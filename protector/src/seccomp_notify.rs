//! seccomp_notify.rs — content substitution for in-process secret reads (Linux).
//!
//! `read_guard.rs` (fanotify) can only **deny** a read; it cannot hand the
//! agent masked bytes.  This module does the substitution: the launcher
//! (`proxy-injector`) installs a seccomp filter that traps `open`/`openat`/
//! `openat2` with `SECCOMP_RET_USER_NOTIF` on the agent process tree and passes
//! the resulting listener fd to this daemon over a Unix socket (SCM_RIGHTS).
//!
//! For every trapped open the supervisor:
//!   1. reads the target path from the agent's `/proc/<pid>/mem`,
//!   2. if it's a policy-sensitive path, masks the real file into a `memfd`
//!      (never touches disk) and **injects that fd** as the syscall's result
//!      via `SECCOMP_IOCTL_NOTIF_ADDFD` (FLAG_SEND) — the agent reads tokens;
//!   3. otherwise responds `CONTINUE` so the real open proceeds untouched.
//!
//! Failsafes:
//!   * Any error while handling a sensitive open → respond `ENOENT` (the agent
//!     gets a clean error, never hangs, never sees real bytes).
//!   * If this daemon dies, the kernel auto-fails outstanding/again traps with
//!     `ENOSYS` once the listener fd closes — the agent still never hangs.
//!   * Oversized files are not substituted (bounded handler time) → `ENOENT`.
//!
//! Known limitation: `CONTINUE` on non-sensitive paths has the documented
//! seccomp-notify TOCTOU window (the agent could rewrite the path pointer after
//! we classify).  That only risks a *non*-sensitive verdict being raced; for
//! the agent threat model it is a far higher bar than `python -c open('.env')`.

#![cfg(target_os = "linux")]

use std::ffi::c_void;
use std::mem::size_of;
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::alert_store::SharedAlertStore;
use crate::data_policy::DataPolicy;
use crate::event_bus::{now_ms, record, EventSender, InspectEvent, InspectOutcome, SharedHistory};
use crate::secret_proxy::{self, SharedSecretStore};
use crate::siem::SiemSender;

/// Largest file we will read+mask inline (keeps each notification fast).
const MAX_MASK_BYTES: u64 = 4 * 1024 * 1024;

/// Unix socket the launcher sends seccomp listener fds to.
pub fn sock_path() -> String {
    std::env::var("PROTECTOR_SECCOMP_SOCK")
        .unwrap_or_else(|_| "/run/protector-seccomp.sock".to_string())
}

// ── ioctl number construction (asm-generic _IOC encoding) ─────────────────────

const SECCOMP_IOC_MAGIC: u64 = '!' as u64;
fn ioc(dir: u64, nr: u64, size: usize) -> u64 {
    (dir << 30) | (SECCOMP_IOC_MAGIC << 8) | nr | ((size as u64) << 16)
}
fn req_recv() -> u64 { ioc(3, 0, size_of::<libc::seccomp_notif>()) }       // _IOWR
fn req_send() -> u64 { ioc(3, 1, size_of::<libc::seccomp_notif_resp>()) }  // _IOWR
fn req_id_valid() -> u64 { ioc(1, 2, size_of::<u64>()) }                   // _IOW
fn req_addfd() -> u64 { ioc(1, 3, size_of::<libc::seccomp_notif_addfd>()) } // _IOW

unsafe fn sec_ioctl(lfd: RawFd, request: u64, arg: *mut c_void) -> libc::c_long {
    libc::syscall(libc::SYS_ioctl, lfd as libc::c_long, request as libc::c_long, arg)
}

// ── Public entry point ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn start(
    policy:  Arc<DataPolicy>,
    secrets: SharedSecretStore,
    events:  EventSender,
    history: SharedHistory,
    alerts:  SharedAlertStore,
    siem:    Arc<Mutex<SiemSender>>,
) {
    let path = sock_path();
    let _ = std::fs::remove_file(&path);
    let listener = match std::os::unix::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("[seccomp] cannot bind {path}: {e}; content substitution disabled");
            return;
        }
    };
    // The daemon runs as root but the launcher may relaunch the agent as the
    // unprivileged user; let it connect.  Only an fd is passed in (validated by
    // the kernel as a real fd), so a world-connectable socket is acceptable here.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
    }
    log::info!("[seccomp] listening for agent seccomp handoffs on {path}");

    std::thread::Builder::new()
        .name("seccomp-accept".into())
        .spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let Some(lfd) = (unsafe { recv_fd(conn.as_raw_fd()) }) else {
                    log::warn!("[seccomp] handoff carried no listener fd");
                    continue;
                };
                log::info!("[seccomp] received listener fd for an agent process tree");
                let p  = Arc::clone(&policy);
                let s  = Arc::clone(&secrets);
                let ev = events.clone();
                let hi = Arc::clone(&history);
                let al = Arc::clone(&alerts);
                let si = Arc::clone(&siem);
                std::thread::Builder::new()
                    .name("seccomp-supervise".into())
                    .spawn(move || supervise(lfd, p, s, ev, hi, al, si))
                    .ok();
            }
        })
        .ok();
}

// ── Per-agent supervisor loop ─────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn supervise(
    lfd:     RawFd,
    policy:  Arc<DataPolicy>,
    secrets: SharedSecretStore,
    events:  EventSender,
    history: SharedHistory,
    alerts:  SharedAlertStore,
    siem:    Arc<Mutex<SiemSender>>,
) {
    loop {
        // Wait for a notification, but wake every 5s so a dead listener (POLLHUP)
        // is noticed and the thread can exit instead of blocking forever.
        let mut pfd = libc::pollfd { fd: lfd, events: libc::POLLIN, revents: 0 };
        let pr = unsafe { libc::poll(&mut pfd, 1, 5000) };
        if pr < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if pr == 0 {
            continue; // timeout, just loop (liveness)
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            break; // agent tree gone → tear down
        }

        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        let rc = unsafe { sec_ioctl(lfd, req_recv(), &mut req as *mut _ as *mut c_void) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) | Some(libc::ENOENT) => continue, // retry / target vanished
                _ => break,
            }
        }

        handle(lfd, &req, &policy, &secrets, &events, &history, &alerts, &siem);
    }
    unsafe { libc::close(lfd) };
    log::info!("[seccomp] supervisor for one agent tree exited");
}

#[allow(clippy::too_many_arguments)]
fn handle(
    lfd:     RawFd,
    req:     &libc::seccomp_notif,
    policy:  &DataPolicy,
    secrets: &SharedSecretStore,
    events:  &EventSender,
    history: &SharedHistory,
    alerts:  &SharedAlertStore,
    siem:    &Arc<Mutex<SiemSender>>,
) {
    let pid = req.pid;

    // Resolve the path the agent is trying to open.  If anything is off, let the
    // real syscall proceed (CONTINUE) — these are non-sensitive by assumption.
    let path = match resolve_target_path(req) {
        Some(p) => p,
        None => return respond_continue(lfd, req.id),
    };

    let sensitive =
        policy.find_fs_rule(&path).is_some() || secret_proxy::is_secret_path(&path);
    if !sensitive {
        return respond_continue(lfd, req.id);
    }

    // Bound handler time: don't read/mask very large files.
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(u64::MAX) > MAX_MASK_BYTES {
        return respond_errno(lfd, req.id, libc::ENOENT);
    }

    // Mask the real file into memory and store tokens in the vault.
    let (masked, count) = {
        let mut store = secrets.lock().unwrap_or_else(|e| e.into_inner());
        match secret_proxy::mask_file(&path, &mut store) {
            Ok(v) => v,
            Err(_) => return respond_errno(lfd, req.id, libc::ENOENT),
        }
    };

    // Back the masked content with an anonymous memfd and inject it as the
    // syscall result.  ADDFD with FLAG_SEND atomically completes the notify.
    match inject_memfd(lfd, req.id, masked.as_bytes()) {
        Ok(()) => report_substituted(&path, pid, count, events, history, alerts, siem),
        Err(_) => respond_errno(lfd, req.id, libc::ENOENT),
    }
}

// ── Path resolution from the trapped syscall ──────────────────────────────────

fn resolve_target_path(req: &libc::seccomp_notif) -> Option<PathBuf> {
    let pid = req.pid;
    let (dirfd, path_ptr) = match req.data.nr as libc::c_long {
        libc::SYS_openat | libc::SYS_openat2 => (req.data.args[0] as i32, req.data.args[1]),
        // SYS_open only exists on arches that aren't openat-only.
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        libc::SYS_open => (libc::AT_FDCWD, req.data.args[0]),
        _ => return None,
    };

    let raw = read_proc_mem_cstr(pid, path_ptr)?;
    let p = Path::new(&raw);
    if p.is_absolute() {
        return Some(normalize(p));
    }

    // Relative: resolve against the agent's cwd or the dir referred to by dirfd.
    let base = if dirfd == libc::AT_FDCWD {
        std::fs::read_link(format!("/proc/{pid}/cwd")).ok()?
    } else {
        std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()?
    };
    Some(normalize(&base.join(p)))
}

/// Lexical normalisation (resolve `.`/`..`) without touching the filesystem.
fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => { out.pop(); }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Read a NUL-terminated string of up to PATH_MAX bytes from another process.
fn read_proc_mem_cstr(pid: u32, addr: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 4096];
    let n = f.read(&mut buf).ok()?;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

// ── Notification responses ────────────────────────────────────────────────────

fn respond_continue(lfd: RawFd, id: u64) {
    let resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    unsafe { sec_ioctl(lfd, req_send(), &resp as *const _ as *mut c_void) };
}

fn respond_errno(lfd: RawFd, id: u64, errno: libc::c_int) {
    let resp = libc::seccomp_notif_resp { id, val: 0, error: -errno, flags: 0 };
    unsafe { sec_ioctl(lfd, req_send(), &resp as *const _ as *mut c_void) };
}

/// Create an in-memory file holding `content` and inject it into the agent as
/// the result of the trapped open (FLAG_SEND completes the notification).
fn inject_memfd(lfd: RawFd, id: u64, content: &[u8]) -> std::io::Result<()> {
    let name = b"protector-masked\0";
    let mfd = unsafe { libc::memfd_create(name.as_ptr() as *const libc::c_char, libc::MFD_CLOEXEC) };
    if mfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Write the masked bytes, then rewind so the agent reads from offset 0.
    let mut off = 0usize;
    while off < content.len() {
        let w = unsafe {
            libc::write(mfd, content[off..].as_ptr() as *const c_void, content.len() - off)
        };
        if w <= 0 {
            unsafe { libc::close(mfd) };
            return Err(std::io::Error::last_os_error());
        }
        off += w as usize;
    }
    unsafe { libc::lseek(mfd, 0, libc::SEEK_SET) };

    let addfd = libc::seccomp_notif_addfd {
        id,
        flags: libc::SECCOMP_ADDFD_FLAG_SEND as u32,
        srcfd: mfd as u32,
        newfd: 0,
        newfd_flags: 0,
    };
    let rc = unsafe { sec_ioctl(lfd, req_addfd(), &addfd as *const _ as *mut c_void) };
    unsafe { libc::close(mfd) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ── SCM_RIGHTS: receive a single fd over a Unix socket ────────────────────────

unsafe fn recv_fd(sock: RawFd) -> Option<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut c_void,
        iov_len: 1,
    };
    let mut cmsgbuf = [0u8; 64];
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsgbuf.len() as _;

    let n = libc::recvmsg(sock, &mut msg, 0);
    if n < 0 {
        return None;
    }
    let cmsg = libc::CMSG_FIRSTHDR(&msg);
    if cmsg.is_null()
        || (*cmsg).cmsg_level != libc::SOL_SOCKET
        || (*cmsg).cmsg_type != libc::SCM_RIGHTS
    {
        return None;
    }
    let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd);
    if fd < 0 { None } else { Some(fd) }
}

// ── Telemetry ─────────────────────────────────────────────────────────────────

fn report_substituted(
    path:    &Path,
    pid:     u32,
    count:   usize,
    events:  &EventSender,
    history: &SharedHistory,
    alerts:  &SharedAlertStore,
    siem:    &Arc<Mutex<SiemSender>>,
) {
    const CODE: &str = "SECRET_SUBSTITUTED";
    let p = path.display().to_string();
    let message = format!("Substituted masked content ({count} secret(s)) for in-process read of {p}");
    log::info!("[seccomp] {message}");

    let ev = InspectEvent {
        ts_ms: now_ms(),
        pid,
        tool: "seccomp".to_string(),
        args: vec![p.clone()],
        outcome: InspectOutcome::Alerted {
            threat_code: CODE.to_string(),
            message: message.clone(),
        },
    };
    record(history, &ev);
    let _ = events.send(ev);

    if let Ok(mut a) = alerts.lock() {
        a.push(
            "seccomp".to_string(),
            "secret-substitute".to_string(),
            CODE.to_string(),
            message.clone(),
            vec![p.clone()],
            pid,
        );
    }
    if let Ok(mut s) = siem.lock() {
        s.send_alert("seccomp", pid, &[p], CODE, &message);
    }
}
