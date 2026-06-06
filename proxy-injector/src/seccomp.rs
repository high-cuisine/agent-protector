//! seccomp.rs — install a seccomp user-notification filter on the relaunched
//! Claude process tree and hand the listener fd to the protector daemon.
//!
//! Flow (per relaunched agent):
//!   * parent: connect a Unix socket to the daemon and pre-build the BPF filter
//!     (must exist before `fork`, so the child can reference it COW-safely);
//!   * child (`pre_exec`, after fork / before execve):
//!       1. `PR_SET_NO_NEW_PRIVS` (required for unprivileged seccomp, and makes
//!          the filter survive execve + be inherited by every descendant),
//!       2. install the filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` → fd,
//!       3. send that fd to the daemon over SCM_RIGHTS, then close both fds.
//!
//! The daemon then virtualises sensitive `open`s for the whole tree.  If the
//! daemon isn't listening, `prepare()` returns `None` and the agent launches
//! normally (fanotify read-guard still applies) — never blocked by us.

#[cfg(target_os = "linux")]
use std::ffi::c_void;
use std::os::fd::RawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

pub fn sock_path() -> String {
    std::env::var("PROTECTOR_SECCOMP_SOCK")
        .unwrap_or_else(|_| "/run/protector-seccomp.sock".to_string())
}

/// Held by the parent across `spawn()` so the socket and the filter program stay
/// alive while the child references them in `pre_exec`.
#[cfg(target_os = "linux")]
pub struct Handoff {
    sock:   UnixStream,
    filter: Vec<libc::sock_filter>,
}

#[cfg(target_os = "linux")]
impl Handoff {
    pub fn sock_fd(&self) -> RawFd { self.sock.as_raw_fd() }
    /// Pointer passed to the child as `usize` (raw pointers aren't `Send`).
    pub fn filter_addr(&self) -> usize { self.filter.as_ptr() as usize }
    pub fn filter_len(&self) -> u16 { self.filter.len() as u16 }
}

/// Connect to the daemon and prepare the filter.  `None` ⇒ no daemon ⇒ skip.
#[cfg(target_os = "linux")]
pub fn prepare() -> Option<Handoff> {
    let sock = UnixStream::connect(sock_path()).ok()?;
    Some(Handoff { sock, filter: build_filter() })
}

#[cfg(not(target_os = "linux"))]
pub fn prepare() -> Option<()> { None }

/// Syscall numbers whose `open` we trap.  `SYS_open` doesn't exist on arches
/// that only have `openat` (aarch64, riscv64), so it's conditional.
#[cfg(target_os = "linux")]
fn trapped_open_syscalls() -> Vec<u32> {
    let mut v = vec![libc::SYS_openat as u32, libc::SYS_openat2 as u32];
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    v.push(libc::SYS_open as u32);
    v
}

/// Build a classic-BPF program: trap the open syscalls with USER_NOTIF, allow
/// everything else.  Jump offsets are computed so the program stays correct for
/// any number of trapped syscalls.
#[cfg(target_os = "linux")]
fn build_filter() -> Vec<libc::sock_filter> {
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jeq  = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16, jt, jf, k,
    };
    let ld_nr = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16; // seccomp_data.nr @ off 0
    let ret   = (libc::BPF_RET | libc::BPF_K) as u16;

    let nrs = trapped_open_syscalls();
    let n = nrs.len();

    // Layout: [0]=load nr, [1..=n]=one jeq per syscall, [n+1]=ALLOW, [n+2]=NOTIF.
    // A matching jeq jumps forward to the NOTIF return; non-matches fall through
    // and the final fall-through hits ALLOW.
    let mut prog = Vec::with_capacity(n + 3);
    prog.push(stmt(ld_nr, 0));
    for (i, nr) in nrs.iter().enumerate() {
        let pos = i + 1;                  // this instruction's index
        let jt = (n + 2 - pos) as u8;     // distance to the NOTIF instruction
        prog.push(jeq(*nr, jt, 0));
    }
    prog.push(stmt(ret, libc::SECCOMP_RET_ALLOW));
    prog.push(stmt(ret, libc::SECCOMP_RET_USER_NOTIF));
    prog
}

/// Runs inside the freshly-forked child, before execve.  Best-effort: on any
/// failure it simply returns so the agent still launches (unprotected by
/// substitution, but fanotify deny still applies) — we never block the agent.
///
/// # Safety
/// Must be async-signal-safe: only raw syscalls, no allocation, no locks.
#[cfg(target_os = "linux")]
pub unsafe fn child_install(sock_fd: RawFd, filter_addr: usize, filter_len: u16) {
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return;
    }
    let prog = libc::sock_fprog {
        len:    filter_len,
        filter: filter_addr as *mut libc::sock_filter,
    };
    let lfd = libc::syscall(
        libc::SYS_seccomp,
        libc::SECCOMP_SET_MODE_FILTER,
        libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
        &prog as *const _ as *const c_void,
    );
    if lfd < 0 {
        return;
    }
    send_fd(sock_fd, lfd as RawFd);
    libc::close(lfd as RawFd);
    libc::close(sock_fd);
}

/// Send a single fd to `sock` via SCM_RIGHTS.  Async-signal-safe.
#[cfg(target_os = "linux")]
unsafe fn send_fd(sock: RawFd, fd: RawFd) {
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

    let cmsg = libc::CMSG_FIRSTHDR(&msg);
    if cmsg.is_null() {
        return;
    }
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
    (*cmsg).cmsg_len = libc::CMSG_LEN(size_of_fd()) as _;
    std::ptr::copy_nonoverlapping(&fd as *const RawFd, libc::CMSG_DATA(cmsg) as *mut RawFd, 1);

    libc::sendmsg(sock, &msg, 0);
}

#[cfg(target_os = "linux")]
fn size_of_fd() -> u32 {
    std::mem::size_of::<RawFd>() as u32
}
