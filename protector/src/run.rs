//! run.rs — `protector run -- <program> [args…]`
//!
//! Launches a program (typically `claude`) **as the protector-controlled
//! process itself**: it installs the seccomp user-notification filter on the
//! current process and then `execve`s the target, so the new program is under
//! full secret-substitution control from its very first syscall — no
//! kill/relaunch, no MITM-proxy coupling, and guaranteed in the agent process
//! tree the daemon watches.
//!
//! Because there is no `fork`, the filter install runs in normal process
//! context (allocation is fine), and the program is `execve`d by **absolute
//! path** so no userspace `open` happens between filter-install and exec.
//!
//! Best-effort: if the daemon socket isn't reachable or seccomp setup fails,
//! the program is still launched (without substitution) — `run` never blocks
//! the user from starting their tool.

#[cfg(target_os = "linux")]
pub fn exec(cmd: &[String]) -> ! {
    use std::ffi::CString;
    use std::os::fd::RawFd;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    if cmd.is_empty() {
        eprintln!("Usage: protector run -- <program> [args…]");
        std::process::exit(2);
    }

    let prog = match which(&cmd[0]) {
        Some(p) => p,
        None => {
            eprintln!("protector run: '{}' not found in PATH", cmd[0]);
            std::process::exit(127);
        }
    };

    // Best-effort seccomp handoff to the daemon.
    match UnixStream::connect(crate::seccomp_notify::sock_path()) {
        Ok(sock) => {
            if install_and_handoff(sock.as_raw_fd()) {
                eprintln!("[protector] launching '{}' under seccomp secret-substitution control", cmd[0]);
            } else {
                eprintln!("[protector] seccomp setup failed; launching '{}' unprotected", cmd[0]);
            }
            // Keep `sock` alive until after the handoff; it is closed inside
            // install_and_handoff (and again here on drop — harmless).
            let _ = sock;
        }
        Err(_) => {
            eprintln!(
                "[protector] daemon not reachable on {}; launching '{}' without substitution",
                crate::seccomp_notify::sock_path(),
                cmd[0]
            );
        }
    }

    // Replace this process with the target.  argv[0] stays the name the user
    // typed; the kernel loads the resolved absolute `prog`.
    let cprog = CString::new(prog.as_bytes()).unwrap_or_default();
    let cargs: Vec<CString> = cmd
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap_or_default())
        .collect();
    let mut argv: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    unsafe { libc::execv(cprog.as_ptr(), argv.as_ptr()) };

    let e = std::io::Error::last_os_error();
    eprintln!("protector run: exec '{prog}' failed: {e}");
    std::process::exit(127);

    // ── helpers (Linux) ──────────────────────────────────────────────────────

    fn install_and_handoff(sock_fd: RawFd) -> bool {
        use std::ffi::c_void;
        // SAFETY: no fork here, so normal process rules apply; every fd is closed.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return false;
            }
            let mut filter = build_filter();
            let prog = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            let lfd = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &prog as *const _ as *const c_void,
            );
            if lfd < 0 {
                return false;
            }
            send_fd(sock_fd, lfd as RawFd);
            libc::close(lfd as RawFd);
            libc::close(sock_fd);
            true
        }
    }

    fn trapped_open_syscalls() -> Vec<u32> {
        let mut v = vec![libc::SYS_openat as u32, libc::SYS_openat2 as u32];
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        v.push(libc::SYS_open as u32);
        v
    }

    fn build_filter() -> Vec<libc::sock_filter> {
        let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
        let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        };
        let ld_nr = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        let ret = (libc::BPF_RET | libc::BPF_K) as u16;

        let nrs = trapped_open_syscalls();
        let n = nrs.len();
        let mut prog = Vec::with_capacity(n + 3);
        prog.push(stmt(ld_nr, 0));
        for (i, nr) in nrs.iter().enumerate() {
            let pos = i + 1;
            let jt = (n + 2 - pos) as u8;
            prog.push(jeq(*nr, jt, 0));
        }
        prog.push(stmt(ret, libc::SECCOMP_RET_ALLOW));
        prog.push(stmt(ret, libc::SECCOMP_RET_USER_NOTIF));
        prog
    }

    unsafe fn send_fd(sock: RawFd, fd: RawFd) {
        use std::ffi::c_void;
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
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(&fd as *const RawFd, libc::CMSG_DATA(cmsg) as *mut RawFd, 1);
        libc::sendmsg(sock, &msg, 0);
    }

    fn which(prog: &str) -> Option<String> {
        let p = std::path::Path::new(prog);
        if p.is_absolute() {
            return p.is_file().then(|| prog.to_string());
        }
        if prog.contains('/') {
            let abs = std::env::current_dir().ok()?.join(prog);
            return abs.is_file().then(|| abs.to_string_lossy().into_owned());
        }
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let cand = dir.join(prog);
            if cand.is_file() {
                return Some(cand.to_string_lossy().into_owned());
            }
        }
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub fn exec(_cmd: &[String]) -> ! {
    eprintln!("protector run is only supported on Linux");
    std::process::exit(1);
}
