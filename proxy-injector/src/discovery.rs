/// Process-discovery layer.
/// On Linux reads /proc, on macOS uses pgrep + lsof (always available).
use std::path::PathBuf;

/// A discovered Claude Code process.
#[derive(Debug, Clone)]
pub struct ClaudeInstance {
    pub pid: u32,
    /// Absolute path to the claude binary (version-specific symlink target).
    pub exe: PathBuf,
    /// Working directory the instance is running in.
    pub cwd: PathBuf,
}

/// Return all running Claude Code processes.
pub fn scan() -> Vec<ClaudeInstance> {
    let pids = find_pids();
    pids.into_iter().filter_map(instance_from_pid).collect()
}

// ─── PID discovery ────────────────────────────────────────────────────────────

/// Collect PIDs of processes whose executable name is exactly "claude".
fn find_pids() -> Vec<u32> {
    #[cfg(target_os = "linux")]
    return find_pids_linux();
    #[cfg(not(target_os = "linux"))]
    return find_pids_pgrep();
}

#[cfg(target_os = "linux")]
fn find_pids_linux() -> Vec<u32> {
    use std::fs;
    let Ok(dir) = fs::read_dir("/proc") else { return vec![] };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| is_claude_pid_linux(pid))
        .collect()
}

#[cfg(target_os = "linux")]
fn is_claude_pid_linux(pid: u32) -> bool {
    use std::fs;
    // Fast path: /proc/<pid>/comm holds the 15-char process name.
    if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) {
        if comm.trim() == "claude" {
            return true;
        }
    }
    // Slow path: full cmdline (catches "node /path/to/claude …" wrappers).
    if let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) {
        let line = String::from_utf8_lossy(&raw);
        if line.contains("claude") && line.contains("anthropic") {
            return true;
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn find_pids_pgrep() -> Vec<u32> {
    // pgrep -x claude  →  exact name match, one PID per line.
    let output = std::process::Command::new("pgrep")
        .args(["-x", "claude"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect()
        }
        _ => vec![],
    }
}

// ─── Per-instance info ────────────────────────────────────────────────────────

fn instance_from_pid(pid: u32) -> Option<ClaudeInstance> {
    let exe = resolve_exe(pid)?;
    let cwd = resolve_cwd(pid)?;
    Some(ClaudeInstance { pid, exe, cwd })
}

// ── exe ──────────────────────────────────────────────────────────────────────

fn resolve_exe(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        resolve_exe_macos(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn resolve_exe_macos(pid: u32) -> Option<PathBuf> {
    // proc_pidpath(2) — fills a PROC_PIDPATHINFO_MAXSIZE buffer with the exe path.
    // Available via libc on macOS.
    use std::ffi::CStr;
    const MAXSIZE: usize = 4096;
    let mut buf = vec![0u8; MAXSIZE];
    let ret = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_void,
            MAXSIZE as u32,
        )
    };
    if ret <= 0 {
        return None;
    }
    let s = CStr::from_bytes_until_nul(&buf).ok()?.to_str().ok()?;
    Some(PathBuf::from(s))
}

// ── cwd ──────────────────────────────────────────────────────────────────────

fn resolve_cwd(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        resolve_cwd_macos(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn resolve_cwd_macos(pid: u32) -> Option<PathBuf> {
    // PROC_PIDVNODEPATHINFO fills a proc_vnodepathinfo struct where
    // pvi_cdir.vip_path contains the current working directory.
    // We use the libc binding via a raw syscall wrapper.
    // proc_pidinfo constants from <sys/proc_info.h>
    const PROC_PIDVNODEPATHINFO: libc::c_int = 9;

    // The struct layout: two vnode_info_path (each 720 bytes).
    // vnode_info_path = vnode_info (32 bytes) + char path[MAXPATHLEN=1024]
    // So each vnode_info_path = 32 + 1024 = 1056 bytes → total = 2112 bytes.
    // We use a plain byte buffer and extract the path manually.
    const VNODE_INFO_SIZE: usize = 32;
    const MAXPATHLEN: usize = 1024;
    const VNODE_INFO_PATH_SIZE: usize = VNODE_INFO_SIZE + MAXPATHLEN;
    const STRUCT_SIZE: usize = VNODE_INFO_PATH_SIZE * 2;  // pvi_cdir + pvi_rdir

    let mut buf = vec![0u8; STRUCT_SIZE];
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            PROC_PIDVNODEPATHINFO,
            0,
            buf.as_mut_ptr() as *mut libc::c_void,
            STRUCT_SIZE as libc::c_int,
        )
    };
    if ret < STRUCT_SIZE as libc::c_int {
        // Fall back to lsof for older kernels.
        return resolve_cwd_lsof(pid);
    }
    // pvi_cdir starts at offset 0; its path starts at offset VNODE_INFO_SIZE.
    let path_bytes = &buf[VNODE_INFO_SIZE..VNODE_INFO_SIZE + MAXPATHLEN];
    let end = path_bytes.iter().position(|&b| b == 0).unwrap_or(MAXPATHLEN);
    let path_str = std::str::from_utf8(&path_bytes[..end]).ok()?;
    if path_str.is_empty() {
        return resolve_cwd_lsof(pid);
    }
    Some(PathBuf::from(path_str))
}

#[cfg(target_os = "macos")]
fn resolve_cwd_lsof(pid: u32) -> Option<PathBuf> {
    // lsof -a -d cwd -p <pid> -Fn  →  prints "n<path>" for cwd fd.
    let out = std::process::Command::new("lsof")
        .args(["-a", "-d", "cwd", "-p", &pid.to_string(), "-Fn"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix('n') {
            return Some(PathBuf::from(path));
        }
    }
    None
}
