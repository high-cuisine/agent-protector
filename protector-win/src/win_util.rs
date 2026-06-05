//! Windows security helpers shared by the daemon.
//!
//! Two jobs, both security-critical:
//!   1. Determine the PID of the process on the other end of a named pipe from
//!      the *kernel*, never from the request payload (which is attacker-controlled).
//!   2. Resolve the real tool binary by name, excluding the shim directory, so
//!      the daemon never executes an attacker-supplied argv[0] and never
//!      recurses back into a shim.

use std::path::PathBuf;

/// Directories the daemon must never execute tools from (its own install dir
/// and the shim dir), to avoid recursion and to ignore a poisoned argv[0].
fn excluded_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());          // install dir (daemon)
            dirs.push(parent.join("shim"));           // shim dir (setup layout)
        }
    }
    // Absolute fallback matching setup.rs default install layout.
    dirs.push(PathBuf::from(r"C:\Program Files\Protector"));
    dirs.push(PathBuf::from(r"C:\Program Files\Protector\shim"));
    dirs
}

fn same_dir(a: &std::path::Path, b: &std::path::Path) -> bool {
    // Case-insensitive comparison (Windows paths are case-insensitive).
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

/// Resolve the genuine executable for `tool` by scanning PATH, skipping the
/// shim/install directories.  Returns the absolute path, or `None` if not found.
///
/// This is the ONLY value the daemon should ever pass to `Command::new` — never
/// the argv[0] sent over the pipe.
pub fn resolve_real_tool(tool: &str) -> Option<PathBuf> {
    let exclude = excluded_dirs();
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if exclude.iter().any(|e| same_dir(e, &dir)) {
            continue;
        }
        for cand in [
            format!("{tool}.exe"),
            format!("{tool}.cmd"),
            format!("{tool}.bat"),
            tool.to_string(),
        ] {
            let p = dir.join(cand);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// Get the client process id of a connected named-pipe server end, straight
/// from the kernel.  This is trustworthy, unlike any PID in the request body.
#[cfg(windows)]
pub fn pipe_client_pid<H: std::os::windows::io::AsRawHandle>(server: &H) -> Option<u32> {
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let handle = server.as_raw_handle();
    let mut pid: u32 = 0;
    // SAFETY: `handle` is a valid, connected named-pipe handle owned by `server`.
    let ok = unsafe { GetNamedPipeClientProcessId(handle as _, &mut pid) };
    if ok != 0 && pid != 0 { Some(pid) } else { None }
}

#[cfg(not(windows))]
pub fn pipe_client_pid<H>(_server: &H) -> Option<u32> {
    None
}
