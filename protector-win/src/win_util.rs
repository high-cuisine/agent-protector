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

/// Read a process's full command line straight from its PEB.
///
/// Why this exists: Claude Code frequently runs under a *generic host* image
/// (e.g. `node.exe` for the npm install) whose **name** gives no hint that it
/// is Claude.  Matching on the image name alone (`claude*`) misses those, so
/// the daemon never recognises the agent and validates nothing.  The command
/// line — which contains the `claude-code` cli path — is the reliable signal.
///
/// Returns `None` if the process can't be opened or its memory can't be read
/// (access denied, already exited, cross-bitness edge cases).  Best-effort.
#[cfg(windows)]
pub fn process_command_line(pid: u32) -> Option<String> {
    use std::ffi::c_void;

    use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PEB, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_VM_READ, RTL_USER_PROCESS_PARAMETERS,
    };

    // SAFETY: every pointer handed to ReadProcessMemory is read-checked (the
    // returned byte count must equal the requested length), the handle is closed
    // on every path, and all structs are zero-initialised before being filled.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return None;
        }

        let read_mem = |addr: *const c_void, buf: *mut c_void, len: usize| -> bool {
            let mut got: usize = 0;
            ReadProcessMemory(handle, addr, buf, len, &mut got) != 0 && got == len
        };

        let result = (|| {
            // 1. Locate the PEB via NtQueryInformationProcess(ProcessBasicInformation).
            let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            let mut ret_len: u32 = 0;
            let status = NtQueryInformationProcess(
                handle,
                ProcessBasicInformation,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut ret_len,
            );
            if status != 0 || pbi.PebBaseAddress.is_null() {
                return None;
            }

            // 2. Read the PEB → ProcessParameters pointer.
            let mut peb: PEB = std::mem::zeroed();
            if !read_mem(
                pbi.PebBaseAddress as *const c_void,
                &mut peb as *mut _ as *mut c_void,
                std::mem::size_of::<PEB>(),
            ) || peb.ProcessParameters.is_null()
            {
                return None;
            }

            // 3. Read RTL_USER_PROCESS_PARAMETERS → CommandLine (UNICODE_STRING).
            let mut params: RTL_USER_PROCESS_PARAMETERS = std::mem::zeroed();
            if !read_mem(
                peb.ProcessParameters as *const c_void,
                &mut params as *mut _ as *mut c_void,
                std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>(),
            ) {
                return None;
            }

            let bytes = params.CommandLine.Length as usize; // UTF-16 byte length
            if bytes == 0 || params.CommandLine.Buffer.is_null() || bytes > 64 * 1024 {
                return None;
            }

            // 4. Read the UTF-16 command-line buffer itself.
            let mut buf: Vec<u16> = vec![0u16; bytes / 2];
            if !read_mem(
                params.CommandLine.Buffer as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                bytes,
            ) {
                return None;
            }
            Some(String::from_utf16_lossy(&buf))
        })();

        CloseHandle(handle);
        result
    }
}

#[cfg(not(windows))]
pub fn process_command_line(_pid: u32) -> Option<String> {
    None
}

// ── Privilege elevation (UAC) ─────────────────────────────────────────────────

/// Is the current process running with an elevated (administrator) token?
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: the token handle is closed on every path; the buffer matches the
    // size we declare to GetTokenInformation.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// If not already elevated, relaunch this exact process (same args) through the
/// shell with the `runas` verb — which raises the UAC prompt — then exit the
/// current, non-elevated instance.  Returns normally only when already elevated.
///
/// The Windows service path (LocalSystem) is already elevated, so this is a
/// no-op there; it only matters for interactive launches.
#[cfg(windows)]
pub fn ensure_elevated() {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::UI::Shell::ShellExecuteW;

    if is_elevated() {
        return;
    }

    let Ok(exe) = std::env::current_exe() else { return };

    // Re-quote argv (skip argv[0]) so paths with spaces survive the round-trip.
    let params = std::env::args()
        .skip(1)
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a })
        .collect::<Vec<_>>()
        .join(" ");

    let to_wide = |s: &std::ffi::OsStr| -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    };
    let wexe = to_wide(exe.as_os_str());
    let wverb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
    let wparams: Vec<u16> = params.encode_utf16().chain(std::iter::once(0)).collect();

    eprintln!("Requesting administrator privileges (UAC)…");

    // SAFETY: all string pointers are NUL-terminated and outlive the call.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wverb.as_ptr(),
            wexe.as_ptr(),
            if params.is_empty() { std::ptr::null() } else { wparams.as_ptr() },
            std::ptr::null(),
            1, // SW_NORMAL
        )
    };

    // ShellExecuteW returns a value > 32 on success.  If the user declined the
    // UAC prompt (or it failed), fall through so the caller can report the
    // missing-privilege error itself rather than silently exiting.
    if (result as isize) > 32 {
        std::process::exit(0);
    }
    eprintln!("Elevation was declined or failed — continuing without admin rights.");
}

#[cfg(not(windows))]
pub fn ensure_elevated() {}
