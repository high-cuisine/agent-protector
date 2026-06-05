//! protector-win shim — transparent wrapper for watched tools.
//!
//! Installed as `git.exe`, `psql.exe`, etc. in a directory placed first in
//! PATH.  On each invocation it:
//!   1. Detects its own tool name from the exe filename stem.
//!   2. Sends a request to the protector-win daemon over a named pipe.
//!   3. Acts on the response:
//!      - ExecReal  → exec the real tool (found in PATH minus the shim dir)
//!      - Block     → print error to stderr, exit 1
//!      - Output    → print content to stdout, exit with given code
//!   4. Falls back to ExecReal if the daemon is not running.

use std::io::{Read, Write};
use std::path::PathBuf;

const PIPE_NAME: &str = r"\\.\pipe\protector-win";

// ── IPC types (must match protector-win/src/ipc.rs) ──────────────────────────

#[derive(serde::Serialize)]
struct ShimRequest<'a> {
    tool: &'a str,
    args: Vec<String>,
    cwd:  String,
    pid:  u32,
}

#[derive(serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum ShimResponse {
    ExecReal,
    Block  { message: String },
    Output { content: String, exit_code: i32 },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let exe = std::env::current_exe().expect("cannot determine own exe");
    let shim_dir = exe.parent().expect("exe has no parent dir").to_path_buf();

    let tool_name = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("cannot determine tool name from exe filename");

    let args: Vec<String> = std::env::args().collect();
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_default();
    let pid = std::process::id();

    let request = ShimRequest { tool: tool_name, args: args.clone(), cwd, pid };

    // Talk to the daemon on a worker thread with an overall deadline so a hung
    // or crashed daemon can never freeze the wrapped tool indefinitely.
    let json = serde_json::to_string(&request).unwrap_or_default();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(try_daemon(&json));
    });

    let outcome = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(res) => res,
        Err(_) => {
            // Timed out waiting for the daemon — fail open (run the tool) so the
            // user is never blocked by an unresponsive daemon.
            eprintln!("[PROTECTOR]: daemon timeout — running '{tool_name}' unmonitored");
            Err(())
        }
    };

    match outcome {
        Ok(ShimResponse::ExecReal) => exec_real(tool_name, &args[1..], &shim_dir),
        Ok(ShimResponse::Block { message }) => {
            eprintln!("[PROTECTOR BLOCKED]: {message}");
            std::process::exit(1);
        }
        Ok(ShimResponse::Output { content, exit_code }) => {
            print!("{content}");
            std::process::exit(exit_code);
        }
        Err(()) => {
            // Daemon not running / unreachable — pass through transparently.
            exec_real(tool_name, &args[1..], &shim_dir);
        }
    }
}

// ── Daemon communication ──────────────────────────────────────────────────────

/// Connect to the daemon, send the (pre-serialized) request, read one response
/// line.  Returns `Err(())` for any failure so the caller can fail open.
///
/// ERROR_PIPE_BUSY (231) means all server instances are momentarily occupied;
/// we retry a few times rather than silently bypassing enforcement.
fn try_daemon(json: &str) -> Result<ShimResponse, ()> {
    const ERROR_PIPE_BUSY: i32 = 231;

    let mut pipe = None;
    for attempt in 0..20 {
        match std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            Ok(p) => { pipe = Some(p); break; }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(std::time::Duration::from_millis(25 * (attempt + 1)));
            }
            Err(_) => return Err(()), // daemon not running → fail open
        }
    }
    let mut pipe = pipe.ok_or(())?;

    writeln!(pipe, "{json}").map_err(|_| ())?;
    pipe.flush().map_err(|_| ())?;

    // Read exactly one response line.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match pipe.read_exact(&mut byte) {
            Ok(()) => {
                if byte[0] == b'\n' { break; }
                buf.push(byte[0]);
                if buf.len() > 16 * 1024 * 1024 { return Err(()); } // sanity cap
            }
            Err(_) => return Err(()),
        }
    }

    serde_json::from_slice(&buf).map_err(|_| ())
}

// ── Real-tool execution ───────────────────────────────────────────────────────

fn exec_real(tool_name: &str, args: &[String], shim_dir: &PathBuf) {
    let real_path = find_real_tool(tool_name, shim_dir).unwrap_or_else(|| {
        eprintln!("[PROTECTOR]: Cannot find real '{tool_name}' executable in PATH.");
        std::process::exit(127);
    });

    // Build PATH excluding the shim directory so no recursive shim invocation.
    let path_env = std::env::var_os("PATH").unwrap_or_default();
    let filtered: Vec<PathBuf> = std::env::split_paths(&path_env)
        .filter(|p| p != shim_dir)
        .collect();
    let new_path = std::env::join_paths(&filtered).expect("cannot rebuild PATH");

    let status = std::process::Command::new(&real_path)
        .args(args)
        .env("PATH", &new_path)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("[PROTECTOR]: Failed to run {}: {e}", real_path.display());
            std::process::exit(1);
        });

    std::process::exit(status.code().unwrap_or(1));
}

fn find_real_tool(tool_name: &str, shim_dir: &PathBuf) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        if &dir == shim_dir { continue; }
        // Try tool.exe first (Windows convention), then bare name.
        for candidate in [
            dir.join(format!("{tool_name}.exe")),
            dir.join(format!("{tool_name}.cmd")),
            dir.join(format!("{tool_name}.bat")),
            dir.join(tool_name),
        ] {
            if candidate.exists() { return Some(candidate); }
        }
    }
    None
}
