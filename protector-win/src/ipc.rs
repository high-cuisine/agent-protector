//! Named-pipe IPC protocol between shim wrappers and the protector-win daemon.
use serde::{Deserialize, Serialize};

/// Pipe name used on all Windows machines (a local named pipe).
pub const PIPE_NAME: &str = r"\\.\pipe\protector-win";

/// Sent by a shim wrapper to the daemon once per invocation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ShimRequest {
    /// Bare tool name as detected from the exe stem (e.g. "git", "psql").
    pub tool: String,
    /// Full argv including argv[0].
    pub args: Vec<String>,
    /// Working directory of the shim process.
    pub cwd: String,
    /// PID of the shim process (used for Claude-descendant check).
    pub pid: u32,
}

/// Daemon response — tells the shim what to do next.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ShimResponse {
    /// Run the real tool found in PATH (excluding the shim directory).
    ExecReal,
    /// Print `message` to stderr and exit 1.
    Block { message: String },
    /// Print `content` to stdout and exit `exit_code`.
    Output { content: String, exit_code: i32 },
}
