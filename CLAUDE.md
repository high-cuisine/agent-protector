# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build all crates (requires bpf-linker in PATH for eBPF compilation)
cargo build --release

# Run the daemon (requires root for eBPF attachment)
sudo cargo run --release

# Format code (rustfmt.toml enforces grouped/reordered imports)
cargo fmt
```

### Cross-compilation on macOS

The eBPF program targets Linux. On macOS, build with musl-cross:

```bash
CC=x86_64-linux-musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl
```

The `build.rs` in the `protector` crate automatically invokes `aya_build::build_ebpf()` to compile the eBPF object file before linking the userspace binary.

## Testing

There is currently no test suite. No `#[cfg(test)]` blocks or `tests/` directories exist.

## Architecture

Protector is a Rust workspace with four crates that together form a kernel-userspace security system for intercepting and validating Claude Code agent actions before they execute.

### Crates

- **`protector-ebpf`** — eBPF tracepoint attached to `sys_enter_execve`; captures pid, uid, comm, and filename into a 256 KB ring buffer. Runs in kernel space.
- **`protector-common`** — Shared `ExecEvent` struct used by both the eBPF program and the userspace daemon.
- **`protector`** — Main userspace daemon: loads the eBPF object, reads events from the ring buffer, validates commands, and kills or resumes processes.
- **`proxy-injector`** — Standalone CLI that finds running Claude Code instances via `/proc` scanning and restarts them with MITM proxy env vars injected.

### Event Flow

1. **Kernel** (`protector-ebpf/src/main.rs`): `sys_enter_execve` fires → writes `ExecEvent` to ring buffer → returns 0 (never blocks the execve).
2. **Daemon loop** (`protector/src/main.rs`): `tokio::select!` reads ring buffer events via `AsyncFd`. Filters with `looks_interesting()` to skip binaries not in the watchlist.
3. **Process tree** (`protector/src/tracker.rs`): `ProcessTracker` walks `/proc` PPID chains (max 32 levels) to decide if the execve came from a Claude Code descendant. Refreshes the list of Claude PIDs every 5 seconds.
4. **Tool matching** (`protector/src/tool_db.rs`): `ToolDb::find_action()` matches the binary name plus required/excluded argv patterns against a registry of watched tools (git, psql, mysql, redis-cli, docker, kubectl).
5. **Validation**: The daemon sends `SIGSTOP` to freeze the target process, runs the matched validator, then either `SIGCONT` (allow) or `SIGKILL` (block).

### Validators (`protector/src/validators/`)

| Validator | What it blocks |
|-----------|---------------|
| `git_commit.rs` | Commits containing secrets (reads staged diff) |
| `secret.rs` | 33+ regex patterns: AWS keys, GitHub tokens, private keys, etc. |
| `sql_guard.rs` | DROP, TRUNCATE, unqualified DELETE, privilege escalation, injection patterns |
| `docker_guard.rs` | `--privileged`, dangerous caps, `docker.sock` mounts, volume destructive ops |
| `redis_guard.rs` | FLUSHALL, FLUSHDB, SHUTDOWN, CONFIG SET |
| `kubectl_guard.rs` | Delegates to `sql_guard` for SQL commands inside `kubectl exec` |

### Error Types

`ThreatError` (`protector/src/errors.rs`) is the central enum for all threat variants (`SecretLeak`, `SqlDestructive`, `DockerUnsafeRun`, etc.). Each variant carries context (file path, operation name). Display output uses structured prefixes (`SECRET_LEAK:`, `SQL_DESTRUCTIVE:`) for log parsing.

### Adding a New Tool Guard

1. Add a new entry in `ToolDb` (`tool_db.rs`) with `cmd`, `required_args`, and `excluded_args`.
2. Implement the `Validator` trait (`validator.rs`) in a new file under `validators/`.
3. Add a `ThreatError` variant in `errors.rs` and its `Display` arm.
4. Wire the new validator into `tool_db.rs` so `find_action()` returns it.
