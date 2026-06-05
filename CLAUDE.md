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

### CLI flags

```
protector [OPTIONS] [SUBCOMMAND]

Subcommands:
  setup                  Install binary + systemd/launchd service
  inspect                Stream live events from running daemon (Unix socket)

Flags:
  --config-port <port>   Web dashboard port (default 7878)
  --proxy-port  <port>   Enable transparent HTTP/HTTPS redirect to MITM proxy
  --budget-port <port>   Enable token-budget enforcement proxy for Anthropic API
  --hash-password <pw>   Print bcrypt hash of <pw> and exit (for admin.passwd)
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

Protector is a Rust workspace with six crates that together form a kernel-userspace security system for intercepting and validating Claude Code agent actions before they execute.

### Crates

- **`protector-ebpf`** — eBPF tracepoint attached to `sys_enter_execve`; captures pid, uid, comm, and filename into a 256 KB ring buffer. Runs in kernel space. **(Linux only)**
- **`protector-common`** — Shared `ExecEvent` struct used by both the eBPF program and the userspace daemon.
- **`protector`** — Main userspace daemon (Linux): loads the eBPF object, reads events from the ring buffer, validates commands, and kills or resumes processes.
- **`proxy-injector`** — Standalone CLI that finds running Claude Code instances via `/proc` scanning and restarts them with MITM proxy env vars injected.
- **`protector-win`** — Windows daemon. Same validators/policy/web-UI as `protector`, but interception is shim-based (no eBPF). Talks to shims over a named pipe. **(Windows only)**
- **`shim`** — Tiny wrapper executable installed as `git.exe`, `psql.exe`, … in a directory placed first in PATH. Forwards each invocation to `protector-win` and acts on the verdict (run / block / synthetic output).

### Windows port (`protector-win` + `shim`)

The Linux daemon intercepts at the kernel via eBPF — unbypassable. Windows has no equivalent here, so interception is **wrapper-based**: `setup` installs shim copies into `C:\Program Files\Protector\shim` and prepends that dir to the system PATH. The shim talks to the daemon over `\\.\pipe\protector-win`.

Security properties of the Windows IPC (hardened):
- The caller's PID is taken from the kernel via `GetNamedPipeClientProcessId` — **never** from the request body (which is attacker-controlled).
- The daemon resolves the real tool binary itself (excluding the shim dir) and only ever executes that path — never the argv[0] sent over the pipe, preventing arbitrary-command execution and shim recursion.
- Session tokens use the OS CSPRNG (`getrandom`) on both platforms; a predictable fallback is never issued.
- `setup` reads/writes the system PATH defensively and refuses to write an empty value (which would wipe PATH).

**Known limitation (by design):** the wrapper approach only covers tools invoked *by name through PATH*. A process that calls a tool by absolute path, ships its own PATH, or statically links the client logic bypasses the shim entirely. This is a weaker guarantee than the Linux eBPF path. Document/threat-model accordingly.

The credential **relay** (secret-proxy phase 2) substitutes real secrets into outbound `curl`/`wget` only when every URL host is in `PROTECTOR_RELAY_ALLOWLIST` (comma-separated host suffixes). Unset/empty ⇒ deny — this is the anti-exfiltration guard and applies on **both** platforms.

Config files are loaded from a stable directory, not the launch CWD: `PROTECTOR_CONFIG_DIR` if set, else `%ProgramData%\Protector` (Windows) / `/etc/protector` (Linux).

Cross-compile (from Linux/macOS):
```bash
cargo build --release --target x86_64-pc-windows-gnu -p protector-win -p shim
```

### Event Flow

1. **Kernel** (`protector-ebpf/src/main.rs`): `sys_enter_execve` fires → writes `ExecEvent` to ring buffer.
2. **Daemon loop** (`protector/src/main.rs`): `tokio::select!` reads ring buffer events via `AsyncFd`. Filters with `looks_interesting()` to skip binaries not in the watchlist.
3. **Process tree** (`protector/src/tracker.rs`): `ProcessTracker` walks `/proc` PPID chains (max 32 levels) to decide if the execve came from a Claude Code descendant. Refreshes every 5 seconds.
4. **Tool matching** (`protector/src/tool_db.rs`): `ToolDb::find_action()` matches binary name + argv patterns against the registry of watched tools.
5. **Validation**: daemon sends `SIGSTOP` to freeze target process, runs the matched validator, then either `SIGCONT` (allow), `SIGKILL` (block), or substitutes output (mask).

Watched binaries (pre-filter): `git`, `psql`, `mysql`, `mariadb`, `sqlite3`, `redis-cli`, `npm`, `pip`, `pip3`, `curl`, `wget`, `docker`, `kubectl`, `cat`, `head`, `tail`, `grep`, `egrep`, `fgrep`, `diff`, `find`, `cp`, `mv`.

### Validators (`protector/src/validators/`)

| Validator | What it detects |
|-----------|-----------------|
| `git_commit.rs` | Commits containing secrets (reads staged diff) |
| `secret.rs` | 33+ regex patterns: AWS keys, GitHub tokens, private keys, etc. |
| `sql_guard.rs` | DROP, TRUNCATE, unqualified DELETE, privilege escalation, injection patterns |
| `docker_guard.rs` | `--privileged`, dangerous caps, `docker.sock` mounts, volume destructive ops |
| `redis_guard.rs` | FLUSHALL, FLUSHDB, SHUTDOWN, CONFIG SET |
| `kubectl_guard.rs` | Delegates to `sql_guard` for SQL commands inside `kubectl exec` |
| `data_guard.rs` | SQL queries touching tables listed in data policy (block or mask output) |
| `fs_guard.rs` | File reads/copies touching paths listed in data policy (fblock or fmask) |

### Validation outcomes

Each validator returns one of four results:
- `Allow` → `SIGCONT` (process runs normally)
- `Warn` → log + SIEM alert, then `SIGCONT` (process runs, security team notified)
- `Alert` → stored in `AlertStore` + SIEM, then `SIGCONT` (visible in web UI)
- `Block` → `SIGKILL` + `SIGCONT` (process killed)

For mask cases, the daemon kills the process and injects synthetic output into its stdout pipe via `/proc/<pid>/fd/1` before the agent reads it.

### Error Types

`ThreatError` (`protector/src/errors.rs`) is the central enum for all threat variants. Display output uses structured prefixes (`SECRET_LEAK:`, `SQL_DESTRUCTIVE:`, `DATA_POLICY_BLOCK:`, etc.) for log parsing.

## Modules reference (`protector/src/`)

| Module | Purpose |
|--------|---------|
| `main.rs` | Entry point, eBPF loader, main event loop, `handle_event` dispatcher |
| `tracker.rs` | `ProcessTracker` — walks `/proc` PPID chains to find Claude descendants |
| `tool_db.rs` | `ToolDb` — registry of watched tools; `find_action()` → `Validator` |
| `validator.rs` | `Validator` trait + `ValidationContext` + `ValidationResult` |
| `event_bus.rs` | Broadcast channel + Unix socket server for `protector inspect` (2000-event history) |
| `alert_store.rs` | In-memory ring of Alert events, queryable by ID for web UI polling |
| `rules_config.rs` | Per-tool/per-rule actions (`Pass`/`Alert`/`Block`), persisted to `rules.json` |
| `data_policy.rs` | `DataPolicy` parser: `block`/`mask` (SQL tables), `fblock`/`fmask` (FS paths) |
| `secret_proxy.rs` | Two-phase secret isolation: file masking + curl/wget relay with real credentials |
| `fs_guard.rs` → `validators/fs_guard.rs` | FS path guard using `DataPolicy` |
| `data_guard.rs` → `validators/data_guard.rs` | SQL table guard — rewrites queries to mask columns |
| `network_firewall.rs` | L3/L4 firewall via iptables + cgroup v2 (`/sys/fs/cgroup/claude-protector`) |
| `firewall_config.rs` | `FirewallConfig`: blacklist/whitelist mode, rules with CIDR/port/direction |
| `traffic_redirect.rs` | Transparent HTTP/HTTPS redirect (iptables NAT + cgroup v2) |
| `token_proxy.rs` | HTTP proxy for Anthropic API: enforces per-model token budgets |
| `budget.rs` | `Budget`: per-model input/output token limits, auto-reset on idle |
| `siem.rs` | SIEM sender: CEF format over UDP/TCP syslog |
| `siem_config.rs` | `SiemConfig`: host, port, protocol (UDP/TCP), facility, min outcome filter |
| `auth.rs` | bcrypt auth + session tokens; password from `admin.passwd` or `PROTECTOR_ADMIN_HASH` |
| `web_ui.rs` | Axum HTTP dashboard on `127.0.0.1:<config-port>` (default 7878) |
| `inspect.rs` | `protector inspect` subcommand — connects to Unix socket, streams events |
| `setup.rs` | `protector setup` — installs binary, creates `/etc/protector`, registers service |
| `reporter.rs` | Console reporter (structured log output for blocks/warns) |
| `banner.rs` | ASCII art startup banner |
| `errors.rs` | `ThreatError` enum — all threat variants with structured Display |

## Data Policy (`policy.conf`)

Loaded from `PROTECTOR_POLICY` env var, then `/etc/protector/policy.conf`, then `./policy.conf`.

```
# SQL table rules
block  payment_cards                               # deny all queries
mask   users  email:email  ssn:redact  phone:phone # rewrite SELECT to mask columns

# Filesystem path rules  (supports * ** ~)
fblock /etc/shadow
fblock ~/.ssh/id_*
fmask  ~/.aws/credentials
fmask  /var/log/*.log
```

Column mask kinds: `redact` → `[REDACTED]`, `email` → `a***@***.***`, `phone` → `***-**-1234`, `partial:<n>` → first N chars + `***`.

`SELECT *` on a masked table is always blocked (column list required for safe rewriting).

## Secret Proxy (two-phase)

**Phase 1 — file masking**: when the agent runs `cat`/`head`/`tail`/`grep`/`diff`/`cp`/`mv` on a sensitive file (`.env`, `kubeconfig`, `*.pem`, AWS credentials, Docker config, GCP service account JSON, `.netrc`, `*.tfvars`), the daemon:
1. Reads and masks the file: replaces secret values with `PROTECTOR_SECRET_<16hex>` tokens.
2. Kills the original process and injects the masked content into its stdout pipe.
3. Stores the real values in `SecretStore` keyed by token.

**Phase 2 — request relay**: when `curl`/`wget` is called with token-containing args, the daemon re-runs the command with tokens replaced by real credentials, captures output, and relays it back through the stopped process's stdout pipe.

The agent context window never contains real credentials. Tokens are deterministic (hash-based), so the same secret always gets the same token within a daemon session.

## Network Firewall

Requires: root, `iptables` with `xt_cgroup`/`xt_conntrack` modules, cgroup v2.

Config: `firewall.json`. Two modes:
- **Blacklist** (default): allow all, explicit DROP rules.
- **Whitelist**: drop all, explicit ACCEPT rules (ESTABLISHED/RELATED always allowed in).

Rules support: CIDR, port range, direction (`in`/`out`/`both`), protocol (`tcp`/`udp`/`any`), enable/disable per rule.

Implementation: creates `PROTECTOR-FW-OUT` and `PROTECTOR-FW-IN` chains, jumps from OUTPUT/INPUT only for processes in the `/sys/fs/cgroup/claude-protector` cgroup. Rules are hot-reloaded from the web UI without restarting the daemon.

## Token Budget Proxy

Start with `--budget-port <port>`, then set `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>` in the agent's environment.

Intercepts `/v1/messages` POST: checks per-model limits before forwarding to Anthropic, records actual token usage from the response (streaming and non-streaming). When budget is exhausted, returns a synthetic Anthropic-compatible error response so the agent stops gracefully.

Config: `budget.json` — per model `input_tokens`/`output_tokens` limits, `idle_reset_secs` for auto-reset.

## Web Dashboard

`http://127.0.0.1:7878` (or `--config-port`). Protected by bcrypt session cookie auth.

Default credentials: `admin` / `admin`. Change with:
```bash
protector --hash-password <new-pass> > admin.passwd
```
Or set `PROTECTOR_ADMIN_HASH` env var.

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/api/rules` | Tool rule actions (Pass/Alert/Block per tool+rule) |
| `POST` | `/api/rules/reset` | Reset rules to defaults |
| `GET` | `/api/alerts?since=<id>` | Fetch alerts (polling with last_id) |
| `POST` | `/api/alerts/clear` | Clear alert store |
| `POST` | `/api/kill-agent` | SIGTERM all Claude Code processes |
| `GET/POST` | `/api/siem` | SIEM config (host, port, protocol, min_outcome) |
| `POST` | `/api/siem/test` | Send a test CEF event to SIEM |
| `GET` | `/api/secrets` | Secret store summary (tokens + metadata, no real values) |
| `POST` | `/api/secrets/clear` | Clear secret store |
| `GET/POST` | `/api/budget` | Token budget config + current usage + history |
| `POST` | `/api/budget/reset` | Reset current task token counters |
| `GET/POST` | `/api/firewall` | Firewall rules (hot-reloads iptables on POST) |

## SIEM Integration

Sends CEF-formatted events over syslog (UDP default, TCP optional) to any SIEM (Splunk, ELK, QRadar, etc.).

Config: `siem.json` — `host`, `port` (default 514), `protocol` (`udp`/`tcp`), `facility` (0-23, default 16=local0), `min_outcome` filter (`all`/`warn_and_above`/`alert_and_above`/`block_only`).

## Configuration files

| File | Contents |
|------|---------|
| `rules.json` | Per-tool/per-rule Pass/Alert/Block actions |
| `policy.conf` | Data policy: SQL table and FS path block/mask rules |
| `budget.json` | Token budget limits per model |
| `siem.json` | SIEM connection settings |
| `firewall.json` | Network firewall rules |
| `admin.passwd` | bcrypt password hash for web UI admin |

Working directory for config files: wherever the daemon is launched from (or `/etc/protector` when installed via `protector setup`).

## Adding a New Tool Guard

1. Add a new entry in `ToolDb` (`tool_db.rs`) with `cmd`, `required_args`, and `excluded_args`.
2. Add the binary name to `looks_interesting()` in `main.rs`.
3. Implement the `Validator` trait (`validator.rs`) in a new file under `validators/`.
4. Add a `ThreatError` variant in `errors.rs` and its `Display` arm.
5. Wire the new validator into `tool_db.rs` so `find_action()` returns it.
6. Add a default rule entry in `RulesConfig::default_config()` (`rules_config.rs`).
