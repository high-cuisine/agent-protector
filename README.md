# Protector

Protector is a kernel-/OS-level security layer that intercepts and validates the
actions of **Claude Code** (and similar coding agents) *before* they execute — so
an autonomous agent can't leak secrets, run destructive database/infra commands,
or exfiltrate data, even when it tries to.

It runs as a privileged daemon next to the agent and enforces policy on the
agent's whole process tree. On **Linux** interception is at the kernel (eBPF +
fanotify + seccomp) and is unbypassable from user space. A **Windows** port
provides a weaker, wrapper-based equivalent.

> Deep architecture, module map, and API reference live in [`CLAUDE.md`](CLAUDE.md).

## What it does

- **Command validation** — freezes a watched tool (`git`, `psql`, `mysql`,
  `redis-cli`, `docker`, `kubectl`, `curl`, …) at `execve`, runs a validator, then
  allows / warns / alerts / **blocks** it. Catches secret-bearing `git commit`s,
  `DROP`/`TRUNCATE`/unqualified `DELETE`, `docker --privileged`, `FLUSHALL`, etc.
- **Secret protection (three layers, Linux)** — the agent's context window never
  receives real credentials:
  1. *Tool masking* — `cat`/`head`/`grep` of a sensitive file returns masked
     output with `PROTECTOR_SECRET_…` tokens.
  2. *Read deny* (`fanotify`) — **any** in-process read (`python -c
     "open('.env').read()"`, `node -e …`, custom binary) of a policy-protected
     file is denied at the kernel.
  3. *Substitution* (`seccomp` user-notif) — when launched under control, those
     in-process reads transparently receive **masked content** instead of an
     error, so the agent keeps working with tokens, never the real secret.
- **Credential relay** — real secrets are substituted back into outbound
  `curl`/`wget` **only** for hosts in `PROTECTOR_RELAY_ALLOWLIST` (anti-exfil).
- **Network firewall** — L3/L4 egress/ingress control over the agent's cgroup.
- **Token budget** — per-model input/output token caps for the Anthropic API.
- **Observability** — live event stream (`protector inspect`), web dashboard,
  and CEF/syslog **SIEM** export.

## Platforms

| | Linux | Windows |
|---|---|---|
| Interception | eBPF (`execve`) + fanotify + seccomp — **unbypassable** | shim wrappers in PATH + named pipe — best-effort |
| Agent detection | `/proc` comm **and** command line (npm/`node` covered) | process command line via PEB (npm/`node` covered) |
| Secret substitution | yes (seccomp + memfd) | no (shim masks tool output only) |

The Windows path is a weaker guarantee by design: it only covers tools invoked
*by name through PATH*. For real enforcement on Windows, run the agent in a
sandbox/container. See [`CLAUDE.md`](CLAUDE.md) for the threat model.

## Prerequisites

- Rust stable + nightly (`rustup toolchain install nightly --component rust-src`)
- `bpf-linker` in PATH (`cargo install bpf-linker`; `--no-default-features` on macOS)
- Linux daemon: **root**, kernel with `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`, and
  **kernel ≥ 5.14** for seccomp secret-substitution
- (cross-compiling) musl C toolchain + `rustup target add ${ARCH}-unknown-linux-musl`

## Build

```bash
cargo build --release          # builds all crates (compiles the eBPF object via build.rs)
```

## Run (Linux)

```bash
# 1. policy (defaults already protect .env, ~/.ssh/id_*, ~/.aws/credentials, …)
sudo mkdir -p /etc/protector && sudo cp policy.conf /etc/protector/

# 2. start the daemon — must be root (eBPF, fanotify, /proc/<pid>/mem)
sudo ./target/release/protector

# 3a. launch the agent UNDER control (preferred; run as your user, not root):
./target/release/protector run -- claude
#    handy alias:  alias claude='protector run -- claude'

# 3b. …or capture an already-running Claude (also injects MITM proxy env):
./target/release/proxy-injector
```

Verify, from a session started via `protector run`:

```bash
python3 -c "print(open('.env').read())"   # → PROTECTOR_SECRET_… tokens, not real values
git commit -m "oops"                       # → blocked if the staged diff has a secret
```

Dashboard: `http://127.0.0.1:7878` (default `admin`/`admin`). Live events:
`protector inspect`.

## Run (Windows)

```powershell
cargo build --release -p protector-win -p shim
# setup self-elevates (UAC), installs shims into PATH, registers + starts the service
.\target\release\protector-win.exe setup
```

`setup` installs the daemon to `C:\Program Files\Protector`, registers the
auto-start `Protector` service and starts it immediately, and prepends the shim
dir to the system PATH. Open a **new** terminal/agent session afterwards so the
updated PATH takes effect.

## Cross-compiling on macOS

```bash
# Linux daemon
CC=${ARCH}-linux-musl-gcc cargo build --release -p protector \
  --target ${ARCH}-unknown-linux-musl
# Windows daemon + shim
cargo build --release --target x86_64-pc-windows-gnu -p protector-win -p shim
```

## Configuration

Config files load from `PROTECTOR_CONFIG_DIR`, else `/etc/protector` (Linux) /
`%ProgramData%\Protector` (Windows), else the launch CWD:

| File | Contents |
|------|----------|
| `policy.conf` | SQL table + filesystem (`fblock`/`fmask`) rules |
| `rules.json` | Per-tool/per-rule `Pass`/`Alert`/`Block` actions |
| `firewall.json` | Network firewall rules |
| `budget.json` | Per-model token budgets |
| `siem.json` | SIEM connection |
| `admin.passwd` | bcrypt hash for the web UI (`protector --hash-password <pw>`) |

## License

Except for the eBPF code, Protector is dual-licensed under [MIT] or
[Apache-2.0] at your option. eBPF code is dual-licensed under [GPL-2] or [MIT].

Contributions are accepted under the same terms.

[MIT]: LICENSE-MIT
[Apache-2.0]: LICENSE-APACHE
[GPL-2]: LICENSE-GPL2
