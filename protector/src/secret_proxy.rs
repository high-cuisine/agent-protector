//! Secret Proxy — two-phase secret isolation.
//!
//! Phase 1 — File masking:
//!   When the AI reads a sensitive file (.env, kubeconfig, *.pem, …) we
//!   intercept the command, replace every secret value with a reversible token
//!   `PROTECTOR_SECRET_<16-hex-chars>`, and inject the masked content into the
//!   stopped process's stdout pipe via /proc/PID/fd/1.  The real values are
//!   stored in SecretStore keyed by the token.
//!
//! Phase 2 — Request relay:
//!   When curl/wget is called with args that contain a token we re-run the
//!   command with the real values substituted, capture the output, and relay it
//!   back through the original (now dead) process's stdout pipe.  The AI
//!   always sees only tokens; real credentials never appear in its context.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::io::Write as IoWrite;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ── Token store ───────────────────────────────────────────────────────────────

pub const TOKEN_PREFIX: &str = "PROTECTOR_SECRET_";

pub type SharedSecretStore = Arc<Mutex<SecretStore>>;

pub struct SecretEntry {
    pub real_value:  String,
    pub key_name:    String,
    pub source_file: PathBuf,
}

pub struct SecretStore {
    entries: HashMap<String, SecretEntry>,
}

#[derive(serde::Serialize, Clone)]
pub struct SecretSummary {
    pub token:       String,
    pub key_name:    String,
    pub source_file: String,
}

impl SecretStore {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Register a secret value and return its deterministic, non-reversible token.
    pub fn tokenize(&mut self, value: &str, key: &str, source: &Path) -> String {
        let token = value_token(value);
        self.entries.entry(token.clone()).or_insert_with(|| SecretEntry {
            real_value:  value.to_string(),
            key_name:    key.to_string(),
            source_file: source.to_path_buf(),
        });
        token
    }

    /// Replace all tokens in `s` with their real values.
    pub fn detokenize(&self, s: &str) -> String {
        if !s.contains(TOKEN_PREFIX) { return s.to_string(); }
        let mut out = s.to_string();
        for (tok, entry) in &self.entries {
            if out.contains(tok.as_str()) {
                out = out.replace(tok.as_str(), &entry.real_value);
            }
        }
        out
    }

    pub fn has_tokens(&self, s: &str) -> bool {
        s.contains(TOKEN_PREFIX)
    }

    /// Public listing: tokens + metadata but NOT real values.
    pub fn summary(&self) -> Vec<SecretSummary> {
        self.entries.iter().map(|(tok, e)| SecretSummary {
            token:       tok.clone(),
            key_name:    e.key_name.clone(),
            source_file: e.source_file.to_string_lossy().into_owned(),
        }).collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn count(&self) -> usize { self.entries.len() }
}

/// Deterministic token: same secret → same token across daemon lifetime.
fn value_token(value: &str) -> String {
    let mut h = DefaultHasher::new();
    value.hash(&mut h);
    format!("{TOKEN_PREFIX}{:016X}", h.finish())
}

pub fn new_store() -> SharedSecretStore {
    Arc::new(Mutex::new(SecretStore::new()))
}

// ── Sensitive path detection ──────────────────────────────────────────────────

/// Returns true if reading this file should trigger secret masking.
pub fn is_secret_path(path: &Path) -> bool {
    let name = path.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let ext = path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // .env and its variants (.env.local, .env.production, …)
    if name == ".env" || name.starts_with(".env.") { return true; }

    // Kubernetes configs
    if name == "kubeconfig" { return true; }
    if name == "config" && path_contains(path, ".kube") { return true; }
    if (ext == "yaml" || ext == "yml")
        && (name.contains("secret") || name.contains("cred")) { return true; }

    // AWS credentials/config
    if (name == "credentials" || name == "config") && path_contains(path, ".aws") { return true; }

    // Docker auth config
    if name == "config.json" && path_contains(path, ".docker") { return true; }

    // Private keys and certificates
    if matches!(ext.as_str(), "pem" | "key" | "p12" | "pfx" | "cer" | "crt") { return true; }

    // Terraform vars
    if name.ends_with(".tfvars") { return true; }

    // Legacy network credentials
    if name == ".netrc" { return true; }

    // GCP service account JSON
    if ext == "json"
        && (name.contains("service_account") || name.contains("credentials")) { return true; }

    false
}

fn path_contains(path: &Path, segment: &str) -> bool {
    path.components().any(|c| c.as_os_str() == segment)
}

// ── First-pass: extract file paths from argv ──────────────────────────────────

/// Find the primary file-path argument in argv (skip argv[0] and flags).
pub fn first_file_arg(args: &[String], cwd: Option<&Path>) -> Option<PathBuf> {
    let raw = args.iter().skip(1).find(|a| !a.starts_with('-'))?;
    Some(resolve(raw, cwd))
}

/// All non-flag positional args resolved to paths.
pub fn all_file_args(args: &[String], cwd: Option<&Path>) -> Vec<PathBuf> {
    args.iter().skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(|a| resolve(a, cwd))
        .collect()
}

fn resolve(s: &str, cwd: Option<&Path>) -> PathBuf {
    let p = PathBuf::from(s);
    if p.is_absolute() { return p; }
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    cwd.map(|c| c.join(&p)).unwrap_or(p)
}

// ── Content masking ───────────────────────────────────────────────────────────

/// Secret-sounding key names checked in YAML/JSON.
const SECRET_KEYS: &[&str] = &[
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "api_token", "access_key", "access_token", "secret_key", "private_key",
    "auth", "credentials", "credential", "authorization", "bearer",
    "client_secret", "db_pass", "database_password", "database_url",
    "connection_string", "private", "signing_key", "encryption_key",
];

/// Read `path`, mask all secrets, register tokens in `store`.
/// Returns (masked_content, secrets_masked_count).
pub fn mask_file(path: &Path, store: &mut SecretStore) -> std::io::Result<(String, usize)> {
    let content = std::fs::read_to_string(path)?;

    let name = path.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let ext = path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let (masked, count) =
        if name.starts_with(".env") || name.ends_with(".tfvars") || name == ".netrc"
            || (name == "credentials" && path_contains(path, ".aws"))
        {
            mask_env(&content, path, store)
        } else if ext == "yaml" || ext == "yml" || name == "kubeconfig"
            || (name == "config" && path_contains(path, ".kube"))
        {
            mask_yaml(&content, path, store)
        } else if ext == "json"
            || (name == "config.json" && path_contains(path, ".docker"))
        {
            mask_json(&content, path, store)
        } else if matches!(ext.as_str(), "pem" | "key" | "p12" | "pfx" | "cer" | "crt") {
            let tok = store.tokenize(content.trim(), "pem_content", path);
            (tok + "\n", 1)
        } else {
            // Generic fallback: env-style
            mask_env(&content, path, store)
        };

    Ok((masked, count))
}

/// Mask `KEY=VALUE` format (.env, AWS credentials, terraform.tfvars).
fn mask_env(content: &str, path: &Path, store: &mut SecretStore) -> (String, usize) {
    let mut out = String::with_capacity(content.len() + 64);
    let mut count = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Preserve comments, section headers, empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
            out.push_str(line);
            out.push('\n');
            continue;
        }

        if let Some(eq) = trimmed.find('=') {
            let key = trimmed[..eq].trim();
            let raw = trimmed[eq + 1..].trim();

            // Strip surrounding quotes
            let val = raw
                .strip_prefix('"').and_then(|s| s.strip_suffix('"'))
                .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(raw);

            if !val.is_empty() && is_secret_key(key) {
                let tok = store.tokenize(val, key, path);
                out.push_str(&format!("{key}={tok}\n"));
                count += 1;
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, count)
}

/// Mask YAML `key: value` lines where key matches a secret keyword.
fn mask_yaml(content: &str, path: &Path, store: &mut SecretStore) -> (String, usize) {
    let mut out = String::with_capacity(content.len() + 64);
    let mut count = 0;

    for line in content.lines() {
        let trimmed = line.trim_start();

        if trimmed.starts_with('#') || trimmed.starts_with('-') && !trimmed.contains(':') {
            out.push_str(line);
            out.push('\n');
            continue;
        }

        if let Some(colon) = trimmed.find(':') {
            let key = trimmed[..colon].trim().trim_matches('"').trim_matches('\'');
            let rest = trimmed[colon + 1..].trim();

            if !rest.is_empty()
                && !rest.starts_with('{')
                && !rest.starts_with('[')
                && !rest.starts_with('|')  // block scalar
                && !rest.starts_with('>')
                && is_secret_key(key)
            {
                let val = rest.trim_matches('"').trim_matches('\'');
                if !val.is_empty() {
                    let indent = &line[..line.len() - trimmed.len()];
                    let tok = store.tokenize(val, key, path);
                    out.push_str(&format!("{indent}{key}: {tok}\n"));
                    count += 1;
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, count)
}

/// Mask JSON `"key": "value"` pairs where key matches a secret keyword.
/// Works on pretty-printed JSON (one field per line).
fn mask_json(content: &str, path: &Path, store: &mut SecretStore) -> (String, usize) {
    let mut out = String::with_capacity(content.len() + 64);
    let mut count = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        let mut masked = false;

        if let Some(after_quote) = trimmed.strip_prefix('"') {
            if let Some(key_end) = after_quote.find('"') {
                let key = &after_quote[..key_end];
                let after_key = after_quote[key_end + 1..].trim();

                if let Some(val_part) = after_key.strip_prefix(':') {
                    let val_raw = val_part.trim();
                    let trailing = if val_raw.ends_with(',') { "," } else { "" };
                    let val_inner = val_raw.trim_end_matches(',').trim();
                    let val = val_inner.trim_matches('"');

                    if !val.is_empty() && val != "null" && is_secret_key(key) {
                        let indent = &line[..line.len() - trimmed.len()];
                        let tok = store.tokenize(val, key, path);
                        out.push_str(&format!("{indent}\"{key}\": \"{tok}\"{trailing}\n"));
                        count += 1;
                        masked = true;
                    }
                }
            }
        }

        if !masked {
            out.push_str(line);
            out.push('\n');
        }
    }
    (out, count)
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|k| lower.contains(k))
}

// ── Process injection ─────────────────────────────────────────────────────────

/// Inject `content` into the SIGSTOP'd process's stdout, then kill it.
///
/// Works by opening /proc/PID/fd/1 (the process's inherited stdout fd,
/// typically a pipe to the shell) BEFORE killing the process.  Writing to
/// that fd places data in the pipe buffer.  When we close it, the reader
/// gets EOF.  The stopped process never runs and never writes the real content.
pub fn inject_and_terminate(pid: u32, content: &[u8]) -> std::io::Result<()> {
    // Open the write end of the process's stdout pipe.
    // Must happen BEFORE SIGKILL so /proc/<pid>/fd/1 still exists.
    let mut stdout = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/{pid}/fd/1"))?;

    // Kill the stopped process so it never writes the real file content.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
        libc::kill(pid as libc::pid_t, libc::SIGCONT);
    }

    // Write our masked content through the still-open pipe end.
    stdout.write_all(content)?;
    // Drop stdout → our copy of write-end closes → reader gets EOF.
    Ok(())
}

/// Kill the original stopped process and re-run it with tokens replaced by
/// real secrets.  The subprocess's stdout/stderr is captured and relayed back
/// through the original process's stdout pipe.
pub fn relay_with_real_creds(
    pid: u32,
    args: &[String],
    store: &SecretStore,
) -> std::io::Result<()> {
    let real_args: Vec<String> = args.iter().map(|a| store.detokenize(a)).collect();

    let uid = proc_uid(pid).unwrap_or(0);
    let gid = proc_gid(pid).unwrap_or(0);

    // Open stdout BEFORE killing
    let mut relay = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/{pid}/fd/1"))?;

    // Kill original
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
        libc::kill(pid as libc::pid_t, libc::SIGCONT);
    }

    let Some((cmd, rest)) = real_args.split_first() else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty args"));
    };

    // Re-run with real credentials under the original user's identity
    let output = unsafe {
        std::process::Command::new(cmd)
            .args(rest)
            .pre_exec(move || {
                libc::setgid(gid);
                libc::setuid(uid);
                Ok(())
            })
            .output()?
    };

    relay.write_all(&output.stdout)?;
    if !output.stderr.is_empty() {
        relay.write_all(&output.stderr)?;
    }
    Ok(())
}

// ── Arg helpers ───────────────────────────────────────────────────────────────

pub fn args_have_tokens(args: &[String]) -> bool {
    args.iter().any(|a| a.contains(TOKEN_PREFIX))
}

// ── /proc helpers ─────────────────────────────────────────────────────────────

fn proc_uid(pid: u32) -> anyhow::Result<libc::uid_t> { proc_id_field(pid, "Uid:") }
fn proc_gid(pid: u32) -> anyhow::Result<libc::gid_t> { proc_id_field(pid, "Gid:") }

fn proc_id_field(pid: u32, field: &str) -> anyhow::Result<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(v) = rest.split_whitespace().next() {
                return v.parse().map_err(Into::into);
            }
        }
    }
    anyhow::bail!("{field} not found for pid {pid}")
}
