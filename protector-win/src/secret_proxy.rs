//! Secret proxy — Windows-adapted two-phase secret isolation.
//!
//! Phase 1: mask_file() returns the masked content (same as Linux).
//!          The daemon sends it back to the shim via IPC instead of /proc injection.
//!
//! Phase 2: relay_to_output() runs the real curl/wget with de-tokenized args
//!          and returns the captured output. The daemon forwards it to the shim.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
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
    pub fn new() -> Self { Self { entries: HashMap::new() } }

    pub fn tokenize(&mut self, value: &str, key: &str, source: &Path) -> String {
        let token = value_token(value);
        self.entries.entry(token.clone()).or_insert_with(|| SecretEntry {
            real_value:  value.to_string(),
            key_name:    key.to_string(),
            source_file: source.to_path_buf(),
        });
        token
    }

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

    pub fn has_tokens(&self, s: &str) -> bool { s.contains(TOKEN_PREFIX) }

    pub fn summary(&self) -> Vec<SecretSummary> {
        self.entries.iter().map(|(tok, e)| SecretSummary {
            token:       tok.clone(),
            key_name:    e.key_name.clone(),
            source_file: e.source_file.to_string_lossy().into_owned(),
        }).collect()
    }

    pub fn clear(&mut self) { self.entries.clear(); }
    pub fn count(&self) -> usize { self.entries.len() }
}

fn value_token(value: &str) -> String {
    let mut h = DefaultHasher::new();
    value.hash(&mut h);
    format!("{TOKEN_PREFIX}{:016X}", h.finish())
}

pub fn new_store() -> SharedSecretStore {
    Arc::new(Mutex::new(SecretStore::new()))
}

// ── Sensitive path detection ──────────────────────────────────────────────────

pub fn is_secret_path(path: &Path) -> bool {
    let name = path.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let ext = path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if name == ".env" || name.starts_with(".env.") { return true; }
    if name == "kubeconfig" { return true; }
    if name == "config" && path_contains(path, ".kube") { return true; }
    if (ext == "yaml" || ext == "yml")
        && (name.contains("secret") || name.contains("cred")) { return true; }
    if (name == "credentials" || name == "config") && path_contains(path, ".aws") { return true; }
    if name == "config.json" && path_contains(path, ".docker") { return true; }
    if matches!(ext.as_str(), "pem" | "key" | "p12" | "pfx" | "cer" | "crt") { return true; }
    if name.ends_with(".tfvars") { return true; }
    if name == ".netrc" { return true; }
    if ext == "json"
        && (name.contains("service_account") || name.contains("credentials")) { return true; }
    false
}

fn path_contains(path: &Path, segment: &str) -> bool {
    path.components().any(|c| c.as_os_str() == segment)
}

// ── File arg extraction ───────────────────────────────────────────────────────

pub fn first_file_arg(args: &[String], cwd: Option<&Path>) -> Option<PathBuf> {
    let raw = args.iter().skip(1).find(|a| !a.starts_with('-'))?;
    Some(resolve(raw, cwd))
}

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
        if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
            return PathBuf::from(home).join(rest);
        }
    }
    cwd.map(|c| c.join(&p)).unwrap_or(p)
}

// ── Content masking ───────────────────────────────────────────────────────────

const SECRET_KEYS: &[&str] = &[
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "api_token", "access_key", "access_token", "secret_key", "private_key",
    "auth", "credentials", "credential", "authorization", "bearer",
    "client_secret", "db_pass", "database_password", "database_url",
    "connection_string", "private", "signing_key", "encryption_key",
];

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
            mask_env(&content, path, store)
        };

    Ok((masked, count))
}

fn mask_env(content: &str, path: &Path, store: &mut SecretStore) -> (String, usize) {
    let mut out = String::with_capacity(content.len() + 64);
    let mut count = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
            out.push_str(line); out.push('\n'); continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let key = trimmed[..eq].trim();
            let raw = trimmed[eq + 1..].trim();
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
        out.push_str(line); out.push('\n');
    }
    (out, count)
}

fn mask_yaml(content: &str, path: &Path, store: &mut SecretStore) -> (String, usize) {
    let mut out = String::with_capacity(content.len() + 64);
    let mut count = 0;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with('-') && !trimmed.contains(':') {
            out.push_str(line); out.push('\n'); continue;
        }
        if let Some(colon) = trimmed.find(':') {
            let key = trimmed[..colon].trim().trim_matches('"').trim_matches('\'');
            let rest = trimmed[colon + 1..].trim();
            if !rest.is_empty()
                && !rest.starts_with('{') && !rest.starts_with('[')
                && !rest.starts_with('|') && !rest.starts_with('>')
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
        out.push_str(line); out.push('\n');
    }
    (out, count)
}

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
        if !masked { out.push_str(line); out.push('\n'); }
    }
    (out, count)
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|k| lower.contains(k))
}

// ── Token arg helpers ─────────────────────────────────────────────────────────

pub fn args_have_tokens(args: &[String]) -> bool {
    args.iter().any(|a| a.contains(TOKEN_PREFIX))
}

// ── Phase 2: relay on Windows ─────────────────────────────────────────────────

/// Run the command with tokens replaced by real secrets and return captured output.
/// On Windows we cannot drop privileges (no setuid), so runs as the current user.
pub fn relay_to_output(args: &[String], store: &SecretStore) -> std::io::Result<String> {
    let real_args: Vec<String> = args.iter().map(|a| store.detokenize(a)).collect();
    let (cmd, rest) = real_args.split_first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty args")
    })?;
    let output = std::process::Command::new(cmd).args(rest).output()?;
    let mut result = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.stderr.is_empty() {
        result.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    Ok(result)
}
