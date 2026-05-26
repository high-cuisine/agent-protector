use std::collections::HashSet;
use std::io::Read;
use std::sync::{Arc, Mutex};

pub struct AuthState {
    hash:     String,
    sessions: Arc<Mutex<HashSet<String>>>,
}

const PASSWD_FILE: &str = "admin.passwd";

impl AuthState {
    pub fn load() -> Self {
        Self {
            hash:     load_hash(),
            sessions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn verify(&self, password: &str) -> bool {
        bcrypt::verify(password, &self.hash).unwrap_or(false)
    }

    pub fn new_token(&self) -> String {
        let token = random_token();
        self.sessions.lock().unwrap().insert(token.clone());
        token
    }

    pub fn is_valid(&self, token: &str) -> bool {
        self.sessions.lock().unwrap().contains(token)
    }

    pub fn revoke(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

/// Hash a password with bcrypt. Used by the --hash-password CLI flag.
pub fn hash_password(password: &str) -> String {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("bcrypt hash failed")
}

fn load_hash() -> String {
    // 1. environment variable (useful in containers / CI)
    if let Ok(h) = std::env::var("PROTECTOR_ADMIN_HASH") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            log::info!("Auth: password hash loaded from PROTECTOR_ADMIN_HASH env var");
            return h;
        }
    }

    // 2. file next to the binary / in the working directory
    if let Ok(content) = std::fs::read_to_string(PASSWD_FILE) {
        let h = content.trim().to_string();
        if !h.is_empty() {
            log::info!("Auth: password hash loaded from {PASSWD_FILE}");
            return h;
        }
    }

    // 3. first-run: generate default hash for "admin", save it, print warning
    let hash = bcrypt::hash("admin", bcrypt::DEFAULT_COST).expect("bcrypt hash failed");
    if std::fs::write(PASSWD_FILE, &hash).is_ok() {
        log::info!("Auth: created {PASSWD_FILE} with default password");
    } else {
        log::warn!("Auth: could not write {PASSWD_FILE} — using in-memory default");
    }
    eprintln!(
        "\n╔══════════════════════════════════════════════════════════╗\n\
           ║  Config UI — default credentials:  admin / admin         ║\n\
           ║  Change password:                                         ║\n\
           ║    protector --hash-password <new-pass> > {PASSWD_FILE}  ║\n\
           ╚══════════════════════════════════════════════════════════╝\n"
    );
    hash
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}
