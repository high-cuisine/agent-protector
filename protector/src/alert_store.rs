use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use serde::Serialize;

pub type SharedAlertStore = Arc<Mutex<AlertStore>>;

#[derive(Debug, Clone, Serialize)]
pub struct AlertEntry {
    pub id:           u64,
    pub ts_ms:        u64,
    pub tool:         String,
    pub rule:         String,
    pub threat_code:  String,
    pub message:      String,
    pub args:         Vec<String>,
    pub pid:          u32,
}

pub struct AlertStore {
    entries:  VecDeque<AlertEntry>,
    max_size: usize,
    next_id:  u64,
}

impl AlertStore {
    pub fn new() -> Self {
        Self { entries: VecDeque::new(), max_size: 500, next_id: 1 }
    }

    pub fn push(
        &mut self,
        tool:        String,
        rule:        String,
        threat_code: String,
        message:     String,
        args:        Vec<String>,
        pid:         u32,
    ) {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.entries.push_back(AlertEntry {
            id: self.next_id, ts_ms, tool, rule, threat_code, message, args, pid,
        });
        self.next_id += 1;
        if self.entries.len() > self.max_size {
            self.entries.pop_front();
        }
    }

    pub fn since(&self, after_id: u64) -> Vec<AlertEntry> {
        self.entries.iter().filter(|e| e.id > after_id).cloned().collect()
    }

    pub fn all(&self) -> Vec<AlertEntry> {
        self.entries.iter().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn last_id(&self) -> u64 {
        self.next_id.saturating_sub(1)
    }
}
