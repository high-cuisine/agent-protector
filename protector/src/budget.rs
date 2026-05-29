use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

pub type SharedBudget = Arc<RwLock<Budget>>;

const CONFIG_PATH: &str = "budget.json";

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelLimit {
    /// Max input tokens per task. 0 = unlimited.
    #[serde(default)]
    pub input_tokens: u64,
    /// Max output tokens per task. 0 = unlimited.
    #[serde(default)]
    pub output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BudgetConfig {
    pub models:          HashMap<String, ModelLimit>,
    /// Auto-reset after N seconds of inactivity. 0 = disabled.
    pub idle_reset_secs: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            models:          HashMap::new(),
            idle_reset_secs: 600,
        }
    }
}

impl BudgetConfig {
    pub fn load_or_default() -> Self {
        std::fs::read_to_string(CONFIG_PATH)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        std::fs::write(CONFIG_PATH, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

// ── Runtime state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Default)]
pub struct ModelUsage {
    pub input_tokens:  u64,
    pub output_tokens: u64,
    pub calls:         u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskSnapshot {
    pub usage:        HashMap<String, ModelUsage>,
    pub started_ms:   u64,
    pub last_call_ms: u64,
}

impl TaskSnapshot {
    fn new() -> Self {
        let now = now_ms();
        Self { usage: HashMap::new(), started_ms: now, last_call_ms: now }
    }
}

pub struct Budget {
    pub config:  BudgetConfig,
    pub task:    TaskSnapshot,
    pub history: Vec<TaskSnapshot>,
}

impl Budget {
    pub fn new(config: BudgetConfig) -> Self {
        Self { config, task: TaskSnapshot::new(), history: Vec::new() }
    }

    /// Called after a successful API call; updates running totals.
    pub fn record(&mut self, model: &str, input: u64, output: u64) {
        let e = self.task.usage.entry(model.to_string()).or_default();
        e.input_tokens  += input;
        e.output_tokens += output;
        e.calls         += 1;
        self.task.last_call_ms = now_ms();
    }

    /// Check whether a new request for `model` should be blocked.
    /// Also triggers an auto-reset check on every call.
    /// Returns `Some(reason)` when blocked.
    pub fn check_limit(&mut self, model: &str) -> Option<String> {
        self.maybe_auto_reset();

        let limit = self.config.models.get(model)?;
        let used  = self.task.usage.get(model)?;

        if limit.input_tokens > 0 && used.input_tokens >= limit.input_tokens {
            return Some(format!(
                "Input token budget exceeded for model `{}`: {}/{} used",
                model, used.input_tokens, limit.input_tokens
            ));
        }
        if limit.output_tokens > 0 && used.output_tokens >= limit.output_tokens {
            return Some(format!(
                "Output token budget exceeded for model `{}`: {}/{} used",
                model, used.output_tokens, limit.output_tokens
            ));
        }
        None
    }

    /// Manually reset the current task; old task moves to history.
    pub fn reset_task(&mut self) {
        let old = std::mem::replace(&mut self.task, TaskSnapshot::new());
        self.history.push(old);
        if self.history.len() > 50 {
            self.history.remove(0);
        }
        log::info!("[budget] Task reset — token counters cleared");
    }

    fn maybe_auto_reset(&mut self) {
        let timeout = self.config.idle_reset_secs;
        if timeout == 0 || self.task.last_call_ms == 0 { return; }
        let idle_secs = (now_ms() - self.task.last_call_ms) / 1000;
        if idle_secs >= timeout {
            log::info!("[budget] Auto-reset after {idle_secs}s idle");
            self.reset_task();
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn new_shared(config: BudgetConfig) -> SharedBudget {
    Arc::new(RwLock::new(Budget::new(config)))
}
