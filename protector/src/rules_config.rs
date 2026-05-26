use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};

pub type SharedRulesConfig = Arc<RwLock<RulesConfig>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Pass,
    Alert,
    Block,
}

impl Default for RuleAction {
    fn default() -> Self { Self::Block }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    pub enabled: bool,
    #[serde(default)]
    pub rules: HashMap<String, RuleAction>,
}

impl ToolConfig {
    pub fn rule_action(&self, name: &str) -> RuleAction {
        self.rules.get(name).copied().unwrap_or(RuleAction::Block)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    pub tools: HashMap<String, ToolConfig>,
}

fn tool(rules: &[(&str, RuleAction)]) -> ToolConfig {
    ToolConfig {
        enabled: true,
        rules: rules.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
    }
}

impl RulesConfig {
    pub fn default_config() -> Self {
        use RuleAction::*;

        let sql = &[
            ("destructive",          Block),
            ("privilege_escalation", Block),
            ("filesystem_access",    Block),
            ("remote_exec",          Block),
            ("injection",            Block),
            ("suspicious",           Alert), // warns only → show in panel
        ];
        let fs = &[("path_block", Block), ("path_mask", Alert)];

        let mut t = HashMap::new();
        t.insert("git-commit".into(), tool(&[("secret_scan", Block)]));
        t.insert("psql".into(),       tool(sql));
        t.insert("mysql".into(),      tool(sql));
        t.insert("mariadb".into(),    tool(sql));
        t.insert("sqlite3".into(),    tool(sql));
        t.insert("redis-cli".into(), tool(&[
            ("destructive",  Block),
            ("config_change", Alert),
            ("cluster_ops",  Block),
            ("acl_changes",  Block),
        ]));
        t.insert("kubectl-exec-sql".into(), tool(&[("sql_threat", Block)]));
        t.insert("docker".into(), tool(&[
            ("unsafe_run",    Block),
            ("volume_destroy",Block),
            ("force_remove",  Alert),
            ("system_prune",  Block),
            ("swarm_ops",     Alert),
            ("exec_warn",     Alert),
            ("push_warn",     Alert),
            ("login_warn",    Alert),
            ("commit_warn",   Alert),
            ("cp_warn",       Alert),
        ]));
        for name in ["cat", "head", "tail", "diff", "grep", "egrep", "find", "cp", "mv"] {
            t.insert(name.to_string(), tool(fs));
        }
        Self { tools: t }
    }

    pub fn load_or_default(path: &str) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(Self::default_config)
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let s = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, s)
    }

    pub fn is_tool_enabled(&self, name: &str) -> bool {
        self.tools.get(name).map_or(true, |t| t.enabled)
    }

    pub fn rule_action(&self, tool: &str, rule: &str) -> RuleAction {
        self.tools
            .get(tool)
            .map(|t| t.rule_action(rule))
            .unwrap_or(RuleAction::Block)
    }
}
