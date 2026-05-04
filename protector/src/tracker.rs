use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

pub struct ProcessTracker {
    /// Cache of PID -> PPID to avoid repeated /proc reads
    ppid_cache: HashMap<u32, u32>,
    /// PIDs we've identified as Claude Code instances
    claude_pids: HashSet<u32>,
    last_claude_refresh: Instant,
    /// Last snapshot we logged at `info` (avoid spamming every refresh)
    last_logged_claude_snapshot: Option<Vec<u32>>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        let mut tracker = Self {
            ppid_cache: HashMap::new(),
            claude_pids: HashSet::new(),
            last_claude_refresh: Instant::now() - Duration::from_secs(60),
            last_logged_claude_snapshot: None,
        };
        tracker.refresh_claude_pids();
        tracker
    }

    /// Root PIDs we treat as Claude/Code (sorted). Descendants of these are validated.
    pub fn claude_root_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self.claude_pids.iter().copied().collect();
        pids.sort_unstable();
        pids
    }

    /// Returns true if `pid` is a descendant of a Claude Code process.
    pub fn is_claude_descendant(&mut self, pid: u32) -> bool {
        if self.last_claude_refresh.elapsed() > Duration::from_secs(5) {
            self.refresh_claude_pids();
            self.last_claude_refresh = Instant::now();
        }

        let mut current = pid;
        // Avoid infinite loops from malformed /proc entries
        for _ in 0..32 {
            if self.claude_pids.contains(&current) {
                return true;
            }
            if current <= 1 {
                break;
            }
            match self.ppid(current) {
                Some(ppid) if ppid != current => current = ppid,
                _ => break,
            }
        }
        false
    }

    fn ppid(&mut self, pid: u32) -> Option<u32> {
        if let Some(&cached) = self.ppid_cache.get(&pid) {
            return Some(cached);
        }
        let ppid = read_ppid(pid)?;
        self.ppid_cache.insert(pid, ppid);
        Some(ppid)
    }

    /// Scan /proc to find all running Claude Code processes.
    fn refresh_claude_pids(&mut self) {
        self.claude_pids.clear();
        // Evict stale ppid cache entries too
        self.ppid_cache.retain(|pid, _| proc_exists(*pid));

        let Ok(entries) = fs::read_dir("/proc") else {
            return;
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };

            if is_claude_process(pid) {
                self.claude_pids.insert(pid);
            }
        }

        let mut sorted: Vec<u32> = self.claude_pids.iter().copied().collect();
        sorted.sort_unstable();
        if self.last_logged_claude_snapshot.as_ref() != Some(&sorted) {
            self.last_logged_claude_snapshot = Some(sorted.clone());
            if sorted.is_empty() {
                log::warn!(
                    "No Claude/Code root processes found in /proc — only descendants of detected roots are monitored. \
                     Run Claude Code on this host (or use RUST_LOG=debug to see every exec we skip)."
                );
            } else {
                log::info!(
                    "Claude/Code root PIDs (watching descendants): {:?}",
                    sorted
                );
            }
        } else {
            log::debug!("Claude/Code root PIDs unchanged: {:?}", sorted);
        }
    }
}

fn cmdline_indicates_claude(cmdline_str: &str) -> bool {
    let lower = cmdline_str.to_ascii_lowercase();
    lower.contains("claude")
        || lower.contains("claude-code")
        || lower.contains("@anthropic-ai/claude")
        || lower.contains("anthropic-ai/claude")
        || lower.contains("/.claude/")
        || lower.contains("claude code")
}

fn is_claude_process(pid: u32) -> bool {
    // Check the comm name (first 15 chars of argv[0])
    if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid)) {
        let comm = comm.trim().to_ascii_lowercase();
        if comm == "claude" || comm.starts_with("claude") {
            return true;
        }
    }

    // Check full cmdline for node processes running Claude Code
    if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", pid)) {
        let cmdline_str = cmdline
            .split(|&b| b == 0)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        if cmdline_indicates_claude(&cmdline_str) {
            return true;
        }
    }

    false
}

fn read_ppid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn proc_exists(pid: u32) -> bool {
    fs::metadata(format!("/proc/{}", pid)).is_ok()
}
