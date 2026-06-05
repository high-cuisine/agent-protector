//! Windows ProcessTracker — enumerates running processes via Toolhelp32
//! to decide whether a given PID is a descendant of a Claude Code process.
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub struct ProcessTracker {
    ppid_cache:  HashMap<u32, u32>,
    exe_cache:   HashMap<u32, String>,
    claude_pids: HashSet<u32>,
    last_refresh: Instant,
    last_logged:  Option<Vec<u32>>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        let mut t = Self {
            ppid_cache:  HashMap::new(),
            exe_cache:   HashMap::new(),
            claude_pids: HashSet::new(),
            last_refresh: Instant::now() - Duration::from_secs(60),
            last_logged:  None,
        };
        t.refresh();
        t
    }

    pub fn claude_root_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self.claude_pids.iter().copied().collect();
        pids.sort_unstable();
        pids
    }

    pub fn refresh_and_diff(&mut self) -> (Vec<u32>, Vec<u32>) {
        let old = self.claude_pids.clone();
        self.refresh();
        let added   = self.claude_pids.difference(&old).copied().collect();
        let removed = old.difference(&self.claude_pids).copied().collect();
        (added, removed)
    }

    pub fn is_claude_descendant(&mut self, pid: u32) -> bool {
        if self.last_refresh.elapsed() > Duration::from_secs(5) {
            self.refresh();
        }
        let mut current = pid;
        for _ in 0..32 {
            if self.claude_pids.contains(&current) { return true; }
            if current <= 4 { break; }
            match self.ppid_cache.get(&current).copied() {
                Some(ppid) if ppid != current => current = ppid,
                _ => break,
            }
        }
        false
    }

    fn refresh(&mut self) {
        self.last_refresh = Instant::now();
        self.ppid_cache.clear();
        self.exe_cache.clear();
        self.claude_pids.clear();

        #[cfg(windows)]
        self.refresh_windows();

        let mut sorted: Vec<u32> = self.claude_pids.iter().copied().collect();
        sorted.sort_unstable();
        if self.last_logged.as_ref() != Some(&sorted) {
            self.last_logged = Some(sorted.clone());
            if sorted.is_empty() {
                log::warn!(
                    "No Claude/Code root processes found — run Claude Code on this host."
                );
            } else {
                log::info!("Claude/Code root PIDs (watching descendants): {:?}", sorted);
            }
        } else {
            log::debug!("Claude/Code root PIDs unchanged: {:?}", sorted);
        }
    }

    #[cfg(windows)]
    fn refresh_windows(&mut self) {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE { return; }

        let mut entry = PROCESSENTRY32W {
            dwSize:             std::mem::size_of::<PROCESSENTRY32W>() as u32,
            cntUsage:           0,
            th32ProcessID:      0,
            th32DefaultHeapID:  0,
            th32ModuleID:       0,
            cntThreads:         0,
            th32ParentProcessID: 0,
            pcPriClassBase:     0,
            dwFlags:            0,
            szExeFile:          [0u16; 260],
        };

        let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
        while ok != 0 {
            let pid  = entry.th32ProcessID;
            let ppid = entry.th32ParentProcessID;
            let end  = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
            let exe  = OsString::from_wide(&entry.szExeFile[..end])
                .to_string_lossy()
                .to_ascii_lowercase();

            self.ppid_cache.insert(pid, ppid);
            self.exe_cache.insert(pid, exe.clone());

            if is_claude_exe(&exe) {
                self.claude_pids.insert(pid);
            }

            ok = unsafe { Process32NextW(snapshot, &mut entry) };
        }
        unsafe { CloseHandle(snapshot) };
    }
}

fn is_claude_exe(exe: &str) -> bool {
    exe == "claude.exe"
        || exe.starts_with("claude")
        || exe.contains("claude-code")
        || exe.contains("claude_code")
}

/// Terminate a process on Windows (equivalent of SIGKILL + SIGCONT on Linux).
pub fn terminate_process(pid: u32) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !handle.is_null() {
            TerminateProcess(handle, 1);
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
    }
    #[cfg(not(windows))]
    log::warn!("terminate_process called on non-Windows (pid={pid})");
}
