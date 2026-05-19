/// Block/warn event reporter.
///
/// On every Block or Warn event:
///  1. Prints a coloured mini-report with pixel-art knight to stderr.
///  2. Appends a plain-text record to a daily log file.
///
/// Report directory (first writable):
///   $PROTECTOR_REPORT_DIR  → /var/log/protector  → /tmp/protector
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::errors::ThreatError;

// ── ANSI palette ──────────────────────────────────────────────────────────────

const RS:     &str = "\x1b[0m";
const BOLD:   &str = "\x1b[1m";
const DIM:    &str = "\x1b[2m";
const RED:    &str = "\x1b[38;2;210;55;55m";
const YELLOW: &str = "\x1b[38;2;220;185;40m";
const CYAN:   &str = "\x1b[38;2;80;200;200m";

fn knight_color(c: char) -> &'static str {
    match c {
        'K' => "\x1b[38;2;15;15;15m",
        'D' => "\x1b[38;2;26;74;74m",
        'M' => "\x1b[38;2;42;110;110m",
        'R' => "\x1b[38;2;176;32;32m",
        'N' => "\x1b[38;2;212;168;112m",
        _   => "",
    }
}

// ── Mini pixel-art knight (8 × 8 chars, each char → "██") ────────────────────
//
// Color key:  R=red plume  D=dark-teal  M=mid-teal  K=near-black  N=gold-tan

const MINI: [&str; 8] = [
    "..RRRR..",   //  plume
    ".DMMMMM.",   //  helmet top
    ".DMDMMD.",   //  visor (D = eye-slit dark)
    ".DKKKKKD",   //  visor shadow
    ".DMMMMMD",   //  chin guard
    "NDDDDDDN",   //  shoulder pauldrons
    "NDDKKDDN",   //  chest plate
    ".DD..DD.",   //  lower body
];

fn render_knight_row(row: &str) -> String {
    let mut out = String::new();
    let mut cur: Option<char> = None;
    for ch in row.chars() {
        if ch == '.' {
            if cur.is_some() { out.push_str(RS); cur = None; }
            out.push_str("  ");
        } else {
            if cur != Some(ch) { out.push_str(knight_color(ch)); cur = Some(ch); }
            out.push_str("██");
        }
    }
    if cur.is_some() { out.push_str(RS); }
    out
}

// ── Reporter ──────────────────────────────────────────────────────────────────

pub struct Reporter {
    report_dir: PathBuf,
}

impl Reporter {
    pub fn new() -> Self {
        let dir = resolve_report_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            log::warn!("reporter: cannot create {:?}: {e}", dir);
        } else {
            log::info!("reporter: block reports → {:?}", dir);
        }
        Self { report_dir: dir }
    }

    /// Call after a Block result.
    pub fn block(&self, action: &str, pid: u32, args: &[String], threat: &ThreatError) {
        let ts = now();
        let path = self.append_report("BLOCKED", action, pid, args, threat, &ts);
        print_report("BLOCKED", action, pid, args, threat, &ts, path.as_deref());
    }

    /// Call after a Warn result.
    pub fn warn(&self, action: &str, pid: u32, args: &[String], threat: &ThreatError) {
        let ts = now();
        let path = self.append_report("WARNING", action, pid, args, threat, &ts);
        print_report("WARNING", action, pid, args, threat, &ts, path.as_deref());
    }

    fn append_report(
        &self,
        kind:   &str,
        action: &str,
        pid:    u32,
        args:   &[String],
        threat: &ThreatError,
        ts:     &str,
    ) -> Option<PathBuf> {
        // One file per day: YYYY-MM-DD.log
        let date = &ts[..10];
        let path = self.report_dir.join(format!("{date}.log"));

        let body = format!(
            "{eq}\n\
             [{ts}]  {kind}  [{code}]\n\
             Tool:    {action}\n\
             PID:     {pid}\n\
             Command: {cmd}\n\
             \n\
             {detail}\n\
             {dash}\n\n",
            eq     = "═".repeat(64),
            dash   = "─".repeat(64),
            code   = threat.code(),
            cmd    = args.join(" "),
            detail = threat,
        );

        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| f.write_all(body.as_bytes()).map(|_| ()))
            .map(|_| path.clone())
            .map_err(|e| log::warn!("reporter: write {:?}: {e}", path))
            .ok()
    }
}

// ── Terminal report ───────────────────────────────────────────────────────────

fn print_report(
    kind:   &str,
    action: &str,
    pid:    u32,
    args:   &[String],
    threat: &ThreatError,
    ts:     &str,
    report: Option<&Path>,
) {
    let (accent, icon) = if kind == "BLOCKED" {
        (RED,    "⚔  ")
    } else {
        (YELLOW, "⚠  ")
    };

    let code    = threat.code();
    let cmd     = args.join(" ");
    let detail  = threat.to_string();
    let d_lines = detail_lines(&detail);

    // Eight info lines — one per knight row.
    let sep = format!("{DIM}{}{}",
        "─".repeat(48), RS);
    let saved = report
        .map(|p| format!("{DIM}saved → {}{RS}", p.display()))
        .unwrap_or_default();

    let info: [String; 8] = [
        format!("{accent}{BOLD}{icon}{kind}{RS}  {CYAN}{action}{RS}  {DIM}[{code}]{RS}"),
        format!("{DIM}pid={pid}   {ts}{RS}"),
        format!("{DIM}cmd:{RS} {}", clip(&cmd, 46)),
        sep,
        d_line(&d_lines, 0),
        d_line(&d_lines, 1),
        d_line(&d_lines, 2),
        saved,
    ];

    // Accent bar width: knight(16px) + indent(2) + gap(3) + content
    let bar = format!("{accent}  {}{RS}", "─".repeat(66));

    eprintln!();
    eprintln!("{bar}");
    for (row, side) in MINI.iter().zip(info.iter()) {
        eprintln!("  {}   {}", render_knight_row(row), side);
    }
    eprintln!("{bar}");
    eprintln!();
}

fn detail_lines(detail: &str) -> Vec<String> {
    detail.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| clip(l, 52).to_string())
        .collect()
}

fn d_line(lines: &[String], i: usize) -> String {
    lines.get(i).cloned().unwrap_or_default()
}

fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    &s[..end]
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn resolve_report_dir() -> PathBuf {
    if let Ok(d) = std::env::var("PROTECTOR_REPORT_DIR") {
        return PathBuf::from(d);
    }
    if unsafe { libc::geteuid() == 0 } {
        return PathBuf::from("/var/log/protector");
    }
    std::env::var("XDG_STATE_HOME")
        .map(|d| PathBuf::from(d).join("protector"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/protector"))
}

fn now() -> String {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
        )
    }
}
