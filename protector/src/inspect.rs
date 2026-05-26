use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;

use crate::event_bus::{InspectEvent, InspectOutcome};

// ANSI color helpers
const RESET:  &str = "\x1b[0m";
const BOLD:   &str = "\x1b[1m";
const GREEN:  &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED:    &str = "\x1b[31m";
const DIM:    &str = "\x1b[2m";

pub async fn run(socket_path: &str) -> anyhow::Result<()> {
    let stream = connect_with_retry(socket_path, 3).await?;
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    print_header();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n{DIM}[inspect] disconnected{RESET}");
                break;
            }
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => print_event(&l),
                    Ok(None)    => {
                        println!("{DIM}[inspect] daemon closed connection{RESET}");
                        break;
                    }
                    Err(e) => {
                        eprintln!("{RED}[inspect] read error: {e}{RESET}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn connect_with_retry(path: &str, retries: u32) -> anyhow::Result<UnixStream> {
    let mut last_err = anyhow::anyhow!("no attempts made");
    for attempt in 0..retries {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        match UnixStream::connect(path).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = e.into(),
        }
    }
    Err(last_err).map_err(|e| {
        anyhow::anyhow!(
            "Cannot connect to inspect socket {path}: {e}\n\
             Is the protector daemon running? (sudo protector)"
        )
    })
}

fn print_header() {
    println!(
        "{BOLD}{DIM}{:<12} {:<9} {:<18} {:<35} {}{RESET}",
        "TIME", "OUTCOME", "TOOL", "COMMAND", "DETAIL"
    );
    println!("{DIM}{}{RESET}", "─".repeat(100));
}

fn print_event(line: &str) {
    let ev: InspectEvent = match serde_json::from_str(line) {
        Ok(e)  => e,
        Err(_) => return,
    };

    let time = format_time(ev.ts_ms);
    let cmd  = ev.args.join(" ");
    let cmd  = truncate(&cmd, 35);

    let (color, label, detail) = match &ev.outcome {
        InspectOutcome::Allowed => (GREEN, "ALLOWED  ", String::new()),
        InspectOutcome::Alerted { message, .. } => {
            (YELLOW, "ALERTED  ", first_line(message))
        }
        InspectOutcome::Warned { message, .. } => {
            (YELLOW, "WARNED   ", first_line(message))
        }
        InspectOutcome::Blocked { message, .. } => {
            (RED, "BLOCKED  ", first_line(message))
        }
    };

    println!(
        "{color}{:<12} {BOLD}{:<9}{RESET}{color} {:<18} {:<35} {}{RESET}",
        time, label, truncate(&ev.tool, 18), cmd, detail,
    );

    if !detail.is_empty() {
        println!("  {DIM}↳ pid={} args: {}{RESET}", ev.pid, ev.args.join(" "));
    }
}

fn format_time(ts_ms: u64) -> String {
    let secs = ts_ms / 1000;
    let ms   = ts_ms % 1000;
    let h    = (secs / 3600) % 24;
    let m    = (secs / 60) % 60;
    let s    = secs % 60;
    format!("{h:02}:{m:02}:{s:02}.{ms:03}")
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
