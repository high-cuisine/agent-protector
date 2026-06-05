//! `protector-win setup` — installs the daemon as a Windows service and
//! installs shim wrapper executables into a dedicated directory in PATH.
use std::path::PathBuf;

/// Default installation directory.
const INSTALL_DIR: &str = r"C:\Program Files\Protector";
/// Subdirectory that holds the shim wrappers (placed first in system PATH).
const SHIM_DIR: &str    = r"C:\Program Files\Protector\shim";

/// Watched tool names that need a shim wrapper.
const WATCHED_TOOLS: &[&str] = &[
    "git", "psql", "mysql", "mariadb", "sqlite3", "redis-cli",
    "npm", "pip", "pip3", "curl", "wget", "docker", "kubectl",
    "cat", "head", "tail", "grep", "egrep", "fgrep",
    "diff", "find", "cp", "mv",
];

pub fn run() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;

    // 1. Copy daemon binary
    let install_dir = PathBuf::from(INSTALL_DIR);
    let shim_dir    = PathBuf::from(SHIM_DIR);
    std::fs::create_dir_all(&install_dir)?;
    std::fs::create_dir_all(&shim_dir)?;

    let daemon_dst = install_dir.join("protector-win.exe");
    std::fs::copy(&exe, &daemon_dst)?;
    println!("Daemon installed: {}", daemon_dst.display());

    // 2. Find shim.exe alongside this binary (built from the `shim` crate)
    let shim_src = exe.parent()
        .map(|p| p.join("shim.exe"))
        .filter(|p| p.exists())
        .ok_or_else(|| anyhow::anyhow!(
            "shim.exe not found next to protector-win.exe — build it with: \
             cargo build --release -p shim"
        ))?;

    // 3. Install one copy of shim.exe per watched tool
    for &tool in WATCHED_TOOLS {
        let dst = shim_dir.join(format!("{tool}.exe"));
        std::fs::copy(&shim_src, &dst)?;
        println!("Shim installed: {}", dst.display());
    }

    // 4. Register Windows service via sc.exe
    install_service(&daemon_dst)?;

    // 5. Prepend shim directory to system PATH (requires elevation)
    prepend_path(&shim_dir)?;

    println!("\nSetup complete.");
    println!("  Service      : Protector (auto-start on boot, running now)");
    println!("  Manage       : sc stop Protector | sc start Protector | sc query Protector");
    println!("  Web dashboard: http://127.0.0.1:7878");
    println!("  Shim dir     : {SHIM_DIR}  (prepended to system PATH)");
    println!("\nOpen a NEW terminal/agent session so the updated PATH takes effect.");
    Ok(())
}

fn install_service(daemon_path: &PathBuf) -> anyhow::Result<()> {
    // Delete old service if present (ignore errors)
    let _ = std::process::Command::new("sc")
        .args(["delete", "Protector"])
        .status();

    let status = std::process::Command::new("sc")
        .args([
            "create", "Protector",
            "binPath=", &daemon_path.to_string_lossy(),
            "start=", "auto",
            "DisplayName=", "Protector Agent Security Daemon",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("sc create failed — are you running as Administrator?");
    }
    println!("Windows service 'Protector' registered (start=auto, runs on every boot).");

    // Start it now so the user doesn't have to reboot or start it manually.
    let started = std::process::Command::new("sc")
        .args(["start", "Protector"])
        .status();
    match started {
        Ok(s) if s.success() => println!("Windows service 'Protector' started."),
        _ => println!(
            "Note: could not auto-start the service now — start it with `sc start Protector` \
             (it will also start automatically on the next boot)."
        ),
    }
    Ok(())
}

const ENV_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

fn prepend_path(shim_dir: &PathBuf) -> anyhow::Result<()> {
    let current = read_system_path()?;

    // SAFETY GUARD: never write back an empty / unparseable PATH — doing so
    // would wipe the system PATH and can render Windows unbootable.
    if current.trim().is_empty() {
        anyhow::bail!(
            "Refusing to modify system PATH: could not read the existing value. \
             Add '{}' to PATH manually.",
            shim_dir.display()
        );
    }

    let shim_str = shim_dir.to_string_lossy();
    if current
        .split(';')
        .any(|p| p.trim().eq_ignore_ascii_case(shim_str.trim()))
    {
        println!("Shim dir already in system PATH.");
        return Ok(());
    }

    let new_path = format!("{shim_str};{current}");
    let status = std::process::Command::new("reg")
        .args([
            "add", ENV_KEY,
            "/v", "Path",
            "/t", "REG_EXPAND_SZ",
            "/d", &new_path,
            "/f",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("reg add failed — are you running as Administrator?");
    }
    println!("Shim dir prepended to system PATH (restart required for existing processes).");
    Ok(())
}

/// Read the current system `Path` value from the registry, robustly.
///
/// `reg query ... /v Path` prints one value line:
///   `    Path    REG_EXPAND_SZ    C:\Windows;C:\Windows\system32;...`
/// We split on the type marker rather than counting spaces so the value is
/// extracted intact regardless of the exact whitespace `reg` emits.
fn read_system_path() -> anyhow::Result<String> {
    let output = std::process::Command::new("reg")
        .args(["query", ENV_KEY, "/v", "Path"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("reg query for system PATH failed (are you Administrator?)");
    }
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        // The value name must be exactly "Path".
        let Some(first) = line.split_whitespace().next() else { continue };
        if !first.eq_ignore_ascii_case("Path") {
            continue;
        }
        for marker in ["REG_EXPAND_SZ", "REG_SZ"] {
            if let Some(idx) = line.find(marker) {
                let val = line[idx + marker.len()..].trim();
                if !val.is_empty() {
                    return Ok(val.to_string());
                }
            }
        }
    }
    anyhow::bail!("could not locate the Path value in reg query output")
}
