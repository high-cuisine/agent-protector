use std::path::{Path, PathBuf};

const INSTALL_PATH: &str = "/usr/local/bin/protector";
const WORK_DIR:     &str = "/etc/protector";

pub fn run() -> anyhow::Result<()> {
    println!("Installing protector...");

    install_binary()?;
    create_work_dir()?;
    install_service()?;
    install_shell_config()?;

    println!("\nprotector installed successfully.");
    println!("  binary      : {INSTALL_PATH}");
    println!("  config dir  : {WORK_DIR}");
    println!("  shell alias : `protector inspect` (reload your shell)");
    Ok(())
}

// ── Binary ────────────────────────────────────────────────────────────────────

fn install_binary() -> anyhow::Result<()> {
    let current = std::env::current_exe()?;
    if Path::new(INSTALL_PATH) == current.as_path() {
        println!("  [skip] already running from {INSTALL_PATH}");
        return Ok(());
    }
    std::fs::copy(&current, INSTALL_PATH)?;
    set_permissions(INSTALL_PATH, 0o755)?;
    println!("  [ok]   copied binary → {INSTALL_PATH}");
    Ok(())
}

// ── Work directory ────────────────────────────────────────────────────────────

fn create_work_dir() -> anyhow::Result<()> {
    std::fs::create_dir_all(WORK_DIR)?;
    println!("  [ok]   work directory {WORK_DIR}");
    Ok(())
}

// ── System service ────────────────────────────────────────────────────────────

fn install_service() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    install_systemd()?;
    #[cfg(target_os = "macos")]
    install_launchd()?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    println!("  [skip] service install not supported on this platform");
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_systemd() -> anyhow::Result<()> {
    let unit = format!(
        "[Unit]\n\
         Description=Protector — AI agent action monitor\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={INSTALL_PATH}\n\
         WorkingDirectory={WORK_DIR}\n\
         Restart=always\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let path = "/etc/systemd/system/protector.service";
    std::fs::write(path, &unit)?;
    println!("  [ok]   systemd unit → {path}");

    let status = std::process::Command::new("systemctl")
        .args(["enable", "--now", "protector"])
        .status();
    match status {
        Ok(s) if s.success() => println!("  [ok]   systemctl enable --now protector"),
        Ok(s) => println!("  [warn] systemctl exited {s}"),
        Err(e) => println!("  [warn] systemctl not available: {e}"),
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launchd() -> anyhow::Result<()> {
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
           <key>Label</key><string>com.protector.daemon</string>\n\
           <key>ProgramArguments</key>\n\
           <array><string>{INSTALL_PATH}</string></array>\n\
           <key>WorkingDirectory</key><string>{WORK_DIR}</string>\n\
           <key>KeepAlive</key><true/>\n\
           <key>RunAtLoad</key><true/>\n\
           <key>StandardOutPath</key><string>/var/log/protector.log</string>\n\
           <key>StandardErrorPath</key><string>/var/log/protector.log</string>\n\
         </dict>\n\
         </plist>\n"
    );
    let path = "/Library/LaunchDaemons/com.protector.daemon.plist";
    std::fs::write(path, &plist)?;
    set_permissions(path, 0o644)?;
    println!("  [ok]   launchd plist → {path}");

    let status = std::process::Command::new("launchctl")
        .args(["load", "-w", path])
        .status();
    match status {
        Ok(s) if s.success() => println!("  [ok]   launchctl load -w {path}"),
        Ok(s) => println!("  [warn] launchctl exited {s}"),
        Err(e) => println!("  [warn] launchctl not available: {e}"),
    }
    Ok(())
}

// ── Shell config ──────────────────────────────────────────────────────────────

const MARKER_BEGIN: &str = "# >>> protector";
const MARKER_END:   &str = "# <<< protector";

const SHELL_SNIPPET: &str = r#"export PATH="/usr/local/bin:$PATH"
alias protector-inspect='protector inspect'"#;

fn install_shell_config() -> anyhow::Result<()> {
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates: &[&str] = &[".bashrc", ".zshrc", ".bash_profile", ".profile"];

    let mut installed = false;
    for rc in candidates {
        let path = PathBuf::from(&home).join(rc);
        if path.exists() {
            match patch_shell_file(&path) {
                Ok(true)  => { println!("  [ok]   patched {}", path.display()); installed = true; }
                Ok(false) => { println!("  [skip] already present in {}", path.display()); installed = true; }
                Err(e)    => println!("  [warn] {}: {e}", path.display()),
            }
        }
    }
    if !installed {
        println!("  [warn] no shell rc files found in {home}; add manually:");
        println!("         {SHELL_SNIPPET}");
    }
    Ok(())
}

fn patch_shell_file(path: &Path) -> anyhow::Result<bool> {
    let content = std::fs::read_to_string(path)?;
    if content.contains(MARKER_BEGIN) {
        return Ok(false); // already patched
    }
    let addition = format!("\n{MARKER_BEGIN}\n{SHELL_SNIPPET}\n{MARKER_END}\n");
    let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
    use std::io::Write;
    f.write_all(addition.as_bytes())?;
    Ok(true)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn set_permissions(path: &str, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_permissions(_path: &str, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}
