use std::io::Write as _;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::siem_config::{MinOutcome, SharedSiemConfig, SiemConfig, SiemProtocol};

// ── Sender ────────────────────────────────────────────────────────────────────

pub struct SiemSender {
    config:   SharedSiemConfig,
    udp_sock: Option<UdpSocket>,
}

impl SiemSender {
    pub fn new(config: SharedSiemConfig) -> Self {
        Self { config, udp_sock: None }
    }

    pub fn send_block(&mut self, tool: &str, pid: u32, args: &[String], code: &str, msg: &str) {
        self.maybe_send(MinOutcome::BlockOnly, 9, 3, "BLOCKED", tool, pid, args, code, msg);
    }

    pub fn send_alert(&mut self, tool: &str, pid: u32, args: &[String], code: &str, msg: &str) {
        self.maybe_send(MinOutcome::AlertAndAbove, 5, 5, "ALERTED", tool, pid, args, code, msg);
    }

    pub fn send_warn(&mut self, tool: &str, pid: u32, args: &[String], code: &str, msg: &str) {
        self.maybe_send(MinOutcome::WarnAndAbove, 7, 4, "WARNED", tool, pid, args, code, msg);
    }

    /// Send a synthetic test event. Returns error string on failure.
    pub fn send_test(&mut self) -> Result<(), String> {
        let cfg = self.config.read().unwrap().clone();
        if cfg.host.is_empty() {
            return Err("No SIEM host configured".into());
        }
        let cef = build_cef(5, "ALERTED", "protector-test", 0, &[], "TEST_EVENT",
                            "Protector SIEM connectivity test");
        let frame = syslog_frame(cfg.facility, 5, &cef);
        self.transmit(&cfg, frame.as_bytes()).map_err(|e| e.to_string())
    }

    fn maybe_send(
        &mut self,
        level:    MinOutcome,
        cef_sev:  u8,
        sl_sev:   u8,
        action:   &str,
        tool:     &str,
        pid:      u32,
        args:     &[String],
        code:     &str,
        msg:      &str,
    ) {
        let cfg = { self.config.read().unwrap().clone() };
        if !cfg.enabled || cfg.host.is_empty() { return; }
        if !passes_filter(cfg.min_outcome, level) { return; }

        let cef   = build_cef(cef_sev, action, tool, pid, args, code, msg);
        let frame = syslog_frame(cfg.facility, sl_sev, &cef);
        if let Err(e) = self.transmit(&cfg, frame.as_bytes()) {
            log::warn!("SIEM transmit failed: {e}");
        }
    }

    fn transmit(&mut self, cfg: &SiemConfig, data: &[u8]) -> anyhow::Result<()> {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        match cfg.protocol {
            SiemProtocol::Udp => self.send_udp(&addr, data),
            SiemProtocol::Tcp => send_tcp(&addr, data),
        }
    }

    fn send_udp(&mut self, addr: &str, data: &[u8]) -> anyhow::Result<()> {
        if self.udp_sock.is_none() {
            self.udp_sock = Some(UdpSocket::bind("0.0.0.0:0")?);
        }
        let dest = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve {addr}"))?;
        self.udp_sock.as_ref().unwrap().send_to(data, dest)?;
        Ok(())
    }
}

fn send_tcp(addr: &str, data: &[u8]) -> anyhow::Result<()> {
    use std::net::TcpStream;
    let dest = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {addr}"))?;
    let mut s = TcpStream::connect_timeout(&dest, Duration::from_secs(3))?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(data)?;
    s.write_all(b"\n")?; // RFC 6587 newline framing
    Ok(())
}

// ── Filtering ─────────────────────────────────────────────────────────────────

fn passes_filter(filter: MinOutcome, event_level: MinOutcome) -> bool {
    level_rank(event_level) >= level_rank(filter)
}

fn level_rank(o: MinOutcome) -> u8 {
    match o {
        MinOutcome::All           => 1,
        MinOutcome::WarnAndAbove  => 2,
        MinOutcome::AlertAndAbove => 3,
        MinOutcome::BlockOnly     => 4,
    }
}

// ── CEF formatter ─────────────────────────────────────────────────────────────

fn build_cef(
    cef_sev: u8,
    action:  &str,
    tool:    &str,
    pid:     u32,
    args:    &[String],
    code:    &str,
    msg:     &str,
) -> String {
    let host = hostname();
    let sig  = cef_hdr(code);
    let name = cef_hdr(code);
    let tool_e = cef_ext(tool);
    let act_e  = cef_ext(action);
    let msg_e  = cef_ext(first_line(msg));
    let args_e = cef_ext(&args.join(" "));

    format!(
        "CEF:0|Protector|Protector Agent Shield|0.1|{sig}|{name}|{cef_sev}|\
         src={host} spt={pid} app={tool_e} act={act_e} msg={msg_e} \
         cs1={args_e} cs1Label=cmdArgs"
    )
}

fn syslog_frame(facility: u8, sev: u8, cef: &str) -> String {
    let pri  = facility as u32 * 8 + sev as u32;
    let ts   = syslog_ts();
    let host = hostname();
    format!("<{pri}>{ts} {host} protector: {cef}")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "protector-host".to_string())
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("")
}

/// Escape CEF header field (pipe-delimited section).
fn cef_hdr(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape CEF extension value (key=value section).
fn cef_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('=', "\\=")
     .replace('\n', "\\n")
     .replace('\r', "")
}

fn syslog_ts() -> String {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        let mon = ["Jan","Feb","Mar","Apr","May","Jun",
                   "Jul","Aug","Sep","Oct","Nov","Dec"]
            .get(tm.tm_mon as usize).unwrap_or(&"Jan");
        format!("{} {:2} {:02}:{:02}:{:02}",
            mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}
