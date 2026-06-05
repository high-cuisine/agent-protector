//! Windows event bus: broadcast channel + named-pipe server for `protector-win inspect`.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

pub type EventSender   = broadcast::Sender<InspectEvent>;
pub type SharedHistory = Arc<Mutex<VecDeque<InspectEvent>>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum InspectOutcome {
    Allowed,
    Alerted { threat_code: String, message: String },
    Warned  { threat_code: String, message: String },
    Blocked { threat_code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectEvent {
    pub ts_ms:   u64,
    pub pid:     u32,
    pub tool:    String,
    pub args:    Vec<String>,
    pub outcome: InspectOutcome,
}

pub fn new_sender() -> EventSender {
    broadcast::channel::<InspectEvent>(1024).0
}

pub fn new_history() -> SharedHistory {
    Arc::new(Mutex::new(VecDeque::new()))
}

pub fn record(history: &SharedHistory, event: &InspectEvent) {
    let mut h = history.lock().unwrap();
    h.push_back(event.clone());
    if h.len() > 2000 { h.pop_front(); }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Named-pipe path for the `inspect` subcommand (Windows equivalent of Unix socket).
pub fn pipe_path() -> String {
    std::env::var("PROTECTOR_INSPECT_PIPE")
        .unwrap_or_else(|_| r"\\.\pipe\protector-win-inspect".to_string())
}

/// Start a named-pipe server that streams events to connecting clients.
/// Each connecting client receives the full history replay first.
#[cfg(windows)]
pub async fn start_inspect_server(tx: EventSender, history: SharedHistory) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = pipe_path();
    log::info!("Inspect pipe: {pipe_name}  (protector-win inspect)");

    loop {
        let server = ServerOptions::new()
            .access_outbound(true)
            .access_inbound(false)
            .create(&pipe_name)?;

        server.connect().await?;

        let rx   = tx.subscribe();
        let hist = Arc::clone(&history);
        tokio::spawn(async move {
            let past: Vec<InspectEvent> = hist.lock().unwrap().iter().cloned().collect();
            let mut conn = server;
            for ev in past {
                if write_event_pipe(&mut conn, &ev).await.is_err() { return; }
            }
            let mut rx = rx;
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if write_event_pipe(&mut conn, &ev).await.is_err() { return; }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
    }
}

#[cfg(windows)]
async fn write_event_pipe<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    ev: &InspectEvent,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let json = serde_json::to_string(ev)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    w.write_all(json.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await
}

/// No-op on non-Windows so the file compiles in cross-check mode.
#[cfg(not(windows))]
pub async fn start_inspect_server(_tx: EventSender, _history: SharedHistory) -> anyhow::Result<()> {
    Ok(())
}
