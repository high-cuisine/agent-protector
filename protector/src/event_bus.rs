use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

pub type EventSender  = broadcast::Sender<InspectEvent>;
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
    if h.len() > 2000 {
        h.pop_front();
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn socket_path() -> String {
    std::env::var("PROTECTOR_SOCKET")
        .unwrap_or_else(|_| "/tmp/protector-inspect.sock".to_string())
}

pub async fn start_unix_server(tx: EventSender, history: SharedHistory) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    log::info!("Inspect socket: {path}  (protector inspect)");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let rx   = tx.subscribe();
                let hist = Arc::clone(&history);
                tokio::spawn(serve_client(stream, rx, hist));
            }
            Err(e) => log::warn!("inspect socket accept: {e}"),
        }
    }
}

async fn serve_client(
    stream:  tokio::net::UnixStream,
    mut rx:  broadcast::Receiver<InspectEvent>,
    history: SharedHistory,
) {
    use tokio::io::BufWriter;

    let mut w = BufWriter::new(stream);

    // Replay history so `inspect` sees lifetime events from daemon start
    let past: Vec<InspectEvent> = history.lock().unwrap().iter().cloned().collect();
    for ev in past {
        if write_event(&mut w, &ev).await.is_err() { return; }
    }

    loop {
        match rx.recv().await {
            Ok(ev) => { if write_event(&mut w, &ev).await.is_err() { return; } }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => break,
        }
    }
}

async fn write_event<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut tokio::io::BufWriter<W>,
    ev: &InspectEvent,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let json = serde_json::to_string(ev)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    w.write_all(json.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await
}
