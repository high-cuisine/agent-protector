use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::Response,
    Router,
};
use bytes::Bytes;
use futures_util::StreamExt;
use log::{debug, info, warn};
use serde_json::Value;

use crate::budget::SharedBudget;

const ANTHROPIC_API: &str = "https://api.anthropic.com";

#[derive(Clone)]
struct ProxyState {
    client: reqwest::Client,
    budget: SharedBudget,
}

pub async fn start(budget: SharedBudget, port: u16) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let state = ProxyState { client, budget };

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Token proxy → http://{addr}  (set ANTHROPIC_BASE_URL=http://{addr})");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn proxy_handler(State(state): State<ProxyState>, req: Request) -> Response<Body> {
    if req.uri().path() == "/v1/messages" && req.method() == Method::POST {
        messages_handler(state, req).await
    } else {
        passthrough_handler(state, req).await
    }
}

// ── /v1/messages interception ─────────────────────────────────────────────────

async fn messages_handler(state: ProxyState, req: Request) -> Response<Body> {
    let (parts, body) = req.into_parts();

    let body_bytes = match axum::body::to_bytes(body, 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "cannot read request body"),
    };

    let model     = extract_model(&body_bytes);
    let is_stream = extract_is_stream(&body_bytes);

    // Block before hitting Anthropic if budget exhausted
    if let Some(reason) = state.budget.write().unwrap().check_limit(&model) {
        info!("[token-proxy] Budget exceeded for '{model}': {reason}");
        return budget_exceeded_response(&model, &reason, is_stream);
    }

    // Forward to Anthropic
    let mut req_builder = state.client.post(format!("{ANTHROPIC_API}/v1/messages"));
    for (name, value) in &parts.headers {
        let n = name.as_str();
        if n != "host" && n != "content-length" {
            req_builder = req_builder.header(n, value);
        }
    }
    req_builder = req_builder.body(body_bytes);

    let upstream = match req_builder.send().await {
        Ok(r)  => r,
        Err(e) => {
            warn!("[token-proxy] upstream: {e}");
            return error_response(StatusCode::BAD_GATEWAY, &e.to_string());
        }
    };

    let axum_status  = StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::OK);
    let resp_headers = upstream.headers().clone();

    // Pipe stream through while accumulating for usage parsing
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let budget = Arc::clone(&state.budget);

    tokio::spawn(async move {
        let mut byte_stream = upstream.bytes_stream();
        let mut buf = String::new();

        while let Some(chunk) = byte_stream.next().await {
            match chunk {
                Ok(b) => {
                    buf.push_str(&String::from_utf8_lossy(&b));
                    if tx.send(Ok(b)).await.is_err() { break; }
                }
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    break;
                }
            }
        }

        let (inp, out) = parse_usage(&buf, is_stream);
        if inp > 0 || out > 0 {
            debug!("[token-proxy] model={model} input={inp} output={out}");
            budget.write().unwrap().record(&model, inp, out);
        }
    });

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });

    let mut builder = Response::builder().status(axum_status);
    for (name, value) in &resp_headers {
        if name.as_str() != "content-length" {
            builder = builder.header(name.as_str(), value);
        }
    }
    builder.body(Body::from_stream(stream)).unwrap_or_else(|_| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "body error")
    })
}

// ── Transparent passthrough for other paths ───────────────────────────────────

async fn passthrough_handler(state: ProxyState, req: Request) -> Response<Body> {
    let pq  = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{ANTHROPIC_API}{pq}");

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 8 * 1024 * 1024).await.ok();

    let mut req_builder = state.client.request(method, &url);
    for (name, value) in &parts.headers {
        let n = name.as_str();
        if n != "host" && n != "content-length" {
            req_builder = req_builder.header(n, value);
        }
    }
    if let Some(b) = body_bytes {
        if !b.is_empty() {
            req_builder = req_builder.body(b);
        }
    }

    match req_builder.send().await {
        Ok(upstream) => {
            let status       = StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::OK);
            let resp_headers = upstream.headers().clone();
            let resp_bytes   = upstream.bytes().await.unwrap_or_default();

            let mut builder = Response::builder().status(status);
            for (name, value) in &resp_headers {
                if name.as_str() != "content-length" {
                    builder = builder.header(name.as_str(), value);
                }
            }
            builder.body(Body::from(resp_bytes)).unwrap_or_else(|_| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "response error")
            })
        }
        Err(e) => error_response(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

// ── Request body helpers ──────────────────────────────────────────────────────

fn extract_model(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["model"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn extract_is_stream(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["stream"].as_bool())
        .unwrap_or(false)
}

// ── Token usage parsing ───────────────────────────────────────────────────────

fn parse_usage(buf: &str, is_stream: bool) -> (u64, u64) {
    if is_stream { parse_sse_usage(buf) } else { parse_json_usage(buf) }
}

fn parse_sse_usage(buf: &str) -> (u64, u64) {
    let mut input  = 0u64;
    let mut output = 0u64;
    for line in buf.lines() {
        let Some(data) = line.strip_prefix("data: ") else { continue };
        if data == "[DONE]" { continue }
        let Ok(v) = serde_json::from_str::<Value>(data) else { continue };
        match v["type"].as_str() {
            Some("message_start") => {
                if let Some(n) = v["message"]["usage"]["input_tokens"].as_u64() { input = n; }
            }
            Some("message_delta") => {
                if let Some(n) = v["usage"]["output_tokens"].as_u64() { output = n; }
            }
            _ => {}
        }
    }
    (input, output)
}

fn parse_json_usage(buf: &str) -> (u64, u64) {
    let Ok(v) = serde_json::from_str::<Value>(buf) else { return (0, 0) };
    (
        v["usage"]["input_tokens"].as_u64().unwrap_or(0),
        v["usage"]["output_tokens"].as_u64().unwrap_or(0),
    )
}

// ── Budget-exceeded synthetic responses ───────────────────────────────────────

fn budget_exceeded_sse(model: &str, reason: &str) -> String {
    use serde_json::json;
    let msg = format!("[Token budget exceeded: {reason}]");
    let events: Vec<Value> = vec![
        json!({ "type": "message_start", "message": {
            "id": "msg_budget", "type": "message", "role": "assistant",
            "model": model, "content": [], "stop_reason": null,
            "usage": { "input_tokens": 0, "output_tokens": 0 }
        }}),
        json!({ "type": "content_block_start", "index": 0,
            "content_block": { "type": "text", "text": "" } }),
        json!({ "type": "content_block_delta", "index": 0,
            "delta": { "type": "text_delta", "text": msg } }),
        json!({ "type": "content_block_stop", "index": 0 }),
        json!({ "type": "message_delta",
            "delta": { "stop_reason": "end_turn", "stop_sequence": null },
            "usage": { "output_tokens": 1 } }),
        json!({ "type": "message_stop" }),
    ];
    events.iter()
        .map(|e| format!("data: {}\n\n", serde_json::to_string(e).unwrap()))
        .collect()
}

fn budget_exceeded_response(model: &str, reason: &str, is_stream: bool) -> Response<Body> {
    if is_stream {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .body(Body::from(budget_exceeded_sse(model, reason)))
            .unwrap()
    } else {
        use serde_json::json;
        let msg  = format!("[Token budget exceeded: {reason}]");
        let body = json!({
            "id": "msg_budget", "type": "message", "role": "assistant", "model": model,
            "content": [{ "type": "text", "text": msg }],
            "stop_reason": "end_turn", "stop_sequence": null,
            "usage": { "input_tokens": 0, "output_tokens": 0 }
        });
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap()
    }
}

fn error_response(status: StatusCode, msg: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": msg });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}
