use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Form, Query, Request, State},
    http::{header, HeaderValue, Response, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use log::{error, info};
use serde::{Deserialize, Serialize};

use crate::alert_store::{AlertEntry, SharedAlertStore};
use crate::auth::AuthState;
use crate::rules_config::{RulesConfig, SharedRulesConfig};

const CONFIG_PATH: &str = "rules.json";
const SESSION_COOKIE: &str = "protector_session";

static UI_HTML: &str    = include_str!("web/index.html");
static LOGIN_HTML: &str = include_str!("web/login.html");

#[derive(Clone)]
struct AppState {
    rules:  SharedRulesConfig,
    auth:   Arc<AuthState>,
    alerts: SharedAlertStore,
}

pub async fn start(
    rules:  SharedRulesConfig,
    auth:   Arc<AuthState>,
    alerts: SharedAlertStore,
    port:   u16,
) -> anyhow::Result<()> {
    let state = AppState { rules, auth, alerts };

    let app = Router::new()
        // Protected routes
        .route("/", get(serve_ui))
        .route("/api/rules", get(get_rules).post(set_rules))
        .route("/api/rules/reset", post(reset_rules))
        .route("/api/alerts", get(get_alerts))
        .route("/api/alerts/clear", post(clear_alerts))
        .route("/logout", post(do_logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        // Public routes
        .route("/login", get(serve_login).post(do_login))
        .with_state(state);

    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Config UI → http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Auth middleware ───────────────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    if let Some(token) = session_cookie(&request) {
        if state.auth.is_valid(&token) {
            return next.run(request).await;
        }
    }
    redirect("/login")
}

fn session_cookie(req: &Request) -> Option<String> {
    let cookies = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for part in cookies.split(';') {
        if let Some(val) = part.trim().strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(val.to_string());
        }
    }
    None
}

// ── Login / logout ────────────────────────────────────────────────────────────

async fn serve_login() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn do_login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> axum::response::Response {
    if form.username == "admin" && state.auth.verify(&form.password) {
        let token = state.auth.new_token();
        info!("Auth: login successful");
        let cookie = format!(
            "{SESSION_COOKIE}={token}; HttpOnly; Path=/; SameSite=Strict"
        );
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, HeaderValue::from_static("/"))
            .header(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap())
            .body(Body::empty())
            .unwrap()
    } else {
        info!("Auth: login failed for user '{}'", form.username);
        redirect("/login?error=1")
    }
}

async fn do_logout(
    State(state): State<AppState>,
    request: Request,
) -> axum::response::Response {
    if let Some(token) = session_cookie(&request) {
        state.auth.revoke(&token);
    }
    let clear = format!(
        "{SESSION_COOKIE}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0"
    );
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, HeaderValue::from_static("/login"))
        .header(header::SET_COOKIE, HeaderValue::from_str(&clear).unwrap())
        .body(Body::empty())
        .unwrap()
}

// ── Rules API ─────────────────────────────────────────────────────────────────

async fn serve_ui() -> Html<&'static str> {
    Html(UI_HTML)
}

async fn get_rules(State(state): State<AppState>) -> Json<RulesConfig> {
    Json(state.rules.read().unwrap().clone())
}

async fn set_rules(
    State(state): State<AppState>,
    Json(new): Json<RulesConfig>,
) -> StatusCode {
    *state.rules.write().unwrap() = new.clone();
    match new.save(CONFIG_PATH) {
        Ok(_)  => StatusCode::OK,
        Err(e) => { error!("save rules: {e}"); StatusCode::INTERNAL_SERVER_ERROR }
    }
}

async fn reset_rules(State(state): State<AppState>) -> Json<RulesConfig> {
    let defaults = RulesConfig::default_config();
    *state.rules.write().unwrap() = defaults.clone();
    let _ = defaults.save(CONFIG_PATH);
    Json(defaults)
}

// ── Alerts API ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AlertsQuery {
    since: Option<u64>,
}

#[derive(Serialize)]
struct AlertsResponse {
    alerts:  Vec<AlertEntry>,
    last_id: u64,
}

async fn get_alerts(
    State(state): State<AppState>,
    Query(q): Query<AlertsQuery>,
) -> Json<AlertsResponse> {
    let store = state.alerts.lock().unwrap();
    let alerts = match q.since {
        Some(id) => store.since(id),
        None     => store.all(),
    };
    let last_id = store.last_id();
    Json(AlertsResponse { alerts, last_id })
}

async fn clear_alerts(State(state): State<AppState>) -> StatusCode {
    state.alerts.lock().unwrap().clear();
    StatusCode::OK
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn redirect(location: &'static str) -> axum::response::Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_static(location))],
    )
        .into_response()
}
