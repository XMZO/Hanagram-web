// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use grammers_client::client::UpdatesConfiguration;
use grammers_client::tl;
use grammers_client::update::Update;
use grammers_client::{Client, SenderPool};
use grammers_session::Session;
use grammers_session::types::{PeerId, PeerInfo, UpdateState, UpdatesState};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod i18n;
mod session_handler;
mod state;

use i18n::{Language, language_options};
use session_handler::{LoadedSession, load_session};
use state::{OtpMessage, SessionInfo, SessionStatus, SharedState};

#[derive(Clone)]
struct AppState {
    shared_state: SharedState,
    tera: Arc<Tera>,
}

struct Config {
    auth_user: String,
    auth_pass: String,
    api_id: i32,
    sessions_dir: PathBuf,
    bind_addr: SocketAddr,
}

#[derive(Clone)]
struct BasicAuth {
    expected_header: HeaderValue,
}

impl BasicAuth {
    fn new(username: &str, password: &str) -> Result<Self> {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        let mut expected_header = HeaderValue::from_str(&format!("Basic {encoded}"))
            .context("failed to build basic authorization header")?;
        expected_header.set_sensitive(true);

        Ok(Self { expected_header })
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        headers
            .get(header::AUTHORIZATION)
            .is_some_and(|value| value == self.expected_header)
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    sessions: usize,
}

#[derive(Debug, Default, Deserialize)]
struct LangQuery {
    lang: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = load_config()?;
    let basic_auth = BasicAuth::new(&config.auth_user, &config.auth_pass)?;
    tokio::fs::create_dir_all(&config.sessions_dir)
        .await
        .with_context(|| format!("failed to create {}", config.sessions_dir.display()))?;

    let template_glob = format!("{}/templates/**/*", env!("CARGO_MANIFEST_DIR"));
    let tera = Arc::new(Tera::new(&template_glob).context("failed to initialize templates")?);
    let shared_state: SharedState = Arc::new(RwLock::new(HashMap::new()));

    let session_files = collect_session_files(&config.sessions_dir)?;
    for session_file in &session_files {
        let key = session_key(session_file);
        initialize_session_entry(&shared_state, &key, session_file).await;

        let worker_state = Arc::clone(&shared_state);
        let worker_key = key.clone();
        let worker_file = session_file.clone();
        let api_id = config.api_id;

        tokio::spawn(async move {
            run_session_worker(worker_key, worker_file, worker_state, api_id).await;
        });
    }

    let app_state = AppState {
        shared_state: Arc::clone(&shared_state),
        tera,
    };

    let protected =
        Router::new()
            .route("/", get(index_handler))
            .route_layer(middleware::from_fn_with_state(
                basic_auth.clone(),
                require_basic_auth,
            ));

    let app = Router::new()
        .merge(protected)
        .route("/health", get(health_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;

    info!("listening on http://{}", config.bind_addr);
    axum::serve(listener, app)
        .await
        .context("axum server exited unexpectedly")
}

fn init_tracing() {
    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
}

fn load_config() -> Result<Config> {
    let auth_user = required_env("AUTH_USER")?;
    let auth_pass = required_env("AUTH_PASS")?;
    let api_id = required_env("API_ID")?
        .parse::<i32>()
        .context("API_ID must be a valid i32")?;
    let _api_hash = required_env("API_HASH")?;

    let sessions_dir = std::env::var("SESSIONS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./sessions"));

    let bind_addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| String::from("0.0.0.0:8080"))
        .parse::<SocketAddr>()
        .context("BIND_ADDR must be a valid socket address")?;

    Ok(Config {
        auth_user,
        auth_pass,
        api_id,
        sessions_dir,
        bind_addr,
    })
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var {name}"))
}

async fn require_basic_auth(
    State(auth): State<BasicAuth>,
    request: Request,
    next: Next,
) -> Response {
    if auth.is_authorized(request.headers()) {
        return next.run(request).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Hanagram\""),
        )],
        "Unauthorized",
    )
        .into_response()
}

fn collect_session_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut session_files = Vec::new();

    for entry in
        std::fs::read_dir(dir).with_context(|| format!("failed reading {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed reading entry in {}", dir.display()))?;
        let path = entry.path();
        let is_session = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.eq_ignore_ascii_case("session"))
            .unwrap_or(false);

        if path.is_file() && is_session {
            session_files.push(path);
        }
    }

    session_files.sort();
    Ok(session_files)
}

fn session_key(session_file: &Path) -> String {
    match session_file.file_stem().and_then(|stem| stem.to_str()) {
        Some(stem) if !stem.is_empty() => stem.to_owned(),
        _ => session_file.display().to_string(),
    }
}

fn fallback_phone(session_file: &Path) -> String {
    match session_file.file_stem().and_then(|stem| stem.to_str()) {
        Some(stem) if !stem.is_empty() => stem.to_owned(),
        _ => String::from("unknown"),
    }
}

async fn initialize_session_entry(shared_state: &SharedState, key: &str, session_file: &Path) {
    let mut state = shared_state.write().await;
    state.entry(key.to_owned()).or_insert_with(|| SessionInfo {
        phone: fallback_phone(session_file),
        session_file: session_file.to_path_buf(),
        status: SessionStatus::Connecting,
        messages: VecDeque::new(),
    });
}

async fn set_session_status(shared_state: &SharedState, key: &str, status: SessionStatus) {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        info.status = status;
    }
}

async fn set_session_phone(shared_state: &SharedState, key: &str, phone: String) {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        info.phone = phone;
    }
}

async fn push_otp_message(shared_state: &SharedState, key: &str, otp: OtpMessage) {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        info.messages.push_front(otp);
        info.messages.truncate(20);
    }
}

async fn run_session_worker(
    key: String,
    session_file: PathBuf,
    shared_state: SharedState,
    api_id: i32,
) {
    let retry_delays = [5_u64, 10, 20, 40, 80];
    let mut attempt = 0_usize;

    loop {
        set_session_status(&shared_state, &key, SessionStatus::Connecting).await;

        match run_session_once(&key, &session_file, &shared_state, api_id).await {
            Ok(()) => {
                set_session_status(
                    &shared_state,
                    &key,
                    SessionStatus::Error(String::from("session loop ended")),
                )
                .await;
                break;
            }
            Err(error) => {
                let message = error.to_string();
                warn!("session {} failed: {}", session_file.display(), message);
                set_session_status(&shared_state, &key, SessionStatus::Error(message)).await;

                if attempt >= retry_delays.len() {
                    break;
                }

                let delay = retry_delays[attempt];
                attempt += 1;
                sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

async fn run_session_once(
    key: &str,
    session_file: &Path,
    shared_state: &SharedState,
    api_id: i32,
) -> Result<()> {
    let session = match load_session(session_file).await {
        Some(session) => Arc::new(session),
        None => anyhow::bail!("failed to load session"),
    };

    let SenderPool {
        runner,
        handle: pool_handle,
        updates,
    } = SenderPool::new(Arc::clone(&session), api_id);
    let client = Client::new(pool_handle.clone());
    let pool_task = tokio::spawn(runner.run());

    let result = async {
        if !client
            .is_authorized()
            .await
            .context("authorization check failed")?
        {
            anyhow::bail!("session is not authorized");
        }

        prime_session(&session, &client, key, shared_state).await;
        set_session_status(shared_state, key, SessionStatus::Connected).await;

        let code_regex = Regex::new(r"\b\d{5,6}\b").context("failed to compile OTP regex")?;
        let mut updates = client
            .stream_updates(
                updates,
                UpdatesConfiguration {
                    catch_up: true,
                    ..Default::default()
                },
            )
            .await;

        loop {
            match updates.next().await {
                Ok(Update::NewMessage(message))
                    if message.sender_id() == Some(PeerId::user(777000)) =>
                {
                    let text = message.text().to_string();
                    let code = code_regex
                        .find(&text)
                        .map(|matched| matched.as_str().to_string());
                    let otp = OtpMessage {
                        received_at: Utc::now(),
                        text,
                        code,
                    };
                    push_otp_message(shared_state, key, otp).await;
                }
                Ok(_) => {}
                Err(error) => {
                    updates.sync_update_state().await;
                    return Err(error).context("update loop failed");
                }
            }
        }
    }
    .await;

    let _ = pool_handle.quit();
    let _ = pool_task.await;
    result
}

async fn prime_session(
    session: &LoadedSession,
    client: &Client,
    key: &str,
    shared_state: &SharedState,
) {
    match client.get_me().await {
        Ok(me) => {
            let auth = me.to_ref().await.map(|peer| peer.auth);
            let peer_info = PeerInfo::User {
                id: me.id().bare_id(),
                auth,
                bot: Some(me.is_bot()),
                is_self: Some(true),
            };
            session.cache_peer(&peer_info).await;

            if let Some(phone) = me.phone() {
                set_session_phone(shared_state, key, phone.to_owned()).await;
            }
        }
        Err(error) => {
            warn!("failed to fetch self user info for {}: {}", key, error);
        }
    }

    match client.invoke(&tl::functions::updates::GetState {}).await {
        Ok(tl::enums::updates::State::State(state)) => {
            session
                .set_update_state(UpdateState::All(UpdatesState {
                    pts: state.pts,
                    qts: state.qts,
                    date: state.date,
                    seq: state.seq,
                    channels: Vec::new(),
                }))
                .await;
        }
        Err(error) => {
            warn!("failed to prime update state for {}: {}", key, error);
        }
    }
}

async fn index_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let accept_language = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok());
    let language = Language::detect(query.lang.as_deref(), accept_language);
    let translations = language.translations();
    let languages = language_options(language);

    let sessions = {
        let state = app_state.shared_state.read().await;
        let mut sessions: Vec<SessionInfo> = state.values().cloned().collect();
        sessions.sort_by(|left, right| left.phone.cmp(&right.phone));
        sessions
    };

    let connected_count = sessions
        .iter()
        .filter(|session| matches!(session.status, SessionStatus::Connected))
        .count();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("sessions", &sessions);
    context.insert("connected_count", &connected_count);
    context.insert(
        "now",
        &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );

    match app_state.tera.render("index.html", &context) {
        Ok(html) => Ok(Html(html)),
        Err(error) => {
            warn!("failed rendering index template: {}", error);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn health_handler(State(app_state): State<AppState>) -> Json<HealthResponse> {
    let sessions = app_state.shared_state.read().await.len();
    Json(HealthResponse {
        status: "ok",
        sessions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_accepts_matching_header() {
        let auth = BasicAuth::new("alice", "s3cr3t").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic YWxpY2U6czNjcjN0"),
        );

        assert!(auth.is_authorized(&headers));
    }

    #[test]
    fn basic_auth_rejects_missing_or_wrong_header() {
        let auth = BasicAuth::new("alice", "s3cr3t").unwrap();
        let mut headers = HeaderMap::new();

        assert!(!auth.is_authorized(&headers));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic d3Jvbmc6Y3JlZGVudGlhbHM="),
        );

        assert!(!auth.is_authorized(&headers));
    }
}
