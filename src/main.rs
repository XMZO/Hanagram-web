// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use axum::extract::{Form, Multipart, Path as AxumPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, Utc};
use grammers_client::client::{LoginToken, PasswordToken, UpdatesConfiguration};
use grammers_client::tl;
use grammers_client::{Client, SenderPool, SignInError, sender::SenderPoolFatHandle};
use grammers_session::Session;
use grammers_session::storages::SqliteSession;
use grammers_session::types::{PeerId, PeerInfo, UpdateState, UpdatesState};
use qrcodegen::{QrCode, QrCodeEcc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod i18n;
mod session_handler;
mod state;

use i18n::{Language, language_options};
use session_handler::{LoadedSession, load_session, save_telethon_string_session};
use state::{OtpMessage, SessionInfo, SessionStatus, SharedState};

const AUTH_COOKIE_NAME: &str = "hanagram_auth";
const QR_AUTO_REFRESH_SECONDS: u64 = 5;

type PendingPhoneFlows = Arc<RwLock<HashMap<String, PendingPhoneLogin>>>;
type PendingQrFlows = Arc<RwLock<HashMap<String, PendingQrLogin>>>;

#[derive(Clone)]
struct AppState {
    shared_state: SharedState,
    tera: Arc<Tera>,
    auth: DashboardAuth,
    runtime: RuntimeConfig,
    phone_flows: PendingPhoneFlows,
    qr_flows: PendingQrFlows,
}

struct Config {
    auth_user: String,
    auth_pass: String,
    api_id: i32,
    api_hash: String,
    sessions_dir: PathBuf,
    bind_addr: SocketAddr,
}

#[derive(Clone)]
struct RuntimeConfig {
    api_id: i32,
    api_hash: String,
    sessions_dir: PathBuf,
    pending_dir: PathBuf,
}

#[derive(Clone)]
struct DashboardAuth {
    username: String,
    password: String,
    session_token: String,
}

impl DashboardAuth {
    fn new(username: String, password: String) -> Self {
        let session_token = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{username}:{password}"));

        Self {
            username,
            password,
            session_token,
        }
    }

    fn verify_credentials(&self, username: &str, password: &str) -> bool {
        username == self.username && password == self.password
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        find_cookie(headers, AUTH_COOKIE_NAME).is_some_and(|value| value == self.session_token)
    }

    fn login_cookie(&self) -> String {
        format!(
            "{AUTH_COOKIE_NAME}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000",
            self.session_token
        )
    }

    fn clear_cookie(&self) -> String {
        format!("{AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
    }
}

struct PendingPhoneLogin {
    session_name: String,
    phone: String,
    temp_path: PathBuf,
    final_path: PathBuf,
    stage: PhoneLoginStage,
}

enum PhoneLoginStage {
    AwaitingCode { token: LoginToken },
    AwaitingPassword { token: PasswordToken },
}

#[derive(Clone, Debug)]
struct PendingQrLogin {
    session_name: String,
    temp_path: PathBuf,
    final_path: PathBuf,
}

struct TelegramClientSession {
    client: Client,
    session: Arc<SqliteSession>,
    pool_handle: SenderPoolFatHandle,
    pool_task: JoinHandle<()>,
}

impl TelegramClientSession {
    async fn open(path: &Path, api_id: i32) -> Result<Self> {
        let session = Arc::new(
            SqliteSession::open(path)
                .await
                .with_context(|| format!("failed to open sqlite session {}", path.display()))?,
        );

        let SenderPool {
            runner,
            handle: pool_handle,
            updates: _,
        } = SenderPool::new(Arc::clone(&session), api_id);
        let client = Client::new(pool_handle.clone());
        let pool_task = tokio::spawn(runner.run());

        Ok(Self {
            client,
            session,
            pool_handle,
            pool_task,
        })
    }

    async fn shutdown(self) {
        let _ = self.pool_handle.quit();
        let _ = self.pool_task.await;
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    sessions: usize,
}

#[derive(Clone, Debug, Serialize)]
struct PageBanner {
    kind: &'static str,
    message: String,
}

impl PageBanner {
    fn error(message: impl Into<String>) -> Self {
        Self {
            kind: "error",
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct PhoneFlowView {
    session_name: String,
    phone: String,
    awaiting_password: bool,
    password_hint: Option<String>,
    submit_action: String,
    cancel_action: String,
}

#[derive(Clone, Debug, Serialize)]
struct QrFlowView {
    session_name: String,
    qr_link: String,
    qr_svg: String,
    expires_at: String,
    cancel_action: String,
}

enum QrStatus {
    Pending(QrPendingState),
    Authorized,
}

struct QrPendingState {
    qr_link: String,
    qr_svg: String,
    expires_at: String,
}

#[derive(Debug, Default, Deserialize)]
struct LangQuery {
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct StringSessionForm {
    session_name: String,
    session_string: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct StartPhoneLoginForm {
    session_name: String,
    phone: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct StartQrLoginForm {
    session_name: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VerifyCodeForm {
    code: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VerifyPasswordForm {
    password: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FlowPageQuery {
    lang: Option<String>,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = load_config()?;
    let auth = DashboardAuth::new(config.auth_user.clone(), config.auth_pass.clone());
    let runtime = RuntimeConfig {
        api_id: config.api_id,
        api_hash: config.api_hash,
        pending_dir: config.sessions_dir.join(".pending"),
        sessions_dir: config.sessions_dir.clone(),
    };

    tokio::fs::create_dir_all(&runtime.sessions_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.sessions_dir.display()))?;
    tokio::fs::create_dir_all(&runtime.pending_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.pending_dir.display()))?;
    cleanup_pending_dir(&runtime.pending_dir).await?;

    let template_glob = format!("{}/templates/**/*", env!("CARGO_MANIFEST_DIR"));
    let tera = Arc::new(Tera::new(&template_glob).context("failed to initialize templates")?);
    let shared_state: SharedState = Arc::new(RwLock::new(HashMap::new()));
    let phone_flows: PendingPhoneFlows = Arc::new(RwLock::new(HashMap::new()));
    let qr_flows: PendingQrFlows = Arc::new(RwLock::new(HashMap::new()));

    let app_state = AppState {
        shared_state: Arc::clone(&shared_state),
        tera,
        auth: auth.clone(),
        runtime,
        phone_flows,
        qr_flows,
    };

    let session_files = collect_session_files(&app_state.runtime.sessions_dir)?;
    for session_file in session_files {
        register_session_file(&app_state, session_file).await;
    }

    let protected = Router::new()
        .route("/", get(index_handler))
        .route("/sessions/new", get(session_setup_page_handler))
        .route(
            "/sessions/import/string",
            post(import_string_session_handler),
        )
        .route("/sessions/import/upload", post(import_session_file_handler))
        .route("/sessions/login/phone", post(start_phone_login_handler))
        .route("/sessions/login/qr", post(start_qr_login_handler))
        .route("/sessions/phone/{flow_id}", get(phone_flow_page_handler))
        .route(
            "/sessions/phone/{flow_id}/code",
            post(verify_phone_code_handler),
        )
        .route(
            "/sessions/phone/{flow_id}/password",
            post(verify_phone_password_handler),
        )
        .route(
            "/sessions/phone/{flow_id}/cancel",
            post(cancel_phone_flow_handler),
        )
        .route("/sessions/qr/{flow_id}", get(qr_flow_page_handler))
        .route(
            "/sessions/qr/{flow_id}/cancel",
            post(cancel_qr_flow_handler),
        )
        .route_layer(middleware::from_fn_with_state(auth.clone(), require_login));

    let app = Router::new()
        .merge(protected)
        .route("/login", get(login_page_handler).post(login_submit_handler))
        .route("/logout", post(logout_handler))
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
    let api_hash = required_env("API_HASH")?;

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
        api_hash,
        sessions_dir,
        bind_addr,
    })
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var {name}"))
}

async fn cleanup_pending_dir(dir: &Path) -> Result<()> {
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("failed reading {}", dir.display()))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if entry.file_type().await?.is_file() {
            tokio::fs::remove_file(&path).await.with_context(|| {
                format!("failed removing stale pending session {}", path.display())
            })?;
        }
    }

    Ok(())
}

fn find_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;

    cookies.split(';').find_map(|cookie| {
        let (cookie_name, cookie_value) = cookie.trim().split_once('=')?;
        if cookie_name == name {
            Some(cookie_value)
        } else {
            None
        }
    })
}

async fn require_login(
    State(auth): State<DashboardAuth>,
    request: Request,
    next: Next,
) -> Response {
    if auth.is_authorized(request.headers()) {
        return next.run(request).await;
    }

    let location = match request.uri().query() {
        Some(query) if !query.is_empty() => format!("/login?{query}"),
        _ => String::from("/login"),
    };

    Redirect::to(&location).into_response()
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

async fn register_session_file(app_state: &AppState, session_file: PathBuf) {
    let key = session_key(&session_file);
    initialize_session_entry(&app_state.shared_state, &key, &session_file).await;

    let worker_key = key;
    let worker_file = session_file;
    let worker_state = Arc::clone(&app_state.shared_state);
    let api_id = app_state.runtime.api_id;

    tokio::spawn(async move {
        run_session_worker(worker_key, worker_file, worker_state, api_id).await;
    });
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
                Ok(grammers_client::update::Update::NewMessage(message))
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

fn login_redirect_target(language: Language) -> String {
    format!("/?lang={}", language.code())
}

fn dashboard_href(language: Language) -> String {
    format!("/?lang={}", language.code())
}

fn setup_href(language: Language) -> String {
    format!("/sessions/new?lang={}", language.code())
}

fn set_cookie_header(value: &str) -> Result<HeaderValue, StatusCode> {
    HeaderValue::from_str(value).map_err(|error| {
        warn!("failed to build auth cookie header: {}", error);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

fn detect_language(headers: &HeaderMap, query_lang: Option<&str>) -> Language {
    let accept_language = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok());
    Language::detect(query_lang, accept_language)
}

fn render_template(
    tera: &Tera,
    template: &str,
    context: &Context,
) -> std::result::Result<Html<String>, StatusCode> {
    match tera.render(template, context) {
        Ok(html) => Ok(Html(html)),
        Err(error) => {
            warn!("failed rendering {} template: {}", template, error);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn render_dashboard_page(
    app_state: &AppState,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/");

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
    context.insert(
        "logout_action",
        &format!("/logout?lang={}", language.code()),
    );
    context.insert("setup_href", &setup_href(language));
    context.insert("banner", &banner);
    context.insert("sessions", &sessions);
    context.insert("connected_count", &connected_count);
    context.insert(
        "now",
        &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );

    render_template(&app_state.tera, "index.html", &context)
}

async fn render_login_page(
    app_state: &AppState,
    language: Language,
    error_message: Option<&str>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/login");

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("error_message", &error_message);

    render_template(&app_state.tera, "login.html", &context)
}

async fn render_setup_page(
    app_state: &AppState,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/sessions/new");

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("banner", &banner);
    context.insert("dashboard_href", &dashboard_href(language));

    render_template(&app_state.tera, "session_setup.html", &context)
}

fn build_phone_flow_view(
    flow_id: &str,
    flow: &PendingPhoneLogin,
    language: Language,
) -> PhoneFlowView {
    let awaiting_password = matches!(flow.stage, PhoneLoginStage::AwaitingPassword { .. });
    let submit_action = if awaiting_password {
        format!("/sessions/phone/{flow_id}/password")
    } else {
        format!("/sessions/phone/{flow_id}/code")
    };
    let password_hint = match &flow.stage {
        PhoneLoginStage::AwaitingPassword { token } => token.hint().map(str::to_owned),
        PhoneLoginStage::AwaitingCode { .. } => None,
    };

    PhoneFlowView {
        session_name: flow.session_name.clone(),
        phone: flow.phone.clone(),
        awaiting_password,
        password_hint,
        submit_action,
        cancel_action: format!("/sessions/phone/{flow_id}/cancel?lang={}", language.code()),
    }
}

async fn render_phone_flow_page(
    app_state: &AppState,
    language: Language,
    flow_id: &str,
    flow: &PendingPhoneLogin,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, &format!("/sessions/phone/{flow_id}"));
    let flow_view = build_phone_flow_view(flow_id, flow, language);

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("banner", &banner);
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("setup_href", &setup_href(language));
    context.insert("flow", &flow_view);

    render_template(&app_state.tera, "phone_login.html", &context)
}

async fn render_qr_flow_page(
    app_state: &AppState,
    language: Language,
    flow_id: &str,
    flow: &PendingQrLogin,
    pending: QrPendingState,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, &format!("/sessions/qr/{flow_id}"));
    let flow_view = QrFlowView {
        session_name: flow.session_name.clone(),
        qr_link: pending.qr_link,
        qr_svg: pending.qr_svg,
        expires_at: pending.expires_at,
        cancel_action: format!("/sessions/qr/{flow_id}/cancel?lang={}", language.code()),
    };

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("banner", &banner);
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("setup_href", &setup_href(language));
    context.insert("flow", &flow_view);
    context.insert("auto_refresh_seconds", &QR_AUTO_REFRESH_SECONDS);

    render_template(&app_state.tera, "qr_login.html", &context)
}

async fn login_page_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    if app_state.auth.is_authorized(&headers) {
        return Redirect::to(&login_redirect_target(language)).into_response();
    }

    match render_login_page(&app_state, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn login_submit_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());

    if app_state
        .auth
        .verify_credentials(&form.username, &form.password)
    {
        let mut response = Redirect::to(&login_redirect_target(language)).into_response();

        match set_cookie_header(&app_state.auth.login_cookie()) {
            Ok(cookie) => {
                response.headers_mut().insert(header::SET_COOKIE, cookie);
                return response;
            }
            Err(status) => return status.into_response(),
        }
    }

    match render_login_page(
        &app_state,
        language,
        Some(language.translations().login_error_invalid),
    )
    .await
    {
        Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
        Err(status) => status.into_response(),
    }
}

async fn logout_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let mut response = Redirect::to(&format!("/login?lang={}", language.code())).into_response();

    match set_cookie_header(&app_state.auth.clear_cookie()) {
        Ok(cookie) => {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(status) => status.into_response(),
    }
}

async fn index_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let language = detect_language(&headers, query.lang.as_deref());
    render_dashboard_page(&app_state, language, None).await
}

async fn session_setup_page_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    match render_setup_page(&app_state, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn import_string_session_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<StringSessionForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.session_string.trim().is_empty() {
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_missing_string,
        )
        .await;
    }

    let session_name = sanitize_session_name(&form.session_name);
    let session_path =
        match allocate_unique_session_path(&app_state.runtime.sessions_dir, &session_name).await {
            Ok(path) => path,
            Err(error) => {
                warn!(
                    "failed allocating session path for string import: {}",
                    error
                );
                return render_setup_error_response(
                    &app_state,
                    language,
                    translations.setup_error_path_alloc,
                )
                .await;
            }
        };

    match save_telethon_string_session(&session_path, &form.session_string).await {
        Ok(()) => {
            register_session_file(&app_state, session_path).await;
            Redirect::to(&dashboard_href(language)).into_response()
        }
        Err(error) => {
            let _ = remove_file_if_exists(&session_path).await;
            warn!("failed importing telethon string session: {}", error);
            render_setup_error_response(
                &app_state,
                language,
                translations.setup_error_invalid_string,
            )
            .await
        }
    }
}

async fn import_session_file_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let mut language = detect_language(&headers, None);
    let mut session_name = String::new();
    let mut upload_name: Option<String> = None;
    let mut upload_bytes: Option<Vec<u8>> = None;

    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let field_name = field.name().unwrap_or_default().to_owned();

                match field_name.as_str() {
                    "lang" => {
                        if let Ok(raw) = field.text().await {
                            if let Some(parsed) = Language::parse(&raw) {
                                language = parsed;
                            }
                        }
                    }
                    "session_name" => {
                        session_name = field.text().await.unwrap_or_default();
                    }
                    "session_file" => {
                        upload_name = field.file_name().map(str::to_owned);
                        upload_bytes = match field.bytes().await {
                            Ok(bytes) => Some(bytes.to_vec()),
                            Err(error) => {
                                warn!("failed reading uploaded session file: {}", error);
                                return render_setup_error_response(
                                    &app_state,
                                    language,
                                    language.translations().setup_error_upload_read,
                                )
                                .await;
                            }
                        };
                    }
                    _ => {}
                }
            }
            Ok(None) => break,
            Err(error) => {
                warn!("failed reading multipart upload: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_upload_read,
                )
                .await;
            }
        }
    }

    let file_bytes = match upload_bytes {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => {
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_missing_upload,
            )
            .await;
        }
    };

    let upload_stem = upload_name
        .as_deref()
        .and_then(|name| Path::new(name).file_stem().and_then(|stem| stem.to_str()))
        .unwrap_or("session");
    let session_name = sanitize_session_name(if session_name.trim().is_empty() {
        upload_stem
    } else {
        &session_name
    });
    let session_path =
        match allocate_unique_session_path(&app_state.runtime.sessions_dir, &session_name).await {
            Ok(path) => path,
            Err(error) => {
                warn!("failed allocating session path for upload: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_path_alloc,
                )
                .await;
            }
        };

    match tokio::fs::write(&session_path, &file_bytes).await {
        Ok(()) => {
            register_session_file(&app_state, session_path).await;
            Redirect::to(&dashboard_href(language)).into_response()
        }
        Err(error) => {
            warn!("failed writing uploaded session file: {}", error);
            let _ = remove_file_if_exists(&session_path).await;
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_upload_write,
            )
            .await
        }
    }
}

async fn start_phone_login_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<StartPhoneLoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let phone = form.phone.trim();

    if phone.is_empty() {
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_missing_phone,
        )
        .await;
    }

    let flow_id = Uuid::new_v4().to_string();
    let session_name = sanitize_session_name(&form.session_name);
    let final_path =
        match allocate_unique_session_path(&app_state.runtime.sessions_dir, &session_name).await {
            Ok(path) => path,
            Err(error) => {
                warn!("failed allocating session path for phone login: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    translations.setup_error_path_alloc,
                )
                .await;
            }
        };
    let temp_path = pending_flow_path(&app_state.runtime.pending_dir, &flow_id);

    let client_session =
        match TelegramClientSession::open(&temp_path, app_state.runtime.api_id).await {
            Ok(client_session) => client_session,
            Err(error) => {
                warn!(
                    "failed opening temporary session for phone login: {}",
                    error
                );
                return render_setup_error_response(
                    &app_state,
                    language,
                    translations.setup_error_phone_unavailable,
                )
                .await;
            }
        };

    let result = client_session
        .client
        .request_login_code(phone, &app_state.runtime.api_hash)
        .await;
    client_session.shutdown().await;

    match result {
        Ok(token) => {
            let flow = PendingPhoneLogin {
                session_name,
                phone: phone.to_owned(),
                temp_path,
                final_path,
                stage: PhoneLoginStage::AwaitingCode { token },
            };
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);

            Redirect::to(&format!(
                "/sessions/phone/{flow_id}?lang={}",
                language.code()
            ))
            .into_response()
        }
        Err(error) => {
            warn!("failed requesting login code: {}", error);
            let _ = remove_file_if_exists(&temp_path).await;
            render_setup_error_response(&app_state, language, translations.setup_error_phone_start)
                .await
        }
    }
}

async fn start_qr_login_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<StartQrLoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let flow_id = Uuid::new_v4().to_string();
    let session_name = sanitize_session_name(&form.session_name);
    let final_path =
        match allocate_unique_session_path(&app_state.runtime.sessions_dir, &session_name).await {
            Ok(path) => path,
            Err(error) => {
                warn!("failed allocating session path for qr login: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    translations.setup_error_path_alloc,
                )
                .await;
            }
        };
    let temp_path = pending_flow_path(&app_state.runtime.pending_dir, &flow_id);

    if let Err(error) = tokio::fs::write(&temp_path, []).await {
        warn!("failed creating temporary qr login session file: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_qr_unavailable,
        )
        .await;
    }

    app_state.qr_flows.write().await.insert(
        flow_id.clone(),
        PendingQrLogin {
            session_name,
            temp_path,
            final_path,
        },
    );

    Redirect::to(&format!("/sessions/qr/{flow_id}?lang={}", language.code())).into_response()
}

async fn phone_flow_page_handler(
    State(app_state): State<AppState>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<FlowPageQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let flow_guard = app_state.phone_flows.read().await;
    let flow = match flow_guard.get(&flow_id) {
        Some(flow) => flow,
        None => {
            drop(flow_guard);
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_phone_flow_missing,
            )
            .await;
        }
    };
    let banner = phone_flow_error_banner(language, query.error.as_deref());

    match render_phone_flow_page(&app_state, language, &flow_id, flow, banner).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn verify_phone_code_handler(
    State(app_state): State<AppState>,
    AxumPath(flow_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<VerifyCodeForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let code = form.code.trim();

    if code.is_empty() {
        return Redirect::to(&format!(
            "/sessions/phone/{flow_id}?lang={}&error=missing_code",
            language.code()
        ))
        .into_response();
    }

    let mut flows = app_state.phone_flows.write().await;
    let Some(mut flow) = flows.remove(&flow_id) else {
        drop(flows);
        return render_setup_error_response(
            &app_state,
            language,
            language.translations().setup_error_phone_flow_missing,
        )
        .await;
    };

    let token = match flow.stage {
        PhoneLoginStage::AwaitingCode { token } => token,
        PhoneLoginStage::AwaitingPassword { token } => {
            flow.stage = PhoneLoginStage::AwaitingPassword { token };
            flows.insert(flow_id.clone(), flow);
            drop(flows);
            return Redirect::to(&format!(
                "/sessions/phone/{flow_id}?lang={}",
                language.code()
            ))
            .into_response();
        }
    };
    drop(flows);

    let client_session =
        match TelegramClientSession::open(&flow.temp_path, app_state.runtime.api_id).await {
            Ok(client_session) => client_session,
            Err(error) => {
                warn!(
                    "failed opening temporary session for code verification: {}",
                    error
                );
                app_state.phone_flows.write().await.insert(
                    flow_id.clone(),
                    PendingPhoneLogin {
                        stage: PhoneLoginStage::AwaitingCode { token },
                        ..flow
                    },
                );
                return Redirect::to(&format!(
                    "/sessions/phone/{flow_id}?lang={}&error=code_failed",
                    language.code()
                ))
                .into_response();
            }
        };

    let result = client_session.client.sign_in(&token, code).await;
    client_session.shutdown().await;

    match result {
        Ok(_) => {
            if let Err(error) =
                finalize_pending_session(&app_state, &flow.temp_path, &flow.final_path).await
            {
                warn!("failed finalizing phone login session: {}", error);
                let _ = remove_file_if_exists(&flow.temp_path).await;
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_finalize,
                )
                .await;
            }

            Redirect::to(&dashboard_href(language)).into_response()
        }
        Err(SignInError::PasswordRequired(password_token)) => {
            flow.stage = PhoneLoginStage::AwaitingPassword {
                token: password_token,
            };
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&format!(
                "/sessions/phone/{flow_id}?lang={}",
                language.code()
            ))
            .into_response()
        }
        Err(SignInError::InvalidCode) => {
            flow.stage = PhoneLoginStage::AwaitingCode { token };
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&format!(
                "/sessions/phone/{flow_id}?lang={}&error=invalid_code",
                language.code()
            ))
            .into_response()
        }
        Err(SignInError::SignUpRequired) => {
            let _ = remove_file_if_exists(&flow.temp_path).await;
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_signup_required,
            )
            .await
        }
        Err(SignInError::Other(error)) => {
            warn!("failed finishing phone login: {}", error);
            flow.stage = PhoneLoginStage::AwaitingCode { token };
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&format!(
                "/sessions/phone/{flow_id}?lang={}&error=code_failed",
                language.code()
            ))
            .into_response()
        }
        Err(SignInError::InvalidPassword(_)) => Redirect::to(&format!(
            "/sessions/phone/{flow_id}?lang={}&error=password_retry",
            language.code()
        ))
        .into_response(),
    }
}

async fn verify_phone_password_handler(
    State(app_state): State<AppState>,
    AxumPath(flow_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<VerifyPasswordForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let password = form.password.trim();

    if password.is_empty() {
        return Redirect::to(&format!(
            "/sessions/phone/{flow_id}?lang={}&error=missing_password",
            language.code()
        ))
        .into_response();
    }

    let mut flows = app_state.phone_flows.write().await;
    let Some(mut flow) = flows.remove(&flow_id) else {
        drop(flows);
        return render_setup_error_response(
            &app_state,
            language,
            language.translations().setup_error_phone_flow_missing,
        )
        .await;
    };

    let token = match flow.stage {
        PhoneLoginStage::AwaitingPassword { token } => token,
        PhoneLoginStage::AwaitingCode { token } => {
            flow.stage = PhoneLoginStage::AwaitingCode { token };
            flows.insert(flow_id.clone(), flow);
            drop(flows);
            return Redirect::to(&format!(
                "/sessions/phone/{flow_id}?lang={}",
                language.code()
            ))
            .into_response();
        }
    };
    drop(flows);

    let client_session =
        match TelegramClientSession::open(&flow.temp_path, app_state.runtime.api_id).await {
            Ok(client_session) => client_session,
            Err(error) => {
                warn!(
                    "failed opening temporary session for password verification: {}",
                    error
                );
                let _ = remove_file_if_exists(&flow.temp_path).await;
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_phone_password_reset,
                )
                .await;
            }
        };

    let result = client_session.client.check_password(token, password).await;
    client_session.shutdown().await;

    match result {
        Ok(_) => {
            if let Err(error) =
                finalize_pending_session(&app_state, &flow.temp_path, &flow.final_path).await
            {
                warn!("failed finalizing password login session: {}", error);
                let _ = remove_file_if_exists(&flow.temp_path).await;
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_finalize,
                )
                .await;
            }

            Redirect::to(&dashboard_href(language)).into_response()
        }
        Err(SignInError::InvalidPassword(password_token)) => {
            flow.stage = PhoneLoginStage::AwaitingPassword {
                token: password_token,
            };
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&format!(
                "/sessions/phone/{flow_id}?lang={}&error=invalid_password",
                language.code()
            ))
            .into_response()
        }
        Err(SignInError::Other(error)) => {
            warn!("failed verifying 2fa password: {}", error);
            let _ = remove_file_if_exists(&flow.temp_path).await;
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_phone_password_reset,
            )
            .await
        }
        Err(SignInError::PasswordRequired(password_token)) => {
            flow.stage = PhoneLoginStage::AwaitingPassword {
                token: password_token,
            };
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&format!(
                "/sessions/phone/{flow_id}?lang={}",
                language.code()
            ))
            .into_response()
        }
        Err(SignInError::InvalidCode) => Redirect::to(&format!(
            "/sessions/phone/{flow_id}?lang={}&error=code_failed",
            language.code()
        ))
        .into_response(),
        Err(SignInError::SignUpRequired) => {
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_signup_required,
            )
            .await
        }
    }
}

async fn cancel_phone_flow_handler(
    State(app_state): State<AppState>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    if let Some(flow) = app_state.phone_flows.write().await.remove(&flow_id) {
        let _ = remove_file_if_exists(&flow.temp_path).await;
    }

    Redirect::to(&setup_href(language)).into_response()
}

async fn qr_flow_page_handler(
    State(app_state): State<AppState>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<FlowPageQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let flow = {
        let flows = app_state.qr_flows.read().await;
        match flows.get(&flow_id) {
            Some(flow) => flow.clone(),
            None => {
                drop(flows);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_qr_flow_missing,
                )
                .await;
            }
        }
    };

    let banner = qr_flow_error_banner(language, query.error.as_deref());
    match poll_qr_flow(&app_state.runtime, &flow).await {
        Ok(QrStatus::Pending(pending)) => {
            match render_qr_flow_page(&app_state, language, &flow_id, &flow, pending, banner).await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            }
        }
        Ok(QrStatus::Authorized) => {
            app_state.qr_flows.write().await.remove(&flow_id);

            if let Err(error) =
                finalize_pending_session(&app_state, &flow.temp_path, &flow.final_path).await
            {
                warn!("failed finalizing qr login session: {}", error);
                let _ = remove_file_if_exists(&flow.temp_path).await;
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_finalize,
                )
                .await;
            }

            Redirect::to(&dashboard_href(language)).into_response()
        }
        Err(error) => {
            warn!("failed polling qr login flow: {}", error);
            Redirect::to(&format!(
                "/sessions/qr/{flow_id}?lang={}&error=qr_failed",
                language.code()
            ))
            .into_response()
        }
    }
}

async fn cancel_qr_flow_handler(
    State(app_state): State<AppState>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    if let Some(flow) = app_state.qr_flows.write().await.remove(&flow_id) {
        let _ = remove_file_if_exists(&flow.temp_path).await;
    }

    Redirect::to(&setup_href(language)).into_response()
}

async fn health_handler(State(app_state): State<AppState>) -> Json<HealthResponse> {
    let sessions = app_state.shared_state.read().await.len();
    Json(HealthResponse {
        status: "ok",
        sessions,
    })
}

async fn render_setup_error_response(
    app_state: &AppState,
    language: Language,
    message: &str,
) -> Response {
    match render_setup_page(app_state, language, Some(PageBanner::error(message))).await {
        Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
        Err(status) => status.into_response(),
    }
}

fn phone_flow_error_banner(language: Language, error: Option<&str>) -> Option<PageBanner> {
    let translations = language.translations();
    let message = match error {
        Some("missing_code") => Some(translations.phone_error_missing_code),
        Some("invalid_code") => Some(translations.phone_error_invalid_code),
        Some("code_failed") => Some(translations.phone_error_code_failed),
        Some("missing_password") => Some(translations.phone_error_missing_password),
        Some("invalid_password") => Some(translations.phone_error_invalid_password),
        Some("password_retry") => Some(translations.phone_error_password_retry),
        _ => None,
    }?;

    Some(PageBanner::error(message))
}

fn qr_flow_error_banner(language: Language, error: Option<&str>) -> Option<PageBanner> {
    let translations = language.translations();
    let message = match error {
        Some("qr_failed") => Some(translations.qr_error_failed),
        _ => None,
    }?;

    Some(PageBanner::error(message))
}

async fn finalize_pending_session(
    app_state: &AppState,
    temp_path: &Path,
    final_path: &Path,
) -> Result<()> {
    tokio::fs::rename(temp_path, final_path)
        .await
        .with_context(|| {
            format!(
                "failed to move pending session {} to {}",
                temp_path.display(),
                final_path.display()
            )
        })?;

    register_session_file(app_state, final_path.to_path_buf()).await;
    Ok(())
}

async fn remove_file_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed removing {}", path.display())),
    }
}

fn sanitize_session_name(raw: &str) -> String {
    let mut cleaned = String::new();
    let mut last_was_dash = false;

    for ch in raw.trim().chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            Some(ch.to_ascii_lowercase())
        } else if matches!(ch, '-' | '_') {
            Some(ch)
        } else if ch.is_whitespace() {
            Some('-')
        } else {
            None
        };

        match mapped {
            Some('-') | Some('_') if last_was_dash => {}
            Some(ch) => {
                last_was_dash = matches!(ch, '-' | '_');
                cleaned.push(ch);
            }
            None => {}
        }
    }

    let cleaned = cleaned.trim_matches(['-', '_']).to_owned();
    if cleaned.is_empty() {
        format!("session-{}", Utc::now().timestamp())
    } else {
        cleaned
    }
}

async fn allocate_unique_session_path(dir: &Path, raw_name: &str) -> Result<PathBuf> {
    let base_name = sanitize_session_name(raw_name);

    for index in 0..10_000_u32 {
        let candidate_name = if index == 0 {
            format!("{base_name}.session")
        } else {
            format!("{base_name}-{index}.session")
        };
        let candidate = dir.join(candidate_name);

        if !tokio::fs::try_exists(&candidate)
            .await
            .with_context(|| format!("failed probing {}", candidate.display()))?
        {
            return Ok(candidate);
        }
    }

    anyhow::bail!(
        "failed to allocate a unique session path in {}",
        dir.display()
    )
}

fn pending_flow_path(dir: &Path, flow_id: &str) -> PathBuf {
    dir.join(format!("{flow_id}.pending"))
}

async fn poll_qr_flow(runtime: &RuntimeConfig, flow: &PendingQrLogin) -> Result<QrStatus> {
    let client_session = TelegramClientSession::open(&flow.temp_path, runtime.api_id).await?;

    let export_result = client_session
        .client
        .invoke(&tl::functions::auth::ExportLoginToken {
            api_id: runtime.api_id,
            api_hash: runtime.api_hash.clone(),
            except_ids: Vec::new(),
        })
        .await;

    let status = match export_result {
        Ok(result) => resolve_qr_status(&client_session, result).await,
        Err(error) => Err(error).context("auth.exportLoginToken failed"),
    };

    client_session.shutdown().await;
    status
}

async fn resolve_qr_status(
    client_session: &TelegramClientSession,
    mut result: tl::enums::auth::LoginToken,
) -> Result<QrStatus> {
    loop {
        match result {
            tl::enums::auth::LoginToken::Token(token) => {
                let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token.token);
                let qr_link = format!("tg://login?token={encoded}");
                let qr_svg = render_qr_svg(&qr_link)?;
                let expires_at = format_qr_expiry(token.expires);

                return Ok(QrStatus::Pending(QrPendingState {
                    qr_link,
                    qr_svg,
                    expires_at,
                }));
            }
            tl::enums::auth::LoginToken::Success(_) => return Ok(QrStatus::Authorized),
            tl::enums::auth::LoginToken::MigrateTo(migrate) => {
                let previous_dc = client_session.session.home_dc_id();
                client_session.session.set_home_dc_id(migrate.dc_id).await;
                let _ = client_session.pool_handle.disconnect_from_dc(previous_dc);
                result = client_session
                    .client
                    .invoke(&tl::functions::auth::ImportLoginToken {
                        token: migrate.token,
                    })
                    .await
                    .context("auth.importLoginToken failed after migration")?;
            }
        }
    }
}

fn render_qr_svg(data: &str) -> Result<String> {
    let code = QrCode::encode_text(data, QrCodeEcc::Medium)
        .map_err(|error| anyhow::anyhow!("failed to encode qr data: {error:?}"))?;
    let border = 3;
    let size = code.size();
    let view_box = size + border * 2;
    let mut svg = String::new();

    write!(
        svg,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {view_box} {view_box}\" shape-rendering=\"crispEdges\">"
    )?;
    svg.push_str("<rect width=\"100%\" height=\"100%\" fill=\"#fffaf2\"/>");

    for y in 0..size {
        for x in 0..size {
            if code.get_module(x, y) {
                let x = x + border;
                let y = y + border;
                write!(
                    svg,
                    "<rect x=\"{x}\" y=\"{y}\" width=\"1\" height=\"1\" fill=\"#4b4038\"/>"
                )?;
            }
        }
    }

    svg.push_str("</svg>");
    Ok(svg)
}

fn format_qr_expiry(expires: i32) -> String {
    match DateTime::from_timestamp(i64::from(expires), 0) {
        Some(expires_at) => expires_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => String::from("-"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_auth_accepts_matching_cookie() {
        let auth = DashboardAuth::new(String::from("alice"), String::from("s3cr3t"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{AUTH_COOKIE_NAME}={}", auth.session_token))
                .unwrap_or_else(|error| panic!("failed to build cookie header for test: {error}")),
        );

        assert!(auth.is_authorized(&headers));
    }

    #[test]
    fn dashboard_auth_rejects_missing_or_wrong_cookie() {
        let auth = DashboardAuth::new(String::from("alice"), String::from("s3cr3t"));
        let mut headers = HeaderMap::new();

        assert!(!auth.is_authorized(&headers));

        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("hanagram_auth=wrong-token"),
        );

        assert!(!auth.is_authorized(&headers));
    }

    #[test]
    fn sanitize_session_name_falls_back_and_normalizes() {
        assert_eq!(sanitize_session_name("Hello World"), "hello-world");
        assert_eq!(sanitize_session_name("test__name"), "test_name");
        assert!(sanitize_session_name("  ").starts_with("session-"));
    }
}
