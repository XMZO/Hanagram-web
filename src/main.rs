// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use axum::extract::{Extension, Form, Multipart, Path as AxumPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, Utc};
use grammers_client::client::{LoginToken, PasswordToken, UpdatesConfiguration};
use grammers_client::tl;
use grammers_client::{
    Client, InvocationError, SenderPool, SignInError, sender::SenderPoolFatHandle,
};
use grammers_session::Session;
use grammers_session::types::{PeerId, PeerInfo, UpdateState, UpdatesState};
use phonenumber::Mode as PhoneNumberMode;
use qrcodegen::{QrCode, QrCodeEcc};
use regex::Regex;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use hanagram_web::account_reset::reset_user_account;
use hanagram_web::security::{
    EncryptedBlob, EnforcementMode, MasterKey, RegistrationPolicy, SensitiveBytes, SharedMasterKey,
    SharedSensitiveBytes, SharedSensitiveString, TotpVerification, decrypt_bytes, encrypt_bytes,
    evaluate_password_strength, hash_session_token, into_sensitive_bytes, share_master_key,
    share_sensitive_bytes, verify_totp,
};
use hanagram_web::store::{
    AuthSessionRecord, MetaStore, NewAuditEntry, SessionRecord, SystemSettings, UserRole,
};

mod i18n;
mod session_handler;
mod state;
mod web_auth;

use i18n::{Language, language_options};
use session_handler::{
    LoadedSession, export_sqlite_session_bytes, export_telethon_string_session, load_session,
    load_telethon_string_session, serialize_session,
};
use state::{OtpMessage, SessionInfo, SessionStatus, SharedState};
use web_auth::{
    AUTH_COOKIE_NAME, AuthenticatedSession, LoginError, RegistrationResult, build_auth_cookie,
    build_totp_setup_material, clear_auth_cookie, extract_client_ip, extract_user_agent,
    find_cookie, initialize_user_credentials, normalize_username, resolve_authenticated_session,
};

const QR_AUTO_REFRESH_SECONDS: u64 = 5;
const DASHBOARD_INCREMENTAL_SYNC_SECONDS: u64 = 3;
const DASHBOARD_FULL_SYNC_SECONDS: u64 = 30;
const BOT_SETTINGS_FILE_NAME: &str = ".hanagram-bot.json";
const META_DB_FILE_NAME: &str = "app.db";
const DEFAULT_BOT_TEMPLATE: &str = "Hanagram OTP Alert\n\nAccount: {phone}\nSession: {session_key}\nCode: {code}\nReceived: {received_at}\nStatus: {status}\nSession file: {session_file}\n\nMessage:\n{message}";
const SESSION_KEY_PREFIX: &str = "hanagram-session-key:v1:";
const SESSION_NOTE_PREFIX: &str = "hanagram-note:v1:";
const EMBEDDED_TEMPLATES: [(&str, &str); 10] = [
    ("admin.html", include_str!("../templates/admin.html")),
    ("index.html", include_str!("../templates/index.html")),
    ("login.html", include_str!("../templates/login.html")),
    (
        "notifications.html",
        include_str!("../templates/notifications.html"),
    ),
    (
        "phone_login.html",
        include_str!("../templates/phone_login.html"),
    ),
    ("qr_login.html", include_str!("../templates/qr_login.html")),
    ("register.html", include_str!("../templates/register.html")),
    (
        "session_setup.html",
        include_str!("../templates/session_setup.html"),
    ),
    ("settings.html", include_str!("../templates/settings.html")),
    (
        "totp_setup.html",
        include_str!("../templates/totp_setup.html"),
    ),
];

type PendingPhoneFlows = Arc<RwLock<HashMap<String, PendingPhoneLogin>>>;
type PendingQrFlows = Arc<RwLock<HashMap<String, PendingQrLogin>>>;
type PendingTotpSetups = Arc<RwLock<HashMap<String, PendingTotpSetup>>>;
type SessionWorkers = Arc<Mutex<HashMap<String, SessionWorkerHandle>>>;
type NotificationSettingsStore = Arc<RwLock<BotNotificationSettings>>;
type MetaStoreHandle = Arc<MetaStore>;
type UnlockCache = Arc<RwLock<HashMap<String, SharedMasterKey>>>;
type UserKeyCache = Arc<RwLock<HashMap<String, SharedMasterKey>>>;

#[derive(Clone)]
struct AppState {
    shared_state: SharedState,
    session_workers: SessionWorkers,
    tera: Arc<Tera>,
    meta_store: MetaStoreHandle,
    system_settings: Arc<RwLock<SystemSettings>>,
    runtime: RuntimeConfig,
    phone_flows: PendingPhoneFlows,
    qr_flows: PendingQrFlows,
    totp_setups: PendingTotpSetups,
    unlock_cache: UnlockCache,
    user_keys: UserKeyCache,
    notification_settings: NotificationSettingsStore,
    http_client: HttpClient,
}

struct Config {
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
    users_dir: PathBuf,
    app_data_dir: PathBuf,
    meta_db_path: PathBuf,
    notification_settings_path: PathBuf,
}

struct PendingPhoneLogin {
    user_id: String,
    auth_session_id: String,
    session_name: String,
    phone: String,
    session_id: String,
    final_path: PathBuf,
    session_data: SharedSensitiveBytes,
    stage: PhoneLoginStage,
}

enum PhoneLoginStage {
    AwaitingCode { token: LoginToken },
    AwaitingPassword { token: PasswordToken },
}

#[derive(Clone)]
struct PendingQrLogin {
    user_id: String,
    auth_session_id: String,
    session_name: String,
    session_id: String,
    final_path: PathBuf,
    session_data: SharedSensitiveBytes,
}

#[derive(Clone)]
struct PendingTotpSetup {
    secret: SharedSensitiveString,
    recovery_codes: Vec<SharedSensitiveString>,
    otp_auth_uri: SharedSensitiveString,
}

struct TelegramClientSession {
    client: Client,
    session: Arc<LoadedSession>,
    pool_handle: SenderPoolFatHandle,
    pool_task: JoinHandle<()>,
}

struct SessionWorkerHandle {
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct BotNotificationSettings {
    enabled: bool,
    bot_token: String,
    chat_id: String,
    template: String,
}

impl BotNotificationSettings {
    fn normalized(mut self) -> Self {
        self.bot_token = self.bot_token.trim().to_owned();
        self.chat_id = self.chat_id.trim().to_owned();
        self.template = if self.template.trim().is_empty() {
            String::from(DEFAULT_BOT_TEMPLATE)
        } else {
            self.template.trim().to_owned()
        };
        self
    }

    fn is_ready(&self) -> bool {
        self.enabled && !self.bot_token.is_empty() && !self.chat_id.is_empty()
    }
}

#[derive(Clone, Debug, Serialize)]
struct BotNotificationSettingsView {
    enabled: bool,
    bot_token: String,
    chat_id: String,
    template: String,
}

#[derive(Clone, Debug, Serialize)]
struct BotPlaceholderHint {
    key: &'static str,
    description: &'static str,
}

#[derive(Clone, Debug)]
struct OtpNotificationPayload {
    session_key: String,
    phone: String,
    code: String,
    message: String,
    received_at: String,
    session_file: String,
    status: String,
}

#[derive(Debug, Default, Deserialize)]
struct BotNotificationSettingsForm {
    enabled: Option<String>,
    bot_token: String,
    chat_id: String,
    template: String,
    lang: Option<String>,
    return_to: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct DashboardSnapshot {
    connected_count: usize,
    generated_at: String,
    sessions: Vec<SessionInfo>,
}

#[derive(Clone, Debug, Serialize)]
struct SessionStringExportResponse {
    session_key: String,
    session_string: String,
}

#[derive(Clone, Debug, Serialize)]
struct ApiErrorResponse {
    error: String,
}

impl TelegramClientSession {
    fn open(session: LoadedSession, api_id: i32) -> Self {
        let session = Arc::new(session);
        let SenderPool {
            runner,
            handle: pool_handle,
            updates: _,
        } = SenderPool::new(Arc::clone(&session), api_id);
        let client = Client::new(pool_handle.clone());
        let pool_task = tokio::spawn(runner.run());

        Self {
            client,
            session,
            pool_handle,
            pool_task,
        }
    }

    fn open_empty(api_id: i32) -> Self {
        Self::open(LoadedSession::default(), api_id)
    }

    fn open_serialized(session_data: &[u8], api_id: i32) -> Result<Self> {
        let load =
            load_session(session_data).context("failed to load serialized session snapshot")?;
        Ok(Self::open(load.session, api_id))
    }

    fn snapshot(&self) -> Result<SensitiveBytes> {
        serialize_session(self.session.as_ref())
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
struct ActiveSessionView {
    id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    issued_at: String,
    expires_at: String,
    is_current: bool,
}

#[derive(Clone, Debug, Serialize)]
struct AdminUserView {
    id: String,
    username: String,
    role: String,
    locked: bool,
    totp_enabled: bool,
    password_ready: bool,
    active_sessions: usize,
    recovery_codes_remaining: i64,
    last_login_ip: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SelectOption {
    value: &'static str,
    label: String,
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

    fn success(message: impl Into<String>) -> Self {
        Self {
            kind: "success",
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
    mfa_code: Option<String>,
    recovery_code: Option<String>,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
    confirm_password: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct IdleTimeoutForm {
    idle_timeout_minutes: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TotpConfirmForm {
    code: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SessionNoteForm {
    note: String,
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
struct RenameSessionForm {
    session_name: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminCreateUserForm {
    username: String,
    password: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminSaveSettingsForm {
    registration_policy: String,
    public_registration_open: Option<String>,
    session_absolute_ttl_hours: u32,
    audit_detail_limit: u32,
    totp_policy: String,
    password_strength_policy: String,
    password_min_length: usize,
    password_require_uppercase: Option<String>,
    password_require_lowercase: Option<String>,
    password_require_number: Option<String>,
    password_require_symbol: Option<String>,
    lockout_threshold: u32,
    lockout_base_delay_seconds: u64,
    lockout_max_delay_seconds: u64,
    max_idle_timeout_minutes: String,
    argon_memory_mib: u32,
    argon_iterations: u32,
    argon_lanes: u32,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RevokeSessionsForm {
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FlowPageQuery {
    lang: Option<String>,
    error: Option<String>,
}

fn load_embedded_templates() -> Result<Tera> {
    let mut tera = Tera::default();
    tera.add_raw_templates(EMBEDDED_TEMPLATES)
        .context("failed to initialize embedded templates")?;
    Ok(tera)
}

#[tokio::main]
async fn main() -> Result<()> {
    if matches!(std::env::args().nth(1).as_deref(), Some("healthcheck")) {
        return run_healthcheck_command().await;
    }

    dotenvy::dotenv().ok();
    init_tracing();
    harden_process_memory();

    let config = load_config()?;
    let runtime = RuntimeConfig {
        api_id: config.api_id,
        api_hash: config.api_hash,
        sessions_dir: config.sessions_dir.clone(),
        users_dir: config.sessions_dir.join("users"),
        app_data_dir: config.sessions_dir.join(".hanagram"),
        meta_db_path: config
            .sessions_dir
            .join(".hanagram")
            .join(META_DB_FILE_NAME),
        notification_settings_path: config
            .sessions_dir
            .join(".hanagram")
            .join(BOT_SETTINGS_FILE_NAME),
    };

    tokio::fs::create_dir_all(&runtime.sessions_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.sessions_dir.display()))?;
    tokio::fs::create_dir_all(&runtime.users_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.users_dir.display()))?;
    tokio::fs::create_dir_all(&runtime.app_data_dir)
        .await
        .with_context(|| format!("failed to create {}", runtime.app_data_dir.display()))?;

    let tera = Arc::new(load_embedded_templates()?);
    let shared_state: SharedState = Arc::new(RwLock::new(HashMap::new()));
    let session_workers: SessionWorkers = Arc::new(Mutex::new(HashMap::new()));
    let phone_flows: PendingPhoneFlows = Arc::new(RwLock::new(HashMap::new()));
    let qr_flows: PendingQrFlows = Arc::new(RwLock::new(HashMap::new()));
    let totp_setups: PendingTotpSetups = Arc::new(RwLock::new(HashMap::new()));
    let unlock_cache: UnlockCache = Arc::new(RwLock::new(HashMap::new()));
    let user_keys: UserKeyCache = Arc::new(RwLock::new(HashMap::new()));
    let meta_store = Arc::new(MetaStore::open(&runtime.meta_db_path).await?);
    let system_settings = Arc::new(RwLock::new(meta_store.load_system_settings().await?));
    let notification_settings = Arc::new(RwLock::new(
        load_bot_notification_settings(&runtime.notification_settings_path).await,
    ));

    let app_state = AppState {
        shared_state: Arc::clone(&shared_state),
        session_workers,
        tera,
        meta_store: Arc::clone(&meta_store),
        system_settings,
        runtime,
        phone_flows,
        qr_flows,
        totp_setups,
        unlock_cache,
        user_keys,
        notification_settings,
        http_client: HttpClient::new(),
    };

    let session_records = app_state.meta_store.list_all_session_records().await?;
    for session_record in session_records {
        register_session_record(&app_state, session_record).await;
    }

    let protected = Router::new()
        .route("/", get(index_handler))
        .route("/settings", get(settings_page_handler))
        .route(
            "/settings/notifications",
            get(notification_settings_page_handler),
        )
        .route("/settings/bot", post(save_bot_settings_handler))
        .route("/settings/security/password", post(change_password_handler))
        .route(
            "/settings/security/idle-timeout",
            post(update_idle_timeout_handler),
        )
        .route(
            "/settings/security/totp/setup",
            get(totp_setup_page_handler),
        )
        .route(
            "/settings/security/totp/setup",
            post(confirm_totp_setup_handler),
        )
        .route("/admin", get(admin_page_handler))
        .route("/admin/users/create", post(admin_create_user_handler))
        .route(
            "/admin/users/{user_id}/unlock",
            post(admin_unlock_user_handler),
        )
        .route(
            "/admin/users/{user_id}/reset",
            post(admin_reset_user_handler),
        )
        .route(
            "/admin/users/{user_id}/sessions/revoke",
            post(admin_revoke_user_sessions_handler),
        )
        .route("/admin/settings", post(admin_save_system_settings_handler))
        .route("/sessions/new", get(session_setup_page_handler))
        .route(
            "/sessions/import/string",
            post(import_string_session_handler),
        )
        .route("/sessions/import/upload", post(import_session_file_handler))
        .route(
            "/sessions/{session_key}/note",
            post(update_session_note_handler),
        )
        .route(
            "/sessions/{session_key}/delete",
            post(delete_session_handler),
        )
        .route(
            "/sessions/{session_key}/rename",
            post(rename_session_handler),
        )
        .route(
            "/sessions/{session_key}/export/file",
            get(export_session_file_handler),
        )
        .route(
            "/sessions/{session_key}/export/string",
            get(export_string_session_handler),
        )
        .route("/sessions/login/phone", post(start_phone_login_handler))
        .route("/sessions/login/qr", post(start_qr_login_handler))
        .route("/api/dashboard/snapshot", get(dashboard_snapshot_handler))
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
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_login,
        ));

    let app = Router::new()
        .merge(protected)
        .route(
            "/register",
            get(register_page_handler).post(register_submit_handler),
        )
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

async fn run_healthcheck_command() -> Result<()> {
    let url = std::env::args()
        .nth(2)
        .unwrap_or_else(|| String::from("http://127.0.0.1:8080/health"));
    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("healthcheck request failed for {url}"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "healthcheck returned {}",
        response.status()
    );
    Ok(())
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

fn harden_process_memory() {
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                warn!(
                    "failed disabling core dumps: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                warn!(
                    "failed disabling process dumpability: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

fn load_config() -> Result<Config> {
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
        api_id,
        api_hash,
        sessions_dir,
        bind_addr,
    })
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var {name}"))
}

async fn load_bot_notification_settings(path: &Path) -> BotNotificationSettings {
    let env_defaults = BotNotificationSettings {
        enabled: std::env::var("BOT_NOTIFY_ENABLED")
            .ok()
            .as_deref()
            .map(parse_env_bool)
            .unwrap_or(false),
        bot_token: std::env::var("BOT_NOTIFY_TOKEN").unwrap_or_default(),
        chat_id: std::env::var("BOT_NOTIFY_CHAT_ID").unwrap_or_default(),
        template: std::env::var("BOT_NOTIFY_TEMPLATE")
            .unwrap_or_else(|_| String::from(DEFAULT_BOT_TEMPLATE)),
    }
    .normalized();

    let raw = match tokio::fs::read(path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return env_defaults,
        Err(error) => {
            warn!(
                "failed reading bot notification settings {}: {}",
                path.display(),
                error
            );
            return env_defaults;
        }
    };

    match serde_json::from_slice::<BotNotificationSettings>(&raw) {
        Ok(settings) => settings.normalized(),
        Err(error) => {
            warn!(
                "failed parsing bot notification settings {}: {}",
                path.display(),
                error
            );
            env_defaults
        }
    }
}

async fn save_bot_notification_settings(
    path: &Path,
    settings: &BotNotificationSettings,
) -> Result<()> {
    let payload = serde_json::to_vec_pretty(settings)
        .context("failed to serialize bot notification settings")?;
    tokio::fs::write(path, payload)
        .await
        .with_context(|| format!("failed writing {}", path.display()))
}

fn parse_env_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

async fn require_login(
    State(app_state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let language = detect_language(request.headers(), None);
    let settings = app_state.system_settings.read().await.clone();
    let Some(authenticated) =
        resolve_authenticated_session(&app_state.meta_store, &settings, request.headers())
            .await
            .ok()
            .flatten()
    else {
        clear_invalid_cookie_state(&app_state, request.headers()).await;
        let location = match request.uri().query() {
            Some(query) if !query.is_empty() => format!("/login?{query}"),
            _ => String::from("/login"),
        };
        let mut response = Redirect::to(&location).into_response();
        if find_cookie(request.headers(), AUTH_COOKIE_NAME).is_some() {
            if let Ok(cookie) = set_cookie_header(&clear_auth_cookie(settings.cookie_secure)) {
                response.headers_mut().insert(header::SET_COOKIE, cookie);
            }
        }
        return response;
    };

    let path = request.uri().path();
    let allow_totp_setup = path.starts_with("/settings/security/totp")
        || path == "/logout"
        || path == "/api/dashboard/snapshot";
    if (authenticated.requires_totp_setup || authenticated.recovery_codes_remaining == 0)
        && !allow_totp_setup
    {
        return Redirect::to(&format!(
            "/settings/security/totp/setup?lang={}",
            language.code()
        ))
        .into_response();
    }

    request.extensions_mut().insert(authenticated);
    next.run(request).await
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

fn sanitize_phone_input(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|ch| ch.is_ascii_digit() || *ch == '+')
        .collect()
}

fn format_phone_display(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let candidate = if trimmed.starts_with('+') {
        trimmed.to_owned()
    } else if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        format!("+{trimmed}")
    } else {
        trimmed.to_owned()
    };

    match phonenumber::parse(None, &candidate) {
        Ok(phone) => phone
            .format()
            .mode(PhoneNumberMode::International)
            .to_string(),
        Err(_) => trimmed.split_whitespace().collect::<Vec<_>>().join(" "),
    }
}

async fn initialize_session_entry(shared_state: &SharedState, record: &SessionRecord) {
    let mut state = shared_state.write().await;
    match state.entry(record.id.clone()) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            let session = entry.get_mut();
            session.user_id = record.user_id.clone();
            session.key = record.session_key.clone();
            session.note = record.note.clone();
            session.session_file = PathBuf::from(&record.storage_path);
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(SessionInfo {
                id: record.id.clone(),
                user_id: record.user_id.clone(),
                key: record.session_key.clone(),
                note: record.note.clone(),
                phone: fallback_phone(Path::new(&record.storage_path)),
                session_file: PathBuf::from(&record.storage_path),
                status: SessionStatus::Connecting,
                messages: VecDeque::new(),
            });
        }
    }
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
        info.phone = format_phone_display(&phone);
    }
}

async fn set_session_note(shared_state: &SharedState, key: &str, note: String) {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        info.note = note;
    }
}

async fn push_otp_message(
    shared_state: &SharedState,
    key: &str,
    otp: OtpMessage,
) -> Option<SessionInfo> {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        if info
            .messages
            .front()
            .is_some_and(|message| message.text == otp.text && message.code == otp.code)
        {
            return None;
        }

        info.messages.push_front(otp);
        info.messages.truncate(20);
        return Some(info.clone());
    }

    None
}

async fn maybe_dispatch_bot_notification(
    settings_store: &NotificationSettingsStore,
    http_client: &HttpClient,
    session: &SessionInfo,
    otp: &OtpMessage,
) {
    let Some(code) = otp.code.clone() else {
        return;
    };

    let settings = settings_store.read().await.clone();
    if !settings.is_ready() {
        return;
    }

    let payload = OtpNotificationPayload {
        session_key: session.key.clone(),
        phone: session.phone.clone(),
        code,
        message: otp.text.clone(),
        received_at: otp.received_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        session_file: session.session_file.display().to_string(),
        status: String::from(current_status_label(&session.status)),
    };
    let text = render_bot_notification_text(&settings.template, &payload);
    let http_client = http_client.clone();

    tokio::spawn(async move {
        if let Err(error) = send_bot_notification(&http_client, &settings, &text).await {
            warn!(
                "failed sending bot notification for {}: {}",
                payload.session_key, error
            );
        }
    });
}

fn render_bot_notification_text(template: &str, payload: &OtpNotificationPayload) -> String {
    [
        ("{code}", payload.code.as_str()),
        ("{phone}", payload.phone.as_str()),
        ("{session_key}", payload.session_key.as_str()),
        ("{session_file}", payload.session_file.as_str()),
        ("{received_at}", payload.received_at.as_str()),
        ("{status}", payload.status.as_str()),
        ("{message}", payload.message.as_str()),
    ]
    .into_iter()
    .fold(template.to_owned(), |message, (placeholder, value)| {
        message.replace(placeholder, value)
    })
}

async fn send_bot_notification(
    http_client: &HttpClient,
    settings: &BotNotificationSettings,
    text: &str,
) -> Result<()> {
    let response = http_client
        .post(format!(
            "https://api.telegram.org/bot{}/sendMessage",
            settings.bot_token
        ))
        .json(&serde_json::json!({
            "chat_id": settings.chat_id,
            "text": text,
            "disable_web_page_preview": true,
        }))
        .send()
        .await
        .context("telegram bot request failed")?;

    response
        .error_for_status()
        .context("telegram bot request returned an error status")?;
    Ok(())
}

async fn register_session_record(app_state: &AppState, session_record: SessionRecord) {
    let mut runtime_record = session_record.clone();
    if let Err(error) = hydrate_session_record(app_state, &mut runtime_record).await {
        warn!(
            "failed hydrating session note for {}: {}",
            session_record.id, error
        );
        runtime_record.note.clear();
    }
    initialize_session_entry(&app_state.shared_state, &runtime_record).await;

    let existing_worker = app_state
        .session_workers
        .lock()
        .await
        .remove(&session_record.id);
    if let Some(existing_worker) = existing_worker {
        existing_worker.cancellation.cancel();
        let _ = existing_worker.task.await;
    }

    let worker_key = session_record.id.clone();
    let encrypted_session_file = PathBuf::from(&session_record.storage_path);
    let Some(master_key) = app_state
        .user_keys
        .read()
        .await
        .get(&session_record.user_id)
        .cloned()
    else {
        set_session_status(
            &app_state.shared_state,
            &worker_key,
            SessionStatus::Error(String::from(
                "Encrypted at rest. Sign in again to unlock this session.",
            )),
        )
        .await;
        return;
    };
    let session =
        match load_persisted_session(master_key.as_ref().as_slice(), &encrypted_session_file).await
        {
            Ok(session) => Arc::new(session),
            Err(error) => {
                warn!(
                    "failed loading persisted session {}: {}",
                    encrypted_session_file.display(),
                    error
                );
                set_session_status(
                    &app_state.shared_state,
                    &worker_key,
                    SessionStatus::Error(String::from("failed to unlock encrypted session")),
                )
                .await;
                return;
            }
        };
    let worker_state = Arc::clone(&app_state.shared_state);
    let api_id = app_state.runtime.api_id;
    let notification_settings = Arc::clone(&app_state.notification_settings);
    let http_client = app_state.http_client.clone();
    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();

    let task = tokio::spawn(async move {
        run_session_worker(
            worker_key,
            encrypted_session_file,
            session,
            worker_state,
            api_id,
            master_key,
            notification_settings,
            http_client,
            worker_cancellation,
        )
        .await;
    });

    app_state.session_workers.lock().await.insert(
        session_record.id,
        SessionWorkerHandle { cancellation, task },
    );
}

#[derive(Debug, Eq, PartialEq)]
enum SessionFailureAction {
    Retryable(String),
    Terminal(String),
}

fn classify_session_failure(error: &anyhow::Error) -> SessionFailureAction {
    const SESSION_LOAD_FAILED: &str = "failed to load session";
    const SESSION_UNAUTHORIZED: &str = "session is no longer authorized";

    if error.to_string() == SESSION_LOAD_FAILED {
        return SessionFailureAction::Terminal(String::from(SESSION_LOAD_FAILED));
    }

    if error.to_string() == "session is not authorized" {
        return SessionFailureAction::Terminal(String::from(SESSION_UNAUTHORIZED));
    }

    for cause in error.chain() {
        if let Some(invocation_error) = cause.downcast_ref::<InvocationError>() {
            match invocation_error {
                InvocationError::Rpc(rpc_error) if rpc_error.code == 401 => {
                    return SessionFailureAction::Terminal(String::from(SESSION_UNAUTHORIZED));
                }
                InvocationError::Transport(transport_error)
                    if transport_error
                        .to_string()
                        .contains("bad status (negative length -404)") =>
                {
                    return SessionFailureAction::Terminal(String::from(SESSION_UNAUTHORIZED));
                }
                _ => {}
            }
        }
    }

    SessionFailureAction::Retryable(error.to_string())
}

async fn run_session_worker(
    key: String,
    encrypted_session_file: PathBuf,
    session: Arc<LoadedSession>,
    shared_state: SharedState,
    api_id: i32,
    master_key: SharedMasterKey,
    notification_settings: NotificationSettingsStore,
    http_client: HttpClient,
    cancellation: CancellationToken,
) {
    let retry_delays = [5_u64, 10, 20, 40, 80];
    let mut attempt = 0_usize;

    loop {
        if cancellation.is_cancelled() {
            break;
        }

        set_session_status(&shared_state, &key, SessionStatus::Connecting).await;

        let result = run_session_once(
            &key,
            Arc::clone(&session),
            &shared_state,
            api_id,
            &notification_settings,
            &http_client,
            &cancellation,
        )
        .await;

        if let Err(error) = persist_loaded_session(
            master_key.as_ref().as_slice(),
            &encrypted_session_file,
            session.as_ref(),
        )
        .await
        {
            warn!(
                "failed persisting encrypted session {}: {}",
                encrypted_session_file.display(),
                error
            );
        }

        match result {
            Ok(()) => break,
            Err(error) => {
                warn!(
                    "session {} failed: {error:#}",
                    encrypted_session_file.display()
                );

                match classify_session_failure(&error) {
                    SessionFailureAction::Terminal(message) => {
                        set_session_status(&shared_state, &key, SessionStatus::Error(message))
                            .await;
                        break;
                    }
                    SessionFailureAction::Retryable(message) => {
                        set_session_status(&shared_state, &key, SessionStatus::Error(message))
                            .await;

                        if attempt >= retry_delays.len() {
                            break;
                        }

                        let delay = retry_delays[attempt];
                        attempt += 1;
                        tokio::select! {
                            _ = cancellation.cancelled() => break,
                            _ = sleep(Duration::from_secs(delay)) => {}
                        }
                    }
                }
            }
        }
    }

    if let Err(error) = persist_loaded_session(
        master_key.as_ref().as_slice(),
        &encrypted_session_file,
        session.as_ref(),
    )
    .await
    {
        warn!(
            "failed final session persistence {}: {}",
            encrypted_session_file.display(),
            error
        );
    }
}

async fn run_session_once(
    key: &str,
    session: Arc<LoadedSession>,
    shared_state: &SharedState,
    api_id: i32,
    notification_settings: &NotificationSettingsStore,
    http_client: &HttpClient,
    cancellation: &CancellationToken,
) -> Result<()> {
    let SenderPool {
        runner,
        handle: pool_handle,
        updates,
    } = SenderPool::new(Arc::clone(&session), api_id);
    let client = Client::new(pool_handle.clone());
    let pool_task = tokio::spawn(runner.run());

    let result = tokio::select! {
        _ = cancellation.cancelled() => Ok(()),
        result = async {
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
                tokio::select! {
                    _ = cancellation.cancelled() => return Ok(()),
                    update = updates.next() => match update {
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
                            let session_snapshot = push_otp_message(shared_state, key, otp.clone()).await;
                            if let Some(session_snapshot) = session_snapshot {
                                maybe_dispatch_bot_notification(
                                    notification_settings,
                                    http_client,
                                    &session_snapshot,
                                    &otp,
                                )
                                .await;
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            updates.sync_update_state().await;
                            return Err(error).context("update loop failed");
                        }
                    }
                }
            }
        } => result,
    };

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

fn settings_href(language: Language) -> String {
    format!("/settings?lang={}", language.code())
}

fn notifications_href(language: Language) -> String {
    format!("/settings/notifications?lang={}", language.code())
}

fn admin_href(language: Language) -> String {
    format!("/admin?lang={}", language.code())
}

fn user_sessions_dir(runtime: &RuntimeConfig, user_id: &str) -> PathBuf {
    runtime.users_dir.join(user_id)
}

fn session_storage_path(runtime: &RuntimeConfig, user_id: &str, session_id: &str) -> PathBuf {
    user_sessions_dir(runtime, user_id).join(format!("{session_id}.session"))
}

async fn ensure_user_sessions_dir(runtime: &RuntimeConfig, user_id: &str) -> Result<PathBuf> {
    let dir = user_sessions_dir(runtime, user_id);
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(dir)
}

fn format_unix_timestamp(unix: i64) -> String {
    match DateTime::from_timestamp(unix, 0) {
        Some(timestamp) => timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => String::from("-"),
    }
}

fn registration_policy_value(policy: RegistrationPolicy) -> &'static str {
    match policy {
        RegistrationPolicy::AlwaysPublic => "always_public",
        RegistrationPolicy::AdminOnly => "admin_only",
        RegistrationPolicy::AdminSelectable => "admin_selectable",
    }
}

fn parse_registration_policy(raw: &str) -> RegistrationPolicy {
    match raw {
        "always_public" => RegistrationPolicy::AlwaysPublic,
        "admin_selectable" => RegistrationPolicy::AdminSelectable,
        _ => RegistrationPolicy::AdminOnly,
    }
}

fn registration_policy_options(language: Language) -> Vec<SelectOption> {
    match language {
        Language::En => vec![
            SelectOption {
                value: "always_public",
                label: String::from("Public Registration"),
            },
            SelectOption {
                value: "admin_only",
                label: String::from("Admin Only"),
            },
            SelectOption {
                value: "admin_selectable",
                label: String::from("Admin Toggle"),
            },
        ],
        Language::ZhCn => vec![
            SelectOption {
                value: "always_public",
                label: String::from("公开注册"),
            },
            SelectOption {
                value: "admin_only",
                label: String::from("仅管理员创建"),
            },
            SelectOption {
                value: "admin_selectable",
                label: String::from("管理员可开关"),
            },
        ],
    }
}

fn enforcement_mode_value(mode: EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::AdminExempt => "admin_exempt",
        EnforcementMode::Disabled => "disabled",
        EnforcementMode::AllUsers => "all_users",
    }
}

fn parse_enforcement_mode(raw: &str) -> EnforcementMode {
    match raw {
        "admin_exempt" => EnforcementMode::AdminExempt,
        "disabled" => EnforcementMode::Disabled,
        _ => EnforcementMode::AllUsers,
    }
}

fn enforcement_mode_options(language: Language) -> Vec<SelectOption> {
    match language {
        Language::En => vec![
            SelectOption {
                value: "all_users",
                label: String::from("All Users"),
            },
            SelectOption {
                value: "disabled",
                label: String::from("Disabled"),
            },
            SelectOption {
                value: "admin_exempt",
                label: String::from("Admin Exempt"),
            },
        ],
        Language::ZhCn => vec![
            SelectOption {
                value: "all_users",
                label: String::from("所有人都要"),
            },
            SelectOption {
                value: "disabled",
                label: String::from("所有人都不需要"),
            },
            SelectOption {
                value: "admin_exempt",
                label: String::from("管理员自己不需要"),
            },
        ],
    }
}

fn selected_option_label(options: &[SelectOption], value: &str) -> String {
    options
        .iter()
        .find(|option| option.value == value)
        .map(|option| option.label.clone())
        .unwrap_or_else(|| value.to_owned())
}

fn bot_status_summary(settings: &BotNotificationSettings, language: Language) -> String {
    if !settings.enabled {
        return match language {
            Language::En => String::from("Disabled"),
            Language::ZhCn => String::from("未启用"),
        };
    }

    if settings.bot_token.is_empty() || settings.chat_id.is_empty() {
        return match language {
            Language::En => String::from("Incomplete"),
            Language::ZhCn => String::from("配置未完成"),
        };
    }

    match language {
        Language::En => String::from("Enabled"),
        Language::ZhCn => String::from("已启用"),
    }
}

fn bot_destination_summary(settings: &BotNotificationSettings, language: Language) -> String {
    if settings.chat_id.is_empty() {
        return match language {
            Language::En => String::from("Not configured"),
            Language::ZhCn => String::from("未配置"),
        };
    }

    settings.chat_id.clone()
}

fn template_preview(template: &str, max_chars: usize) -> String {
    let normalized = template.lines().next().unwrap_or("").trim();
    if normalized.chars().count() <= max_chars {
        return normalized.to_owned();
    }

    let preview = normalized.chars().take(max_chars).collect::<String>();
    format!("{preview}...")
}

fn effective_idle_timeout_minutes(
    user: &hanagram_web::store::UserRecord,
    settings: &SystemSettings,
) -> Option<u32> {
    match (
        user.security.preferred_idle_timeout_minutes,
        settings.max_idle_timeout_minutes,
    ) {
        (Some(0), None) => Some(0),
        (Some(0), Some(maximum)) => Some(maximum),
        (Some(minutes), Some(maximum)) => Some(minutes.min(maximum)),
        (Some(minutes), None) => Some(minutes),
        (None, system_default) => system_default,
    }
}

fn format_idle_timeout_label(idle_timeout_minutes: Option<u32>, language: Language) -> String {
    match idle_timeout_minutes {
        Some(0) => match language {
            Language::En => String::from("Never sign out"),
            Language::ZhCn => String::from("永久不自动登出"),
        },
        Some(minutes) => match language {
            Language::En => format!("{minutes} minutes"),
            Language::ZhCn => format!("{minutes} 分钟"),
        },
        None => match language {
            Language::En => String::from("Use system default"),
            Language::ZhCn => String::from("使用系统默认值"),
        },
    }
}

fn parse_user_idle_timeout_preference(
    raw: &str,
    system_max_idle_timeout_minutes: Option<u32>,
) -> Result<Option<u32>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("default") {
        return Ok(None);
    }
    if trimmed == "0" || trimmed.eq_ignore_ascii_case("never") {
        anyhow::ensure!(
            system_max_idle_timeout_minutes.is_none(),
            "the current system policy does not allow permanent sign-in sessions"
        );
        return Ok(Some(0));
    }

    let minutes = trimmed
        .parse::<u32>()
        .with_context(|| format!("invalid idle timeout value: {trimmed}"))?;
    anyhow::ensure!(minutes > 0, "idle timeout must be at least 1 minute");
    if let Some(system_maximum) = system_max_idle_timeout_minutes {
        anyhow::ensure!(
            minutes <= system_maximum,
            "idle timeout cannot exceed the system maximum of {system_maximum} minutes"
        );
    }

    Ok(Some(minutes))
}

fn parse_admin_idle_timeout_cap(raw: &str) -> Result<Option<u32>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let minutes = trimmed
        .parse::<u32>()
        .with_context(|| format!("invalid system idle timeout value: {trimmed}"))?;
    anyhow::ensure!(minutes > 0, "system idle timeout must be at least 1 minute");
    Ok(Some(minutes))
}

async fn registration_page_allowed(store: &MetaStore, settings: &SystemSettings) -> bool {
    if store.count_users().await.unwrap_or(0) == 0
        || settings
            .registration_policy
            .allows_public_registration(settings.public_registration_open)
    {
        return true;
    }

    store
        .list_users()
        .await
        .map(|users| {
            users
                .into_iter()
                .any(|user| user.security.password_hash.is_none())
        })
        .unwrap_or(false)
}

async fn registration_submit_allowed(
    store: &MetaStore,
    settings: &SystemSettings,
    username: &str,
) -> bool {
    if store.count_users().await.unwrap_or(0) == 0
        || settings
            .registration_policy
            .allows_public_registration(settings.public_registration_open)
    {
        return true;
    }

    let Ok(username) = normalize_username(username) else {
        return false;
    };

    matches!(
        store.get_user_by_username(&username).await,
        Ok(Some(user)) if user.security.password_hash.is_none()
    )
}

async fn sync_active_session_idle_timeouts(
    app_state: &AppState,
    settings: &SystemSettings,
) -> Result<()> {
    let users = app_state.meta_store.list_users().await?;
    for user in users {
        app_state
            .meta_store
            .set_idle_timeout_for_user_sessions(
                &user.id,
                effective_idle_timeout_minutes(&user, settings),
            )
            .await?;
    }
    Ok(())
}

async fn resolved_user_master_key(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
) -> Option<SharedMasterKey> {
    if let Some(master_key) = app_state
        .user_keys
        .read()
        .await
        .get(&authenticated.user.id)
        .cloned()
    {
        return Some(master_key);
    }

    app_state
        .unlock_cache
        .read()
        .await
        .get(&authenticated.auth_session.id)
        .cloned()
}

async fn cache_user_master_key(
    app_state: &AppState,
    user_id: &str,
    auth_session_id: &str,
    master_key: MasterKey,
) {
    let shared_master_key = share_master_key(master_key);
    app_state
        .unlock_cache
        .write()
        .await
        .insert(auth_session_id.to_owned(), Arc::clone(&shared_master_key));
    app_state
        .user_keys
        .write()
        .await
        .insert(user_id.to_owned(), shared_master_key);
    unlock_user_sessions(app_state, user_id).await;
}

async fn unlock_user_sessions(app_state: &AppState, user_id: &str) {
    if let Ok(session_records) = app_state
        .meta_store
        .list_session_records_for_user(user_id)
        .await
    {
        for session_record in session_records {
            register_session_record(app_state, session_record).await;
        }
    }
}

fn auth_session_is_active(auth_session: &AuthSessionRecord, now: i64) -> bool {
    if auth_session.revoked_at_unix.is_some() || auth_session.expires_at_unix <= now {
        return false;
    }

    match auth_session.idle_timeout_minutes {
        Some(0) | None => true,
        Some(idle_timeout_minutes) => {
            auth_session.last_seen_at_unix + i64::from(idle_timeout_minutes) * 60 > now
        }
    }
}

async fn clear_pending_flows_for_auth_session(app_state: &AppState, auth_session_id: &str) {
    app_state.totp_setups.write().await.remove(auth_session_id);
    app_state
        .phone_flows
        .write()
        .await
        .retain(|_, flow| flow.auth_session_id != auth_session_id);
    app_state
        .qr_flows
        .write()
        .await
        .retain(|_, flow| flow.auth_session_id != auth_session_id);
}

async fn clear_pending_flows_for_user(app_state: &AppState, user_id: &str) {
    app_state
        .phone_flows
        .write()
        .await
        .retain(|_, flow| flow.user_id != user_id);
    app_state
        .qr_flows
        .write()
        .await
        .retain(|_, flow| flow.user_id != user_id);
}

async fn clear_auth_session_sensitive_state(app_state: &AppState, auth_session_id: &str) {
    app_state.unlock_cache.write().await.remove(auth_session_id);
    clear_pending_flows_for_auth_session(app_state, auth_session_id).await;
}

async fn drop_user_master_key_if_no_active_sessions(app_state: &AppState, user_id: &str) {
    let Ok(sessions) = app_state
        .meta_store
        .list_auth_sessions_for_user(user_id)
        .await
    else {
        return;
    };
    let now = Utc::now().timestamp();
    if sessions
        .iter()
        .any(|auth_session| auth_session_is_active(auth_session, now))
    {
        return;
    }

    {
        let mut unlock_cache = app_state.unlock_cache.write().await;
        for auth_session in &sessions {
            unlock_cache.remove(&auth_session.id);
        }
    }
    {
        let mut totp_setups = app_state.totp_setups.write().await;
        for auth_session in &sessions {
            totp_setups.remove(&auth_session.id);
        }
    }
    app_state.user_keys.write().await.remove(user_id);
    clear_pending_flows_for_user(app_state, user_id).await;
}

async fn clear_invalid_cookie_state(app_state: &AppState, headers: &HeaderMap) {
    let Some(token) = find_cookie(headers, AUTH_COOKIE_NAME) else {
        return;
    };
    let token_hash = hash_session_token(token);
    let Ok(Some(auth_session)) = app_state
        .meta_store
        .get_auth_session_by_token_hash(&token_hash)
        .await
    else {
        return;
    };

    let now = Utc::now().timestamp();
    if auth_session_is_active(&auth_session, now) {
        return;
    }

    if auth_session.revoked_at_unix.is_none() {
        let _ = app_state
            .meta_store
            .revoke_auth_session(&auth_session.id)
            .await;
    }
    clear_auth_session_sensitive_state(app_state, &auth_session.id).await;
    drop_user_master_key_if_no_active_sessions(app_state, &auth_session.user_id).await;
}

fn encrypt_session_text_field(
    raw_value: &str,
    master_key: &[u8],
    prefix: &str,
    field_name: &str,
) -> Result<String> {
    if raw_value.is_empty() {
        return Ok(String::new());
    }
    let payload = encrypt_bytes(master_key, raw_value.as_bytes())?;
    let encoded = serde_json::to_string(&payload)
        .with_context(|| format!("failed to encode encrypted {field_name}"))?;
    Ok(format!("{prefix}{encoded}"))
}

fn decrypt_session_text_field(
    raw_value: &str,
    master_key: &[u8],
    prefix: &str,
    field_name: &str,
) -> Result<(String, bool)> {
    if raw_value.is_empty() {
        return Ok((String::new(), false));
    }
    let Some(payload) = raw_value.strip_prefix(prefix) else {
        return Ok((raw_value.to_owned(), true));
    };
    let payload: EncryptedBlob = serde_json::from_str(payload)
        .with_context(|| format!("failed to decode encrypted {field_name}"))?;
    let plaintext = decrypt_bytes(master_key, &payload)?;
    let value = String::from_utf8(plaintext.to_vec())
        .with_context(|| format!("{field_name} was not valid utf-8"))?;
    Ok((value, false))
}

fn encrypt_session_key(session_key: &str, master_key: &[u8]) -> Result<String> {
    encrypt_session_text_field(
        session_key,
        master_key,
        SESSION_KEY_PREFIX,
        "session key payload",
    )
}

fn decrypt_session_key(raw_session_key: &str, master_key: &[u8]) -> Result<(String, bool)> {
    decrypt_session_text_field(
        raw_session_key,
        master_key,
        SESSION_KEY_PREFIX,
        "session key payload",
    )
}

fn encrypt_session_note(note: &str, master_key: &[u8]) -> Result<String> {
    encrypt_session_text_field(note, master_key, SESSION_NOTE_PREFIX, "session note")
}

fn decrypt_session_note(raw_note: &str, master_key: &[u8]) -> Result<(String, bool)> {
    decrypt_session_text_field(raw_note, master_key, SESSION_NOTE_PREFIX, "session note")
}

async fn persist_session_record(app_state: &AppState, record: &SessionRecord) -> Result<()> {
    let master_key = app_state
        .user_keys
        .read()
        .await
        .get(&record.user_id)
        .cloned()
        .context("user data is locked; sign in again to unlock it")?;
    let mut encrypted_record = record.clone();
    encrypted_record.session_key =
        encrypt_session_key(&record.session_key, master_key.as_ref().as_slice())?;
    encrypted_record.note = encrypt_session_note(&record.note, master_key.as_ref().as_slice())?;
    app_state
        .meta_store
        .save_session_record(&encrypted_record)
        .await
}

async fn hydrate_session_record(app_state: &AppState, record: &mut SessionRecord) -> Result<()> {
    let Some(master_key) = app_state
        .user_keys
        .read()
        .await
        .get(&record.user_id)
        .cloned()
    else {
        record.session_key = session_key(Path::new(&record.storage_path));
        record.note.clear();
        return Ok(());
    };
    let (session_key_value, key_was_legacy_plaintext) =
        decrypt_session_key(&record.session_key, master_key.as_ref().as_slice())?;
    let (note, note_was_legacy_plaintext) =
        decrypt_session_note(&record.note, master_key.as_ref().as_slice())?;
    record.session_key = session_key_value;
    record.note = note;
    if key_was_legacy_plaintext || note_was_legacy_plaintext {
        persist_session_record(app_state, record).await?;
    }
    Ok(())
}

fn decrypt_session_storage_bytes(master_key: &[u8], raw: &[u8]) -> Result<(SensitiveBytes, bool)> {
    match serde_json::from_slice::<EncryptedBlob>(raw) {
        Ok(payload) => Ok((decrypt_bytes(master_key, &payload)?, false)),
        Err(_) => Ok((into_sensitive_bytes(raw.to_vec()), true)),
    }
}

async fn write_encrypted_session_bytes(
    master_key: &[u8],
    encrypted_path: &Path,
    plaintext: &[u8],
) -> Result<()> {
    let payload = encrypt_bytes(master_key, plaintext)?;
    let encoded =
        serde_json::to_vec(&payload).context("failed to encode encrypted session payload")?;
    tokio::fs::write(encrypted_path, encoded)
        .await
        .with_context(|| format!("failed writing {}", encrypted_path.display()))
}

async fn read_decrypted_session_bytes(
    master_key: &[u8],
    encrypted_path: &Path,
) -> Result<SensitiveBytes> {
    let raw = tokio::fs::read(encrypted_path)
        .await
        .with_context(|| format!("failed reading {}", encrypted_path.display()))?;
    let (plaintext, was_legacy_plaintext) = decrypt_session_storage_bytes(master_key, &raw)?;
    if was_legacy_plaintext {
        write_encrypted_session_bytes(master_key, encrypted_path, plaintext.as_slice()).await?;
    }
    Ok(plaintext)
}

async fn load_persisted_session(master_key: &[u8], encrypted_path: &Path) -> Result<LoadedSession> {
    let plaintext = read_decrypted_session_bytes(master_key, encrypted_path).await?;
    let loaded =
        load_session(plaintext.as_slice()).context("failed to decode stored session payload")?;
    if loaded.needs_persist {
        persist_loaded_session(master_key, encrypted_path, &loaded.session).await?;
    }
    Ok(loaded.session)
}

async fn persist_loaded_session(
    master_key: &[u8],
    encrypted_path: &Path,
    session: &LoadedSession,
) -> Result<()> {
    let plaintext = serialize_session(session)?;
    write_encrypted_session_bytes(master_key, encrypted_path, plaintext.as_slice()).await
}

async fn save_new_session_record(
    app_state: &AppState,
    user_id: &str,
    session_id: &str,
    session_name: &str,
    session: &LoadedSession,
) -> Result<SessionRecord> {
    let master_key = app_state
        .user_keys
        .read()
        .await
        .get(user_id)
        .cloned()
        .context("user data is locked; sign in again to unlock it")?;
    let session_path = session_storage_path(&app_state.runtime, user_id, session_id);
    persist_loaded_session(master_key.as_ref().as_slice(), &session_path, session).await?;

    let record = SessionRecord::new(
        user_id.to_owned(),
        session_name.to_owned(),
        session_path.display().to_string(),
    );
    let mut record = record;
    record.id = session_id.to_owned();
    persist_session_record(app_state, &record).await?;
    register_session_record(app_state, record.clone()).await;
    Ok(record)
}

async fn load_owned_session_record(
    app_state: &AppState,
    user_id: &str,
    session_id: &str,
) -> Result<Option<SessionRecord>> {
    let Some(record) = app_state
        .meta_store
        .get_session_record_by_id(session_id)
        .await?
    else {
        return Ok(None);
    };
    if record.user_id != user_id {
        return Ok(None);
    }
    let mut record = record;
    if let Err(error) = hydrate_session_record(app_state, &mut record).await {
        warn!(
            "failed hydrating owned session note for {}: {}",
            record.id, error
        );
        record.note.clear();
    }
    Ok(Some(record))
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

fn current_status_label(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Connecting => "connecting",
        SessionStatus::Connected => "connected",
        SessionStatus::Error(_) => "error",
    }
}

fn build_bot_settings_view(settings: &BotNotificationSettings) -> BotNotificationSettingsView {
    BotNotificationSettingsView {
        enabled: settings.enabled,
        bot_token: settings.bot_token.clone(),
        chat_id: settings.chat_id.clone(),
        template: settings.template.clone(),
    }
}

fn build_bot_placeholder_hints(language: Language) -> [BotPlaceholderHint; 7] {
    let i18n = language.translations();
    [
        BotPlaceholderHint {
            key: "{code}",
            description: i18n.bot_placeholder_code,
        },
        BotPlaceholderHint {
            key: "{phone}",
            description: i18n.bot_placeholder_phone,
        },
        BotPlaceholderHint {
            key: "{session_key}",
            description: i18n.bot_placeholder_session_key,
        },
        BotPlaceholderHint {
            key: "{session_file}",
            description: i18n.bot_placeholder_session_file,
        },
        BotPlaceholderHint {
            key: "{received_at}",
            description: i18n.bot_placeholder_received_at,
        },
        BotPlaceholderHint {
            key: "{status}",
            description: i18n.bot_placeholder_status,
        },
        BotPlaceholderHint {
            key: "{message}",
            description: i18n.bot_placeholder_message,
        },
    ]
}

async fn build_dashboard_snapshot(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
) -> DashboardSnapshot {
    let sessions = {
        let state = app_state.shared_state.read().await;
        let mut sessions: Vec<SessionInfo> = state
            .values()
            .filter(|session| session.user_id == authenticated.user.id)
            .cloned()
            .collect();
        sessions.sort_by(|left, right| {
            right
                .latest_code_message()
                .map(|message| message.received_at)
                .cmp(
                    &left
                        .latest_code_message()
                        .map(|message| message.received_at),
                )
                .then_with(|| left.phone.cmp(&right.phone))
        });
        sessions
    };

    let connected_count = sessions
        .iter()
        .filter(|session| matches!(session.status, SessionStatus::Connected))
        .count();

    DashboardSnapshot {
        connected_count,
        generated_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        sessions,
    }
}

async fn render_dashboard_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/");
    let snapshot = build_dashboard_snapshot(app_state, authenticated).await;
    let settings_page_href = settings_href(language);

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("current_username", &authenticated.user.username);
    context.insert("show_admin", &(authenticated.user.role == UserRole::Admin));
    context.insert(
        "logout_action",
        &format!("/logout?lang={}", language.code()),
    );
    context.insert("setup_href", &setup_href(language));
    context.insert("settings_href", &settings_page_href);
    context.insert("admin_href", &admin_href(language));
    context.insert(
        "settings_label",
        &match language {
            Language::En => "Settings",
            Language::ZhCn => "设置",
        },
    );
    context.insert(
        "admin_label",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理后台",
        },
    );
    context.insert(
        "settings_security_href",
        &format!("{settings_page_href}#security"),
    );
    context.insert(
        "settings_notifications_href",
        &format!("{settings_page_href}#notifications"),
    );
    context.insert(
        "settings_access_href",
        &format!("{settings_page_href}#access"),
    );
    context.insert(
        "admin_overview_href",
        &format!("{}#overview", admin_href(language)),
    );
    context.insert(
        "dashboard_workspace_eyebrow",
        &match language {
            Language::En => "Workspace Map",
            Language::ZhCn => "工作区地图",
        },
    );
    context.insert(
        "dashboard_workspace_title",
        &match language {
            Language::En => "Session-first dashboard",
            Language::ZhCn => "会话优先主面板",
        },
    );
    context.insert(
        "dashboard_workspace_description",
        &match language {
            Language::En => "This screen is reserved for Telegram sessions and OTP flow. Security, reminder delivery, and browser access management are routed into Settings, while user policy and audit stay in Admin.",
            Language::ZhCn => "这个页面只保留给 Telegram 会话和验证码流。安全设置、提醒投递、网页登录管理统一收进设置页，用户策略和审计则集中在后台。",
        },
    );
    context.insert(
        "dashboard_lane_sessions_title",
        &match language {
            Language::En => "Dashboard",
            Language::ZhCn => "主面板",
        },
    );
    context.insert(
        "dashboard_lane_sessions_body",
        &match language {
            Language::En => "Watch live OTP state, open details, copy codes, rename sessions, and export access data.",
            Language::ZhCn => "查看实时验证码状态、打开详情、复制验证码、重命名会话和导出访问数据。",
        },
    );
    context.insert(
        "dashboard_lane_settings_title",
        &match language {
            Language::En => "Settings",
            Language::ZhCn => "设置",
        },
    );
    context.insert(
        "dashboard_lane_settings_body",
        &match language {
            Language::En => "Password changes, TOTP, recovery codes, reminder delivery, idle timeout, and active web sessions.",
            Language::ZhCn => "密码修改、TOTP、恢复码、提醒投递、空闲登出和网页登录会话都在这里。",
        },
    );
    context.insert(
        "dashboard_lane_admin_title",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理后台",
        },
    );
    context.insert(
        "dashboard_lane_admin_body",
        &match language {
            Language::En => "Create users, unlock accounts, tune policies, and review audit history without crowding the session view.",
            Language::ZhCn => "创建用户、解锁账号、调整策略和查看审计历史，避免挤占会话视图。",
        },
    );
    context.insert(
        "dashboard_shortcuts_title",
        &match language {
            Language::En => "Jump Directly",
            Language::ZhCn => "快速直达",
        },
    );
    context.insert(
        "dashboard_shortcuts_description",
        &match language {
            Language::En => "Secondary capabilities stay one click away and land on the exact section that owns them.",
            Language::ZhCn => "所有次级能力都保持一跳直达，并且直接落到对应的设置区块。",
        },
    );
    context.insert(
        "dashboard_security_card_title",
        &match language {
            Language::En => "Security Hub",
            Language::ZhCn => "安全中心",
        },
    );
    context.insert(
        "dashboard_security_card_body",
        &match language {
            Language::En => "Password, TOTP, recovery codes, and security posture.",
            Language::ZhCn => "密码、TOTP、恢复码和整体安全状态。",
        },
    );
    context.insert(
        "dashboard_notifications_card_title",
        &match language {
            Language::En => "Reminder Center",
            Language::ZhCn => "提醒中心",
        },
    );
    context.insert(
        "dashboard_notifications_card_body",
        &match language {
            Language::En => "Compact bot reminder controls without leaving the session workflow.",
            Language::ZhCn => "不离开会话工作流即可管理紧凑型 Bot 提醒设置。",
        },
    );
    context.insert(
        "dashboard_access_card_title",
        &match language {
            Language::En => "Web Access",
            Language::ZhCn => "网页登录",
        },
    );
    context.insert(
        "dashboard_access_card_body",
        &match language {
            Language::En => "Review active browser sessions and tune idle auto logout.",
            Language::ZhCn => "查看活跃浏览器会话并调整空闲自动登出策略。",
        },
    );
    context.insert(
        "dashboard_admin_card_title",
        &match language {
            Language::En => "Control Center",
            Language::ZhCn => "后台控制",
        },
    );
    context.insert(
        "dashboard_admin_card_body",
        &match language {
            Language::En => "User operations, policy tuning, lockouts, and audit visibility.",
            Language::ZhCn => "用户操作、策略调优、锁定状态和审计可见性。",
        },
    );
    context.insert(
        "session_note_placeholder",
        &match language {
            Language::En => "No note",
            Language::ZhCn => "暂无备注",
        },
    );
    context.insert(
        "session_note_label",
        &match language {
            Language::En => "Note",
            Language::ZhCn => "备注",
        },
    );
    context.insert(
        "save_note_label",
        &match language {
            Language::En => "Save Note",
            Language::ZhCn => "保存备注",
        },
    );
    context.insert("banner", &banner);
    context.insert("sessions", &snapshot.sessions);
    context.insert("connected_count", &snapshot.connected_count);
    context.insert("now", &snapshot.generated_at);
    context.insert(
        "snapshot_api",
        &format!("/api/dashboard/snapshot?lang={}", language.code()),
    );
    context.insert(
        "dashboard_incremental_refresh_seconds",
        &DASHBOARD_INCREMENTAL_SYNC_SECONDS,
    );
    context.insert(
        "dashboard_full_refresh_seconds",
        &DASHBOARD_FULL_SYNC_SECONDS,
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
    let settings = app_state.system_settings.read().await.clone();
    let show_register = registration_page_allowed(&app_state.meta_store, &settings).await;
    let register_label = match language {
        Language::En => "Create Account",
        Language::ZhCn => "创建账号",
    };
    let mfa_label = match language {
        Language::En => "TOTP Code",
        Language::ZhCn => "TOTP 动态码",
    };
    let recovery_label = match language {
        Language::En => "Recovery Code",
        Language::ZhCn => "恢复码",
    };
    let mfa_hint = match language {
        Language::En => {
            "If the account already enabled MFA, enter either a TOTP code or one recovery code."
        }
        Language::ZhCn => "如果账号已经启用二次验证，请填写 TOTP 动态码或一条恢复码。",
    };

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("error_message", &error_message);
    context.insert("show_register", &show_register);
    context.insert(
        "register_href",
        &format!("/register?lang={}", language.code()),
    );
    context.insert("register_label", &register_label);
    context.insert("mfa_label", &mfa_label);
    context.insert("recovery_label", &recovery_label);
    context.insert("mfa_hint", &mfa_hint);

    render_template(&app_state.tera, "login.html", &context)
}

async fn render_register_page(
    app_state: &AppState,
    language: Language,
    error_message: Option<&str>,
) -> std::result::Result<Html<String>, StatusCode> {
    let languages = language_options(language, "/register");
    let mut context = Context::new();
    let title = match language {
        Language::En => "Create Account",
        Language::ZhCn => "创建账号",
    };
    let description = match language {
        Language::En => {
            "The first account becomes the only admin. New accounts must finish TOTP setup before entering the dashboard. If an administrator reset your account, reclaim it by registering again with the same username."
        }
        Language::ZhCn => {
            "第一个注册的账号会成为唯一管理员。新账号进入面板前必须先完成 TOTP 设置。如果管理员清空了你的账号凭据，请使用相同用户名重新注册以接管原账号。"
        }
    };
    let username_label = match language {
        Language::En => "Username",
        Language::ZhCn => "用户名",
    };
    let password_label = match language {
        Language::En => "Password",
        Language::ZhCn => "密码",
    };
    let confirm_label = match language {
        Language::En => "Confirm Password",
        Language::ZhCn => "确认密码",
    };
    let submit_label = match language {
        Language::En => "Create Account",
        Language::ZhCn => "创建账号",
    };
    let back_label = match language {
        Language::En => "Back to Login",
        Language::ZhCn => "返回登录",
    };

    context.insert("lang", &language.code());
    context.insert("languages", &languages);
    context.insert("title", &title);
    context.insert("description", &description);
    context.insert("username_label", &username_label);
    context.insert("password_label", &password_label);
    context.insert("confirm_label", &confirm_label);
    context.insert("submit_label", &submit_label);
    context.insert("back_label", &back_label);
    context.insert("back_href", &format!("/login?lang={}", language.code()));
    context.insert("error_message", &error_message);

    render_template(&app_state.tera, "register.html", &context)
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

async fn render_settings_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let active_sessions = app_state
        .meta_store
        .list_auth_sessions_for_user(&authenticated.user.id)
        .await
        .map_err(|error| {
            warn!(
                "failed loading auth sessions for {}: {}",
                authenticated.user.username, error
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let active_sessions: Vec<ActiveSessionView> = active_sessions
        .into_iter()
        .filter(|session| session.revoked_at_unix.is_none())
        .map(|session| ActiveSessionView {
            is_current: session.id == authenticated.auth_session.id,
            id: session.id,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            issued_at: format_unix_timestamp(session.issued_at_unix),
            expires_at: format_unix_timestamp(session.expires_at_unix),
        })
        .collect();

    let totp_status = match language {
        Language::En if authenticated.user.security.totp_enabled => "Enabled",
        Language::En => "Not enabled",
        Language::ZhCn if authenticated.user.security.totp_enabled => "已启用",
        Language::ZhCn => "未启用",
    };
    let idle_timeout = format_idle_timeout_label(
        authenticated.user.security.preferred_idle_timeout_minutes,
        language,
    );
    let effective_idle_timeout =
        format_idle_timeout_label(authenticated.auth_session.idle_timeout_minutes, language);
    let idle_timeout_field_value = authenticated
        .user
        .security
        .preferred_idle_timeout_minutes
        .map(|minutes| minutes.to_string())
        .unwrap_or_default();
    let system_settings = app_state.system_settings.read().await.clone();
    let idle_timeout_hint = match system_settings.max_idle_timeout_minutes {
        Some(maximum) => match language {
            Language::En => {
                format!("Leave blank to use the system default. Maximum: {maximum} minutes.")
            }
            Language::ZhCn => format!("留空表示使用系统默认值。当前上限：{maximum} 分钟。"),
        },
        None => match language {
            Language::En => String::from(
                "Leave blank to use the system default. Enter 0 for a permanent session.",
            ),
            Language::ZhCn => String::from("留空表示使用系统默认值。输入 0 表示永久不自动登出。"),
        },
    };
    let bot_settings = app_state.notification_settings.read().await.clone();
    let bot_status = bot_status_summary(&bot_settings, language);
    let bot_destination = bot_destination_summary(&bot_settings, language);
    let bot_template_preview = template_preview(&bot_settings.template, 68);
    let bot_placeholders = build_bot_placeholder_hints(language).to_vec();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert(
        "title",
        &match language {
            Language::En => "Settings",
            Language::ZhCn => "设置",
        },
    );
    context.insert("description", &match language {
        Language::En => "Security, active sessions, and notification preferences live here so the main dashboard stays focused on Telegram sessions.",
        Language::ZhCn => "安全、活跃会话和提醒设置都放在这里，让主面板专注于 Telegram 会话本身。",
    });
    context.insert("current_username", &authenticated.user.username);
    context.insert("show_admin", &(authenticated.user.role == UserRole::Admin));
    context.insert("admin_href", &admin_href(language));
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("notifications_href", &notifications_href(language));
    context.insert(
        "settings_sections_title",
        &match language {
            Language::En => "Workspace",
            Language::ZhCn => "工作区",
        },
    );
    context.insert(
        "settings_overview_title",
        &match language {
            Language::En => "Overview",
            Language::ZhCn => "概览",
        },
    );
    context.insert(
        "settings_nav_security",
        &match language {
            Language::En => "Security",
            Language::ZhCn => "安全",
        },
    );
    context.insert(
        "settings_nav_notifications",
        &match language {
            Language::En => "Reminders",
            Language::ZhCn => "提醒",
        },
    );
    context.insert(
        "settings_nav_access",
        &match language {
            Language::En => "Access",
            Language::ZhCn => "访问控制",
        },
    );
    context.insert(
        "dashboard_label",
        &match language {
            Language::En => "Dashboard",
            Language::ZhCn => "主面板",
        },
    );
    context.insert(
        "admin_label",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理后台",
        },
    );
    context.insert(
        "notifications_label",
        &match language {
            Language::En => "Notifications",
            Language::ZhCn => "提醒设置",
        },
    );
    context.insert(
        "admin_access_description",
        &match language {
            Language::En => "User resets, policy tuning, and audit logs live in the admin console.",
            Language::ZhCn => "用户重置、策略调优和审计日志都在管理后台。",
        },
    );
    context.insert(
        "security_title",
        &match language {
            Language::En => "Security",
            Language::ZhCn => "安全",
        },
    );
    context.insert(
        "security_description",
        &match language {
            Language::En => "Password, TOTP, recovery coverage, and your personal sign-in policy are grouped here.",
            Language::ZhCn => "密码、TOTP、恢复码覆盖情况和你的个人登录策略统一放在这里。",
        },
    );
    context.insert(
        "totp_label",
        &match language {
            Language::En => "TOTP",
            Language::ZhCn => "TOTP",
        },
    );
    context.insert("totp_status", &totp_status);
    context.insert(
        "totp_hint",
        &match language {
            Language::En => "If TOTP is required and not configured, this page is the only path back into the dashboard.",
            Language::ZhCn => "如果系统要求 TOTP 但还没启用，这里就是重新进入主面板前必须完成的步骤。",
        },
    );
    context.insert(
        "recovery_label",
        &match language {
            Language::En => "Recovery Codes",
            Language::ZhCn => "恢复码",
        },
    );
    context.insert(
        "recovery_remaining",
        &authenticated.recovery_codes_remaining.to_string(),
    );
    context.insert(
        "recovery_hint",
        &match language {
            Language::En => "Each recovery code works once. Once all 5 are consumed, you must generate a new set.",
            Language::ZhCn => "每个恢复码只能用一次。5 个都用完后，必须重新生成一组新的恢复码。",
        },
    );
    context.insert(
        "idle_label",
        &match language {
            Language::En => "Idle Timeout Preference",
            Language::ZhCn => "空闲登出偏好",
        },
    );
    context.insert("idle_timeout", &idle_timeout);
    context.insert(
        "idle_effective_label",
        &match language {
            Language::En => "Current Session Timeout",
            Language::ZhCn => "当前登录会话超时",
        },
    );
    context.insert("idle_effective_timeout", &effective_idle_timeout);
    context.insert(
        "idle_summary_label",
        &match language {
            Language::En => "Current Auto Logout",
            Language::ZhCn => "当前自动登出规则",
        },
    );
    context.insert(
        "idle_form_title",
        &match language {
            Language::En => "Auto Logout",
            Language::ZhCn => "自动登出设置",
        },
    );
    context.insert(
        "idle_form_action",
        &format!("/settings/security/idle-timeout?lang={}", language.code()),
    );
    context.insert(
        "idle_input_label",
        &match language {
            Language::En => "Minutes",
            Language::ZhCn => "分钟数",
        },
    );
    context.insert("idle_timeout_field_value", &idle_timeout_field_value);
    context.insert("idle_timeout_hint", &idle_timeout_hint);
    context.insert(
        "idle_submit_label",
        &match language {
            Language::En => "Save Idle Timeout",
            Language::ZhCn => "保存空闲登出设置",
        },
    );
    context.insert(
        "totp_setup_href",
        &format!("/settings/security/totp/setup?lang={}", language.code()),
    );
    context.insert(
        "totp_setup_label",
        &match language {
            Language::En => "Manage TOTP",
            Language::ZhCn => "管理 TOTP",
        },
    );
    context.insert(
        "password_title",
        &match language {
            Language::En => "Change Password",
            Language::ZhCn => "修改密码",
        },
    );
    context.insert(
        "password_action",
        &format!("/settings/security/password?lang={}", language.code()),
    );
    context.insert(
        "current_password_label",
        &match language {
            Language::En => "Current Password",
            Language::ZhCn => "当前密码",
        },
    );
    context.insert(
        "new_password_label",
        &match language {
            Language::En => "New Password",
            Language::ZhCn => "新密码",
        },
    );
    context.insert(
        "confirm_password_label",
        &match language {
            Language::En => "Confirm New Password",
            Language::ZhCn => "确认新密码",
        },
    );
    context.insert(
        "change_password_label",
        &match language {
            Language::En => "Update Password",
            Language::ZhCn => "更新密码",
        },
    );
    context.insert(
        "password_description",
        &match language {
            Language::En => "Changing the password re-wraps your user master key and immediately refreshes this sign-in session.",
            Language::ZhCn => "修改密码会重新包裹你的用户主密钥，并立即刷新当前登录会话的解锁状态。",
        },
    );
    context.insert(
        "notifications_section_title",
        &match language {
            Language::En => "Reminder Center",
            Language::ZhCn => "提醒中心",
        },
    );
    context.insert(
        "notifications_section_description",
        &match language {
            Language::En => "Reminder settings stay compact by default, then expand in place when you need to edit the bot destination or template.",
            Language::ZhCn => "提醒默认保持紧凑，只在你需要修改 Bot 目标或模板时在本页展开。",
        },
    );
    context.insert(
        "notifications_expand_label",
        &match language {
            Language::En => "Expand Reminder Settings",
            Language::ZhCn => "展开提醒设置",
        },
    );
    context.insert(
        "notifications_manage_fullpage_label",
        &match language {
            Language::En => "Open Full Page",
            Language::ZhCn => "打开独立页面",
        },
    );
    context.insert(
        "notification_status_label",
        &match language {
            Language::En => "Status",
            Language::ZhCn => "状态",
        },
    );
    context.insert("notification_status_value", &bot_status);
    context.insert(
        "notification_destination_label",
        &match language {
            Language::En => "Target Chat",
            Language::ZhCn => "目标聊天",
        },
    );
    context.insert("notification_destination_value", &bot_destination);
    context.insert(
        "notification_template_preview_label",
        &match language {
            Language::En => "Template Preview",
            Language::ZhCn => "模板预览",
        },
    );
    context.insert("notification_template_preview", &bot_template_preview);
    context.insert("bot_settings", &build_bot_settings_view(&bot_settings));
    context.insert("bot_placeholders", &bot_placeholders);
    context.insert(
        "bot_settings_action",
        &format!("/settings/bot?lang={}", language.code()),
    );
    context.insert(
        "sessions_title",
        &match language {
            Language::En => "Active Sessions",
            Language::ZhCn => "活跃登录会话",
        },
    );
    context.insert(
        "sessions_description",
        &match language {
            Language::En => "You can review every live browser session here and cut off stale devices without leaving the settings page.",
            Language::ZhCn => "你可以在这里查看所有仍然在线的浏览器会话，并直接清理不再需要的设备登录。",
        },
    );
    context.insert("sessions", &active_sessions);
    context.insert("active_session_count", &active_sessions.len());
    context.insert("current_session_id", &authenticated.auth_session.id);
    context.insert("current_user_id", &authenticated.user.id);
    context.insert(
        "revoke_label",
        &match language {
            Language::En => "Force Logout",
            Language::ZhCn => "强制下线",
        },
    );
    context.insert(
        "revoke_all_action",
        &format!(
            "/admin/users/{}/sessions/revoke?lang={}",
            authenticated.user.id,
            language.code()
        ),
    );
    context.insert(
        "revoke_all_label",
        &match language {
            Language::En => "Force Logout Other Sessions",
            Language::ZhCn => "强制下线其他会话",
        },
    );
    context.insert(
        "session_device_label",
        &match language {
            Language::En => "Device",
            Language::ZhCn => "设备",
        },
    );
    context.insert(
        "unknown_user_agent_label",
        &match language {
            Language::En => "Unknown User Agent",
            Language::ZhCn => "未知设备",
        },
    );
    context.insert(
        "session_ip_label",
        &match language {
            Language::En => "IP",
            Language::ZhCn => "IP",
        },
    );
    context.insert(
        "session_issued_label",
        &match language {
            Language::En => "Issued",
            Language::ZhCn => "签发时间",
        },
    );
    context.insert(
        "session_expires_label",
        &match language {
            Language::En => "Expires",
            Language::ZhCn => "到期时间",
        },
    );
    context.insert(
        "session_empty_label",
        &match language {
            Language::En => "No active browser sessions are currently recorded.",
            Language::ZhCn => "当前没有记录到活跃的浏览器登录会话。",
        },
    );
    context.insert(
        "current_session_label",
        &match language {
            Language::En => "Current Session",
            Language::ZhCn => "当前会话",
        },
    );
    context.insert("banner", &banner);

    render_template(&app_state.tera, "settings.html", &context)
}

async fn render_notification_settings_page(
    app_state: &AppState,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let bot_settings = app_state.notification_settings.read().await.clone();
    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("settings_href", &settings_href(language));
    context.insert(
        "back_label",
        &match language {
            Language::En => "Back to Settings",
            Language::ZhCn => "返回设置",
        },
    );
    context.insert("bot_settings", &build_bot_settings_view(&bot_settings));
    context.insert(
        "bot_placeholders",
        &build_bot_placeholder_hints(language).to_vec(),
    );
    context.insert(
        "bot_settings_action",
        &format!("/settings/bot?lang={}", language.code()),
    );
    context.insert("banner", &banner);

    render_template(&app_state.tera, "notifications.html", &context)
}

async fn render_notification_workspace_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    return_to_settings: bool,
) -> std::result::Result<Html<String>, StatusCode> {
    if return_to_settings {
        render_settings_page(app_state, authenticated, language, banner).await
    } else {
        render_notification_settings_page(app_state, language, banner).await
    }
}

async fn render_totp_setup_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let pending = {
        let mut setups = app_state.totp_setups.write().await;
        setups
            .entry(authenticated.auth_session.id.clone())
            .or_insert_with(|| {
                let material = build_totp_setup_material(&authenticated.user.username);
                PendingTotpSetup {
                    secret: material.secret,
                    recovery_codes: material.recovery_codes,
                    otp_auth_uri: material.otp_auth_uri,
                }
            })
            .clone()
    };
    let qr_svg = render_qr_svg(pending.otp_auth_uri.as_ref().as_str()).map_err(|error| {
        warn!(
            "failed rendering totp qr for {}: {}",
            authenticated.user.username, error
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert(
        "title",
        &match language {
            Language::En => "TOTP Setup",
            Language::ZhCn => "TOTP 设置",
        },
    );
    context.insert("description", &match language {
        Language::En => "Scan the QR code, store the recovery codes, then confirm with one TOTP code before entering the dashboard.",
        Language::ZhCn => "先扫码、保存恢复码，再输入一次 TOTP 动态码完成确认，然后才能进入主面板。",
    });
    context.insert("settings_href", &settings_href(language));
    context.insert(
        "back_label",
        &match language {
            Language::En => "Back to Settings",
            Language::ZhCn => "返回设置",
        },
    );
    context.insert(
        "qr_title",
        &match language {
            Language::En => "Authenticator QR",
            Language::ZhCn => "认证器二维码",
        },
    );
    context.insert("qr_svg", &qr_svg);
    context.insert(
        "secret_label",
        &match language {
            Language::En => "Manual Secret",
            Language::ZhCn => "手动输入密钥",
        },
    );
    context.insert("secret", pending.secret.as_ref().as_str());
    context.insert(
        "recovery_title",
        &match language {
            Language::En => "Recovery Codes",
            Language::ZhCn => "恢复码",
        },
    );
    context.insert(
        "recovery_description",
        &match language {
            Language::En => {
                "Each code works once. After all 5 are used, you must generate a new set."
            }
            Language::ZhCn => "每个恢复码只能使用一次。5 个都用完后，必须重新生成一组。",
        },
    );
    let recovery_codes = pending
        .recovery_codes
        .iter()
        .map(|code| code.as_ref().as_str().to_owned())
        .collect::<Vec<_>>();
    context.insert("recovery_codes", &recovery_codes);
    context.insert(
        "confirm_action",
        &format!("/settings/security/totp/setup?lang={}", language.code()),
    );
    context.insert(
        "confirm_label",
        &match language {
            Language::En => "Enter One TOTP Code",
            Language::ZhCn => "输入一个 TOTP 动态码",
        },
    );
    context.insert(
        "confirm_submit",
        &match language {
            Language::En => "Enable TOTP",
            Language::ZhCn => "启用 TOTP",
        },
    );
    context.insert("banner", &banner);

    render_template(&app_state.tera, "totp_setup.html", &context)
}

async fn render_admin_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let system_settings = app_state.system_settings.read().await.clone();
    let raw_users = app_state.meta_store.list_users().await.map_err(|error| {
        warn!("failed loading users for admin page: {}", error);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let audit_logs = app_state
        .meta_store
        .list_audit_logs()
        .await
        .map_err(|error| {
            warn!("failed loading audit logs: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let audit_rollups = app_state
        .meta_store
        .list_audit_rollups()
        .await
        .map_err(|error| {
            warn!("failed loading audit rollups: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let now = Utc::now().timestamp();
    let registration_options = registration_policy_options(language);
    let totp_policy_options = enforcement_mode_options(language);
    let password_policy_options = enforcement_mode_options(language);
    let current_registration_label = selected_option_label(
        &registration_options,
        registration_policy_value(system_settings.registration_policy),
    );
    let current_totp_policy_label = selected_option_label(
        &totp_policy_options,
        enforcement_mode_value(system_settings.totp_policy),
    );
    let current_password_policy_label = selected_option_label(
        &password_policy_options,
        enforcement_mode_value(system_settings.password_strength_rules.mode),
    );

    let mut locked_users_count = 0_usize;
    let mut total_active_auth_sessions = 0_usize;
    let mut mfa_enabled_users = 0_usize;
    let mut users = Vec::new();
    for user in raw_users {
        let locked = user.security.locked_until_unix.unwrap_or_default() > now;
        let auth_sessions = app_state
            .meta_store
            .list_auth_sessions_for_user(&user.id)
            .await
            .map_err(|error| {
                warn!(
                    "failed loading auth sessions for admin user card: {}",
                    error
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        let active_sessions = auth_sessions
            .iter()
            .filter(|session| auth_session_is_active(session, now))
            .count();
        let recovery_codes_remaining = app_state
            .meta_store
            .count_active_recovery_codes(&user.id)
            .await
            .map_err(|error| {
                warn!(
                    "failed counting recovery codes for admin user card: {}",
                    error
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        if locked {
            locked_users_count += 1;
        }
        if user.security.totp_enabled {
            mfa_enabled_users += 1;
        }
        total_active_auth_sessions += active_sessions;
        users.push(AdminUserView {
            id: user.id,
            username: user.username,
            role: match user.role {
                UserRole::Admin => String::from("admin"),
                UserRole::User => String::from("user"),
            },
            locked,
            totp_enabled: user.security.totp_enabled,
            password_ready: user.security.password_hash.is_some(),
            active_sessions,
            recovery_codes_remaining,
            last_login_ip: user.security.last_login_ip,
        });
    }
    let total_users = users.len();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert(
        "title",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理后台",
        },
    );
    context.insert("description", &match language {
        Language::En => "Manage users, registration strategy, session lifetime, and audit visibility from one place.",
        Language::ZhCn => "在这里统一管理用户、注册策略、登录会话时长和审计可见性。",
    });
    context.insert(
        "admin_sections_title",
        &match language {
            Language::En => "Control Center",
            Language::ZhCn => "控制中心",
        },
    );
    context.insert(
        "admin_nav_overview",
        &match language {
            Language::En => "Overview",
            Language::ZhCn => "总览",
        },
    );
    context.insert(
        "admin_nav_users",
        &match language {
            Language::En => "Users",
            Language::ZhCn => "用户",
        },
    );
    context.insert(
        "admin_nav_policy",
        &match language {
            Language::En => "Policy",
            Language::ZhCn => "策略",
        },
    );
    context.insert(
        "admin_nav_audit",
        &match language {
            Language::En => "Audit",
            Language::ZhCn => "审计",
        },
    );
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("settings_href", &settings_href(language));
    context.insert(
        "dashboard_label",
        &match language {
            Language::En => "Dashboard",
            Language::ZhCn => "主面板",
        },
    );
    context.insert(
        "settings_label",
        &match language {
            Language::En => "Settings",
            Language::ZhCn => "设置",
        },
    );
    context.insert(
        "create_user_title",
        &match language {
            Language::En => "Create User",
            Language::ZhCn => "创建用户",
        },
    );
    context.insert(
        "username_label",
        &match language {
            Language::En => "Username",
            Language::ZhCn => "用户名",
        },
    );
    context.insert(
        "password_label",
        &match language {
            Language::En => "Password",
            Language::ZhCn => "密码",
        },
    );
    context.insert(
        "create_user_label",
        &match language {
            Language::En => "Create User",
            Language::ZhCn => "创建用户",
        },
    );
    context.insert(
        "policy_title",
        &match language {
            Language::En => "System Policy",
            Language::ZhCn => "系统策略",
        },
    );
    context.insert(
        "registration_label",
        &match language {
            Language::En => "Registration Mode",
            Language::ZhCn => "注册模式",
        },
    );
    context.insert("registration_options", &registration_options);
    context.insert(
        "current_registration_policy",
        &registration_policy_value(system_settings.registration_policy),
    );
    context.insert("totp_policy_options", &totp_policy_options);
    context.insert(
        "current_totp_policy",
        &enforcement_mode_value(system_settings.totp_policy),
    );
    context.insert("password_policy_options", &password_policy_options);
    context.insert(
        "current_password_policy",
        &enforcement_mode_value(system_settings.password_strength_rules.mode),
    );
    context.insert("current_registration_label", &current_registration_label);
    context.insert("current_totp_policy_label", &current_totp_policy_label);
    context.insert(
        "current_password_policy_label",
        &current_password_policy_label,
    );
    context.insert(
        "public_registration_open",
        &system_settings.public_registration_open,
    );
    context.insert(
        "public_registration_label",
        &match language {
            Language::En => "Open registration when using admin toggle mode",
            Language::ZhCn => "当模式为管理员可开关时，当前允许公开注册",
        },
    );
    context.insert(
        "session_ttl_label",
        &match language {
            Language::En => "Session TTL (hours)",
            Language::ZhCn => "登录会话有效期（小时）",
        },
    );
    context.insert(
        "audit_limit_label",
        &match language {
            Language::En => "Detailed Audit Rows",
            Language::ZhCn => "审计详细记录保留条数",
        },
    );
    context.insert(
        "totp_policy_label",
        &match language {
            Language::En => "TOTP Requirement",
            Language::ZhCn => "TOTP 强制策略",
        },
    );
    context.insert(
        "password_policy_label",
        &match language {
            Language::En => "Password Strength Rule",
            Language::ZhCn => "密码强度策略",
        },
    );
    context.insert(
        "password_min_length_label",
        &match language {
            Language::En => "Password Minimum Length",
            Language::ZhCn => "密码最小长度",
        },
    );
    context.insert(
        "password_require_uppercase_label",
        &match language {
            Language::En => "Require uppercase letters",
            Language::ZhCn => "必须包含大写字母",
        },
    );
    context.insert(
        "password_require_lowercase_label",
        &match language {
            Language::En => "Require lowercase letters",
            Language::ZhCn => "必须包含小写字母",
        },
    );
    context.insert(
        "password_require_number_label",
        &match language {
            Language::En => "Require numbers",
            Language::ZhCn => "必须包含数字",
        },
    );
    context.insert(
        "password_require_symbol_label",
        &match language {
            Language::En => "Require symbols",
            Language::ZhCn => "必须包含符号",
        },
    );
    context.insert(
        "lockout_threshold_label",
        &match language {
            Language::En => "Lock After Failures",
            Language::ZhCn => "连续失败多少次后开始锁定",
        },
    );
    context.insert(
        "lockout_base_label",
        &match language {
            Language::En => "Initial Delay (seconds)",
            Language::ZhCn => "初始延迟（秒）",
        },
    );
    context.insert(
        "lockout_max_label",
        &match language {
            Language::En => "Maximum Delay (seconds)",
            Language::ZhCn => "最大延迟（秒）",
        },
    );
    context.insert(
        "system_idle_limit_label",
        &match language {
            Language::En => "System Idle Timeout Cap (minutes)",
            Language::ZhCn => "系统空闲登出上限（分钟）",
        },
    );
    context.insert(
        "system_idle_limit_hint",
        &match language {
            Language::En => "Leave blank to allow permanent sessions.",
            Language::ZhCn => "留空表示允许永久不登出。",
        },
    );
    context.insert(
        "argon_memory_label",
        &match language {
            Language::En => "Argon2 Memory (MiB)",
            Language::ZhCn => "Argon2 内存（MiB）",
        },
    );
    context.insert(
        "argon_iterations_label",
        &match language {
            Language::En => "Argon2 Iterations",
            Language::ZhCn => "Argon2 迭代次数",
        },
    );
    context.insert(
        "argon_lanes_label",
        &match language {
            Language::En => "Argon2 Lanes",
            Language::ZhCn => "Argon2 并行线程数",
        },
    );
    context.insert("argon_raise_only_hint", &match language {
        Language::En => "These minimums can only move upward. Existing users are rehashed after their next successful login.",
        Language::ZhCn => "这些下限只能调高不能调低。现有用户在下次成功登录后会自动重新派生。",
    });
    context.insert(
        "save_policy_label",
        &match language {
            Language::En => "Save Policy",
            Language::ZhCn => "保存策略",
        },
    );
    context.insert(
        "users_title",
        &match language {
            Language::En => "Users",
            Language::ZhCn => "用户列表",
        },
    );
    context.insert(
        "users_description",
        &match language {
            Language::En => "Create regular users, unlock them, revoke their web sessions, or fully reset their encrypted account state.",
            Language::ZhCn => "在这里创建普通用户、解锁账号、踢下线，或彻底重置其加密账户状态。",
        },
    );
    context.insert(
        "unlock_label",
        &match language {
            Language::En => "Unlock",
            Language::ZhCn => "解锁",
        },
    );
    context.insert(
        "revoke_sessions_label",
        &match language {
            Language::En => "Force Logout",
            Language::ZhCn => "强制下线",
        },
    );
    context.insert(
        "reset_label",
        &match language {
            Language::En => "Reset",
            Language::ZhCn => "重置",
        },
    );
    context.insert(
        "role_admin_label",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理员",
        },
    );
    context.insert(
        "role_user_label",
        &match language {
            Language::En => "User",
            Language::ZhCn => "普通用户",
        },
    );
    context.insert(
        "locked_badge_label",
        &match language {
            Language::En => "Locked",
            Language::ZhCn => "已锁定",
        },
    );
    context.insert(
        "totp_enabled_badge_label",
        &match language {
            Language::En => "TOTP On",
            Language::ZhCn => "TOTP 已开",
        },
    );
    context.insert(
        "totp_missing_badge_label",
        &match language {
            Language::En => "TOTP Off",
            Language::ZhCn => "TOTP 未开",
        },
    );
    context.insert(
        "password_ready_badge_label",
        &match language {
            Language::En => "Password Ready",
            Language::ZhCn => "密码已配置",
        },
    );
    context.insert(
        "password_reset_badge_label",
        &match language {
            Language::En => "Reset Pending",
            Language::ZhCn => "等待重新设置",
        },
    );
    context.insert(
        "user_active_sessions_label",
        &match language {
            Language::En => "Active Web Sessions",
            Language::ZhCn => "活跃网页登录会话",
        },
    );
    context.insert(
        "user_recovery_codes_label",
        &match language {
            Language::En => "Recovery Codes",
            Language::ZhCn => "恢复码剩余",
        },
    );
    context.insert(
        "user_last_ip_label",
        &match language {
            Language::En => "Last Login IP",
            Language::ZhCn => "最近登录 IP",
        },
    );
    context.insert(
        "audit_title",
        &match language {
            Language::En => "Audit Log",
            Language::ZhCn => "审计日志",
        },
    );
    context.insert(
        "audit_description",
        &match language {
            Language::En => "Detailed rows stay visible until the configured cap, then older detail collapses into rollups.",
            Language::ZhCn => "详细审计保留到配置上限，超出后旧数据会折叠成汇总统计。",
        },
    );
    context.insert(
        "rollup_title",
        &match language {
            Language::En => "Audit Rollups",
            Language::ZhCn => "审计汇总",
        },
    );
    context.insert(
        "audit_success_label",
        &match language {
            Language::En => "OK",
            Language::ZhCn => "成功",
        },
    );
    context.insert(
        "audit_failure_label",
        &match language {
            Language::En => "FAIL",
            Language::ZhCn => "失败",
        },
    );
    context.insert(
        "audit_empty_label",
        &match language {
            Language::En => "No detailed audit rows have been recorded yet.",
            Language::ZhCn => "当前还没有详细审计记录。",
        },
    );
    context.insert(
        "rollup_empty_label",
        &match language {
            Language::En => "No audit rollups have been generated yet.",
            Language::ZhCn => "当前还没有生成审计汇总。",
        },
    );
    context.insert(
        "overview_title",
        &match language {
            Language::En => "System Snapshot",
            Language::ZhCn => "系统快照",
        },
    );
    context.insert(
        "overview_users_label",
        &match language {
            Language::En => "Users",
            Language::ZhCn => "用户数",
        },
    );
    context.insert(
        "overview_locked_label",
        &match language {
            Language::En => "Locked Users",
            Language::ZhCn => "锁定用户",
        },
    );
    context.insert(
        "overview_web_sessions_label",
        &match language {
            Language::En => "Active Web Sessions",
            Language::ZhCn => "活跃网页登录会话",
        },
    );
    context.insert(
        "overview_mfa_label",
        &match language {
            Language::En => "Users With TOTP",
            Language::ZhCn => "已启用 TOTP 的用户",
        },
    );
    context.insert(
        "overview_audit_rows_label",
        &match language {
            Language::En => "Detailed Audit Rows",
            Language::ZhCn => "详细审计记录",
        },
    );
    context.insert(
        "policy_stack_title",
        &match language {
            Language::En => "Policy Stack",
            Language::ZhCn => "策略栈",
        },
    );
    context.insert(
        "policy_description",
        &match language {
            Language::En => "Each control is grouped by outcome: who can enter, how strong credentials must be, how long sessions stay alive, and how expensive key derivation should become.",
            Language::ZhCn => "所有策略按结果分组：谁能进入、凭据强度、会话存活时长，以及密钥派生成本。",
        },
    );
    context.insert("total_users", &total_users);
    context.insert("locked_users_count", &locked_users_count);
    context.insert("total_active_auth_sessions", &total_active_auth_sessions);
    context.insert("mfa_enabled_users", &mfa_enabled_users);
    context.insert("audit_log_count", &audit_logs.len());
    context.insert("users", &users);
    context.insert("audit_logs", &audit_logs);
    context.insert("audit_rollups", &audit_rollups);
    context.insert("system_settings", &system_settings);
    context.insert(
        "system_max_idle_timeout_minutes",
        &system_settings
            .max_idle_timeout_minutes
            .map(|minutes| minutes.to_string())
            .unwrap_or_default(),
    );
    context.insert(
        "argon_memory_mib",
        &(system_settings.argon_policy.memory_kib / 1024),
    );
    context.insert("argon_iterations", &system_settings.argon_policy.iterations);
    context.insert("argon_lanes", &system_settings.argon_policy.lanes);
    context.insert("banner", &banner);
    context.insert("current_admin_username", &authenticated.user.username);

    render_template(&app_state.tera, "admin.html", &context)
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

    let settings = app_state.system_settings.read().await.clone();
    if let Ok(Some(authenticated)) =
        resolve_authenticated_session(&app_state.meta_store, &settings, &headers).await
    {
        let target =
            if authenticated.requires_totp_setup || authenticated.recovery_codes_remaining == 0 {
                format!("/settings/security/totp/setup?lang={}", language.code())
            } else {
                login_redirect_target(language)
            };
        return Redirect::to(&target).into_response();
    }
    clear_invalid_cookie_state(&app_state, &headers).await;

    match render_login_page(&app_state, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn register_page_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let settings = app_state.system_settings.read().await.clone();
    let allowed = registration_page_allowed(&app_state.meta_store, &settings).await;

    if !allowed {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    }

    match render_register_page(&app_state, language, None).await {
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
    let settings = app_state.system_settings.read().await.clone();
    let ip_address = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    match web_auth::authenticate_user(
        &app_state.meta_store,
        &settings,
        &form.username,
        &form.password,
        form.mfa_code.as_deref(),
        form.recovery_code.as_deref(),
        ip_address.as_deref(),
        user_agent.as_deref(),
    )
    .await
    {
        Ok(login_result) => {
            cache_user_master_key(
                &app_state,
                &login_result.auth_session.user_id,
                &login_result.auth_session.id,
                login_result.master_key,
            )
            .await;

            let max_age = i64::from(settings.session_absolute_ttl_hours) * 3600;
            let redirect_target = if login_result.requires_totp_setup {
                format!("/settings/security/totp/setup?lang={}", language.code())
            } else {
                login_redirect_target(language)
            };
            let mut response = Redirect::to(&redirect_target).into_response();

            match set_cookie_header(&build_auth_cookie(
                &login_result.session_token,
                max_age,
                settings.cookie_secure,
            )) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                    response
                }
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::LockedUntil(locked_until)) => {
            let message = match language {
                Language::En => format!("This account is locked until {locked_until}."),
                Language::ZhCn => format!("这个账号已被锁定，解锁时间戳：{locked_until}。"),
            };
            match render_login_page(&app_state, language, Some(&message)).await {
                Ok(html) => (StatusCode::TOO_MANY_REQUESTS, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::MissingSecondFactor) => {
            let message = match language {
                Language::En => "Enter a TOTP code or recovery code to finish signing in.",
                Language::ZhCn => "请输入 TOTP 动态码或恢复码以完成登录。",
            };
            match render_login_page(&app_state, language, Some(message)).await {
                Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::InvalidSecondFactor) => {
            let message = match language {
                Language::En => "The TOTP code or recovery code was invalid.",
                Language::ZhCn => "TOTP 动态码或恢复码不正确。",
            };
            match render_login_page(&app_state, language, Some(message)).await {
                Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::InvalidCredentials) => {
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
    }
}

async fn register_submit_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let settings = app_state.system_settings.read().await.clone();
    let allowed =
        registration_submit_allowed(&app_state.meta_store, &settings, &form.username).await;

    if !allowed {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    }
    if form.password != form.confirm_password {
        let message = match language {
            Language::En => "The two password fields must match.",
            Language::ZhCn => "两次输入的密码必须一致。",
        };
        return match render_register_page(&app_state, language, Some(message)).await {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    match web_auth::register_user(
        &app_state.meta_store,
        &settings,
        &form.username,
        &form.password,
        extract_client_ip(&headers).as_deref(),
        extract_user_agent(&headers).as_deref(),
    )
    .await
    {
        Ok(RegistrationResult {
            user,
            auth_session,
            session_token,
            master_key,
        }) => {
            cache_user_master_key(&app_state, &user.id, &auth_session.id, master_key).await;

            let max_age = i64::from(settings.session_absolute_ttl_hours) * 3600;
            let mut response = Redirect::to(&format!(
                "/settings/security/totp/setup?lang={}",
                language.code()
            ))
            .into_response();
            match set_cookie_header(&build_auth_cookie(
                &session_token,
                max_age,
                settings.cookie_secure,
            )) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                    response
                }
                Err(status) => status.into_response(),
            }
        }
        Err(error) => {
            match render_register_page(&app_state, language, Some(&error.to_string())).await {
                Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
    }
}

async fn settings_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    match render_settings_page(&app_state, &authenticated, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn notification_settings_page_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    match render_notification_settings_page(&app_state, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn change_password_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    if form.new_password != form.confirm_password {
        let message = match language {
            Language::En => "The new password fields must match.",
            Language::ZhCn => "两次输入的新密码必须一致。",
        };
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(message)),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let settings = app_state.system_settings.read().await.clone();
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    };

    match web_auth::change_password(
        &app_state.meta_store,
        &settings,
        &mut user,
        &form.current_password,
        &form.new_password,
    )
    .await
    {
        Ok(master_key) => {
            cache_user_master_key(
                &app_state,
                &user.id,
                &authenticated.auth_session.id,
                master_key,
            )
            .await;
            let mut refreshed = authenticated.clone();
            refreshed.user = user;
            match render_settings_page(
                &app_state,
                &refreshed,
                language,
                Some(PageBanner::success(match language {
                    Language::En => "Password updated.",
                    Language::ZhCn => "密码已更新。",
                })),
            )
            .await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(error) => match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        },
    }
}

async fn update_idle_timeout_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<IdleTimeoutForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let settings = app_state.system_settings.read().await.clone();
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    };

    let preferred_idle_timeout_minutes = match parse_user_idle_timeout_preference(
        &form.idle_timeout_minutes,
        settings.max_idle_timeout_minutes,
    ) {
        Ok(value) => value,
        Err(error) => {
            return match render_settings_page(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(error.to_string())),
            )
            .await
            {
                Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                Err(status) => status.into_response(),
            };
        }
    };

    user.security.preferred_idle_timeout_minutes = preferred_idle_timeout_minutes;
    user.updated_at_unix = Utc::now().timestamp();

    if let Err(error) = app_state.meta_store.save_user(&user).await {
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let effective_idle_timeout = effective_idle_timeout_minutes(&user, &settings);
    if let Err(error) = app_state
        .meta_store
        .set_idle_timeout_for_user_sessions(&user.id, effective_idle_timeout)
        .await
    {
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("user_idle_timeout_updated"),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "preferred_idle_timeout_minutes": preferred_idle_timeout_minutes,
                "effective_idle_timeout_minutes": effective_idle_timeout
            })
            .to_string(),
        })
        .await;

    let mut refreshed = authenticated.clone();
    refreshed.user = user;
    refreshed.auth_session.idle_timeout_minutes = effective_idle_timeout;

    match render_settings_page(
        &app_state,
        &refreshed,
        language,
        Some(PageBanner::success(match language {
            Language::En => "Idle timeout updated.",
            Language::ZhCn => "空闲登出设置已更新。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn totp_setup_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    match render_totp_setup_page(&app_state, &authenticated, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn confirm_totp_setup_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<TotpConfirmForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let code = form.code.trim();
    if code.is_empty() {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "Enter a TOTP code to confirm setup.",
                Language::ZhCn => "请输入一个 TOTP 动态码完成确认。",
            })),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let pending = {
        let mut setups = app_state.totp_setups.write().await;
        setups
            .entry(authenticated.auth_session.id.clone())
            .or_insert_with(|| {
                let material = build_totp_setup_material(&authenticated.user.username);
                PendingTotpSetup {
                    secret: material.secret,
                    recovery_codes: material.recovery_codes,
                    otp_auth_uri: material.otp_auth_uri,
                }
            })
            .clone()
    };
    let verification = verify_totp(
        pending.secret.as_ref().as_str(),
        code,
        Utc::now().timestamp(),
        1,
        &HashSet::new(),
    );
    let valid = matches!(verification, Ok(TotpVerification::Valid { .. }));
    if !valid {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "That TOTP code did not match the new secret.",
                Language::ZhCn => "这个 TOTP 动态码与新的密钥不匹配。",
            })),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let Some(master_key) = app_state
        .unlock_cache
        .read()
        .await
        .get(&authenticated.auth_session.id)
        .cloned()
    else {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "Your unlock state expired. Sign in again and retry TOTP setup.",
                Language::ZhCn => "当前解锁状态已失效，请重新登录后再完成 TOTP 设置。",
            })),
        )
        .await
        {
            Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
            Err(status) => status.into_response(),
        };
    };

    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    };

    match web_auth::save_totp_setup(
        &app_state.meta_store,
        &mut user,
        master_key.as_ref().as_slice(),
        pending.secret.as_ref().as_str(),
        &pending.recovery_codes,
    )
    .await
    {
        Ok(()) => {
            app_state
                .totp_setups
                .write()
                .await
                .remove(&authenticated.auth_session.id);
            Redirect::to(&settings_href(language)).into_response()
        }
        Err(error) => match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        },
    }
}

async fn admin_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }
    match render_admin_page(&app_state, &authenticated, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_create_user_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<AdminCreateUserForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }

    let settings = app_state.system_settings.read().await.clone();
    let username = match normalize_username(&form.username) {
        Ok(value) => value,
        Err(error) => {
            return match render_admin_page(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(error.to_string())),
            )
            .await
            {
                Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                Err(status) => status.into_response(),
            };
        }
    };
    let strength =
        evaluate_password_strength(&form.password, &settings.password_strength_rules, false);
    if !strength.valid {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(strength.reasons.join("; "))),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    if app_state
        .meta_store
        .get_user_by_username(&username)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "That username already exists.",
                Language::ZhCn => "这个用户名已经存在。",
            })),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let mut user = hanagram_web::store::UserRecord::new(username.clone(), UserRole::User);
    if let Err(error) =
        initialize_user_credentials(&mut user, &form.password, &settings.argon_policy)
    {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let save_result = app_state.meta_store.save_user(&user).await;
    if let Err(error) = save_result {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_user_created"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({ "username": username }).to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "User created.",
            Language::ZhCn => "用户已创建。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_unlock_user_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(user_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&user_id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&admin_href(language)).into_response();
    };
    if user.role == UserRole::Admin {
        return Redirect::to(&admin_href(language)).into_response();
    }

    user.security.login_failures = 0;
    user.security.lockout_level = 0;
    user.security.locked_until_unix = None;
    user.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = app_state.meta_store.save_user(&user).await {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_user_unlocked"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({ "username": user.username }).to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "User unlocked.",
            Language::ZhCn => "用户已解锁。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_reset_user_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(user_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&user_id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&admin_href(language)).into_response();
    };
    if user.role == UserRole::Admin {
        return Redirect::to(&admin_href(language)).into_response();
    }

    if let Ok(session_records) = app_state
        .meta_store
        .list_session_records_for_user(&user.id)
        .await
    {
        for record in session_records {
            if let Some(worker) = app_state.session_workers.lock().await.remove(&record.id) {
                worker.cancellation.cancel();
                let _ = worker.task.await;
            }
        }
    }
    let reset_result = match reset_user_account(
        &app_state.meta_store,
        &mut user,
        &app_state.runtime.users_dir,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            return match render_admin_page(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(error.to_string())),
            )
            .await
            {
                Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
                Err(status) => status.into_response(),
            };
        }
    };

    for auth_session_id in &reset_result.auth_session_ids {
        clear_auth_session_sensitive_state(&app_state, auth_session_id).await;
    }
    app_state.user_keys.write().await.remove(&user.id);
    clear_pending_flows_for_user(&app_state, &user.id).await;
    {
        let mut shared_state = app_state.shared_state.write().await;
        for session_record_id in &reset_result.session_record_ids {
            shared_state.remove(session_record_id);
        }
    }
    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_user_reset"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "username": user.username,
                "credentials_cleared": true,
                "session_records_removed": reset_result.session_record_ids.len(),
                "auth_sessions_revoked": reset_result.auth_session_ids.len()
            })
            .to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "User credentials and encrypted data were cleared. They must register again with the same username.",
            Language::ZhCn => "该用户的凭据和加密数据已清空。对方需要使用相同用户名重新注册。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_revoke_user_sessions_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(user_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
    Form(form): Form<RevokeSessionsForm>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let allow_self = authenticated.user.id == user_id;
    if authenticated.user.role != UserRole::Admin && !allow_self {
        return Redirect::to(&dashboard_href(language)).into_response();
    }

    if let Some(session_id) = form.session_id.as_deref() {
        if let Ok(Some(session)) = app_state
            .meta_store
            .get_auth_session_by_id(session_id)
            .await
        {
            if session.user_id == user_id {
                let _ = app_state.meta_store.revoke_auth_session(session_id).await;
                clear_auth_session_sensitive_state(&app_state, session_id).await;
                drop_user_master_key_if_no_active_sessions(&app_state, &user_id).await;
            }
        }
    } else {
        if let Ok(sessions) = app_state
            .meta_store
            .list_auth_sessions_for_user(&user_id)
            .await
        {
            for session in sessions {
                clear_auth_session_sensitive_state(&app_state, &session.id).await;
            }
        }
        let _ = app_state
            .meta_store
            .revoke_all_auth_sessions_for_user(&user_id)
            .await;
        app_state.user_keys.write().await.remove(&user_id);
        clear_pending_flows_for_user(&app_state, &user_id).await;
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("auth_sessions_revoked"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user_id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({ "single_session": form.session_id.is_some() })
                .to_string(),
        })
        .await;

    if authenticated.user.role == UserRole::Admin && authenticated.user.id != user_id {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::success(match language {
                Language::En => "User sessions revoked.",
                Language::ZhCn => "该用户的登录会话已强制下线。",
            })),
        )
        .await
        {
            Ok(html) => html.into_response(),
            Err(status) => status.into_response(),
        };
    }

    match render_settings_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "Selected sessions were revoked.",
            Language::ZhCn => "选中的登录会话已被强制下线。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_save_system_settings_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<AdminSaveSettingsForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }

    let mut settings = app_state.system_settings.read().await.clone();
    settings.registration_policy = parse_registration_policy(&form.registration_policy);
    settings.public_registration_open = form.public_registration_open.is_some();
    settings.session_absolute_ttl_hours = form.session_absolute_ttl_hours.max(1);
    settings.audit_detail_limit = form.audit_detail_limit.max(1);
    settings.totp_policy = parse_enforcement_mode(&form.totp_policy);
    settings.password_strength_policy = parse_enforcement_mode(&form.password_strength_policy);
    settings.password_strength_rules.mode = settings.password_strength_policy;
    settings.password_strength_rules.min_length = form.password_min_length.max(1);
    settings.password_strength_rules.require_uppercase = form.password_require_uppercase.is_some();
    settings.password_strength_rules.require_lowercase = form.password_require_lowercase.is_some();
    settings.password_strength_rules.require_number = form.password_require_number.is_some();
    settings.password_strength_rules.require_symbol = form.password_require_symbol.is_some();
    settings.lockout_policy.threshold = form.lockout_threshold.max(1);
    settings.lockout_policy.base_delay_seconds = form.lockout_base_delay_seconds.max(1);
    settings.lockout_policy.max_delay_seconds = form
        .lockout_max_delay_seconds
        .max(settings.lockout_policy.base_delay_seconds);
    settings.max_idle_timeout_minutes =
        match parse_admin_idle_timeout_cap(&form.max_idle_timeout_minutes) {
            Ok(value) => value,
            Err(error) => {
                return match render_admin_page(
                    &app_state,
                    &authenticated,
                    language,
                    Some(PageBanner::error(error.to_string())),
                )
                .await
                {
                    Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                    Err(status) => status.into_response(),
                };
            }
        };

    let requested_memory_kib = form.argon_memory_mib.max(64).saturating_mul(1024);
    let requested_iterations = form.argon_iterations.max(3);
    let requested_lanes = form.argon_lanes.max(2);
    let current_argon_policy = settings.argon_policy.clone();
    let next_argon_version = current_argon_policy.version + 1;
    let argon_policy_changed = requested_memory_kib > current_argon_policy.memory_kib
        || requested_iterations > current_argon_policy.iterations
        || requested_lanes > current_argon_policy.lanes;
    if argon_policy_changed {
        settings.argon_policy = current_argon_policy.raised(
            next_argon_version,
            requested_memory_kib,
            requested_iterations,
            requested_lanes,
        );
    }

    if let Err(error) = app_state.meta_store.save_system_settings(&settings).await {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    if let Err(error) = sync_active_session_idle_timeouts(&app_state, &settings).await {
        *app_state.system_settings.write().await = settings.clone();
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(format!(
                "{}{}",
                match language {
                    Language::En =>
                        "Settings were saved, but refreshing active session timeouts failed: ",
                    Language::ZhCn => "系统设置已保存，但刷新活跃登录会话超时失败：",
                },
                error
            ))),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    *app_state.system_settings.write().await = settings;

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("system_settings_updated"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(authenticated.user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "registration_policy": form.registration_policy,
                "totp_policy": form.totp_policy,
                "password_strength_policy": form.password_strength_policy,
                "argon_policy_changed": argon_policy_changed
            })
            .to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "System settings saved.",
            Language::ZhCn => "系统设置已保存。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
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
    let settings = app_state.system_settings.read().await.clone();
    if let Some(token) = find_cookie(&headers, AUTH_COOKIE_NAME) {
        let token_hash = hash_session_token(token);
        if let Ok(Some(session)) = app_state
            .meta_store
            .get_auth_session_by_token_hash(&token_hash)
            .await
        {
            clear_auth_session_sensitive_state(&app_state, &session.id).await;
            let _ = app_state.meta_store.revoke_auth_session(&session.id).await;
            drop_user_master_key_if_no_active_sessions(&app_state, &session.user_id).await;
        } else {
            clear_invalid_cookie_state(&app_state, &headers).await;
        }
    }

    match set_cookie_header(&clear_auth_cookie(settings.cookie_secure)) {
        Ok(cookie) => {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(status) => status.into_response(),
    }
}

async fn index_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let language = detect_language(&headers, query.lang.as_deref());
    render_dashboard_page(&app_state, &authenticated, language, None).await
}

async fn dashboard_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
) -> Json<DashboardSnapshot> {
    Json(build_dashboard_snapshot(&app_state, &authenticated).await)
}

async fn save_bot_settings_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<BotNotificationSettingsForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let return_to_settings = form.return_to.as_deref() == Some("settings");
    let settings = BotNotificationSettings {
        enabled: form.enabled.is_some(),
        bot_token: form.bot_token,
        chat_id: form.chat_id,
        template: form.template,
    }
    .normalized();

    if settings.enabled && settings.bot_token.is_empty() {
        return match render_notification_workspace_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.bot_error_missing_token)),
            return_to_settings,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    if settings.enabled && settings.chat_id.is_empty() {
        return match render_notification_workspace_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.bot_error_missing_chat_id)),
            return_to_settings,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    if let Err(error) =
        save_bot_notification_settings(&app_state.runtime.notification_settings_path, &settings)
            .await
    {
        warn!("failed saving bot notification settings: {}", error);
        return match render_notification_workspace_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.bot_error_save)),
            return_to_settings,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    *app_state.notification_settings.write().await = settings;
    match render_notification_workspace_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(translations.bot_saved)),
        return_to_settings,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
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
    Extension(authenticated): Extension<AuthenticatedSession>,
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

    let session_id = Uuid::new_v4().to_string();
    let session_name = sanitize_session_name(&form.session_name);
    if let Err(error) = ensure_user_sessions_dir(&app_state.runtime, &authenticated.user.id).await {
        warn!("failed preparing user session dir: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_path_alloc,
        )
        .await;
    }
    match load_telethon_string_session(&form.session_string) {
        Ok(session) => {
            if let Err(error) = save_new_session_record(
                &app_state,
                &authenticated.user.id,
                &session_id,
                &session_name,
                &session,
            )
            .await
            {
                warn!("failed saving imported string session record: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    translations.setup_error_path_alloc,
                )
                .await;
            }
            Redirect::to(&dashboard_href(language)).into_response()
        }
        Err(error) => {
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

async fn export_session_file_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for export: {}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let Some(session) = session else {
        return (StatusCode::NOT_FOUND, String::from("session not found")).into_response();
    };
    let Some(master_key) = resolved_user_master_key(&app_state, &authenticated).await else {
        return (
            StatusCode::LOCKED,
            String::from("session data is locked; sign out and sign in again"),
        )
            .into_response();
    };

    let session_path = PathBuf::from(&session.storage_path);
    match load_persisted_session(master_key.as_ref().as_slice(), &session_path).await {
        Ok(loaded_session) => match export_sqlite_session_bytes(&loaded_session) {
            Ok(bytes) => {
                let mut response = bytes.as_slice().to_vec().into_response();
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
                match HeaderValue::from_str(&format!(
                    "attachment; filename=\"{}.session\"",
                    session.session_key
                )) {
                    Ok(value) => {
                        response
                            .headers_mut()
                            .insert(header::CONTENT_DISPOSITION, value);
                        response
                    }
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
            Err(error) => {
                warn!(
                    "failed exporting sqlite session file {}: {}",
                    session_path.display(),
                    error
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("failed to export session file"),
                )
                    .into_response()
            }
        },
        Err(error) => {
            warn!(
                "failed reading session file {} for export: {}",
                session_path.display(),
                error
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("failed to read session file"),
            )
                .into_response()
        }
    }
}

async fn export_string_session_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<LangQuery>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for string export: {}", error);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiErrorResponse {
                        error: String::from(language.translations().export_string_error),
                    }),
                )
                    .into_response();
            }
        };

    let Some(session) = session else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                error: String::from(language.translations().dashboard_session_missing),
            }),
        )
            .into_response();
    };
    let Some(master_key) = resolved_user_master_key(&app_state, &authenticated).await else {
        return (
            StatusCode::LOCKED,
            Json(ApiErrorResponse {
                error: String::from("Session data is locked. Sign out and sign in again."),
            }),
        )
            .into_response();
    };
    let session_file = PathBuf::from(&session.storage_path);
    let loaded_session =
        match load_persisted_session(master_key.as_ref().as_slice(), &session_file).await {
            Ok(session) => session,
            Err(error) => {
                warn!(
                    "failed decrypting session file {} for string export: {}",
                    session_file.display(),
                    error
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorResponse {
                        error: String::from(language.translations().export_string_error),
                    }),
                )
                    .into_response();
            }
        };
    let export_result = export_telethon_string_session(&loaded_session);

    match export_result {
        Ok(session_string) => Json(SessionStringExportResponse {
            session_key: session.session_key,
            session_string,
        })
        .into_response(),
        Err(error) => {
            warn!(
                "failed exporting telethon string session {}: {}",
                session_file.display(),
                error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    error: String::from(language.translations().export_string_error),
                }),
            )
                .into_response()
        }
    }
}

async fn import_session_file_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
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
    if let Err(error) = ensure_user_sessions_dir(&app_state.runtime, &authenticated.user.id).await {
        warn!("failed preparing user session dir: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            language.translations().setup_error_path_alloc,
        )
        .await;
    }
    let session_id = Uuid::new_v4().to_string();
    match load_session(&file_bytes) {
        Ok(loaded_session) => {
            if let Err(error) = save_new_session_record(
                &app_state,
                &authenticated.user.id,
                &session_id,
                &session_name,
                &loaded_session.session,
            )
            .await
            {
                warn!("failed saving uploaded session record: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_upload_write,
                )
                .await;
            }
            Redirect::to(&dashboard_href(language)).into_response()
        }
        Err(error) => {
            warn!("failed decoding uploaded session file: {}", error);
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_upload_write,
            )
            .await
        }
    }
}

async fn delete_session_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for deletion: {}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    let Some(session) = session else {
        return Redirect::to(&dashboard_href(language)).into_response();
    };

    let worker = app_state.session_workers.lock().await.remove(&session.id);
    if let Some(worker) = worker {
        worker.cancellation.cancel();
        let _ = worker.task.await;
    }

    let session_file = PathBuf::from(&session.storage_path);
    if let Err(error) = remove_file_if_exists(&session_file).await {
        warn!(
            "failed deleting session file {}: {}",
            session_file.display(),
            error
        );
        return match render_dashboard_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language.translations().dashboard_delete_error,
            )),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    if let Err(error) = app_state
        .meta_store
        .delete_session_record(&session.id)
        .await
    {
        warn!("failed deleting session record {}: {}", session.id, error);
    }

    app_state.shared_state.write().await.remove(&session.id);
    Redirect::to(&dashboard_href(language)).into_response()
}

async fn rename_session_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<RenameSessionForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let new_name = form.session_name.trim();

    if new_name.is_empty() {
        return match render_dashboard_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.dashboard_rename_missing)),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let current_session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for rename: {}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    let Some(current_session) = current_session else {
        return match render_dashboard_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.dashboard_session_missing)),
        )
        .await
        {
            Ok(html) => (StatusCode::NOT_FOUND, html).into_response(),
            Err(status) => status.into_response(),
        };
    };
    let next_session_name = sanitize_session_name(new_name);

    if next_session_name == current_session.session_key {
        return Redirect::to(&dashboard_href(language)).into_response();
    }

    let mut updated_session = current_session.clone();
    updated_session.session_key = next_session_name;
    updated_session.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = persist_session_record(&app_state, &updated_session).await {
        warn!("failed saving renamed session record: {}", error);
        return match render_dashboard_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.dashboard_rename_error)),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    {
        let mut state = app_state.shared_state.write().await;
        if let Some(session) = state.get_mut(&session_id) {
            session.key = updated_session.session_key.clone();
            session.note = updated_session.note.clone();
        }
    }
    Redirect::to(&dashboard_href(language)).into_response()
}

async fn update_session_note_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<SessionNoteForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let note = form.note.trim().chars().take(240).collect::<String>();
    let session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for note update: {}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    let Some(mut session) = session else {
        return Redirect::to(&dashboard_href(language)).into_response();
    };
    session.note = note.clone();
    session.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = persist_session_record(&app_state, &session).await {
        warn!("failed saving session note: {}", error);
        return match render_dashboard_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "Failed to update session note.",
                Language::ZhCn => "更新会话备注失败。",
            })),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    set_session_note(&app_state.shared_state, &session.id, note).await;
    Redirect::to(&dashboard_href(language)).into_response()
}

async fn start_phone_login_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<StartPhoneLoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let phone = form.phone.trim();
    let login_phone = sanitize_phone_input(phone);

    if login_phone.is_empty() {
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_missing_phone,
        )
        .await;
    }

    let flow_id = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string();
    let session_name = sanitize_session_name(&form.session_name);
    if let Err(error) = ensure_user_sessions_dir(&app_state.runtime, &authenticated.user.id).await {
        warn!("failed preparing user session dir: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_path_alloc,
        )
        .await;
    }
    let final_path = session_storage_path(&app_state.runtime, &authenticated.user.id, &session_id);
    let client_session = TelegramClientSession::open_empty(app_state.runtime.api_id);

    let result = client_session
        .client
        .request_login_code(&login_phone, &app_state.runtime.api_hash)
        .await;
    let session_data = client_session.snapshot();
    client_session.shutdown().await;

    match result {
        Ok(token) => {
            let session_data = match session_data {
                Ok(data) => data,
                Err(error) => {
                    warn!("failed capturing phone login session snapshot: {}", error);
                    return render_setup_error_response(
                        &app_state,
                        language,
                        translations.setup_error_phone_unavailable,
                    )
                    .await;
                }
            };
            let flow = PendingPhoneLogin {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                session_name,
                phone: format_phone_display(phone),
                session_id,
                final_path,
                session_data: share_sensitive_bytes(session_data),
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
            render_setup_error_response(&app_state, language, translations.setup_error_phone_start)
                .await
        }
    }
}

async fn start_qr_login_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<StartQrLoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let flow_id = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string();
    let session_name = sanitize_session_name(&form.session_name);
    if let Err(error) = ensure_user_sessions_dir(&app_state.runtime, &authenticated.user.id).await {
        warn!("failed preparing user session dir: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_path_alloc,
        )
        .await;
    }
    let final_path = session_storage_path(&app_state.runtime, &authenticated.user.id, &session_id);
    let session_data = match serialize_session(&LoadedSession::default()) {
        Ok(data) => data,
        Err(error) => {
            warn!(
                "failed creating initial qr login session snapshot: {}",
                error
            );
            return render_setup_error_response(
                &app_state,
                language,
                translations.setup_error_qr_unavailable,
            )
            .await;
        }
    };

    app_state.qr_flows.write().await.insert(
        flow_id.clone(),
        PendingQrLogin {
            user_id: authenticated.user.id.clone(),
            auth_session_id: authenticated.auth_session.id.clone(),
            session_name,
            session_id,
            final_path,
            session_data: share_sensitive_bytes(session_data),
        },
    );

    Redirect::to(&format!("/sessions/qr/{flow_id}?lang={}", language.code())).into_response()
}

async fn phone_flow_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<FlowPageQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let flow_guard = app_state.phone_flows.read().await;
    let flow = match flow_guard.get(&flow_id) {
        Some(flow) if flow.user_id == authenticated.user.id => flow,
        Some(_) => {
            drop(flow_guard);
            return Redirect::to(&dashboard_href(language)).into_response();
        }
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
    Extension(authenticated): Extension<AuthenticatedSession>,
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

    let owner_matches = app_state
        .phone_flows
        .read()
        .await
        .get(&flow_id)
        .map(|flow| flow.user_id == authenticated.user.id)
        .unwrap_or(false);
    if !owner_matches {
        return Redirect::to(&dashboard_href(language)).into_response();
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
    if flow.user_id != authenticated.user.id {
        drop(flows);
        return Redirect::to(&dashboard_href(language)).into_response();
    }

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

    let client_session = match TelegramClientSession::open_serialized(
        flow.session_data.as_ref().as_slice(),
        app_state.runtime.api_id,
    ) {
        Ok(client_session) => client_session,
        Err(error) => {
            warn!(
                "failed opening in-memory session for code verification: {}",
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
    let session_data = client_session.snapshot();
    client_session.shutdown().await;
    let session_data = match session_data {
        Ok(data) => data,
        Err(error) => {
            warn!(
                "failed capturing phone code verification snapshot: {}",
                error
            );
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_finalize,
            )
            .await;
        }
    };

    match result {
        Ok(_) => {
            if let Err(error) = finalize_pending_session(
                &app_state,
                &flow.user_id,
                &flow.session_id,
                &flow.session_name,
                &flow.final_path,
                session_data.as_slice(),
            )
            .await
            {
                warn!("failed finalizing phone login session: {}", error);
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
            flow.session_data = share_sensitive_bytes(session_data);
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
            flow.session_data = share_sensitive_bytes(session_data);
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
    Extension(authenticated): Extension<AuthenticatedSession>,
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

    let owner_matches = app_state
        .phone_flows
        .read()
        .await
        .get(&flow_id)
        .map(|flow| flow.user_id == authenticated.user.id)
        .unwrap_or(false);
    if !owner_matches {
        return Redirect::to(&dashboard_href(language)).into_response();
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
    if flow.user_id != authenticated.user.id {
        drop(flows);
        return Redirect::to(&dashboard_href(language)).into_response();
    }

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

    let client_session = match TelegramClientSession::open_serialized(
        flow.session_data.as_ref().as_slice(),
        app_state.runtime.api_id,
    ) {
        Ok(client_session) => client_session,
        Err(error) => {
            warn!(
                "failed opening in-memory session for password verification: {}",
                error
            );
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_phone_password_reset,
            )
            .await;
        }
    };

    let result = client_session.client.check_password(token, password).await;
    let session_data = client_session.snapshot();
    client_session.shutdown().await;
    let session_data = match session_data {
        Ok(data) => data,
        Err(error) => {
            warn!(
                "failed capturing phone password verification snapshot: {}",
                error
            );
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_phone_password_reset,
            )
            .await;
        }
    };

    match result {
        Ok(_) => {
            if let Err(error) = finalize_pending_session(
                &app_state,
                &flow.user_id,
                &flow.session_id,
                &flow.session_name,
                &flow.final_path,
                session_data.as_slice(),
            )
            .await
            {
                warn!("failed finalizing password login session: {}", error);
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
            flow.session_data = share_sensitive_bytes(session_data);
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
            flow.session_data = share_sensitive_bytes(session_data);
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
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    let owner_matches = app_state
        .phone_flows
        .read()
        .await
        .get(&flow_id)
        .map(|flow| flow.user_id == authenticated.user.id)
        .unwrap_or(false);
    if owner_matches {
        let _ = app_state.phone_flows.write().await.remove(&flow_id);
    } else if app_state.phone_flows.read().await.contains_key(&flow_id) {
        return Redirect::to(&dashboard_href(language)).into_response();
    }

    Redirect::to(&setup_href(language)).into_response()
}

async fn qr_flow_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<FlowPageQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let flow = {
        let flows = app_state.qr_flows.read().await;
        match flows.get(&flow_id) {
            Some(flow) if flow.user_id == authenticated.user.id => flow.clone(),
            Some(_) => {
                drop(flows);
                return Redirect::to(&dashboard_href(language)).into_response();
            }
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
        Ok((QrStatus::Pending(pending), session_data)) => {
            if let Some(active_flow) = app_state.qr_flows.write().await.get_mut(&flow_id) {
                active_flow.session_data = share_sensitive_bytes(session_data);
            }
            match render_qr_flow_page(&app_state, language, &flow_id, &flow, pending, banner).await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            }
        }
        Ok((QrStatus::Authorized, session_data)) => {
            app_state.qr_flows.write().await.remove(&flow_id);

            if let Err(error) = finalize_pending_session(
                &app_state,
                &flow.user_id,
                &flow.session_id,
                &flow.session_name,
                &flow.final_path,
                session_data.as_slice(),
            )
            .await
            {
                warn!("failed finalizing qr login session: {}", error);
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
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    let flow = app_state.qr_flows.read().await.get(&flow_id).cloned();
    if let Some(flow) = flow {
        if flow.user_id != authenticated.user.id {
            return Redirect::to(&dashboard_href(language)).into_response();
        }
        app_state.qr_flows.write().await.remove(&flow_id);
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
    user_id: &str,
    session_id: &str,
    session_name: &str,
    final_path: &Path,
    session_data: &[u8],
) -> Result<()> {
    let master_key = app_state
        .user_keys
        .read()
        .await
        .get(user_id)
        .cloned()
        .context("user data is locked; sign in again to unlock it")?;
    let loaded = load_session(session_data).context("failed to decode pending session payload")?;
    persist_loaded_session(master_key.as_ref().as_slice(), final_path, &loaded.session).await?;

    let mut record = SessionRecord::new(
        user_id.to_owned(),
        session_name.to_owned(),
        final_path.display().to_string(),
    );
    record.id = session_id.to_owned();
    persist_session_record(app_state, &record).await?;
    register_session_record(app_state, record).await;
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

async fn poll_qr_flow(
    runtime: &RuntimeConfig,
    flow: &PendingQrLogin,
) -> Result<(QrStatus, SensitiveBytes)> {
    let client_session = TelegramClientSession::open_serialized(
        flow.session_data.as_ref().as_slice(),
        runtime.api_id,
    )
    .context("failed to open qr login session")?;

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

    let session_data = client_session.snapshot()?;
    client_session.shutdown().await;
    status.map(|status| (status, session_data))
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
    use std::io;

    #[test]
    fn find_cookie_extracts_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=light; hanagram_auth=session-token; other=value"),
        );

        assert_eq!(
            find_cookie(&headers, AUTH_COOKIE_NAME),
            Some("session-token")
        );
    }

    #[test]
    fn find_cookie_rejects_missing_cookie() {
        let mut headers = HeaderMap::new();

        assert_eq!(find_cookie(&headers, AUTH_COOKIE_NAME), None);

        headers.insert(header::COOKIE, HeaderValue::from_static("other=value"));

        assert_eq!(find_cookie(&headers, AUTH_COOKIE_NAME), None);
    }

    #[test]
    fn sanitize_session_name_falls_back_and_normalizes() {
        assert_eq!(sanitize_session_name("Hello World"), "hello-world");
        assert_eq!(sanitize_session_name("test__name"), "test_name");
        assert!(sanitize_session_name("  ").starts_with("session-"));
    }

    #[test]
    fn decrypt_session_storage_bytes_round_trips_encrypted_payload() {
        let master_key = [7_u8; 32];
        let plaintext = b"telegram-session-sqlite";
        let payload = encrypt_bytes(&master_key, plaintext).expect("encrypt payload");
        let encoded = serde_json::to_vec(&payload).expect("encode encrypted payload");

        let (decrypted, was_legacy_plaintext) =
            decrypt_session_storage_bytes(&master_key, &encoded).expect("decrypt payload");

        assert_eq!(decrypted.as_slice(), plaintext);
        assert!(!was_legacy_plaintext);
    }

    #[test]
    fn decrypt_session_storage_bytes_accepts_legacy_plaintext() {
        let master_key = [9_u8; 32];
        let plaintext = b"legacy-session";

        let (decrypted, was_legacy_plaintext) =
            decrypt_session_storage_bytes(&master_key, plaintext).expect("accept legacy payload");

        assert_eq!(decrypted.as_slice(), plaintext);
        assert!(was_legacy_plaintext);
    }

    #[test]
    fn encrypt_session_metadata_round_trips_and_accepts_legacy_plaintext() {
        let master_key = [11_u8; 32];
        let encrypted_key =
            encrypt_session_key("primary-account", &master_key).expect("encrypt session key");
        let (decrypted_key, key_was_legacy_plaintext) =
            decrypt_session_key(&encrypted_key, &master_key).expect("decrypt session key");
        assert_eq!(decrypted_key, "primary-account");
        assert!(!key_was_legacy_plaintext);

        let encrypted = encrypt_session_note("Primary phone", &master_key).expect("encrypt note");

        let (decrypted, was_legacy_plaintext) =
            decrypt_session_note(&encrypted, &master_key).expect("decrypt note");
        assert_eq!(decrypted, "Primary phone");
        assert!(!was_legacy_plaintext);

        let (legacy_decrypted, legacy_plaintext) =
            decrypt_session_note("legacy note", &master_key).expect("accept legacy note");
        assert_eq!(legacy_decrypted, "legacy note");
        assert!(legacy_plaintext);
    }

    #[test]
    fn classify_session_failure_stops_on_unauthorized_rpc() {
        let error = anyhow::Error::new(InvocationError::Rpc(grammers_client::sender::RpcError {
            code: 401,
            name: String::from("AUTH_KEY_UNREGISTERED"),
            value: None,
            caused_by: None,
        }))
        .context("update loop failed");

        assert_eq!(
            classify_session_failure(&error),
            SessionFailureAction::Terminal(String::from("session is no longer authorized"))
        );
    }

    #[test]
    fn classify_session_failure_stops_on_missing_session_file() {
        let error = anyhow::anyhow!("failed to load session");

        assert_eq!(
            classify_session_failure(&error),
            SessionFailureAction::Terminal(String::from("failed to load session"))
        );
    }

    #[test]
    fn classify_session_failure_retries_on_transient_io_error() {
        let error = anyhow::Error::new(InvocationError::Io(io::Error::other("temporary outage")))
            .context("update loop failed");

        assert_eq!(
            classify_session_failure(&error),
            SessionFailureAction::Retryable(String::from("update loop failed"))
        );
    }

    #[test]
    fn format_phone_display_formats_plain_digits() {
        let display = format_phone_display("13146288470");

        assert!(display.starts_with("+1 "));
        assert!(display.contains("314"));
    }

    #[test]
    fn render_bot_notification_text_replaces_placeholders() {
        let payload = OtpNotificationPayload {
            session_key: String::from("alpha"),
            phone: String::from("+1 314 628 8470"),
            code: String::from("58670"),
            message: String::from("Login code: 58670"),
            received_at: String::from("2026-03-12 14:20:00 UTC"),
            session_file: String::from("./sessions/alpha.session"),
            status: String::from("connected"),
        };

        let rendered = render_bot_notification_text(
            "Code={code}\nPhone={phone}\nName={session_key}\nFile={session_file}\nAt={received_at}\nStatus={status}\nBody={message}",
            &payload,
        );

        assert!(rendered.contains("Code=58670"));
        assert!(rendered.contains("Phone=+1 314 628 8470"));
        assert!(rendered.contains("Name=alpha"));
        assert!(rendered.contains("File=./sessions/alpha.session"));
        assert!(rendered.contains("At=2026-03-12 14:20:00 UTC"));
        assert!(rendered.contains("Status=connected"));
        assert!(rendered.contains("Body=Login code: 58670"));
    }
}
