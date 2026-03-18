// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

pub(crate) use std::collections::{HashMap, HashSet, VecDeque};
pub(crate) use std::fmt::Write as _;
pub(crate) use std::net::SocketAddr;
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::sync::Arc;
pub(crate) use std::time::Duration;

pub(crate) use anyhow::{Context as AnyhowContext, Result};
pub(crate) use axum::extract::{
    Extension, Form, Multipart, Path as AxumPath, Query, Request, State,
};
pub(crate) use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
pub(crate) use axum::middleware::Next;
pub(crate) use axum::response::{Html, IntoResponse, Redirect, Response};
pub(crate) use axum::routing::{get, post};
pub(crate) use axum::{Json, Router};
pub(crate) use base64::Engine;
pub(crate) use chrono::{DateTime, Months, TimeDelta, Utc};
pub(crate) use grammers_client::client::{LoginToken, PasswordToken, UpdatesConfiguration};
pub(crate) use grammers_client::tl;
pub(crate) use grammers_client::{
    Client, InvocationError, SenderPool, SignInError, sender::SenderPoolFatHandle,
};
pub(crate) use grammers_session::Session;
pub(crate) use grammers_session::types::{PeerId, PeerInfo, UpdateState, UpdatesState};
pub(crate) use phonenumber::Mode as PhoneNumberMode;
pub(crate) use qrcodegen::{QrCode, QrCodeEcc};
pub(crate) use regex::Regex;
pub(crate) use reqwest::Client as HttpClient;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use tera::{Context, Tera};
pub(crate) use tokio::net::TcpListener;
pub(crate) use tokio::sync::{Mutex, RwLock};
pub(crate) use tokio::task::JoinHandle;
pub(crate) use tokio::time::sleep;
pub(crate) use tokio_util::sync::CancellationToken;
pub(crate) use tower_http::trace::TraceLayer;
pub(crate) use tracing::{info, warn};
pub(crate) use tracing_subscriber::EnvFilter;
pub(crate) use uuid::Uuid;
pub(crate) use webauthn_rp::request::auth::AuthenticationServerState;
pub(crate) use webauthn_rp::request::register::RegistrationServerState;

pub(crate) use hanagram_web::account_reset::{delete_user_account, reset_user_account};
pub(crate) use hanagram_web::security::{
    EncryptedBlob, EnforcementMode, MasterKey, RegistrationPolicy, SensitiveBytes, SharedMasterKey,
    SharedSensitiveBytes, SharedSensitiveString, TotpVerification, decrypt_bytes, encrypt_bytes,
    evaluate_password_strength, hash_session_token, into_sensitive_bytes, share_master_key,
    share_sensitive_bytes, verify_totp,
};
pub(crate) use hanagram_web::store::{
    AuthSessionRecord, BotNotificationSettings, MetaStore, NewAuditEntry, SessionRecord,
    SystemSettings, TelegramApiSettings, UserRecord, UserRole,
};

pub(crate) use super::platform_key;
pub(crate) use super::runtime_cache::{RuntimeCache, RuntimeCacheHandle};
pub(crate) use crate::i18n::{Language, language_options};
pub(crate) use crate::session_handler::{
    LoadedSession, export_sqlite_session_bytes, export_telethon_string_session, load_session,
    load_telethon_string_session, serialize_session,
};
pub(crate) use crate::state::{
    OtpMessage, SessionErrorKind, SessionInfo, SessionNotificationContext, SessionStatus,
    SharedState,
};
pub(crate) use crate::web_auth::{
    AUTH_COOKIE_NAME, AuthenticatedSession, LANGUAGE_COOKIE_NAME, LoginError, RegistrationResult,
    build_auth_cookie, build_language_cookie, build_totp_setup_material, clear_auth_cookie,
    effective_auth_cookie_secure, extract_client_ip, extract_user_agent, find_cookie,
    initialize_user_credentials, normalize_username, request_uses_https,
    resolve_authenticated_session,
};

pub(crate) const QR_AUTO_REFRESH_SECONDS: u64 = 5;
pub(crate) const DASHBOARD_INCREMENTAL_SYNC_SECONDS: u64 = 3;
pub(crate) const DASHBOARD_FULL_SYNC_SECONDS: u64 = 30;
pub(crate) const META_DB_FILE_NAME: &str = "app.db";
pub(crate) const DEFAULT_BOT_TEMPLATE: &str = "Hanagram OTP Alert\n\nAccount: {phone}\nSession: {session_key}\nCode: {code}\nReceived: {received_at}\nStatus: {status}\nSession file: {session_file}\n\nMessage:\n{message}";
pub(crate) const SESSION_KEY_PREFIX: &str = "hanagram-session-key:v1:";
pub(crate) const SESSION_NOTE_PREFIX: &str = "hanagram-note:v1:";
pub(crate) const EMBEDDED_TEMPLATES: [(&str, &str); 10] = [
    ("admin.html", include_str!("../../templates/admin.html")),
    ("index.html", include_str!("../../templates/index.html")),
    ("login.html", include_str!("../../templates/login.html")),
    (
        "notifications.html",
        include_str!("../../templates/notifications.html"),
    ),
    (
        "phone_login.html",
        include_str!("../../templates/phone_login.html"),
    ),
    (
        "qr_login.html",
        include_str!("../../templates/qr_login.html"),
    ),
    (
        "register.html",
        include_str!("../../templates/register.html"),
    ),
    (
        "session_setup.html",
        include_str!("../../templates/session_setup.html"),
    ),
    (
        "settings.html",
        include_str!("../../templates/settings.html"),
    ),
    (
        "totp_setup.html",
        include_str!("../../templates/totp_setup.html"),
    ),
];

pub(crate) type PendingPhoneFlows = Arc<RwLock<HashMap<String, PendingPhoneLogin>>>;
pub(crate) type PendingQrFlows = Arc<RwLock<HashMap<String, PendingQrLogin>>>;
pub(crate) type PendingTotpSetups = Arc<RwLock<HashMap<String, PendingTotpSetup>>>;
pub(crate) type PendingPasskeyRegistrations =
    Arc<RwLock<HashMap<String, PendingPasskeyRegistration>>>;
pub(crate) type PendingPasskeyAuthentications =
    Arc<RwLock<HashMap<String, PendingPasskeyAuthentication>>>;
pub(crate) type PendingRecoveryNotices = Arc<RwLock<HashMap<String, PendingRecoveryNotice>>>;
pub(crate) type SessionWorkers = Arc<Mutex<HashMap<String, SessionWorkerHandle>>>;
pub(crate) type MetaStoreHandle = Arc<MetaStore>;
pub(crate) type UnlockCache = Arc<RwLock<HashMap<String, SharedMasterKey>>>;
pub(crate) type UserKeyCache = Arc<RwLock<HashMap<String, SharedMasterKey>>>;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) shared_state: SharedState,
    pub(crate) session_workers: SessionWorkers,
    pub(crate) runtime_cache: RuntimeCacheHandle,
    pub(crate) tera: Arc<Tera>,
    pub(crate) meta_store: MetaStoreHandle,
    pub(crate) system_settings: Arc<RwLock<SystemSettings>>,
    pub(crate) runtime: RuntimeConfig,
    pub(crate) phone_flows: PendingPhoneFlows,
    pub(crate) qr_flows: PendingQrFlows,
    pub(crate) totp_setups: PendingTotpSetups,
    pub(crate) passkey_registrations: PendingPasskeyRegistrations,
    pub(crate) passkey_authentications: PendingPasskeyAuthentications,
    pub(crate) recovery_notices: PendingRecoveryNotices,
    pub(crate) unlock_cache: UnlockCache,
    pub(crate) user_keys: UserKeyCache,
    pub(crate) passkey_login_key: SharedMasterKey,
    pub(crate) http_client: HttpClient,
}

pub(crate) struct Config {
    pub(crate) sessions_dir: PathBuf,
    pub(crate) bind_addr: SocketAddr,
}

#[derive(Clone)]
pub(crate) struct RuntimeConfig {
    pub(crate) sessions_dir: PathBuf,
    pub(crate) users_dir: PathBuf,
    pub(crate) app_data_dir: PathBuf,
    pub(crate) runtime_cache_dir: PathBuf,
    pub(crate) meta_db_path: PathBuf,
    pub(crate) passkey_login_key_path: PathBuf,
}

pub(crate) struct PendingPhoneLogin {
    pub(crate) user_id: String,
    pub(crate) auth_session_id: String,
    pub(crate) session_name: String,
    pub(crate) phone: String,
    pub(crate) session_id: String,
    pub(crate) final_path: PathBuf,
    pub(crate) session_data: SharedSensitiveBytes,
    pub(crate) stage: PhoneLoginStage,
}

pub(crate) enum PhoneLoginStage {
    AwaitingCode { token: LoginToken },
    AwaitingPassword { token: PasswordToken },
}

#[derive(Clone)]
pub(crate) struct PendingQrLogin {
    pub(crate) user_id: String,
    pub(crate) auth_session_id: String,
    pub(crate) session_name: String,
    pub(crate) session_id: String,
    pub(crate) final_path: PathBuf,
    pub(crate) session_data: SharedSensitiveBytes,
}

#[derive(Clone)]
pub(crate) struct PendingTotpSetup {
    pub(crate) secret: SharedSensitiveString,
    pub(crate) recovery_codes: Vec<SharedSensitiveString>,
    pub(crate) otp_auth_uri: SharedSensitiveString,
    pub(crate) is_rotation: bool,
}

pub(crate) struct PendingPasskeyRegistration {
    pub(crate) user_id: String,
    pub(crate) auth_session_id: String,
    pub(crate) label: String,
    pub(crate) rp_id: String,
    pub(crate) origin: String,
    pub(crate) state: RegistrationServerState,
}

pub(crate) struct PendingPasskeyAuthentication {
    pub(crate) rp_id: String,
    pub(crate) origin: String,
    pub(crate) state: AuthenticationServerState,
}

#[derive(Clone)]
pub(crate) struct PendingRecoveryNotice {
    pub(crate) user_id: String,
    pub(crate) recovery_codes: Vec<SharedSensitiveString>,
}

pub(crate) struct TelegramClientSession {
    pub(crate) client: Client,
    pub(crate) session: Arc<LoadedSession>,
    pub(crate) pool_handle: SenderPoolFatHandle,
    pub(crate) pool_task: JoinHandle<()>,
}

impl TelegramClientSession {
    pub(crate) fn open(session: LoadedSession, api_id: i32) -> Self {
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

    pub(crate) fn open_empty(api_id: i32) -> Self {
        Self::open(LoadedSession::default(), api_id)
    }

    pub(crate) fn open_serialized(session_data: &[u8], api_id: i32) -> Result<Self> {
        let load =
            load_session(session_data).context("failed to load serialized session snapshot")?;
        Ok(Self::open(load.session, api_id))
    }

    pub(crate) fn snapshot(&self) -> Result<SensitiveBytes> {
        serialize_session(self.session.as_ref())
    }

    pub(crate) async fn shutdown(self) {
        let _ = self.pool_handle.quit();
        let _ = self.pool_task.await;
    }
}

pub(crate) struct SessionWorkerHandle {
    pub(crate) cancellation: CancellationToken,
    pub(crate) task: JoinHandle<()>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BotNotificationSettingsView {
    pub(crate) enabled: bool,
    pub(crate) bot_token: String,
    pub(crate) chat_id: String,
    pub(crate) template: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BotPlaceholderHint {
    pub(crate) key: &'static str,
    pub(crate) description: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct OtpNotificationPayload {
    pub(crate) session_key: String,
    pub(crate) phone: String,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) received_at: String,
    pub(crate) session_file: String,
    pub(crate) status: String,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct BotNotificationSettingsForm {
    pub(crate) enabled: Option<String>,
    pub(crate) bot_token: String,
    pub(crate) chat_id: String,
    pub(crate) template: String,
    pub(crate) lang: Option<String>,
    pub(crate) return_to: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DashboardStatusView {
    pub(crate) kind: &'static str,
    pub(crate) connected: bool,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DashboardMessageView {
    pub(crate) received_at: String,
    pub(crate) text: String,
    pub(crate) code: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DashboardSessionView {
    pub(crate) id: String,
    pub(crate) key: String,
    pub(crate) note: String,
    pub(crate) phone: String,
    pub(crate) masked_phone: String,
    pub(crate) session_file: String,
    pub(crate) status: DashboardStatusView,
    pub(crate) latest_code: Option<String>,
    pub(crate) latest_message_at: Option<String>,
    pub(crate) latest_code_at_unix: Option<i64>,
    pub(crate) recent_messages: Vec<DashboardMessageView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DashboardSnapshot {
    pub(crate) total_count: usize,
    pub(crate) connected_count: usize,
    pub(crate) connecting_count: usize,
    pub(crate) error_count: usize,
    pub(crate) generated_at: String,
    pub(crate) sessions: Vec<DashboardSessionView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SessionStringExportResponse {
    pub(crate) session_key: String,
    pub(crate) session_string: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ApiErrorResponse {
    pub(crate) error: String,
}

#[derive(Serialize)]
pub(crate) struct HealthResponse {
    pub(crate) status: &'static str,
    pub(crate) sessions: usize,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ActiveSessionView {
    pub(crate) id: String,
    pub(crate) ip_address: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) issued_at: String,
    pub(crate) expires_at: String,
    pub(crate) is_current: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AdminUserView {
    pub(crate) id: String,
    pub(crate) username: String,
    pub(crate) role: String,
    pub(crate) is_admin: bool,
    pub(crate) locked: bool,
    pub(crate) banned: bool,
    pub(crate) ban_reason: Option<String>,
    pub(crate) ban_until_unix: Option<i64>,
    pub(crate) ban_until_label: Option<String>,
    pub(crate) ban_remaining_label: Option<String>,
    pub(crate) totp_enabled: bool,
    pub(crate) password_ready: bool,
    pub(crate) password_reset_required: bool,
    pub(crate) active_sessions: usize,
    pub(crate) recovery_codes_remaining: i64,
    pub(crate) passkey_count: usize,
    pub(crate) last_login_ip: Option<String>,
    pub(crate) last_auth_method: Option<String>,
    pub(crate) last_auth_at_unix: Option<i64>,
    pub(crate) last_auth_success: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PasskeyView {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) created_at: String,
    pub(crate) last_used_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RecoveryNoticeView {
    pub(crate) codes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AuditLogView {
    pub(crate) action_type: String,
    pub(crate) action_label: String,
    pub(crate) actor_user_id: Option<String>,
    pub(crate) actor_username: Option<String>,
    pub(crate) subject_user_id: Option<String>,
    pub(crate) subject_username: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) ip_address: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) success: bool,
    pub(crate) created_at_unix: i64,
    pub(crate) login_method: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) passkey_label: Option<String>,
    pub(crate) details_pretty: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RecentAuthActivityView {
    pub(crate) username: String,
    pub(crate) action_label: String,
    pub(crate) method_label: String,
    pub(crate) success: bool,
    pub(crate) created_at_unix: i64,
    pub(crate) ip_address: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) passkey_label: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SelectOption {
    pub(crate) value: &'static str,
    pub(crate) label: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PageBanner {
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

impl PageBanner {
    pub(crate) fn error(message: impl Into<String>) -> Self {
        Self {
            kind: "error",
            message: message.into(),
        }
    }

    pub(crate) fn success(message: impl Into<String>) -> Self {
        Self {
            kind: "success",
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TransportSecurityWarning {
    pub(crate) title: String,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PhoneFlowView {
    pub(crate) session_name: String,
    pub(crate) phone: String,
    pub(crate) awaiting_password: bool,
    pub(crate) password_hint: Option<String>,
    pub(crate) submit_action: String,
    pub(crate) cancel_action: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct QrFlowView {
    pub(crate) session_name: String,
    pub(crate) qr_link: String,
    pub(crate) qr_svg: String,
    pub(crate) expires_at: String,
    pub(crate) cancel_action: String,
}

pub(crate) enum QrStatus {
    Pending(QrPendingState),
    Authorized,
}

pub(crate) struct QrPendingState {
    pub(crate) qr_link: String,
    pub(crate) qr_svg: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct LangQuery {
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AdminPageQuery {
    pub(crate) lang: Option<String>,
    pub(crate) audit_search: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct LoginForm {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) mfa_code: Option<String>,
    pub(crate) recovery_code: Option<String>,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PasskeyStartLoginRequest {
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PasskeyFinishLoginRequest {
    pub(crate) request_id: String,
    pub(crate) credential: serde_json::Value,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PasskeyStartRegistrationRequest {
    pub(crate) label: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PasskeyFinishRegistrationRequest {
    pub(crate) registration_id: String,
    pub(crate) credential: serde_json::Value,
    pub(crate) lang: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PasskeyChallengeResponse {
    pub(crate) request_id: String,
    pub(crate) options: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PasskeyRegistrationChallengeResponse {
    pub(crate) registration_id: String,
    pub(crate) options: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PasskeyFinishResponse {
    pub(crate) redirect_to: String,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RegisterForm {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) confirm_password: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ChangePasswordForm {
    pub(crate) current_password: String,
    pub(crate) new_password: String,
    pub(crate) confirm_password: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct IdleTimeoutForm {
    pub(crate) idle_timeout_minutes: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct TotpConfirmForm {
    pub(crate) action: Option<String>,
    pub(crate) code: Option<String>,
    pub(crate) confirm_saved_codes: Option<String>,
    pub(crate) confirm_replace_totp: Option<String>,
    pub(crate) confirm_replace_recovery: Option<String>,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct SessionNoteForm {
    pub(crate) note: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct StringSessionForm {
    pub(crate) session_name: String,
    pub(crate) session_string: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct StartPhoneLoginForm {
    pub(crate) session_name: String,
    pub(crate) phone: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct StartQrLoginForm {
    pub(crate) session_name: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct VerifyCodeForm {
    pub(crate) code: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct VerifyPasswordForm {
    pub(crate) password: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RenameSessionForm {
    pub(crate) session_name: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AdminCreateUserForm {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AdminBanUserForm {
    pub(crate) duration_value: String,
    pub(crate) duration_unit: String,
    pub(crate) reason: String,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AdminSaveSettingsForm {
    pub(crate) telegram_api_id: String,
    pub(crate) telegram_api_hash: String,
    pub(crate) registration_policy: String,
    pub(crate) public_registration_open: Option<String>,
    pub(crate) session_absolute_ttl_hours: u32,
    pub(crate) audit_detail_limit: u32,
    pub(crate) totp_policy: String,
    pub(crate) password_strength_policy: String,
    pub(crate) password_min_length: usize,
    pub(crate) password_require_uppercase: Option<String>,
    pub(crate) password_require_lowercase: Option<String>,
    pub(crate) password_require_number: Option<String>,
    pub(crate) password_require_symbol: Option<String>,
    pub(crate) lockout_threshold: u32,
    pub(crate) lockout_base_delay_seconds: u64,
    pub(crate) lockout_max_delay_seconds: u64,
    pub(crate) max_idle_timeout_minutes: String,
    pub(crate) argon_memory_mib: u32,
    pub(crate) argon_iterations: u32,
    pub(crate) argon_lanes: u32,
    pub(crate) lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RevokeSessionsForm {
    pub(crate) session_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BanDurationUnit {
    Seconds,
    Minutes,
    Hours,
    Days,
    Months,
    Years,
    Permanent,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct FlowPageQuery {
    pub(crate) lang: Option<String>,
    pub(crate) error: Option<String>,
}

pub(crate) fn login_redirect_target(language: Language) -> String {
    let _ = language;
    String::from("/")
}

pub(crate) fn dashboard_href(language: Language) -> String {
    let _ = language;
    String::from("/")
}

pub(crate) fn setup_href(language: Language) -> String {
    let _ = language;
    String::from("/sessions/new")
}

pub(crate) fn settings_href(language: Language) -> String {
    let _ = language;
    String::from("/settings")
}

pub(crate) fn notifications_href(language: Language) -> String {
    let _ = language;
    String::from("/settings/notifications")
}

pub(crate) fn admin_href(language: Language) -> String {
    let _ = language;
    String::from("/admin")
}

pub(crate) fn format_unix_timestamp(unix: i64) -> String {
    match DateTime::from_timestamp(unix, 0) {
        Some(datetime) => datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => String::from("-"),
    }
}

pub(crate) fn format_duration_for_display(language: Language, total_seconds: i64) -> String {
    let translations = language.translations();
    let total_seconds = total_seconds.max(0);
    let units = [
        (
            31_536_000_i64,
            translations.duration_year_singular_label,
            translations.duration_year_plural_label,
        ),
        (
            2_592_000_i64,
            translations.duration_month_singular_label,
            translations.duration_month_plural_label,
        ),
        (
            86_400_i64,
            translations.duration_day_singular_label,
            translations.duration_day_plural_label,
        ),
        (
            3_600_i64,
            translations.duration_hour_singular_label,
            translations.duration_hour_plural_label,
        ),
        (
            60_i64,
            translations.duration_minute_singular_label,
            translations.duration_minute_plural_label,
        ),
        (
            1_i64,
            translations.duration_second_singular_label,
            translations.duration_second_plural_label,
        ),
    ];

    let mut remaining = total_seconds;
    let mut parts = Vec::new();
    for (unit_seconds, singular_label, plural_label) in units {
        if remaining < unit_seconds {
            continue;
        }
        let value = remaining / unit_seconds;
        remaining %= unit_seconds;
        let label = if value == 1 {
            singular_label
        } else {
            plural_label
        };
        parts.push(match language {
            Language::En => format!("{value} {label}"),
            Language::ZhCn => format!("{value}{label}"),
        });
        if parts.len() == 2 {
            break;
        }
    }

    if parts.is_empty() {
        translations.duration_zero_label.to_owned()
    } else {
        parts.join(" ")
    }
}

pub(crate) fn registration_policy_value(policy: RegistrationPolicy) -> &'static str {
    match policy {
        RegistrationPolicy::AlwaysPublic => "always_public",
        RegistrationPolicy::AdminOnly => "admin_only",
        RegistrationPolicy::AdminSelectable => "admin_selectable",
    }
}

pub(crate) fn parse_registration_policy(raw: &str) -> RegistrationPolicy {
    match raw {
        "always_public" => RegistrationPolicy::AlwaysPublic,
        "admin_selectable" => RegistrationPolicy::AdminSelectable,
        _ => RegistrationPolicy::AdminOnly,
    }
}

pub(crate) fn registration_policy_options(language: Language) -> Vec<SelectOption> {
    let translations = language.translations();
    vec![
        SelectOption {
            value: "admin_only",
            label: translations.registration_policy_admin_only_label.to_owned(),
        },
        SelectOption {
            value: "admin_selectable",
            label: translations
                .registration_policy_admin_selectable_label
                .to_owned(),
        },
        SelectOption {
            value: "always_public",
            label: translations
                .registration_policy_always_public_label
                .to_owned(),
        },
    ]
}

pub(crate) fn enforcement_mode_value(mode: EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::AdminExempt => "admin_exempt",
        EnforcementMode::Disabled => "disabled",
        EnforcementMode::AllUsers => "all_users",
    }
}

pub(crate) fn parse_enforcement_mode(raw: &str) -> EnforcementMode {
    match raw {
        "admin_exempt" => EnforcementMode::AdminExempt,
        "disabled" => EnforcementMode::Disabled,
        _ => EnforcementMode::AllUsers,
    }
}

pub(crate) fn enforcement_mode_options(language: Language) -> Vec<SelectOption> {
    let translations = language.translations();
    vec![
        SelectOption {
            value: "all_users",
            label: translations.enforcement_mode_all_users_label.to_owned(),
        },
        SelectOption {
            value: "admin_exempt",
            label: translations.enforcement_mode_admin_exempt_label.to_owned(),
        },
        SelectOption {
            value: "disabled",
            label: translations.enforcement_mode_disabled_label.to_owned(),
        },
    ]
}

pub(crate) fn ban_duration_options(language: Language) -> Vec<SelectOption> {
    let translations = language.translations();
    vec![
        SelectOption {
            value: "seconds",
            label: translations.admin_ban_unit_seconds_label.to_owned(),
        },
        SelectOption {
            value: "minutes",
            label: translations.admin_ban_unit_minutes_label.to_owned(),
        },
        SelectOption {
            value: "hours",
            label: translations.admin_ban_unit_hours_label.to_owned(),
        },
        SelectOption {
            value: "days",
            label: translations.admin_ban_unit_days_label.to_owned(),
        },
        SelectOption {
            value: "months",
            label: translations.admin_ban_unit_months_label.to_owned(),
        },
        SelectOption {
            value: "years",
            label: translations.admin_ban_unit_years_label.to_owned(),
        },
        SelectOption {
            value: "permanent",
            label: translations.admin_ban_unit_permanent_label.to_owned(),
        },
    ]
}

pub(crate) fn parse_ban_duration_unit(raw: &str) -> Option<BanDurationUnit> {
    match raw.trim() {
        "seconds" => Some(BanDurationUnit::Seconds),
        "minutes" => Some(BanDurationUnit::Minutes),
        "hours" => Some(BanDurationUnit::Hours),
        "days" => Some(BanDurationUnit::Days),
        "months" => Some(BanDurationUnit::Months),
        "years" => Some(BanDurationUnit::Years),
        "permanent" => Some(BanDurationUnit::Permanent),
        _ => None,
    }
}

pub(crate) fn parse_ban_expires_at(
    duration_value_raw: &str,
    duration_unit_raw: &str,
) -> Result<Option<i64>> {
    let Some(unit) = parse_ban_duration_unit(duration_unit_raw) else {
        anyhow::bail!("invalid ban duration unit");
    };
    if unit == BanDurationUnit::Permanent {
        return Ok(None);
    }

    let duration_value = duration_value_raw
        .trim()
        .parse::<u32>()
        .context("invalid ban duration value")?;
    anyhow::ensure!(duration_value > 0, "ban duration must be greater than 0");

    let now = Utc::now();
    let until = match unit {
        BanDurationUnit::Seconds => {
            now.checked_add_signed(TimeDelta::seconds(i64::from(duration_value)))
        }
        BanDurationUnit::Minutes => {
            now.checked_add_signed(TimeDelta::minutes(i64::from(duration_value)))
        }
        BanDurationUnit::Hours => {
            now.checked_add_signed(TimeDelta::hours(i64::from(duration_value)))
        }
        BanDurationUnit::Days => now.checked_add_signed(TimeDelta::days(i64::from(duration_value))),
        BanDurationUnit::Months => now.checked_add_months(Months::new(duration_value)),
        BanDurationUnit::Years => {
            now.checked_add_months(Months::new(duration_value.saturating_mul(12)))
        }
        BanDurationUnit::Permanent => Some(now),
    };

    until
        .map(|value| Some(value.timestamp()))
        .context("ban duration is out of supported range")
}

pub(crate) fn normalize_optional_text(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(crate) fn selected_option_label(options: &[SelectOption], value: &str) -> String {
    options
        .iter()
        .find(|option| option.value == value)
        .map(|option| option.label.clone())
        .unwrap_or_else(|| value.to_owned())
}

pub(crate) fn normalized_bot_settings(
    mut settings: BotNotificationSettings,
) -> BotNotificationSettings {
    settings.bot_token = settings.bot_token.trim().to_owned();
    settings.chat_id = settings.chat_id.trim().to_owned();
    settings.template = if settings.template.trim().is_empty() {
        String::from(DEFAULT_BOT_TEMPLATE)
    } else {
        settings.template.trim().to_owned()
    };
    settings
}

pub(crate) fn bot_settings_ready(settings: &BotNotificationSettings) -> bool {
    settings.enabled && !settings.bot_token.is_empty() && !settings.chat_id.is_empty()
}

pub(crate) fn configured_telegram_api(settings: &SystemSettings) -> Option<TelegramApiSettings> {
    let api_id = settings.telegram_api.api_id?;
    let api_hash = settings.telegram_api.api_hash.trim();
    if api_id <= 0 || api_hash.is_empty() {
        return None;
    }

    Some(TelegramApiSettings {
        api_id: Some(api_id),
        api_hash: api_hash.to_owned(),
    })
}

pub(crate) fn parse_telegram_api_settings(
    api_id_raw: &str,
    api_hash_raw: &str,
) -> Result<TelegramApiSettings> {
    let api_id = match api_id_raw.trim() {
        "" => None,
        raw => {
            let parsed = raw
                .parse::<i32>()
                .with_context(|| format!("invalid Telegram API ID value: {raw}"))?;
            anyhow::ensure!(parsed > 0, "Telegram API ID must be greater than 0");
            Some(parsed)
        }
    };
    let api_hash = api_hash_raw.trim().to_owned();

    anyhow::ensure!(
        api_id.is_some() == !api_hash.is_empty(),
        "Telegram API ID and API hash must be filled together"
    );

    Ok(TelegramApiSettings { api_id, api_hash })
}

pub(crate) fn telegram_api_status_summary(settings: &SystemSettings, language: Language) -> String {
    let translations = language.translations();
    if configured_telegram_api(settings).is_some() {
        translations.status_configured_label.to_owned()
    } else {
        translations.status_not_configured_label.to_owned()
    }
}

pub(crate) fn telegram_api_missing_message(language: Language) -> &'static str {
    language.translations().telegram_api_missing_message
}

pub(crate) fn bot_status_summary(settings: &BotNotificationSettings, language: Language) -> String {
    let settings = normalized_bot_settings(settings.clone());
    let translations = language.translations();
    if settings.enabled {
        translations.bot_status_enabled.to_owned()
    } else {
        translations.bot_status_disabled.to_owned()
    }
}

pub(crate) fn bot_destination_summary(
    settings: &BotNotificationSettings,
    language: Language,
) -> String {
    let settings = normalized_bot_settings(settings.clone());
    if settings.bot_token.is_empty() || settings.chat_id.is_empty() {
        return language
            .translations()
            .status_not_configured_label
            .to_owned();
    }

    settings.chat_id.clone()
}

pub(crate) fn template_preview(template: &str, max_chars: usize) -> String {
    let normalized = template.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.chars().count() <= max_chars {
        return normalized;
    }

    let preview = normalized.chars().take(max_chars).collect::<String>();
    format!("{preview}...")
}

pub(crate) fn effective_idle_timeout_minutes(
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

pub(crate) fn format_idle_timeout_label(
    idle_timeout_minutes: Option<u32>,
    language: Language,
) -> String {
    let translations = language.translations();
    match idle_timeout_minutes {
        Some(0) => translations.idle_timeout_never_sign_out_label.to_owned(),
        Some(minutes) => translations
            .idle_timeout_minutes_label
            .replace("{minutes}", &minutes.to_string()),
        None => translations
            .idle_timeout_use_system_default_label
            .to_owned(),
    }
}

pub(crate) fn parse_user_idle_timeout_preference(
    raw: &str,
    settings: &SystemSettings,
) -> Result<Option<u32>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let minutes = trimmed
        .parse::<u32>()
        .with_context(|| format!("invalid idle timeout value: {trimmed}"))?;
    if minutes == 0 {
        anyhow::ensure!(
            settings.max_idle_timeout_minutes.is_none(),
            "the current system policy does not allow permanent sign-in sessions"
        );
    }

    Ok(Some(minutes))
}

pub(crate) fn parse_admin_idle_timeout_cap(raw: &str) -> Result<Option<u32>> {
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

pub(crate) async fn registration_page_allowed(
    store: &MetaStore,
    settings: &SystemSettings,
) -> bool {
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

pub(crate) async fn registration_submit_allowed(
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

pub(crate) fn set_cookie_header(value: &str) -> Result<HeaderValue, StatusCode> {
    HeaderValue::from_str(value).map_err(|_| {
        warn!("failed encoding Set-Cookie header");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

pub(crate) fn detect_language(headers: &HeaderMap, query_lang: Option<&str>) -> Language {
    let accept_language = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok());
    if let Some(language) = query_lang.and_then(Language::parse) {
        return language;
    }
    if let Some(language) = find_cookie(headers, LANGUAGE_COOKIE_NAME).and_then(Language::parse) {
        return language;
    }
    Language::detect(None, accept_language)
}

pub(crate) fn build_transport_security_warning(
    language: Language,
    headers: &HeaderMap,
) -> Option<TransportSecurityWarning> {
    if request_uses_https(headers) {
        return None;
    }

    let translations = language.translations();
    Some(TransportSecurityWarning {
        title: translations.transport_warning_title.to_owned(),
        message: translations.transport_warning_message.to_owned(),
    })
}

pub(crate) fn insert_transport_security_warning(
    context: &mut Context,
    language: Language,
    headers: &HeaderMap,
) {
    context.insert(
        "transport_warning",
        &build_transport_security_warning(language, headers),
    );
}

pub(crate) fn render_template(
    tera: &Tera,
    template_name: &str,
    context: &Context,
) -> std::result::Result<Html<String>, StatusCode> {
    tera.render(template_name, context)
        .map(Html)
        .map_err(|error| {
            warn!("failed rendering {template_name}: {error}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

pub(crate) fn current_status_label(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Connecting => "connecting",
        SessionStatus::Connected => "connected",
        SessionStatus::Error(_) => "error",
    }
}

pub(crate) fn build_bot_settings_view(
    settings: &BotNotificationSettings,
) -> BotNotificationSettingsView {
    let settings = normalized_bot_settings(settings.clone());
    BotNotificationSettingsView {
        enabled: settings.enabled,
        bot_token: settings.bot_token.clone(),
        chat_id: settings.chat_id.clone(),
        template: settings.template.clone(),
    }
}

pub(crate) fn build_bot_placeholder_hints(language: Language) -> [BotPlaceholderHint; 7] {
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

pub(crate) fn render_qr_svg(data: &str) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ban_expires_at_accepts_permanent_without_value() {
        assert_eq!(
            parse_ban_expires_at("", "permanent").expect("permanent ban should parse"),
            None
        );
    }

    #[test]
    fn parse_ban_expires_at_rejects_zero_length() {
        assert!(parse_ban_expires_at("0", "minutes").is_err());
    }

    #[test]
    fn login_template_renders_with_login_page_context() {
        let mut tera = Tera::default();
        tera.add_raw_templates(EMBEDDED_TEMPLATES)
            .expect("embedded templates should load");

        let language = Language::ZhCn;
        let translations = language.translations();
        let mut context = Context::new();
        context.insert("lang", &language.code());
        context.insert("i18n", translations);
        context.insert("languages", &language_options(language, "/login"));
        context.insert("error_message", &Option::<String>::None);
        context.insert("show_register", &true);
        context.insert("register_href", "/register");
        context.insert("register_label", &translations.register_title);
        context.insert("mfa_label", &translations.login_mfa_label);
        context.insert("recovery_label", &translations.login_recovery_label);
        context.insert("mfa_hint", &translations.login_mfa_hint);
        context.insert("ready_label", &translations.login_ready_label);
        context.insert(
            "recovery_toggle_label",
            &translations.login_recovery_toggle_label,
        );
        context.insert(
            "recovery_back_label",
            &translations.login_recovery_back_label,
        );
        context.insert("passkey_label", &translations.login_passkey_label);
        context.insert("passkey_hint", &translations.login_passkey_hint);
        context.insert("passkey_supported", &true);
        context.insert("passkey_unavailable_message", "");
        context.insert(
            "transport_warning",
            &Option::<TransportSecurityWarning>::None,
        );

        let rendered = tera
            .render("login.html", &context)
            .expect("login template should render");

        assert!(rendered.contains(translations.login_title));
        assert!(rendered.contains(translations.login_password_tab_label));
    }

    #[test]
    fn register_template_renders_with_register_page_context() {
        let mut tera = Tera::default();
        tera.add_raw_templates(EMBEDDED_TEMPLATES)
            .expect("embedded templates should load");

        let language = Language::ZhCn;
        let translations = language.translations();
        let mut context = Context::new();
        context.insert("lang", &language.code());
        context.insert("i18n", translations);
        context.insert("languages", &language_options(language, "/register"));
        context.insert("error_message", &Option::<String>::None);
        context.insert(
            "transport_warning",
            &Option::<TransportSecurityWarning>::None,
        );

        let rendered = tera
            .render("register.html", &context)
            .expect("register template should render");

        assert!(rendered.contains(translations.register_title));
        assert!(rendered.contains(translations.register_submit_label));
    }

    #[test]
    fn dashboard_template_renders_unicode_session_cards() {
        let mut tera = Tera::default();
        tera.add_raw_templates(EMBEDDED_TEMPLATES)
            .expect("embedded templates should load");

        let language = Language::ZhCn;
        let translations = language.translations();
        let sessions = vec![DashboardSessionView {
            id: String::from("session-1"),
            key: String::from("会话 🚀 España العربية"),
            note: String::from("用于测试复制卡片"),
            phone: String::from("+86 138 0000 0000"),
            masked_phone: String::from("+86 138 **** 0000"),
            session_file: String::from("sessions/session-1.session"),
            status: DashboardStatusView {
                kind: "connected",
                connected: true,
                error: None,
            },
            latest_code: Some(String::from("123456")),
            latest_message_at: Some(String::from("2026-03-14 09:00:00 UTC")),
            latest_code_at_unix: Some(1_773_486_000),
            recent_messages: vec![DashboardMessageView {
                received_at: String::from("2026-03-14 09:00:00 UTC"),
                text: String::from("Telegram code: 123456"),
                code: Some(String::from("123456")),
            }],
        }];

        let mut context = Context::new();
        context.insert("lang", &language.code());
        context.insert("i18n", translations);
        context.insert("languages", &language_options(language, "/"));
        context.insert("current_username", "alice");
        context.insert("show_admin", &false);
        context.insert("logout_action", "/logout");
        context.insert("setup_href", "/sessions/new");
        context.insert("settings_href", "/settings");
        context.insert("admin_href", "/admin");
        context.insert("settings_label", &translations.nav_settings_label);
        context.insert("admin_label", &translations.nav_admin_label);
        context.insert("settings_security_href", "/settings#security");
        context.insert("settings_notifications_href", "/settings#notifications");
        context.insert("settings_access_href", "/settings#access");
        context.insert("admin_overview_href", "/admin#users");
        context.insert("banner", &Option::<PageBanner>::None);
        context.insert("sessions", &sessions);
        context.insert("attention_sessions", &Vec::<DashboardSessionView>::new());
        context.insert("recent_activity_sessions", &sessions);
        context.insert("total_sessions", &1);
        context.insert("connected_count", &1);
        context.insert("connecting_count", &0);
        context.insert("error_count", &0);
        context.insert("attention_count", &0);
        context.insert("now", "2026-03-14 09:00:00 UTC");
        context.insert("snapshot_api", "/api/dashboard/snapshot");
        context.insert("dashboard_incremental_refresh_seconds", &3_u64);
        context.insert("dashboard_full_refresh_seconds", &30_u64);
        context.insert(
            "transport_warning",
            &Option::<TransportSecurityWarning>::None,
        );

        let rendered = tera
            .render("index.html", &context)
            .expect("dashboard template should render");

        assert!(rendered.contains("会话 🚀 España العربية"));
        assert!(rendered.contains("data-role=\"copy-code-chip\""));
        assert!(rendered.contains("copyDashboardCode(this)"));
    }
}
