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
    Client, InvocationError, SenderPool, SignInError,
    sender::{ConnectionParams, SenderPoolFatHandle},
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
    SystemSettings, UserRecord, UserRole,
};

pub(crate) use super::platform_key;
pub(crate) use super::runtime_cache::{RuntimeCache, RuntimeCacheHandle};
pub(crate) use crate::i18n::{Language, language_options};
pub(crate) use crate::platforms::telegram::{
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
pub(crate) const TELEGRAM_WORKSPACE_INCREMENTAL_SYNC_SECONDS: u64 = 3;
pub(crate) const TELEGRAM_WORKSPACE_FULL_SYNC_SECONDS: u64 = 30;
pub(crate) const TELEGRAM_OTP_VISIBILITY_SECONDS: i64 = 600;
pub(crate) const TELEGRAM_WORKSPACE_PATH: &str = "/platforms/telegram";
pub(crate) const STEAM_WORKSPACE_PATH: &str = "/platforms/steam";
pub(crate) const STEAM_SNAPSHOT_API_PATH: &str = "/api/platforms/steam/snapshot";
pub(crate) const STEAM_CONFIRMATIONS_API_PATH: &str = "/api/platforms/steam/confirmations";
pub(crate) const STEAM_APPROVALS_API_PATH: &str = "/api/platforms/steam/approvals";
pub(crate) const STEAM_IMPORT_UPLOAD_PATH: &str = "/platforms/steam/import/upload";
pub(crate) const STEAM_IMPORT_MANUAL_PATH: &str = "/platforms/steam/import/manual";
pub(crate) const STEAM_IMPORT_LOGIN_PATH: &str = "/platforms/steam/import/login";
pub(crate) const STEAM_APPROVAL_CHALLENGE_PATH: &str = "/platforms/steam/approvals/challenge";
pub(crate) const STEAM_APPROVAL_CHALLENGE_UPLOAD_PATH: &str =
    "/platforms/steam/approvals/challenge/upload";
pub(crate) const TELEGRAM_SETUP_PATH: &str = "/platforms/telegram/setup";
pub(crate) const TELEGRAM_IMPORT_STRING_PATH: &str = "/platforms/telegram/import/string";
pub(crate) const TELEGRAM_IMPORT_UPLOAD_PATH: &str = "/platforms/telegram/import/upload";
pub(crate) const TELEGRAM_PHONE_LOGIN_PATH: &str = "/platforms/telegram/login/phone";
pub(crate) const TELEGRAM_QR_LOGIN_PATH: &str = "/platforms/telegram/login/qr";
pub(crate) const TELEGRAM_SNAPSHOT_API_PATH: &str = "/api/platforms/telegram/snapshot";
pub(crate) const META_DB_FILE_NAME: &str = "app.db";
pub(crate) const DEFAULT_BOT_TEMPLATE: &str = "Hanagram OTP Alert\n\nAccount: {phone}\nSession: {session_key}\nCode: {code}\nReceived: {received_at}\nStatus: {status}\nSession file: {session_file}\n\nMessage:\n{message}";
pub(crate) const SESSION_KEY_PREFIX: &str = "hanagram-session-key:v1:";
pub(crate) const SESSION_NOTE_PREFIX: &str = "hanagram-note:v1:";
pub(crate) const TELEGRAM_WEBK_API_ID: i32 = 2496;
pub(crate) const TELEGRAM_WEBK_API_HASH: &str = "8da85b0d5bfe62527e5b244c209159c3";
pub(crate) const TELEGRAM_WEBK_DEVICE_MODEL: &str =
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0";
pub(crate) const TELEGRAM_WEBK_SYSTEM_VERSION: &str = "Win32";
pub(crate) const TELEGRAM_WEBK_APP_VERSION: &str = "6.1.4 K";
pub(crate) const TELEGRAM_WEBK_SYSTEM_LANG_CODE: &str = "en-US";
pub(crate) const TELEGRAM_WEBK_LANG_CODE: &str = "en";
pub(crate) const TELEGRAM_WEBK_LANG_PACK: &str = "webk";
pub(crate) const EMBEDDED_TEMPLATES: [(&str, &str); 12] = [
    ("admin.html", include_str!("../../templates/admin.html")),
    (
        "dashboard_home.html",
        include_str!("../../templates/dashboard_home.html"),
    ),
    (
        "telegram_workspace.html",
        include_str!("../../templates/telegram_workspace.html"),
    ),
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
        "steam_workspace.html",
        include_str!("../../templates/steam_workspace.html"),
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
pub(crate) type SessionLoginThrottle = Arc<Mutex<HashMap<String, i64>>>;

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
    pub(crate) session_login_throttle: SessionLoginThrottle,
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
    pub(crate) pending_state: Option<QrPendingState>,
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

#[derive(Clone, Debug)]
pub(crate) struct TelegramClientProfile {
    pub(crate) api_id: i32,
    pub(crate) api_hash: String,
}

impl TelegramClientProfile {
    pub(crate) fn connection_params(&self) -> ConnectionParams {
        ConnectionParams {
            device_model: String::from(TELEGRAM_WEBK_DEVICE_MODEL),
            system_version: String::from(TELEGRAM_WEBK_SYSTEM_VERSION),
            app_version: String::from(TELEGRAM_WEBK_APP_VERSION),
            system_lang_code: String::from(TELEGRAM_WEBK_SYSTEM_LANG_CODE),
            lang_code: String::from(TELEGRAM_WEBK_LANG_CODE),
            lang_pack: String::from(TELEGRAM_WEBK_LANG_PACK),
            ..Default::default()
        }
    }
}

impl TelegramClientSession {
    pub(crate) fn open(session: LoadedSession, profile: &TelegramClientProfile) -> Self {
        let session = Arc::new(session);
        let SenderPool {
            runner,
            handle: pool_handle,
            updates: _,
        } = SenderPool::with_configuration(
            Arc::clone(&session),
            profile.api_id,
            profile.connection_params(),
        );
        let client = Client::new(pool_handle.clone());
        let pool_task = tokio::spawn(runner.run());

        Self {
            client,
            session,
            pool_handle,
            pool_task,
        }
    }

    pub(crate) fn open_empty(profile: &TelegramClientProfile) -> Self {
        Self::open(LoadedSession::default(), profile)
    }

    pub(crate) fn open_serialized(
        session_data: &[u8],
        profile: &TelegramClientProfile,
    ) -> Result<Self> {
        let load =
            load_session(session_data).context("failed to load serialized session snapshot")?;
        Ok(Self::open(load.session, profile))
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
pub(crate) struct TelegramWorkspaceStatusView {
    pub(crate) kind: &'static str,
    pub(crate) connected: bool,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TelegramWorkspaceMessageView {
    pub(crate) received_at: String,
    pub(crate) text: String,
    pub(crate) code: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TelegramWorkspaceSessionView {
    pub(crate) id: String,
    pub(crate) key: String,
    pub(crate) note: String,
    pub(crate) phone: String,
    pub(crate) masked_phone: String,
    pub(crate) session_file: String,
    pub(crate) status: TelegramWorkspaceStatusView,
    pub(crate) latest_code: Option<String>,
    pub(crate) latest_message_at: Option<String>,
    pub(crate) latest_code_at_unix: Option<i64>,
    pub(crate) latest_code_expires_at_unix: Option<i64>,
    pub(crate) recent_messages: Vec<TelegramWorkspaceMessageView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TelegramWorkspaceSnapshot {
    pub(crate) total_count: usize,
    pub(crate) connected_count: usize,
    pub(crate) connecting_count: usize,
    pub(crate) error_count: usize,
    pub(crate) generated_at: String,
    pub(crate) sessions: Vec<TelegramWorkspaceSessionView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PlatformWorkspaceCardView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) total_count: usize,
    pub(crate) connected_count: usize,
    pub(crate) attention_count: usize,
    pub(crate) workspace_href: String,
    pub(crate) secondary_href: String,
    pub(crate) secondary_label: String,
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

#[derive(Clone)]
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
    pub(crate) wait_seconds: Option<u32>,
}

pub(crate) fn login_redirect_target(language: Language) -> String {
    let _ = language;
    String::from("/")
}

pub(crate) fn dashboard_href(language: Language) -> String {
    let _ = language;
    String::from("/")
}

pub(crate) fn telegram_setup_href(language: Language) -> String {
    let _ = language;
    String::from(TELEGRAM_SETUP_PATH)
}

pub(crate) fn telegram_workspace_href(language: Language) -> String {
    let _ = language;
    String::from(TELEGRAM_WORKSPACE_PATH)
}

pub(crate) fn steam_workspace_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_WORKSPACE_PATH)
}

pub(crate) fn steam_snapshot_api_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_SNAPSHOT_API_PATH)
}

pub(crate) fn steam_import_upload_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_IMPORT_UPLOAD_PATH)
}

pub(crate) fn steam_import_manual_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_IMPORT_MANUAL_PATH)
}

pub(crate) fn steam_confirmations_api_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_CONFIRMATIONS_API_PATH)
}

pub(crate) fn steam_approvals_api_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_APPROVALS_API_PATH)
}

pub(crate) fn steam_import_login_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_IMPORT_LOGIN_PATH)
}

pub(crate) fn steam_approval_challenge_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_APPROVAL_CHALLENGE_PATH)
}

pub(crate) fn steam_approval_challenge_upload_href(language: Language) -> String {
    let _ = language;
    String::from(STEAM_APPROVAL_CHALLENGE_UPLOAD_PATH)
}

pub(crate) fn telegram_snapshot_api_href(language: Language) -> String {
    let _ = language;
    String::from(TELEGRAM_SNAPSHOT_API_PATH)
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

pub(crate) fn configured_telegram_client_profile() -> TelegramClientProfile {
    TelegramClientProfile {
        api_id: TELEGRAM_WEBK_API_ID,
        api_hash: String::from(TELEGRAM_WEBK_API_HASH),
    }
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
    fn telegram_workspace_template_renders_unicode_session_cards() {
        let mut tera = Tera::default();
        tera.add_raw_templates(EMBEDDED_TEMPLATES)
            .expect("embedded templates should load");

        let language = Language::ZhCn;
        let translations = language.translations();
        let sessions = vec![TelegramWorkspaceSessionView {
            id: String::from("session-1"),
            key: String::from("会话 🚀 España العربية"),
            note: String::from("用于测试复制卡片"),
            phone: String::from("+86 138 0000 0000"),
            masked_phone: String::from("+86 138 **** 0000"),
            session_file: String::from("sessions/session-1.session"),
            status: TelegramWorkspaceStatusView {
                kind: "connected",
                connected: true,
                error: None,
            },
            latest_code: Some(String::from("123456")),
            latest_message_at: Some(String::from("2026-03-14 09:00:00 UTC")),
            latest_code_at_unix: Some(1_773_486_000),
            latest_code_expires_at_unix: Some(1_773_486_120),
            recent_messages: vec![TelegramWorkspaceMessageView {
                received_at: String::from("2026-03-14 09:00:00 UTC"),
                text: String::from("Telegram code: 123456"),
                code: Some(String::from("123456")),
            }],
        }];

        let mut context = Context::new();
        context.insert("lang", &language.code());
        context.insert("i18n", translations);
        context.insert(
            "languages",
            &language_options(language, TELEGRAM_WORKSPACE_PATH),
        );
        context.insert("current_username", "alice");
        context.insert("show_admin", &false);
        context.insert("logout_action", "/logout");
        context.insert("dashboard_href", "/");
        context.insert("setup_href", TELEGRAM_SETUP_PATH);
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
        context.insert(
            "attention_sessions",
            &Vec::<TelegramWorkspaceSessionView>::new(),
        );
        context.insert("recent_activity_sessions", &sessions);
        context.insert("total_sessions", &1);
        context.insert("connected_count", &1);
        context.insert("connecting_count", &0);
        context.insert("error_count", &0);
        context.insert("attention_count", &0);
        context.insert("now", "2026-03-14 09:00:00 UTC");
        context.insert("snapshot_api", TELEGRAM_SNAPSHOT_API_PATH);
        context.insert("telegram_workspace_incremental_refresh_seconds", &3_u64);
        context.insert("telegram_workspace_full_refresh_seconds", &30_u64);
        context.insert(
            "transport_warning",
            &Option::<TransportSecurityWarning>::None,
        );

        let rendered = tera
            .render("telegram_workspace.html", &context)
            .expect("telegram workspace template should render");

        assert!(rendered.contains("会话 🚀 España العربية"));
        assert!(rendered.contains("data-role=\"copy-code-chip\""));
        assert!(rendered.contains("copyWorkspaceCode(this)"));
    }

    #[test]
    fn dashboard_home_template_renders_platform_directory() {
        let mut tera = Tera::default();
        tera.add_raw_templates(EMBEDDED_TEMPLATES)
            .expect("embedded templates should load");

        let language = Language::ZhCn;
        let translations = language.translations();
        let platforms = vec![
            PlatformWorkspaceCardView {
                id: String::from("telegram"),
                name: String::from("Telegram"),
                description: String::from("独立工作区"),
                total_count: 4,
                connected_count: 3,
                attention_count: 1,
                workspace_href: String::from(TELEGRAM_WORKSPACE_PATH),
                secondary_href: String::from(TELEGRAM_SETUP_PATH),
                secondary_label: String::from(translations.dashboard_add_session),
            },
            PlatformWorkspaceCardView {
                id: String::from("steam"),
                name: String::from("Steam"),
                description: String::from("模块预留"),
                total_count: 0,
                connected_count: 0,
                attention_count: 0,
                workspace_href: String::from(STEAM_WORKSPACE_PATH),
                secondary_href: String::from("/platforms/steam#codes"),
                secondary_label: String::from(translations.steam_codes_title),
            },
        ];

        let mut context = Context::new();
        context.insert("lang", &language.code());
        context.insert("i18n", translations);
        context.insert("languages", &language_options(language, "/"));
        context.insert("current_username", "alice");
        context.insert("show_admin", &false);
        context.insert("logout_action", "/logout");
        context.insert("settings_href", "/settings");
        context.insert("admin_href", "/admin");
        context.insert("settings_label", &translations.nav_settings_label);
        context.insert("admin_label", &translations.nav_admin_label);
        context.insert("settings_security_href", "/settings#security");
        context.insert("settings_notifications_href", "/settings#notifications");
        context.insert("settings_access_href", "/settings#access");
        context.insert("admin_overview_href", "/admin#users");
        context.insert("banner", &Option::<PageBanner>::None);
        context.insert("platforms", &platforms);
        context.insert("now", "2026-03-14 09:00:00 UTC");
        context.insert(
            "transport_warning",
            &Option::<TransportSecurityWarning>::None,
        );

        let rendered = tera
            .render("dashboard_home.html", &context)
            .expect("dashboard home template should render");

        assert!(rendered.contains("Telegram"));
        assert!(rendered.contains("Steam"));
        assert!(rendered.contains(translations.dashboard_platforms_title));
        assert!(rendered.contains(translations.dashboard_open_workspace_label));
        assert!(rendered.contains(translations.steam_codes_title));
    }

    #[test]
    fn steam_workspace_template_renders_dynamic_codes_workspace() {
        let mut tera = Tera::default();
        tera.add_raw_templates(EMBEDDED_TEMPLATES)
            .expect("embedded templates should load");

        let language = Language::ZhCn;
        let translations = language.translations();

        let mut context = Context::new();
        context.insert("lang", &language.code());
        context.insert("i18n", translations);
        context.insert(
            "languages",
            &language_options(language, STEAM_WORKSPACE_PATH),
        );
        context.insert("current_username", "alice");
        context.insert("show_admin", &false);
        context.insert("logout_action", "/logout");
        context.insert("dashboard_href", "/");
        context.insert("workspace_href", STEAM_WORKSPACE_PATH);
        context.insert("settings_href", "/settings");
        context.insert("admin_href", "/admin");
        context.insert("settings_label", &translations.nav_settings_label);
        context.insert("admin_label", &translations.nav_admin_label);
        context.insert("settings_security_href", "/settings#security");
        context.insert("settings_notifications_href", "/settings#notifications");
        context.insert("settings_access_href", "/settings#access");
        context.insert("admin_overview_href", "/admin#users");
        context.insert("banner", &Option::<PageBanner>::None);
        context.insert("default_tab", "codes");
        context.insert("snapshot_api", STEAM_SNAPSHOT_API_PATH);
        context.insert("approvals_api", STEAM_APPROVALS_API_PATH);
        context.insert("confirmations_api", STEAM_CONFIRMATIONS_API_PATH);
        context.insert("steam_import_upload_action", STEAM_IMPORT_UPLOAD_PATH);
        context.insert("steam_import_manual_action", STEAM_IMPORT_MANUAL_PATH);
        context.insert("steam_import_login_action", STEAM_IMPORT_LOGIN_PATH);
        context.insert(
            "steam_approval_challenge_action",
            STEAM_APPROVAL_CHALLENGE_PATH,
        );
        context.insert(
            "steam_approval_challenge_upload_action",
            STEAM_APPROVAL_CHALLENGE_UPLOAD_PATH,
        );
        context.insert("steam_accounts_dir", "users/alice/steam");
        context.insert("steam_managed_dir", "users/alice/steam/accounts");
        context.insert("total_accounts", &1);
        context.insert("ready_accounts", &1);
        context.insert("managed_accounts", &1);
        context.insert("encrypted_accounts", &1);
        context.insert("confirmation_ready_accounts", &1);
        context.insert("issue_count", &0);
        context.insert(
            "approval_ready_accounts",
            &serde_json::json!([{
                "id": "alice.maFile",
                "account_name": "alice",
                "steam_username": "alice_steam",
            }]),
        );
        context.insert(
            "snapshot",
            &serde_json::json!({
                "total_count": 1,
                "ready_count": 1,
                "managed_count": 1,
                "encrypted_count": 1,
                "confirmation_ready_count": 1,
                "issue_count": 0,
                "generated_at": "2026-03-14 09:00:00 UTC",
                "generated_at_unix": 1_773_486_000_i64,
                "code_period_seconds": 30,
                "accounts": [{
                    "id": "alice.maFile",
                    "account_name": "alice",
                    "steam_username": "alice_steam",
                    "steam_id": "76561198000000000",
                    "storage_file": "steam/alice.maFile",
                    "current_code": "2F9J5",
                    "code_started_at_unix": 1_773_486_000_i64,
                    "code_expires_at_unix": 1_773_486_030_i64,
                    "encrypted_at_rest": true,
                    "can_manage": true,
                    "is_manual_entry": false,
                    "is_uploaded_mafile": true,
                    "is_legacy_mafile": false,
                    "has_identity_secret": true,
                    "has_confirmation_secret_material": true,
                    "has_confirmation_session": true,
                    "confirmation_ready": true,
                    "has_session_tokens": true,
                    "has_refreshable_session": true,
                    "login_approval_ready": true,
                    "imported_from": "alice.maFile",
                    "created_at": "2026-03-14 09:00:00 UTC",
                    "updated_at": "2026-03-14 09:00:00 UTC",
                    "update_material_action": "/platforms/steam/accounts/demo/materials",
                    "login_action": "/platforms/steam/accounts/demo/login",
                    "rename_action": "/platforms/steam/accounts/demo/rename",
                    "delete_action": "/platforms/steam/accounts/demo/delete"
                }],
                "issues": []
            }),
        );
        context.insert("now", "2026-03-14 09:00:00 UTC");
        context.insert(
            "transport_warning",
            &Option::<TransportSecurityWarning>::None,
        );

        let rendered = tera
            .render("steam_workspace.html", &context)
            .expect("steam workspace template should render");

        assert!(rendered.contains(translations.steam_workspace_title));
        assert!(rendered.contains(translations.steam_codes_title));
        assert!(rendered.contains("2F9J5"));
        assert!(rendered.contains("copySteamCode(this)"));
    }

    #[test]
    fn telegram_client_profile_uses_webk_fingerprint() {
        let profile = configured_telegram_client_profile();
        let params = profile.connection_params();

        assert_eq!(profile.api_id, TELEGRAM_WEBK_API_ID);
        assert_eq!(profile.api_hash, TELEGRAM_WEBK_API_HASH);
        assert_eq!(params.device_model, TELEGRAM_WEBK_DEVICE_MODEL);
        assert_eq!(params.system_version, TELEGRAM_WEBK_SYSTEM_VERSION);
        assert_eq!(params.app_version, TELEGRAM_WEBK_APP_VERSION);
        assert_eq!(params.system_lang_code, TELEGRAM_WEBK_SYSTEM_LANG_CODE);
        assert_eq!(params.lang_code, TELEGRAM_WEBK_LANG_CODE);
        assert_eq!(params.lang_pack, TELEGRAM_WEBK_LANG_PACK);
    }
}
