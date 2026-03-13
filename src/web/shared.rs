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
pub(crate) use chrono::{DateTime, Utc};
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

pub(crate) use hanagram_web::account_reset::reset_user_account;
pub(crate) use hanagram_web::security::{
    EncryptedBlob, EnforcementMode, MasterKey, RegistrationPolicy, SensitiveBytes, SharedMasterKey,
    SharedSensitiveBytes, SharedSensitiveString, TotpVerification, decrypt_bytes, encrypt_bytes,
    evaluate_password_strength, hash_session_token, into_sensitive_bytes, share_master_key,
    share_sensitive_bytes, verify_totp,
};
pub(crate) use hanagram_web::store::{
    AuthSessionRecord, BotNotificationSettings, MetaStore, NewAuditEntry, SessionRecord,
    SystemSettings, TelegramApiSettings, UserRole,
};

pub(crate) use super::runtime_cache::{RuntimeCache, RuntimeCacheHandle};
pub(crate) use crate::i18n::{Language, language_options};
pub(crate) use crate::session_handler::{
    LoadedSession, export_sqlite_session_bytes, export_telethon_string_session, load_session,
    load_telethon_string_session, serialize_session,
};
pub(crate) use crate::state::{
    OtpMessage, SessionInfo, SessionNotificationContext, SessionStatus, SharedState,
};
pub(crate) use crate::web_auth::{
    AUTH_COOKIE_NAME, AuthenticatedSession, LoginError, RegistrationResult, build_auth_cookie,
    build_totp_setup_material, clear_auth_cookie, effective_auth_cookie_secure, extract_client_ip,
    extract_user_agent, find_cookie, initialize_user_credentials, normalize_username,
    request_uses_https, resolve_authenticated_session,
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
    pub(crate) unlock_cache: UnlockCache,
    pub(crate) user_keys: UserKeyCache,
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
pub(crate) struct DashboardSnapshot {
    pub(crate) connected_count: usize,
    pub(crate) generated_at: String,
    pub(crate) sessions: Vec<SessionInfo>,
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
    pub(crate) locked: bool,
    pub(crate) totp_enabled: bool,
    pub(crate) password_ready: bool,
    pub(crate) active_sessions: usize,
    pub(crate) recovery_codes_remaining: i64,
    pub(crate) last_login_ip: Option<String>,
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
pub(crate) struct LoginForm {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) mfa_code: Option<String>,
    pub(crate) recovery_code: Option<String>,
    pub(crate) lang: Option<String>,
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
    pub(crate) code: String,
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

#[derive(Debug, Default, Deserialize)]
pub(crate) struct FlowPageQuery {
    pub(crate) lang: Option<String>,
    pub(crate) error: Option<String>,
}

pub(crate) fn login_redirect_target(language: Language) -> String {
    format!("/?lang={}", language.code())
}

pub(crate) fn dashboard_href(language: Language) -> String {
    format!("/?lang={}", language.code())
}

pub(crate) fn setup_href(language: Language) -> String {
    format!("/sessions/new?lang={}", language.code())
}

pub(crate) fn settings_href(language: Language) -> String {
    format!("/settings?lang={}", language.code())
}

pub(crate) fn notifications_href(language: Language) -> String {
    format!("/settings/notifications?lang={}", language.code())
}

pub(crate) fn admin_href(language: Language) -> String {
    format!("/admin?lang={}", language.code())
}

pub(crate) fn format_unix_timestamp(unix: i64) -> String {
    match DateTime::from_timestamp(unix, 0) {
        Some(datetime) => datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => String::from("-"),
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
    match language {
        Language::En => vec![
            SelectOption {
                value: "admin_only",
                label: String::from("Admin Only"),
            },
            SelectOption {
                value: "admin_selectable",
                label: String::from("Admin Toggle"),
            },
            SelectOption {
                value: "always_public",
                label: String::from("Always Public"),
            },
        ],
        Language::ZhCn => vec![
            SelectOption {
                value: "admin_only",
                label: String::from("仅管理员创建"),
            },
            SelectOption {
                value: "admin_selectable",
                label: String::from("管理员可切换开放"),
            },
            SelectOption {
                value: "always_public",
                label: String::from("始终开放注册"),
            },
        ],
    }
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
    match language {
        Language::En => vec![
            SelectOption {
                value: "all_users",
                label: String::from("All Users"),
            },
            SelectOption {
                value: "admin_exempt",
                label: String::from("Admins Exempt"),
            },
            SelectOption {
                value: "disabled",
                label: String::from("Disabled"),
            },
        ],
        Language::ZhCn => vec![
            SelectOption {
                value: "all_users",
                label: String::from("所有用户"),
            },
            SelectOption {
                value: "admin_exempt",
                label: String::from("管理员豁免"),
            },
            SelectOption {
                value: "disabled",
                label: String::from("关闭"),
            },
        ],
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
    if configured_telegram_api(settings).is_some() {
        match language {
            Language::En => String::from("Configured"),
            Language::ZhCn => String::from("已配置"),
        }
    } else {
        match language {
            Language::En => String::from("Not configured"),
            Language::ZhCn => String::from("未配置"),
        }
    }
}

pub(crate) fn telegram_api_missing_message(language: Language) -> &'static str {
    match language {
        Language::En => {
            "Telegram API credentials are not configured yet. Ask the admin to save API ID and API hash first."
        }
        Language::ZhCn => "Telegram API 凭据还没有配置，请先让管理员保存 API ID 和 API Hash。",
    }
}

pub(crate) fn bot_status_summary(settings: &BotNotificationSettings, language: Language) -> String {
    let settings = normalized_bot_settings(settings.clone());
    if settings.enabled {
        match language {
            Language::En => String::from("Enabled"),
            Language::ZhCn => String::from("已启用"),
        }
    } else {
        match language {
            Language::En => String::from("Disabled"),
            Language::ZhCn => String::from("已关闭"),
        }
    }
}

pub(crate) fn bot_destination_summary(
    settings: &BotNotificationSettings,
    language: Language,
) -> String {
    let settings = normalized_bot_settings(settings.clone());
    if settings.bot_token.is_empty() || settings.chat_id.is_empty() {
        return match language {
            Language::En => String::from("Not configured"),
            Language::ZhCn => String::from("未配置"),
        };
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
    Language::detect(query_lang, accept_language)
}

pub(crate) fn build_transport_security_warning(
    language: Language,
    headers: &HeaderMap,
) -> Option<TransportSecurityWarning> {
    if request_uses_https(headers) {
        return None;
    }

    Some(TransportSecurityWarning {
        title: match language {
            Language::En => String::from("Plain HTTP is in use"),
            Language::ZhCn => String::from("当前正在使用明文 HTTP"),
        },
        message: match language {
            Language::En => String::from(
                "Passwords, TOTP codes, recovery codes, bot tokens, Telegram API credentials, and session management requests can be intercepted or modified in transit. Only use plain HTTP for temporary local testing. For shared or public access, enable HTTPS directly or place Hanagram Web behind an HTTPS reverse proxy that forwards proto=https.",
            ),
            Language::ZhCn => String::from(
                "密码、TOTP 动态码、恢复码、Bot Token、Telegram API 凭据以及会话管理请求都可能在传输过程中被窃听或篡改。明文 HTTP 只建议用于本机临时调试；如果要给局域网或公网使用，请启用 HTTPS，或者放在 HTTPS 反向代理后面并正确转发 proto=https。",
            ),
        },
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
