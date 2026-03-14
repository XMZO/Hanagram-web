// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::web_auth;

use super::auth;
use super::middleware::{
    auth_session_is_active, clear_auth_session_sensitive_state, clear_pending_flows_for_user,
    drop_user_master_key_if_no_active_sessions, sync_active_session_idle_timeouts,
};
use super::sessions;
use super::shared::*;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(admin_page_handler))
        .route("/admin/users/list", get(admin_users_list_handler))
        .route("/admin/users/create", post(admin_create_user_handler))
        .route("/admin/users/{user_id}/ban", post(admin_ban_user_handler))
        .route(
            "/admin/users/{user_id}/unban",
            post(admin_unban_user_handler),
        )
        .route(
            "/admin/users/{user_id}/unlock",
            post(admin_unlock_user_handler),
        )
        .route(
            "/admin/users/{user_id}/reset",
            post(admin_reset_user_handler),
        )
        .route(
            "/admin/users/{user_id}/delete",
            post(admin_delete_user_handler),
        )
        .route(
            "/admin/users/{user_id}/sessions/revoke",
            post(admin_revoke_user_sessions_handler),
        )
        .route("/admin/settings", post(admin_save_system_settings_handler))
}

fn admin_login_method_label(language: Language, method: Option<&str>) -> String {
    match method.unwrap_or_default() {
        web_auth::LOGIN_METHOD_PASSWORD_ONLY => {
            String::from(language.translations().login_method_password_only_label)
        }
        web_auth::LOGIN_METHOD_PASSWORD_TOTP => {
            String::from(language.translations().login_method_password_totp_label)
        }
        web_auth::LOGIN_METHOD_PASSWORD_RECOVERY => {
            String::from(language.translations().login_method_password_recovery_label)
        }
        web_auth::LOGIN_METHOD_PASSKEY | web_auth::LOGIN_METHOD_PASSWORD_PASSKEY => {
            String::from(language.translations().login_method_password_passkey_label)
        }
        _ => String::from(language.translations().login_method_unknown_label),
    }
}

fn humanize_audit_action(action_type: &str) -> String {
    action_type.replace('_', " ")
}

fn audit_detail_field(details: &serde_json::Value, key: &str) -> Option<String> {
    details.get(key).and_then(|value| match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        other => Some(other.to_string()),
    })
}

fn pretty_audit_details(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| serde_json::to_string_pretty(&value).ok())
        .unwrap_or_else(|| raw.to_owned())
}

const ADMIN_USERS_PAGE_SIZE: usize = 20;

#[derive(Clone, Debug)]
struct AdminUserSearchRecord {
    id: String,
    username: String,
    role: String,
    is_admin: bool,
    locked: bool,
    banned: bool,
    ban_reason: Option<String>,
    ban_until_unix: Option<i64>,
    totp_enabled: bool,
    password_ready: bool,
    password_reset_required: bool,
    active_sessions: usize,
    passkey_count: usize,
    last_login_ip: Option<String>,
    last_auth_method: Option<String>,
    last_auth_at_unix: Option<i64>,
    last_auth_success: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminUsersQuery {
    lang: Option<String>,
    search: Option<String>,
    page: Option<usize>,
}

#[derive(Debug, Serialize)]
struct AdminUsersPageResponse {
    items: Vec<AdminUserView>,
    total_users: usize,
    filtered_total: usize,
    page: usize,
    page_count: usize,
    page_size: usize,
}

#[derive(Debug, Serialize)]
struct AdminUsersUiConfig {
    lang: String,
    list_endpoint: String,
    filtered_label: String,
    loading_label: String,
    no_matches_label: String,
    select_user_label: String,
    page_label: String,
    previous_label: String,
    next_label: String,
    role_admin_label: String,
    role_user_label: String,
    locked_badge_label: String,
    banned_badge_label: String,
    totp_enabled_badge_label: String,
    totp_missing_badge_label: String,
    password_ready_badge_label: String,
    password_reset_badge_label: String,
    password_missing_badge_label: String,
    user_active_sessions_label: String,
    user_recovery_codes_label: String,
    user_passkeys_label: String,
    user_last_ip_label: String,
    user_last_auth_label: String,
    audit_success_label: String,
    audit_failure_label: String,
    unlock_label: String,
    ban_label: String,
    unban_label: String,
    revoke_sessions_label: String,
    reset_label: String,
    delete_label: String,
    delete_confirm_message: String,
    ban_duration_value_label: String,
    ban_duration_unit_label: String,
    ban_reason_label: String,
    ban_reason_placeholder: String,
    ban_until_label: String,
    ban_remaining_label: String,
    ban_permanent_label: String,
    ban_duration_options: Vec<SelectOption>,
}

fn audit_search_matches(log: &AuditLogView, search: &str) -> bool {
    let needle = search.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    [
        Some(log.action_type.as_str()),
        Some(log.action_label.as_str()),
        log.actor_user_id.as_deref(),
        log.actor_username.as_deref(),
        log.subject_user_id.as_deref(),
        log.subject_username.as_deref(),
        log.username.as_deref(),
        log.login_method.as_deref(),
        log.reason.as_deref(),
        log.passkey_label.as_deref(),
        log.user_agent.as_deref(),
        log.ip_address.as_deref(),
        Some(log.details_pretty.as_str()),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.to_ascii_lowercase().contains(&needle))
}

fn user_ban_remaining_label(language: Language, until_unix: i64, now: i64) -> String {
    format_duration_for_display(language, until_unix.saturating_sub(now))
}

fn latest_auth_by_user_id_from_audit_logs(
    audit_logs: &[hanagram_web::store::AuditEntry],
    language: Language,
) -> HashMap<String, (Option<String>, i64, bool)> {
    let mut latest_auth_by_user_id = HashMap::<String, (Option<String>, i64, bool)>::new();

    for log in audit_logs {
        if log.action_type != web_auth::AUTH_AUDIT_LOGIN_SUCCESS
            && log.action_type != web_auth::AUTH_AUDIT_LOGIN_FAILURE
        {
            continue;
        }

        let Some(subject_user_id) = &log.subject_user_id else {
            continue;
        };
        let parsed_details =
            serde_json::from_str::<serde_json::Value>(&log.details_json).unwrap_or_default();
        let login_method = audit_detail_field(&parsed_details, "login_method")
            .as_deref()
            .map(|method| admin_login_method_label(language, Some(method)));

        latest_auth_by_user_id
            .entry(subject_user_id.clone())
            .or_insert((login_method, log.created_at_unix, log.success));
    }

    latest_auth_by_user_id
}

fn build_active_session_count_by_user_id(
    auth_sessions: &[AuthSessionRecord],
    now: i64,
) -> (HashMap<String, usize>, usize) {
    let mut counts = HashMap::<String, usize>::new();
    let mut total_active_auth_sessions = 0_usize;

    for auth_session in auth_sessions {
        if !auth_session_is_active(auth_session, now) {
            continue;
        }
        total_active_auth_sessions += 1;
        *counts.entry(auth_session.user_id.clone()).or_default() += 1;
    }

    (counts, total_active_auth_sessions)
}

fn build_admin_user_search_records(
    users: Vec<hanagram_web::store::UserRecord>,
    active_sessions_by_user_id: &HashMap<String, usize>,
    latest_auth_by_user_id: &HashMap<String, (Option<String>, i64, bool)>,
    now: i64,
) -> Vec<AdminUserSearchRecord> {
    users
        .into_iter()
        .map(|user| {
            let active_ban = web_auth::current_ban_status(&user, now);
            let user_id = user.id.clone();
            AdminUserSearchRecord {
                id: user.id,
                username: user.username,
                role: match user.role {
                    UserRole::Admin => String::from("admin"),
                    UserRole::User => String::from("user"),
                },
                is_admin: user.role == UserRole::Admin,
                locked: user.security.locked_until_unix.unwrap_or_default() > now,
                banned: active_ban.is_some(),
                ban_reason: active_ban.as_ref().and_then(|status| status.reason.clone()),
                ban_until_unix: active_ban.as_ref().and_then(|status| status.until_unix),
                totp_enabled: user.security.totp_enabled,
                password_ready: user.security.password_hash.is_some(),
                password_reset_required: user.security.password_needs_reset,
                active_sessions: active_sessions_by_user_id
                    .get(&user_id)
                    .copied()
                    .unwrap_or(0),
                passkey_count: user.security.passkeys.len(),
                last_login_ip: user.security.last_login_ip,
                last_auth_method: latest_auth_by_user_id
                    .get(&user_id)
                    .and_then(|value| value.0.clone()),
                last_auth_at_unix: latest_auth_by_user_id.get(&user_id).map(|value| value.1),
                last_auth_success: latest_auth_by_user_id.get(&user_id).map(|value| value.2),
            }
        })
        .collect()
}

fn admin_user_search_matches(record: &AdminUserSearchRecord, search: &str) -> bool {
    let needle = search.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }

    let role_terms = if record.is_admin {
        "admin administrator 管理员"
    } else {
        "user 用户"
    };
    let mut status_terms = String::new();
    if record.locked {
        status_terms.push_str(" locked lock 锁定");
    }
    if record.banned {
        status_terms.push_str(" banned ban 封禁");
    }
    if record.totp_enabled {
        status_terms.push_str(" totp mfa 2fa 二步 二次验证 双重验证");
    } else {
        status_terms.push_str(" no-totp no-mfa 未启用totp");
    }
    if record.password_reset_required {
        status_terms.push_str(" reset temporary 临时密码 重置");
    }
    if !record.password_ready {
        status_terms.push_str(" passwordless no-password 无密码");
    }

    [
        record.username.as_str(),
        role_terms,
        record.last_login_ip.as_deref().unwrap_or_default(),
        record.last_auth_method.as_deref().unwrap_or_default(),
        record.ban_reason.as_deref().unwrap_or_default(),
        status_terms.as_str(),
    ]
    .join(" ")
    .to_ascii_lowercase()
    .contains(&needle)
}

fn build_admin_user_view(
    record: &AdminUserSearchRecord,
    recovery_codes_remaining: i64,
    language: Language,
    now: i64,
) -> AdminUserView {
    AdminUserView {
        id: record.id.clone(),
        username: record.username.clone(),
        role: record.role.clone(),
        is_admin: record.is_admin,
        locked: record.locked,
        banned: record.banned,
        ban_reason: record.ban_reason.clone(),
        ban_until_unix: record.ban_until_unix,
        ban_until_label: record.ban_until_unix.map(format_unix_timestamp),
        ban_remaining_label: record
            .ban_until_unix
            .map(|until_unix| user_ban_remaining_label(language, until_unix, now)),
        totp_enabled: record.totp_enabled,
        password_ready: record.password_ready,
        password_reset_required: record.password_reset_required,
        active_sessions: record.active_sessions,
        recovery_codes_remaining,
        passkey_count: record.passkey_count,
        last_login_ip: record.last_login_ip.clone(),
        last_auth_method: record.last_auth_method.clone(),
        last_auth_at_unix: record.last_auth_at_unix,
        last_auth_success: record.last_auth_success,
    }
}

async fn load_admin_users_page(
    app_state: &AppState,
    language: Language,
    search: Option<&str>,
    page: usize,
) -> std::result::Result<AdminUsersPageResponse, StatusCode> {
    let raw_users = app_state.meta_store.list_users().await.map_err(|error| {
        warn!("failed loading users for admin users page: {}", error);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let audit_logs = app_state
        .meta_store
        .list_audit_logs()
        .await
        .map_err(|error| {
            warn!("failed loading audit logs for admin users page: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let auth_sessions = app_state
        .meta_store
        .list_all_auth_sessions()
        .await
        .map_err(|error| {
            warn!(
                "failed loading auth sessions for admin users page: {}",
                error
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let now = Utc::now().timestamp();
    let latest_auth_by_user_id = latest_auth_by_user_id_from_audit_logs(&audit_logs, language);
    let (active_sessions_by_user_id, _) =
        build_active_session_count_by_user_id(&auth_sessions, now);
    let user_records = build_admin_user_search_records(
        raw_users,
        &active_sessions_by_user_id,
        &latest_auth_by_user_id,
        now,
    );

    let total_users = user_records.len();
    let search = search.map(str::trim).filter(|value| !value.is_empty());
    let filtered_records = user_records
        .into_iter()
        .filter(|record| match search {
            Some(needle) => admin_user_search_matches(record, needle),
            None => true,
        })
        .collect::<Vec<_>>();
    let filtered_total = filtered_records.len();
    let page_count = filtered_total.div_ceil(ADMIN_USERS_PAGE_SIZE).max(1);
    let page = page.clamp(1, page_count);
    let start = filtered_total.min((page - 1) * ADMIN_USERS_PAGE_SIZE);
    let end = filtered_total.min(start + ADMIN_USERS_PAGE_SIZE);

    let mut items = Vec::with_capacity(end.saturating_sub(start));
    for record in &filtered_records[start..end] {
        let recovery_codes_remaining = app_state
            .meta_store
            .count_active_recovery_codes(&record.id)
            .await
            .map_err(|error| {
                warn!(
                    "failed counting recovery codes for admin users page {}: {}",
                    record.username, error
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        items.push(build_admin_user_view(
            record,
            recovery_codes_remaining,
            language,
            now,
        ));
    }

    Ok(AdminUsersPageResponse {
        items,
        total_users,
        filtered_total,
        page,
        page_count,
        page_size: ADMIN_USERS_PAGE_SIZE,
    })
}

pub(crate) async fn render_admin_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    audit_search: Option<&str>,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
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
    let all_auth_sessions = app_state
        .meta_store
        .list_all_auth_sessions()
        .await
        .map_err(|error| {
            warn!("failed loading auth sessions for admin page: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let now = Utc::now().timestamp();
    let registration_options = registration_policy_options(language);
    let totp_policy_options = enforcement_mode_options(language);
    let password_policy_options = enforcement_mode_options(language);
    let ban_duration_choices = ban_duration_options(language);
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
    let bot_settings = normalized_bot_settings(
        authenticated
            .user
            .security
            .bot_notification_settings
            .clone(),
    );
    let telegram_api_status = telegram_api_status_summary(&system_settings, language);
    let usernames_by_id = raw_users
        .iter()
        .map(|user| (user.id.clone(), user.username.clone()))
        .collect::<HashMap<_, _>>();
    let audit_log_views = audit_logs
        .iter()
        .map(|log| {
            let parsed_details = serde_json::from_str::<serde_json::Value>(&log.details_json)
                .unwrap_or(serde_json::Value::Null);
            let actor_username = log
                .actor_user_id
                .as_ref()
                .and_then(|id| usernames_by_id.get(id))
                .cloned();
            let subject_username = log
                .subject_user_id
                .as_ref()
                .and_then(|id| usernames_by_id.get(id))
                .cloned();
            let login_method_raw = audit_detail_field(&parsed_details, "login_method");
            let reason =
                audit_detail_field(&parsed_details, "reason").map(|value| value.replace('_', " "));

            AuditLogView {
                action_type: log.action_type.clone(),
                action_label: humanize_audit_action(&log.action_type),
                actor_user_id: log.actor_user_id.clone(),
                actor_username,
                subject_user_id: log.subject_user_id.clone(),
                subject_username: subject_username.clone(),
                username: audit_detail_field(&parsed_details, "username")
                    .or_else(|| subject_username.clone()),
                ip_address: log.ip_address.clone(),
                user_agent: audit_detail_field(&parsed_details, "user_agent"),
                success: log.success,
                created_at_unix: log.created_at_unix,
                login_method: login_method_raw
                    .as_deref()
                    .map(|method| admin_login_method_label(language, Some(method))),
                reason,
                passkey_label: audit_detail_field(&parsed_details, "passkey_label"),
                details_pretty: pretty_audit_details(&log.details_json),
            }
        })
        .collect::<Vec<_>>();
    let filtered_audit_logs = audit_search
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|search| {
            audit_log_views
                .iter()
                .filter(|log| audit_search_matches(log, search))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| audit_log_views.clone());
    let recent_auth_activity = audit_log_views
        .iter()
        .filter(|log| {
            log.action_type == web_auth::AUTH_AUDIT_LOGIN_SUCCESS
                || log.action_type == web_auth::AUTH_AUDIT_LOGIN_FAILURE
        })
        .take(8)
        .map(|log| RecentAuthActivityView {
            username: log
                .username
                .clone()
                .or_else(|| log.subject_username.clone())
                .or_else(|| log.actor_username.clone())
                .unwrap_or_else(|| String::from("-")),
            action_label: log.action_label.clone(),
            method_label: log
                .login_method
                .clone()
                .unwrap_or_else(|| admin_login_method_label(language, None)),
            success: log.success,
            created_at_unix: log.created_at_unix,
            ip_address: log.ip_address.clone(),
            reason: log.reason.clone(),
            passkey_label: log.passkey_label.clone(),
        })
        .collect::<Vec<_>>();
    let total_users = raw_users.len();
    let locked_users_count = raw_users
        .iter()
        .filter(|user| user.security.locked_until_unix.unwrap_or_default() > now)
        .count();
    let mfa_enabled_users = raw_users
        .iter()
        .filter(|user| user.security.totp_enabled)
        .count();
    let (_, total_active_auth_sessions) =
        build_active_session_count_by_user_id(&all_auth_sessions, now);

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("title", &translations.admin_page_title);
    context.insert("description", &translations.admin_page_description);
    context.insert("admin_sections_title", &translations.admin_sections_title);
    context.insert("admin_nav_users", &translations.admin_nav_users);
    context.insert("admin_nav_policy", &translations.admin_nav_policy);
    context.insert("admin_nav_audit", &translations.admin_nav_audit);
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("settings_href", &settings_href(language));
    context.insert("dashboard_label", &translations.nav_dashboard_label);
    context.insert("settings_label", &translations.nav_settings_label);
    context.insert("api_title", &translations.admin_api_title);
    context.insert("api_description", &translations.admin_api_description);
    context.insert("api_status_label", &translations.admin_api_status_label);
    context.insert("api_status_value", &telegram_api_status);
    context.insert("api_id_label", &translations.admin_api_id_label);
    context.insert("api_hash_label", &translations.admin_api_hash_label);
    context.insert("api_hint", &translations.admin_api_hint);
    context.insert(
        "telegram_api_id",
        &system_settings
            .telegram_api
            .api_id
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    context.insert("telegram_api_hash", &system_settings.telegram_api.api_hash);
    context.insert("create_user_title", &translations.admin_create_user_title);
    context.insert("username_label", &translations.login_username);
    context.insert("password_label", &translations.login_password);
    context.insert("create_user_label", &translations.admin_create_user_label);
    context.insert("policy_title", &translations.admin_policy_title);
    context.insert("personal_bot_title", &translations.admin_personal_bot_title);
    context.insert(
        "personal_bot_description",
        &translations.admin_personal_bot_description,
    );
    context.insert("bot_settings", &build_bot_settings_view(&bot_settings));
    context.insert("bot_settings_action", "/settings/bot");
    context.insert("registration_label", &translations.admin_registration_label);
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
        &translations.admin_public_registration_label,
    );
    context.insert("session_ttl_label", &translations.admin_session_ttl_label);
    context.insert("audit_limit_label", &translations.admin_audit_limit_label);
    context.insert("totp_policy_label", &translations.admin_totp_policy_label);
    context.insert(
        "password_policy_label",
        &translations.admin_password_policy_label,
    );
    context.insert(
        "password_min_length_label",
        &translations.admin_password_min_length_label,
    );
    context.insert(
        "password_require_uppercase_label",
        &translations.admin_password_require_uppercase_label,
    );
    context.insert(
        "password_require_lowercase_label",
        &translations.admin_password_require_lowercase_label,
    );
    context.insert(
        "password_require_number_label",
        &translations.admin_password_require_number_label,
    );
    context.insert(
        "password_require_symbol_label",
        &translations.admin_password_require_symbol_label,
    );
    context.insert(
        "lockout_threshold_label",
        &translations.admin_lockout_threshold_label,
    );
    context.insert("lockout_base_label", &translations.admin_lockout_base_label);
    context.insert("lockout_max_label", &translations.admin_lockout_max_label);
    context.insert(
        "system_idle_limit_label",
        &translations.admin_system_idle_limit_label,
    );
    context.insert(
        "system_idle_limit_hint",
        &translations.admin_system_idle_limit_hint,
    );
    context.insert("argon_memory_label", &translations.admin_argon_memory_label);
    context.insert(
        "argon_iterations_label",
        &translations.admin_argon_iterations_label,
    );
    context.insert("argon_lanes_label", &translations.admin_argon_lanes_label);
    context.insert(
        "argon_raise_only_hint",
        &translations.admin_argon_raise_only_hint,
    );
    context.insert("save_policy_label", &translations.admin_save_policy_label);
    context.insert("users_title", &translations.admin_users_title);
    context.insert("users_description", &translations.admin_users_description);
    context.insert("users_search_label", &translations.admin_users_search_label);
    context.insert(
        "users_search_placeholder",
        &translations.admin_users_search_placeholder,
    );
    context.insert(
        "users_filtered_label",
        &translations.admin_users_filtered_label,
    );
    context.insert(
        "users_no_matches_label",
        &translations.admin_users_no_matches_label,
    );
    context.insert(
        "users_loading_label",
        &translations.admin_users_loading_label,
    );
    context.insert("users_select_label", &translations.admin_users_select_label);
    context.insert("users_page_label", &translations.admin_users_page_label);
    context.insert(
        "pagination_previous_label",
        &translations.admin_pagination_previous_label,
    );
    context.insert(
        "pagination_next_label",
        &translations.admin_pagination_next_label,
    );
    context.insert("unlock_label", &translations.admin_unlock_label);
    context.insert("ban_label", &translations.admin_ban_label);
    context.insert("unban_label", &translations.admin_unban_label);
    context.insert(
        "revoke_sessions_label",
        &translations.admin_revoke_sessions_label,
    );
    context.insert("reset_label", &translations.admin_reset_label);
    context.insert("delete_label", &translations.admin_delete_label);
    context.insert("role_admin_label", &translations.admin_role_admin_label);
    context.insert("role_user_label", &translations.admin_role_user_label);
    context.insert("locked_badge_label", &translations.admin_locked_badge_label);
    context.insert("banned_badge_label", &translations.admin_banned_badge_label);
    context.insert(
        "totp_enabled_badge_label",
        &translations.admin_totp_enabled_badge_label,
    );
    context.insert(
        "totp_missing_badge_label",
        &translations.admin_totp_missing_badge_label,
    );
    context.insert(
        "password_ready_badge_label",
        &translations.admin_password_ready_badge_label,
    );
    context.insert(
        "password_reset_badge_label",
        &translations.admin_password_reset_badge_label,
    );
    context.insert(
        "password_missing_badge_label",
        &translations.admin_password_missing_badge_label,
    );
    context.insert(
        "user_active_sessions_label",
        &translations.admin_user_active_sessions_label,
    );
    context.insert(
        "user_recovery_codes_label",
        &translations.admin_user_recovery_codes_label,
    );
    context.insert(
        "user_passkeys_label",
        &translations.admin_user_passkeys_label,
    );
    context.insert("user_last_ip_label", &translations.admin_user_last_ip_label);
    context.insert(
        "user_last_auth_label",
        &translations.admin_user_last_auth_label,
    );
    context.insert(
        "ban_duration_value_label",
        &translations.admin_ban_duration_value_label,
    );
    context.insert(
        "ban_duration_unit_label",
        &translations.admin_ban_duration_unit_label,
    );
    context.insert("ban_reason_label", &translations.admin_ban_reason_label);
    context.insert(
        "ban_reason_placeholder",
        &translations.admin_ban_reason_placeholder,
    );
    context.insert("ban_until_label", &translations.admin_ban_until_label);
    context.insert(
        "ban_remaining_label",
        &translations.admin_ban_remaining_label,
    );
    context.insert(
        "ban_permanent_label",
        &translations.admin_ban_unit_permanent_label,
    );
    context.insert("ban_duration_options", &ban_duration_choices);
    context.insert("audit_title", &translations.admin_audit_title);
    context.insert("audit_description", &translations.admin_audit_description);
    context.insert("rollup_title", &translations.admin_rollup_title);
    context.insert("rollup_description", &translations.admin_rollup_description);
    context.insert(
        "audit_success_label",
        &translations.admin_audit_success_label,
    );
    context.insert(
        "audit_failure_label",
        &translations.admin_audit_failure_label,
    );
    context.insert("audit_actor_label", &translations.admin_audit_actor_label);
    context.insert(
        "audit_subject_label",
        &translations.admin_audit_subject_label,
    );
    context.insert(
        "audit_username_label",
        &translations.admin_audit_username_label,
    );
    context.insert("audit_method_label", &translations.admin_audit_method_label);
    context.insert("audit_reason_label", &translations.admin_audit_reason_label);
    context.insert(
        "audit_user_agent_label",
        &translations.admin_audit_user_agent_label,
    );
    context.insert("audit_time_label", &translations.admin_audit_time_label);
    context.insert(
        "audit_updated_label",
        &translations.admin_audit_updated_label,
    );
    context.insert(
        "audit_details_label",
        &translations.admin_audit_details_label,
    );
    context.insert("audit_empty_label", &translations.admin_audit_empty_label);
    context.insert("rollup_empty_label", &translations.admin_rollup_empty_label);
    context.insert(
        "overview_users_label",
        &translations.admin_overview_users_label,
    );
    context.insert(
        "overview_locked_label",
        &translations.admin_overview_locked_label,
    );
    context.insert(
        "overview_web_sessions_label",
        &translations.admin_overview_web_sessions_label,
    );
    context.insert("overview_mfa_label", &translations.admin_overview_mfa_label);
    context.insert(
        "overview_audit_rows_label",
        &translations.admin_overview_audit_rows_label,
    );
    context.insert("recent_auth_title", &translations.admin_recent_auth_title);
    context.insert(
        "recent_auth_description",
        &translations.admin_recent_auth_description,
    );
    context.insert(
        "recent_auth_empty_label",
        &translations.admin_recent_auth_empty_label,
    );
    context.insert("audit_search_label", &translations.admin_audit_search_label);
    context.insert(
        "audit_search_placeholder",
        &translations.admin_audit_search_placeholder,
    );
    context.insert(
        "audit_search_submit_label",
        &translations.admin_audit_search_submit_label,
    );
    context.insert(
        "audit_search_clear_label",
        &translations.admin_audit_search_clear_label,
    );
    context.insert(
        "audit_filtered_label",
        &translations.admin_audit_filtered_label,
    );
    context.insert(
        "audit_no_matches_label",
        &translations.admin_audit_no_matches_label,
    );
    context.insert("policy_description", &translations.admin_policy_description);
    context.insert("total_users", &total_users);
    context.insert("users_filtered_count", &total_users);
    context.insert("locked_users_count", &locked_users_count);
    context.insert("total_active_auth_sessions", &total_active_auth_sessions);
    context.insert("mfa_enabled_users", &mfa_enabled_users);
    context.insert("audit_log_count", &audit_logs.len());
    context.insert("audit_filtered_count", &filtered_audit_logs.len());
    context.insert("audit_logs", &filtered_audit_logs);
    context.insert("audit_rollups", &audit_rollups);
    context.insert("recent_auth_activity", &recent_auth_activity);
    context.insert(
        "audit_search_value",
        &audit_search.unwrap_or_default().trim(),
    );
    context.insert(
        "delete_confirm_message",
        &translations.admin_delete_confirm_message,
    );
    let admin_users_config_json = serde_json::to_string(&AdminUsersUiConfig {
        lang: language.code().to_owned(),
        list_endpoint: String::from("/admin/users/list"),
        filtered_label: translations.admin_users_filtered_label.to_owned(),
        loading_label: translations.admin_users_loading_label.to_owned(),
        no_matches_label: translations.admin_users_no_matches_label.to_owned(),
        select_user_label: translations.admin_users_select_label.to_owned(),
        page_label: translations.admin_users_page_label.to_owned(),
        previous_label: translations.admin_pagination_previous_label.to_owned(),
        next_label: translations.admin_pagination_next_label.to_owned(),
        role_admin_label: translations.admin_role_admin_label.to_owned(),
        role_user_label: translations.admin_role_user_label.to_owned(),
        locked_badge_label: translations.admin_locked_badge_label.to_owned(),
        banned_badge_label: translations.admin_banned_badge_label.to_owned(),
        totp_enabled_badge_label: translations.admin_totp_enabled_badge_label.to_owned(),
        totp_missing_badge_label: translations.admin_totp_missing_badge_label.to_owned(),
        password_ready_badge_label: translations.admin_password_ready_badge_label.to_owned(),
        password_reset_badge_label: translations.admin_password_reset_badge_label.to_owned(),
        password_missing_badge_label: translations.admin_password_missing_badge_label.to_owned(),
        user_active_sessions_label: translations.admin_user_active_sessions_label.to_owned(),
        user_recovery_codes_label: translations.admin_user_recovery_codes_label.to_owned(),
        user_passkeys_label: translations.admin_user_passkeys_label.to_owned(),
        user_last_ip_label: translations.admin_user_last_ip_label.to_owned(),
        user_last_auth_label: translations.admin_user_last_auth_label.to_owned(),
        audit_success_label: translations.admin_audit_success_label.to_owned(),
        audit_failure_label: translations.admin_audit_failure_label.to_owned(),
        unlock_label: translations.admin_unlock_label.to_owned(),
        ban_label: translations.admin_ban_label.to_owned(),
        unban_label: translations.admin_unban_label.to_owned(),
        revoke_sessions_label: translations.admin_revoke_sessions_label.to_owned(),
        reset_label: translations.admin_reset_label.to_owned(),
        delete_label: translations.admin_delete_label.to_owned(),
        delete_confirm_message: translations.admin_delete_confirm_message.to_owned(),
        ban_duration_value_label: translations.admin_ban_duration_value_label.to_owned(),
        ban_duration_unit_label: translations.admin_ban_duration_unit_label.to_owned(),
        ban_reason_label: translations.admin_ban_reason_label.to_owned(),
        ban_reason_placeholder: translations.admin_ban_reason_placeholder.to_owned(),
        ban_until_label: translations.admin_ban_until_label.to_owned(),
        ban_remaining_label: translations.admin_ban_remaining_label.to_owned(),
        ban_permanent_label: translations.admin_ban_unit_permanent_label.to_owned(),
        ban_duration_options: ban_duration_choices.clone(),
    })
    .map_err(|error| {
        warn!("failed encoding admin users config json: {}", error);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    context.insert("admin_users_config_json", &admin_users_config_json);
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
    context.insert(
        "bot_placeholders",
        &build_bot_placeholder_hints(language).to_vec(),
    );
    context.insert("banner", &banner);
    context.insert("current_admin_username", &authenticated.user.username);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "admin.html", &context)
}

async fn admin_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<AdminPageQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }
    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        query.audit_search.as_deref(),
        None,
        &headers,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_users_list_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<AdminUsersQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return StatusCode::FORBIDDEN.into_response();
    }

    match load_admin_users_page(
        &app_state,
        language,
        query.search.as_deref(),
        query.page.unwrap_or(1),
    )
    .await
    {
        Ok(payload) => Json(payload).into_response(),
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
                None,
                Some(PageBanner::error(error.to_string())),
                &headers,
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
            None,
            Some(PageBanner::error(strength.reasons.join("; "))),
            &headers,
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
            None,
            Some(PageBanner::error(
                language.translations().admin_username_exists_message,
            )),
            &headers,
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
            None,
            Some(PageBanner::error(error.to_string())),
            &headers,
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
            None,
            Some(PageBanner::error(error.to_string())),
            &headers,
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
        None,
        Some(PageBanner::success(
            language.translations().admin_user_created_message,
        )),
        &headers,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_ban_user_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(user_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<AdminBanUserForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
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
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            None,
            Some(PageBanner::error(
                language.translations().admin_cannot_ban_admin_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::FORBIDDEN, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let banned_until_unix = match parse_ban_expires_at(&form.duration_value, &form.duration_unit) {
        Ok(value) => value,
        Err(_) => {
            return match render_admin_page(
                &app_state,
                &authenticated,
                language,
                None,
                Some(PageBanner::error(
                    language.translations().admin_ban_invalid_duration_message,
                )),
                &headers,
            )
            .await
            {
                Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                Err(status) => status.into_response(),
            };
        }
    };
    let ban_reason = normalize_optional_text(&form.reason);

    user.security.ban_active = true;
    user.security.banned_until_unix = banned_until_unix;
    user.security.ban_reason = ban_reason.clone();
    user.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = app_state.meta_store.save_user(&user).await {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            None,
            Some(PageBanner::error(error.to_string())),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let suspended_session_ids = suspend_user_session_runtime(&app_state, &user.id).await;
    revoke_all_user_auth_access(&app_state, &user.id).await;

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_user_banned"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "username": user.username,
                "reason": ban_reason,
                "banned_until_unix": banned_until_unix,
                "permanent": banned_until_unix.is_none(),
                "session_workers_stopped": suspended_session_ids.len()
            })
            .to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        None,
        Some(PageBanner::success(
            language.translations().admin_user_banned_message,
        )),
        &headers,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_unban_user_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(user_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
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
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            None,
            Some(PageBanner::error(
                language.translations().admin_cannot_ban_admin_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::FORBIDDEN, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    user.security.ban_active = false;
    user.security.banned_until_unix = None;
    user.security.ban_reason = None;
    user.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = app_state.meta_store.save_user(&user).await {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            None,
            Some(PageBanner::error(error.to_string())),
            &headers,
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
            action_type: String::from("admin_user_unbanned"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "username": user.username
            })
            .to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        None,
        Some(PageBanner::success(
            language.translations().admin_user_unbanned_message,
        )),
        &headers,
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
            None,
            Some(PageBanner::error(error.to_string())),
            &headers,
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
        None,
        Some(PageBanner::success(
            language.translations().admin_user_unlocked_message,
        )),
        &headers,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn stop_user_session_workers(app_state: &AppState, user_id: &str) -> Vec<String> {
    let Ok(session_records) = app_state
        .meta_store
        .list_session_records_for_user(user_id)
        .await
    else {
        return Vec::new();
    };
    let session_record_ids = session_records
        .iter()
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();

    let mut workers_to_stop = Vec::new();
    {
        let mut workers = app_state.session_workers.lock().await;
        for record in session_records {
            if let Some(worker) = workers.remove(&record.id) {
                workers_to_stop.push(worker);
            }
        }
    }

    for worker in workers_to_stop {
        worker.cancellation.cancel();
        let _ = worker.task.await;
    }

    session_record_ids
}

async fn suspend_user_session_runtime(app_state: &AppState, user_id: &str) -> Vec<String> {
    let session_record_ids = stop_user_session_workers(app_state, user_id).await;
    if session_record_ids.is_empty() {
        return session_record_ids;
    }

    let mut shared_state = app_state.shared_state.write().await;
    for session_record_id in &session_record_ids {
        shared_state.remove(session_record_id);
    }

    session_record_ids
}

async fn clear_user_runtime_state(
    app_state: &AppState,
    user_id: &str,
    auth_session_ids: &[String],
    session_record_ids: &[String],
) {
    for auth_session_id in auth_session_ids {
        clear_auth_session_sensitive_state(app_state, auth_session_id).await;
    }
    app_state.user_keys.write().await.remove(user_id);
    clear_pending_flows_for_user(app_state, user_id).await;

    {
        let mut shared_state = app_state.shared_state.write().await;
        for session_record_id in session_record_ids {
            shared_state.remove(session_record_id);
        }
    }

    for session_record_id in session_record_ids {
        if let Err(error) = app_state
            .runtime_cache
            .remove_session(session_record_id)
            .await
        {
            warn!(
                "failed deleting runtime cache for cleared session {}: {}",
                session_record_id, error
            );
        }
    }
}

async fn revoke_all_user_auth_access(app_state: &AppState, user_id: &str) {
    if let Ok(auth_sessions) = app_state
        .meta_store
        .list_auth_sessions_for_user(user_id)
        .await
    {
        for auth_session in auth_sessions {
            clear_auth_session_sensitive_state(app_state, &auth_session.id).await;
        }
    }
    let _ = app_state
        .meta_store
        .revoke_all_auth_sessions_for_user(user_id)
        .await;
    app_state.user_keys.write().await.remove(user_id);
    clear_pending_flows_for_user(app_state, user_id).await;
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

    let settings = app_state.system_settings.read().await.clone();
    stop_user_session_workers(&app_state, &user.id).await;

    let reset_result = match reset_user_account(
        &app_state.meta_store,
        &mut user,
        &app_state.runtime.users_dir,
        &settings.argon_policy,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            return match render_admin_page(
                &app_state,
                &authenticated,
                language,
                None,
                Some(PageBanner::error(error.to_string())),
                &headers,
            )
            .await
            {
                Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
                Err(status) => status.into_response(),
            };
        }
    };

    clear_user_runtime_state(
        &app_state,
        &user.id,
        &reset_result.auth_session_ids,
        &reset_result.session_record_ids,
    )
    .await;
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
                "temporary_password_issued": true,
                "passkeys_cleared": true,
                "session_records_removed": reset_result.session_record_ids.len(),
                "auth_sessions_revoked": reset_result.auth_session_ids.len()
            })
            .to_string(),
        })
        .await;

    let banner_message = language
        .translations()
        .admin_reset_temporary_password_message
        .replace("{username}", &user.username)
        .replace("{password}", &reset_result.temporary_password);

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        None,
        Some(PageBanner::success(banner_message)),
        &headers,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_delete_user_handler(
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
    let Some(user) = app_state
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

    stop_user_session_workers(&app_state, &user.id).await;

    let delete_result =
        match delete_user_account(&app_state.meta_store, &user, &app_state.runtime.users_dir).await
        {
            Ok(result) => result,
            Err(error) => {
                return match render_admin_page(
                    &app_state,
                    &authenticated,
                    language,
                    None,
                    Some(PageBanner::error(error.to_string())),
                    &headers,
                )
                .await
                {
                    Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
                    Err(status) => status.into_response(),
                };
            }
        };

    clear_user_runtime_state(
        &app_state,
        &user.id,
        &delete_result.auth_session_ids,
        &delete_result.session_record_ids,
    )
    .await;

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_user_deleted"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "username": user.username,
                "session_records_removed": delete_result.session_record_ids.len(),
                "auth_sessions_revoked": delete_result.auth_session_ids.len()
            })
            .to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        None,
        Some(PageBanner::success(
            language.translations().admin_user_deleted_message,
        )),
        &headers,
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
        revoke_all_user_auth_access(&app_state, &user_id).await;
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
            None,
            Some(PageBanner::success(
                language.translations().admin_user_sessions_revoked_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => html.into_response(),
            Err(status) => status.into_response(),
        };
    }

    match auth::render_settings_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(
            language
                .translations()
                .admin_selected_sessions_revoked_message,
        )),
        &headers,
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
    let previous_telegram_api = settings.telegram_api.clone();
    settings.telegram_api =
        match parse_telegram_api_settings(&form.telegram_api_id, &form.telegram_api_hash) {
            Ok(value) => value,
            Err(error) => {
                return match render_admin_page(
                    &app_state,
                    &authenticated,
                    language,
                    None,
                    Some(PageBanner::error(error.to_string())),
                    &headers,
                )
                .await
                {
                    Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                    Err(status) => status.into_response(),
                };
            }
        };
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
                    None,
                    Some(PageBanner::error(error.to_string())),
                    &headers,
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
    let telegram_api_changed = previous_telegram_api != settings.telegram_api;
    let telegram_api_configured = configured_telegram_api(&settings).is_some();

    if let Err(error) = app_state.meta_store.save_system_settings(&settings).await {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            None,
            Some(PageBanner::error(error.to_string())),
            &headers,
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
            None,
            Some(PageBanner::error(format!(
                "{}{}",
                language.translations().admin_settings_refresh_failed_prefix,
                error
            ))),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    *app_state.system_settings.write().await = settings;
    if telegram_api_changed {
        sessions::reload_all_session_workers(&app_state).await;
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("system_settings_updated"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(authenticated.user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "telegram_api_configured": telegram_api_configured,
                "registration_policy": form.registration_policy,
                "totp_policy": form.totp_policy,
                "password_strength_policy": form.password_strength_policy,
                "argon_policy_changed": argon_policy_changed,
                "telegram_api_changed": telegram_api_changed
            })
            .to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        None,
        Some(PageBanner::success(
            language.translations().admin_settings_saved_message,
        )),
        &headers,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}
