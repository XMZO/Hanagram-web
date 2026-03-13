// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::i18n::TranslationSet;
use crate::web_auth;
use webauthn_rp::AuthenticatedCredential;
use webauthn_rp::request::auth::{
    AllowedCredentials, AuthenticationVerificationOptions, PublicKeyCredentialRequestOptions,
};
use webauthn_rp::request::register::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity,
    RegistrationVerificationOptions,
};
use webauthn_rp::request::{
    AsciiDomain, Credentials, DomainOrigin, RpId, UserVerificationRequirement,
};
use webauthn_rp::response::auth::Authentication;
use webauthn_rp::response::register::Registration;
use webauthn_rp::response::register::error::RegCeremonyErr;

use super::middleware::{
    cache_user_master_key, clear_auth_session_sensitive_state, clear_invalid_cookie_state,
    drop_user_master_key_if_no_active_sessions, resolved_user_master_key,
};
use super::shared::*;

pub(crate) fn public_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/register",
            get(register_page_handler).post(register_submit_handler),
        )
        .route("/login", get(login_page_handler).post(login_submit_handler))
        .route(
            "/login/passkey/options",
            post(login_passkey_options_handler),
        )
        .route("/login/passkey/finish", post(login_passkey_finish_handler))
        .route("/logout", post(logout_handler))
        .route("/language/{language_code}", get(select_language_handler))
}

pub(crate) fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/settings", get(settings_page_handler))
        .route("/settings/security/password", post(change_password_handler))
        .route(
            "/settings/security/idle-timeout",
            post(update_idle_timeout_handler),
        )
        .route(
            "/settings/security/totp/setup",
            get(totp_setup_page_handler).post(confirm_totp_setup_handler),
        )
        .route(
            "/settings/security/passkeys/register/options",
            post(start_passkey_registration_handler),
        )
        .route(
            "/settings/security/passkeys/register/finish",
            post(finish_passkey_registration_handler),
        )
        .route(
            "/settings/security/passkeys/{passkey_id}/delete",
            post(delete_passkey_handler),
        )
        .route(
            "/settings/security/recovery/ack",
            post(acknowledge_recovery_notice_handler),
        )
}

fn security_settings_target() -> String {
    String::from("/settings#security")
}

fn sanitized_language_return_path(headers: &HeaderMap) -> String {
    let fallback = String::from("/login");
    let Some(raw_referer) = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
    else {
        return fallback;
    };

    let (path, query) = if raw_referer.starts_with('/') {
        let (path, query) = raw_referer.split_once('?').unwrap_or((raw_referer, ""));
        (path.to_owned(), query.to_owned())
    } else {
        let Ok(url) = reqwest::Url::parse(raw_referer) else {
            return fallback;
        };
        (
            url.path().to_owned(),
            url.query().unwrap_or_default().to_owned(),
        )
    };

    if path.is_empty() || path.starts_with("/language/") {
        return fallback;
    }

    let filtered_query = query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.starts_with("lang="))
        .collect::<Vec<_>>();

    if filtered_query.is_empty() {
        path
    } else {
        format!("{path}?{}", filtered_query.join("&"))
    }
}

struct PasskeyRelyingParty {
    rp_id: String,
    origin: String,
}

fn json_error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

fn login_locked_message(language: Language, locked_until: i64) -> String {
    language
        .translations()
        .login_locked_until_message
        .replace("{locked_until}", &format_unix_timestamp(locked_until))
}

fn login_banned_message(
    language: Language,
    until_unix: Option<i64>,
    reason: Option<&str>,
) -> String {
    let translations = language.translations();
    let reason = reason.map(str::trim).filter(|value| !value.is_empty());

    match (until_unix, reason) {
        (Some(until_unix), Some(reason)) => translations
            .login_banned_remaining_reason_message
            .replace(
                "{remaining}",
                &format_duration_for_display(
                    language,
                    until_unix.saturating_sub(Utc::now().timestamp()),
                ),
            )
            .replace("{reason}", reason),
        (Some(until_unix), None) => translations.login_banned_remaining_message.replace(
            "{remaining}",
            &format_duration_for_display(
                language,
                until_unix.saturating_sub(Utc::now().timestamp()),
            ),
        ),
        (None, Some(reason)) => translations
            .login_banned_permanent_reason_message
            .replace("{reason}", reason),
        (None, None) => translations.login_banned_permanent_message.to_owned(),
    }
}

fn request_host(headers: &HeaderMap) -> Option<String> {
    for header_name in ["x-forwarded-host", "host"] {
        let Some(value) = headers.get(header_name) else {
            continue;
        };
        let Ok(raw_value) = value.to_str() else {
            continue;
        };
        let Some(candidate) = raw_value
            .split(',')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        return Some(candidate.to_owned());
    }

    None
}

fn passkey_relying_party(
    headers: &HeaderMap,
    language: Language,
) -> std::result::Result<PasskeyRelyingParty, String> {
    let translations = language.translations();
    let Some(host) = request_host(headers) else {
        return Err(String::from(translations.passkey_not_supported_message));
    };

    let scheme = if request_uses_https(headers) {
        "https"
    } else {
        "http"
    };
    let origin = format!("{scheme}://{host}");
    let rp_id = host.split(':').next().unwrap_or_default().trim().to_owned();
    if rp_id.is_empty() {
        return Err(String::from(translations.passkey_not_supported_message));
    }
    if scheme != "https" && rp_id != "localhost" {
        return Err(String::from(translations.passkey_not_supported_message));
    }
    if rp_id.parse::<std::net::IpAddr>().is_ok() {
        return Err(String::from(translations.passkey_not_supported_message));
    }

    Ok(PasskeyRelyingParty { rp_id, origin })
}

fn passkey_rp_id(rp_id: &str) -> Result<RpId> {
    Ok(RpId::Domain(
        AsciiDomain::try_from(rp_id.to_owned()).context("failed to parse passkey rp id")?,
    ))
}

fn passkey_allowed_origin(origin: &str) -> Result<DomainOrigin<'_, '_>> {
    DomainOrigin::try_from(origin).context("failed to parse passkey origin")
}

fn passkey_public_key_options<T: serde::Serialize>(client_state: &T) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "publicKey": serde_json::to_value(client_state)
            .context("failed to serialize passkey client state")?
    }))
}

fn passkey_registration_error_message(
    translations: &TranslationSet,
    error: &RegCeremonyErr,
) -> &'static str {
    match error {
        RegCeremonyErr::Timeout => translations.passkey_challenge_expired_message,
        RegCeremonyErr::OriginMismatch
        | RegCeremonyErr::TopOriginMismatch
        | RegCeremonyErr::RpIdHashMismatch => {
            translations.passkey_registration_site_mismatch_message
        }
        _ => translations.passkey_registration_failed_message,
    }
}

async fn render_login_page(
    app_state: &AppState,
    language: Language,
    error_message: Option<&str>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/login");
    let settings = app_state.system_settings.read().await.clone();
    let show_register = registration_page_allowed(&app_state.meta_store, &settings).await;
    let passkey_availability = passkey_relying_party(headers, language).err();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("error_message", &error_message);
    context.insert("show_register", &show_register);
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
    context.insert("passkey_supported", &(passkey_availability.is_none()));
    context.insert(
        "passkey_unavailable_message",
        &passkey_availability.unwrap_or_default(),
    );
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "login.html", &context)
}

async fn render_register_page(
    app_state: &AppState,
    language: Language,
    error_message: Option<&str>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/register");
    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("title", &translations.register_title);
    context.insert("page_title", &translations.register_page_title);
    context.insert("description", &translations.register_description);
    context.insert("username_label", &translations.login_username);
    context.insert("password_label", &translations.login_password);
    context.insert("confirm_label", &translations.register_confirm_label);
    context.insert("submit_label", &translations.register_submit_label);
    context.insert("back_label", &translations.back_to_login_label);
    context.insert("back_href", "/login");
    context.insert("error_message", &error_message);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "register.html", &context)
}

pub(crate) async fn render_settings_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let banner = if banner.is_some() {
        banner
    } else if authenticated.requires_password_reset {
        Some(PageBanner::error(
            translations.settings_password_reset_required_message,
        ))
    } else {
        None
    };
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
    let active_session_count = active_sessions.len();
    let other_session_count = active_sessions
        .iter()
        .filter(|session| !session.is_current)
        .count();

    let totp_status = if authenticated.user.security.totp_enabled {
        translations.settings_totp_status_enabled
    } else {
        translations.settings_totp_status_disabled
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
        Some(maximum) => translations
            .settings_idle_timeout_hint_capped
            .replace("{maximum}", &maximum.to_string()),
        None => String::from(translations.settings_idle_timeout_hint_unlimited),
    };
    let bot_settings = normalized_bot_settings(
        authenticated
            .user
            .security
            .bot_notification_settings
            .clone(),
    );
    let bot_status = bot_status_summary(&bot_settings, language);
    let bot_destination = bot_destination_summary(&bot_settings, language);
    let bot_template_preview = template_preview(&bot_settings.template, 68);
    let bot_placeholders = build_bot_placeholder_hints(language).to_vec();
    let passkey_views = authenticated
        .user
        .security
        .passkeys
        .iter()
        .map(|record| PasskeyView {
            id: record.id.clone(),
            label: record.label.clone(),
            created_at: format_unix_timestamp(record.created_at_unix),
            last_used_at: record
                .last_used_at_unix
                .map(format_unix_timestamp)
                .unwrap_or_else(|| String::from("-")),
        })
        .collect::<Vec<_>>();
    let recovery_notice = app_state
        .recovery_notices
        .read()
        .await
        .get(&authenticated.auth_session.id)
        .cloned()
        .map(|notice| RecoveryNoticeView {
            codes: notice
                .recovery_codes
                .iter()
                .map(|code| code.as_ref().as_str().to_owned())
                .collect(),
        });
    let show_workspace_links = !authenticated.requires_password_reset && recovery_notice.is_none();
    let passkey_unavailable_message = passkey_relying_party(headers, language).err();
    let passkey_supported = passkey_unavailable_message.is_none();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("title", &translations.settings_page_title);
    context.insert("description", &translations.settings_page_description);
    context.insert("current_username", &authenticated.user.username);
    context.insert(
        "password_reset_required",
        &authenticated.requires_password_reset,
    );
    context.insert("show_workspace_links", &show_workspace_links);
    context.insert("show_admin", &(authenticated.user.role == UserRole::Admin));
    context.insert("admin_href", &admin_href(language));
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("notifications_href", &notifications_href(language));
    context.insert(
        "settings_sections_title",
        &translations.settings_sections_title,
    );
    context.insert("settings_nav_security", &translations.settings_nav_security);
    context.insert(
        "settings_nav_notifications",
        &translations.settings_nav_notifications,
    );
    context.insert("settings_nav_access", &translations.settings_nav_access);
    context.insert("dashboard_label", &translations.nav_dashboard_label);
    context.insert("admin_label", &translations.nav_admin_label);
    context.insert("security_title", &translations.settings_security_title);
    context.insert(
        "security_description",
        &translations.settings_security_description,
    );
    context.insert("totp_label", &translations.settings_totp_label);
    context.insert("totp_status", &totp_status);
    context.insert("totp_hint", &translations.settings_totp_hint);
    context.insert("recovery_label", &translations.settings_recovery_label);
    context.insert(
        "recovery_remaining",
        &authenticated.recovery_codes_remaining.to_string(),
    );
    context.insert("recovery_hint", &translations.settings_recovery_hint);
    context.insert("passkeys_label", &translations.settings_passkeys_label);
    context.insert("passkeys_hint", &translations.settings_passkeys_hint);
    context.insert("passkey_count", &authenticated.user.security.passkeys.len());
    context.insert("idle_label", &translations.settings_idle_label);
    context.insert("idle_timeout", &idle_timeout);
    context.insert(
        "idle_effective_label",
        &translations.settings_idle_effective_label,
    );
    context.insert("idle_effective_timeout", &effective_idle_timeout);
    context.insert(
        "idle_summary_label",
        &translations.settings_idle_summary_label,
    );
    context.insert("idle_form_title", &translations.settings_idle_form_title);
    context.insert("idle_form_action", "/settings/security/idle-timeout");
    context.insert("idle_input_label", &translations.settings_idle_input_label);
    context.insert("idle_timeout_field_value", &idle_timeout_field_value);
    context.insert("idle_timeout_hint", &idle_timeout_hint);
    context.insert(
        "idle_submit_label",
        &translations.settings_idle_submit_label,
    );
    context.insert("totp_setup_href", "/settings/security/totp/setup");
    context.insert("totp_setup_label", &translations.settings_totp_setup_label);
    context.insert("passkeys_title", &translations.settings_passkeys_title);
    context.insert(
        "passkeys_description",
        &translations.settings_passkeys_description,
    );
    context.insert("passkeys", &passkey_views);
    context.insert("passkey_supported", &passkey_supported);
    context.insert(
        "passkey_unavailable_message",
        &passkey_unavailable_message.unwrap_or_default(),
    );
    context.insert(
        "passkey_name_label",
        &translations.settings_passkey_name_label,
    );
    context.insert(
        "passkey_name_placeholder",
        &translations.settings_passkey_name_placeholder,
    );
    context.insert(
        "passkey_provider_notes_title",
        &translations.settings_passkey_provider_notes_title,
    );
    context.insert(
        "passkey_google_hint",
        &translations.settings_passkey_google_hint,
    );
    context.insert(
        "passkey_bitwarden_hint",
        &translations.settings_passkey_bitwarden_hint,
    );
    context.insert(
        "passkey_add_label",
        &translations.settings_passkey_add_label,
    );
    context.insert(
        "passkey_created_label",
        &translations.settings_passkey_created_label,
    );
    context.insert(
        "passkey_last_used_label",
        &translations.settings_passkey_last_used_label,
    );
    context.insert(
        "passkey_empty_label",
        &translations.settings_passkey_empty_label,
    );
    context.insert(
        "passkey_delete_label",
        &translations.settings_passkey_delete_label,
    );
    context.insert(
        "passkey_delete_confirm_message",
        &translations.settings_passkey_delete_confirm,
    );
    context.insert(
        "passkey_register_options_action",
        "/settings/security/passkeys/register/options",
    );
    context.insert(
        "passkey_register_finish_action",
        "/settings/security/passkeys/register/finish",
    );
    context.insert("password_title", &translations.settings_password_title);
    context.insert("password_action", "/settings/security/password");
    context.insert(
        "current_password_label",
        &translations.settings_current_password_label,
    );
    context.insert(
        "new_password_label",
        &translations.settings_new_password_label,
    );
    context.insert(
        "confirm_password_label",
        &translations.settings_confirm_password_label,
    );
    context.insert(
        "change_password_label",
        &translations.settings_change_password_label,
    );
    context.insert(
        "password_description",
        &translations.settings_password_description,
    );
    context.insert(
        "notifications_section_title",
        &translations.settings_notifications_section_title,
    );
    context.insert(
        "notifications_section_description",
        &translations.settings_notifications_section_description,
    );
    context.insert(
        "notifications_manage_fullpage_label",
        &translations.settings_notifications_manage_fullpage_label,
    );
    context.insert(
        "notification_status_label",
        &translations.settings_notification_status_label,
    );
    context.insert("notification_status_value", &bot_status);
    context.insert(
        "notification_destination_label",
        &translations.settings_notification_destination_label,
    );
    context.insert("notification_destination_value", &bot_destination);
    context.insert(
        "notification_template_preview_label",
        &translations.settings_notification_template_preview_label,
    );
    context.insert("notification_template_preview", &bot_template_preview);
    context.insert("bot_settings", &build_bot_settings_view(&bot_settings));
    context.insert("bot_placeholders", &bot_placeholders);
    context.insert("bot_settings_action", "/settings/bot");
    context.insert("sessions_title", &translations.settings_sessions_title);
    context.insert(
        "sessions_description",
        &translations.settings_sessions_description,
    );
    context.insert("sessions", &active_sessions);
    context.insert("active_session_count", &active_session_count);
    context.insert("has_other_sessions", &(other_session_count > 0));
    context.insert("other_session_count", &other_session_count);
    context.insert("current_session_id", &authenticated.auth_session.id);
    context.insert("current_user_id", &authenticated.user.id);
    context.insert("revoke_label", &translations.settings_revoke_label);
    context.insert(
        "revoke_all_action",
        &format!("/admin/users/{}/sessions/revoke", authenticated.user.id),
    );
    context.insert("revoke_all_label", &translations.settings_revoke_all_label);
    context.insert(
        "session_device_label",
        &translations.settings_session_device_label,
    );
    context.insert(
        "unknown_user_agent_label",
        &translations.settings_unknown_user_agent_label,
    );
    context.insert("session_ip_label", &translations.settings_session_ip_label);
    context.insert(
        "session_issued_label",
        &translations.settings_session_issued_label,
    );
    context.insert(
        "session_expires_label",
        &translations.settings_session_expires_label,
    );
    context.insert(
        "session_empty_label",
        &translations.settings_session_empty_label,
    );
    context.insert(
        "current_session_label",
        &translations.settings_current_session_label,
    );
    context.insert(
        "access_auto_logout_description",
        &translations.settings_access_auto_logout_description,
    );
    context.insert(
        "access_current_only_hint",
        &translations.settings_access_current_only_hint,
    );
    context.insert(
        "access_other_sessions_hint",
        &translations
            .settings_access_other_sessions_hint
            .replace("{count}", &other_session_count.to_string()),
    );
    context.insert("recovery_notice", &recovery_notice);
    context.insert(
        "recovery_refresh_title",
        &translations.settings_recovery_refresh_title,
    );
    context.insert(
        "recovery_refresh_message",
        &translations.settings_recovery_refresh_message,
    );
    context.insert("recovery_ack_action", "/settings/security/recovery/ack");
    context.insert(
        "recovery_ack_label",
        &translations.settings_recovery_ack_label,
    );
    context.insert("banner", &banner);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "settings.html", &context)
}

fn build_pending_totp_setup(username: &str, is_rotation: bool) -> PendingTotpSetup {
    let material = build_totp_setup_material(username);
    PendingTotpSetup {
        secret: material.secret,
        recovery_codes: material.recovery_codes,
        otp_auth_uri: material.otp_auth_uri,
        is_rotation,
    }
}

async fn render_totp_setup_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let pending = {
        let mut setups = app_state.totp_setups.write().await;
        if authenticated.user.security.totp_enabled {
            setups.get(&authenticated.auth_session.id).cloned()
        } else {
            Some(
                setups
                    .entry(authenticated.auth_session.id.clone())
                    .or_insert_with(|| {
                        build_pending_totp_setup(&authenticated.user.username, false)
                    })
                    .clone(),
            )
        }
    };
    let pending_qr_svg = if let Some(pending) = pending.as_ref() {
        Some(
            render_qr_svg(pending.otp_auth_uri.as_ref().as_str()).map_err(|error| {
                warn!(
                    "failed rendering pending totp qr for {}: {}",
                    authenticated.user.username, error
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?,
        )
    } else {
        None
    };
    let pending_recovery_codes = pending
        .as_ref()
        .map(|setup| {
            setup
                .recovery_codes
                .iter()
                .map(|code| code.as_ref().as_str().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let current_secret = if authenticated.user.security.totp_enabled {
        match resolved_user_master_key(app_state, authenticated).await {
            Some(master_key) => match web_auth::decrypt_user_totp_secret(
                &authenticated.user,
                master_key.as_ref().as_slice(),
            ) {
                Ok(secret) => Some(secret),
                Err(error) => {
                    warn!(
                        "failed decrypting current totp secret for {}: {}",
                        authenticated.user.username, error
                    );
                    None
                }
            },
            None => None,
        }
    } else {
        None
    };
    let current_qr_svg = if let Some(secret) = current_secret.as_ref() {
        let current_uri = hanagram_web::security::build_totp_uri(
            "Hanagram Web",
            &authenticated.user.username,
            secret.as_str(),
        );
        Some(render_qr_svg(&current_uri).map_err(|error| {
            warn!(
                "failed rendering current totp qr for {}: {}",
                authenticated.user.username, error
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?)
    } else {
        None
    };
    let pending_is_rotation = pending.as_ref().is_some_and(|setup| setup.is_rotation);
    let show_current_totp = authenticated.user.security.totp_enabled;
    let title = if show_current_totp {
        translations.totp_manage_title
    } else {
        translations.totp_setup_title
    };
    let description = if show_current_totp {
        translations.totp_manage_description
    } else {
        translations.totp_setup_description
    };

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("title", &title);
    context.insert("description", &description);
    context.insert("settings_href", &settings_href(language));
    context.insert("back_label", &translations.back_to_settings_label);
    context.insert("show_current_totp", &show_current_totp);
    context.insert("current_title", &translations.totp_current_title);
    context.insert(
        "current_description",
        &translations.totp_current_description,
    );
    context.insert("current_qr_title", &translations.totp_setup_qr_title);
    context.insert("current_qr_svg", &current_qr_svg.unwrap_or_default());
    context.insert(
        "current_secret_label",
        &translations.totp_setup_secret_label,
    );
    context.insert(
        "current_secret",
        &current_secret
            .as_ref()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_default(),
    );
    context.insert("current_secret_available", &current_secret.is_some());
    context.insert(
        "current_secret_unavailable_message",
        &translations.totp_current_secret_unavailable_message,
    );
    context.insert(
        "current_recovery_remaining_label",
        &translations.totp_current_recovery_remaining_label,
    );
    context.insert(
        "current_recovery_remaining",
        &authenticated.recovery_codes_remaining.to_string(),
    );
    context.insert(
        "current_recovery_hidden_message",
        &translations.totp_current_recovery_hidden_message,
    );
    context.insert(
        "show_start_rotation",
        &(show_current_totp && pending.is_none()),
    );
    context.insert(
        "rotation_start_label",
        &translations.totp_rotation_start_label,
    );
    context.insert(
        "rotation_required",
        &(show_current_totp && authenticated.recovery_codes_remaining == 0),
    );
    context.insert(
        "rotation_required_message",
        &translations.totp_rotation_required_message,
    );
    context.insert("show_pending_setup", &pending.is_some());
    context.insert("pending_is_rotation", &pending_is_rotation);
    context.insert(
        "pending_title",
        &(if pending_is_rotation {
            translations.totp_rotation_title
        } else {
            translations.totp_setup_title
        }),
    );
    context.insert(
        "pending_description",
        &(if pending_is_rotation {
            translations.totp_rotation_description
        } else {
            translations.totp_setup_description
        }),
    );
    context.insert("pending_qr_title", &translations.totp_setup_qr_title);
    context.insert("pending_qr_svg", &pending_qr_svg.unwrap_or_default());
    context.insert(
        "pending_secret_label",
        &translations.totp_setup_secret_label,
    );
    context.insert(
        "pending_secret",
        &pending
            .as_ref()
            .map(|value| value.secret.as_ref().as_str().to_owned())
            .unwrap_or_default(),
    );
    context.insert("recovery_title", &translations.totp_setup_recovery_title);
    context.insert(
        "recovery_description",
        &translations.totp_setup_recovery_description,
    );
    context.insert("recovery_codes", &pending_recovery_codes);
    context.insert("confirm_action", "/settings/security/totp/setup");
    context.insert("confirm_label", &translations.totp_setup_confirm_label);
    context.insert(
        "confirm_submit",
        &(if pending_is_rotation {
            translations.totp_rotation_confirm_submit
        } else {
            translations.totp_setup_confirm_submit
        }),
    );
    context.insert(
        "rotation_cancel_label",
        &translations.totp_rotation_cancel_label,
    );
    context.insert(
        "confirm_saved_codes_label",
        &translations.totp_setup_saved_codes_confirm_label,
    );
    context.insert(
        "confirm_replace_totp_label",
        &translations.totp_setup_replace_totp_confirm_label,
    );
    context.insert(
        "confirm_replace_recovery_label",
        &translations.totp_setup_replace_recovery_confirm_label,
    );
    context.insert("banner", &banner);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "totp_setup.html", &context)
}

async fn select_language_handler(
    State(app_state): State<AppState>,
    AxumPath(language_code): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(language) = Language::parse(&language_code) else {
        return Redirect::to(&sanitized_language_return_path(&headers)).into_response();
    };

    let settings = app_state.system_settings.read().await.clone();
    let mut response = Redirect::to(&sanitized_language_return_path(&headers)).into_response();
    let cookie_secure = effective_auth_cookie_secure(&settings, &headers);

    match set_cookie_header(&build_language_cookie(language, cookie_secure)) {
        Ok(cookie) => {
            response.headers_mut().append(header::SET_COOKIE, cookie);
            response
        }
        Err(status) => status.into_response(),
    }
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
        let target = if app_state
            .recovery_notices
            .read()
            .await
            .contains_key(&authenticated.auth_session.id)
        {
            security_settings_target()
        } else if authenticated.requires_password_reset {
            security_settings_target()
        } else if authenticated.requires_totp_setup || authenticated.recovery_codes_remaining == 0 {
            String::from("/settings/security/totp/setup")
        } else {
            login_redirect_target(language)
        };
        return Redirect::to(&target).into_response();
    }
    clear_invalid_cookie_state(&app_state, &headers).await;

    match render_login_page(&app_state, language, None, &headers).await {
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
        return Redirect::to("/login").into_response();
    }

    match render_register_page(&app_state, language, None, &headers).await {
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

            if let Some(recovery_notice_codes) = &login_result.recovery_notice_codes {
                app_state.recovery_notices.write().await.insert(
                    login_result.auth_session.id.clone(),
                    PendingRecoveryNotice {
                        user_id: login_result.auth_session.user_id.clone(),
                        recovery_codes: recovery_notice_codes.clone(),
                    },
                );
            }

            let max_age = i64::from(settings.session_absolute_ttl_hours) * 3600;
            let redirect_target = if login_result.recovery_notice_codes.is_some()
                || login_result.requires_password_reset
            {
                security_settings_target()
            } else if login_result.requires_totp_setup {
                String::from("/settings/security/totp/setup")
            } else {
                login_redirect_target(language)
            };
            let mut response = Redirect::to(&redirect_target).into_response();
            let cookie_secure = effective_auth_cookie_secure(&settings, &headers);

            match set_cookie_header(&build_auth_cookie(
                &login_result.session_token,
                max_age,
                cookie_secure,
            )) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                    response
                }
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::LockedUntil(locked_until)) => {
            let message = login_locked_message(language, locked_until);
            match render_login_page(&app_state, language, Some(&message), &headers).await {
                Ok(html) => (StatusCode::TOO_MANY_REQUESTS, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::Banned { until_unix, reason }) => {
            let message = login_banned_message(language, until_unix, reason.as_deref());
            match render_login_page(&app_state, language, Some(&message), &headers).await {
                Ok(html) => (StatusCode::FORBIDDEN, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::MissingSecondFactor) => {
            let message = language.translations().login_require_mfa_message;
            match render_login_page(&app_state, language, Some(message), &headers).await {
                Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::InvalidSecondFactor) => {
            let message = language.translations().login_invalid_mfa_message;
            match render_login_page(&app_state, language, Some(message), &headers).await {
                Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::InvalidCredentials) => {
            match render_login_page(
                &app_state,
                language,
                Some(language.translations().login_error_invalid),
                &headers,
            )
            .await
            {
                Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
    }
}

async fn login_passkey_options_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasskeyStartLoginRequest>,
) -> Response {
    let language = detect_language(&headers, request.lang.as_deref());
    let translations = language.translations();
    let passkey_rp = match passkey_relying_party(&headers, language) {
        Ok(value) => value,
        Err(message) => return json_error_response(StatusCode::BAD_REQUEST, message),
    };
    let settings = app_state.system_settings.read().await.clone();
    let ip_address = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let challenge = match web_auth::begin_passkey_login(
        &app_state.meta_store,
        &settings,
        &request.username,
        &request.password,
        ip_address.as_deref(),
        user_agent.as_deref(),
    )
    .await
    {
        Ok(challenge) => challenge,
        Err(LoginError::LockedUntil(locked_until)) => {
            return json_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                login_locked_message(language, locked_until),
            );
        }
        Err(LoginError::Banned { until_unix, reason }) => {
            return json_error_response(
                StatusCode::FORBIDDEN,
                login_banned_message(language, until_unix, reason.as_deref()),
            );
        }
        Err(LoginError::MissingSecondFactor) => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_no_credentials_message,
            );
        }
        Err(LoginError::InvalidSecondFactor | LoginError::InvalidCredentials) => {
            return json_error_response(StatusCode::UNAUTHORIZED, translations.login_error_invalid);
        }
    };

    let rp_id = match passkey_rp_id(&passkey_rp.rp_id) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed parsing passkey rp id {} for {}: {}",
                passkey_rp.rp_id, challenge.user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };
    let descriptors = match web_auth::passkey_descriptors(&challenge.user) {
        Ok(value) if value.is_empty() => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_no_credentials_message,
            );
        }
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed loading passkey descriptors for {}: {}",
                challenge.user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };
    let mut allowed_credentials = AllowedCredentials::with_capacity(descriptors.len());
    for descriptor in descriptors {
        allowed_credentials.push(descriptor.into());
    }
    let mut request_options =
        match PublicKeyCredentialRequestOptions::second_factor(&rp_id, allowed_credentials) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    "failed configuring passkey authentication for {}: {}",
                    challenge.user.username, error
                );
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    translations.passkey_authentication_failed_message,
                );
            }
        };
    request_options.user_verification = UserVerificationRequirement::Required;
    let (state, client_state) = match request_options.start_ceremony() {
        Ok(values) => values,
        Err(error) => {
            warn!(
                "failed starting passkey authentication for {}: {}",
                challenge.user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };

    let request_id = Uuid::new_v4().to_string();
    let challenge_username = challenge.user.username.clone();
    app_state.passkey_authentications.write().await.insert(
        request_id.clone(),
        PendingPasskeyAuthentication {
            user_id: challenge.user.id,
            username: challenge.user.username,
            rp_id: passkey_rp.rp_id,
            origin: passkey_rp.origin,
            state,
            master_key: share_master_key(challenge.master_key),
            requires_totp_setup: challenge.requires_totp_setup,
            requires_password_reset: challenge.requires_password_reset,
        },
    );
    let options = match passkey_public_key_options(&client_state) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed serializing passkey authentication options for {}: {}",
                challenge_username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };

    Json(PasskeyChallengeResponse {
        request_id,
        options,
    })
    .into_response()
}

async fn login_passkey_finish_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasskeyFinishLoginRequest>,
) -> Response {
    let language = detect_language(&headers, request.lang.as_deref());
    let translations = language.translations();
    let Some(pending) = app_state
        .passkey_authentications
        .write()
        .await
        .remove(&request.request_id)
    else {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            translations.passkey_challenge_expired_message,
        );
    };
    let rp_id = match passkey_rp_id(&pending.rp_id) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed rebuilding passkey rp {} for {}: {}",
                pending.rp_id, pending.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };
    let allowed_origin = match passkey_allowed_origin(&pending.origin) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed rebuilding passkey origin {} for {}: {}",
                pending.origin, pending.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };
    let authentication: Authentication = match serde_json::from_value(request.credential) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed decoding passkey authentication payload for {}: {}",
                pending.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };
    let credential_id = authentication.raw_id().into();

    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&pending.user_id)
        .await
        .ok()
        .flatten()
    else {
        return json_error_response(StatusCode::UNAUTHORIZED, translations.login_error_invalid);
    };
    let passkey = match web_auth::passkey_authentication_material(&user, &credential_id) {
        Ok(Some(value)) => value,
        Ok(None) => {
            web_auth::record_login_failure(
                &app_state.meta_store,
                Some(&user.id),
                &user.username,
                extract_client_ip(&headers).as_deref(),
                extract_user_agent(&headers).as_deref(),
                "passkey_not_found",
                Some(web_auth::LOGIN_METHOD_PASSWORD_PASSKEY),
                None,
            )
            .await;
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_not_found_message,
            );
        }
        Err(error) => {
            warn!(
                "failed loading passkey material for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };
    let user_handle = match web_auth::user_handle_for(&user) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed constructing user handle for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };
    let mut credential = match AuthenticatedCredential::new(
        (&passkey.credential_id).into(),
        (&user_handle).into(),
        passkey.static_state,
        passkey.dynamic_state,
    ) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed constructing passkey credential for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    };
    let verification_options: AuthenticationVerificationOptions<
        '_,
        '_,
        DomainOrigin<'_, '_>,
        DomainOrigin<'_, '_>,
    > = AuthenticationVerificationOptions {
        allowed_origins: std::slice::from_ref(&allowed_origin),
        update_uv: true,
        ..AuthenticationVerificationOptions::default()
    };
    if let Err(error) = pending.state.verify(
        &rp_id,
        &authentication,
        &mut credential,
        &verification_options,
    ) {
        warn!(
            "failed finishing passkey authentication for {}: {}",
            pending.username, error
        );
        web_auth::record_login_failure(
            &app_state.meta_store,
            Some(&user.id),
            &user.username,
            extract_client_ip(&headers).as_deref(),
            extract_user_agent(&headers).as_deref(),
            "passkey_verification_failed",
            Some(web_auth::LOGIN_METHOD_PASSWORD_PASSKEY),
            Some(passkey.label.as_str()),
        )
        .await;
        return json_error_response(
            StatusCode::UNAUTHORIZED,
            translations.passkey_authentication_failed_message,
        );
    }
    let passkey_label = passkey.label;
    let updated_dynamic_state = credential.dynamic_state();
    match web_auth::update_user_passkey_usage(&mut user, &credential_id, updated_dynamic_state) {
        Ok(Some(_)) => {}
        Ok(None) => {
            web_auth::record_login_failure(
                &app_state.meta_store,
                Some(&user.id),
                &user.username,
                extract_client_ip(&headers).as_deref(),
                extract_user_agent(&headers).as_deref(),
                "passkey_not_found",
                Some(web_auth::LOGIN_METHOD_PASSWORD_PASSKEY),
                Some(passkey_label.as_str()),
            )
            .await;
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_not_found_message,
            );
        }
        Err(error) => {
            warn!(
                "failed updating passkey usage for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_authentication_failed_message,
            );
        }
    }
    user.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = app_state.meta_store.save_user(&user).await {
        warn!(
            "failed saving updated passkey usage for {}: {}",
            user.username, error
        );
        return json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            translations.passkey_authentication_failed_message,
        );
    }

    let mut master_key_bytes = [0_u8; 32];
    master_key_bytes.copy_from_slice(pending.master_key.as_ref().as_ref());
    let settings = app_state.system_settings.read().await.clone();
    let login_result = match web_auth::authenticate_user_with_passkey(
        &app_state.meta_store,
        &settings,
        user,
        zeroize::Zeroizing::new(master_key_bytes),
        pending.requires_totp_setup,
        pending.requires_password_reset,
        extract_client_ip(&headers).as_deref(),
        extract_user_agent(&headers).as_deref(),
        Some(passkey_label.as_str()),
    )
    .await
    {
        Ok(result) => result,
        Err(LoginError::LockedUntil(locked_until)) => {
            return json_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                login_locked_message(language, locked_until),
            );
        }
        Err(LoginError::Banned { until_unix, reason }) => {
            return json_error_response(
                StatusCode::FORBIDDEN,
                login_banned_message(language, until_unix, reason.as_deref()),
            );
        }
        Err(_) => {
            return json_error_response(
                StatusCode::UNAUTHORIZED,
                translations.passkey_authentication_failed_message,
            );
        }
    };

    cache_user_master_key(
        &app_state,
        &login_result.auth_session.user_id,
        &login_result.auth_session.id,
        login_result.master_key,
    )
    .await;

    let max_age = i64::from(settings.session_absolute_ttl_hours) * 3600;
    let redirect_target = if login_result.requires_password_reset {
        security_settings_target()
    } else if login_result.requires_totp_setup {
        String::from("/settings/security/totp/setup")
    } else {
        login_redirect_target(language)
    };
    let mut response = Json(PasskeyFinishResponse {
        redirect_to: redirect_target,
    })
    .into_response();
    let cookie_secure = effective_auth_cookie_secure(&settings, &headers);
    match set_cookie_header(&build_auth_cookie(
        &login_result.session_token,
        max_age,
        cookie_secure,
    )) {
        Ok(cookie) => {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(status) => status.into_response(),
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
        return Redirect::to("/login").into_response();
    }
    if form.password != form.confirm_password {
        let message = language.translations().password_fields_must_match_message;
        return match render_register_page(&app_state, language, Some(message), &headers).await {
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
            let mut response = Redirect::to("/settings/security/totp/setup").into_response();
            let cookie_secure = effective_auth_cookie_secure(&settings, &headers);
            match set_cookie_header(&build_auth_cookie(&session_token, max_age, cookie_secure)) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                    response
                }
                Err(status) => status.into_response(),
            }
        }
        Err(error) => {
            match render_register_page(&app_state, language, Some(&error.to_string()), &headers)
                .await
            {
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
    match render_settings_page(&app_state, &authenticated, language, None, &headers).await {
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
        let message = language
            .translations()
            .new_password_fields_must_match_message;
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(message)),
            &headers,
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
        return Redirect::to("/login").into_response();
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
                Some(PageBanner::success(
                    language.translations().password_updated_message,
                )),
                &headers,
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
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        },
    }
}

async fn start_passkey_registration_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(request): Json<PasskeyStartRegistrationRequest>,
) -> Response {
    let language = detect_language(&headers, request.lang.as_deref());
    let translations = language.translations();
    if authenticated.requires_password_reset {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            translations.settings_password_reset_required_message,
        );
    }
    let label = request.label.trim();
    if label.is_empty() {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            translations.passkey_label_required_message,
        );
    }
    let passkey_rp = match passkey_relying_party(&headers, language) {
        Ok(value) => value,
        Err(message) => return json_error_response(StatusCode::BAD_REQUEST, message),
    };
    let Some(user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return json_error_response(StatusCode::UNAUTHORIZED, translations.login_error_invalid);
    };
    let rp_id = match passkey_rp_id(&passkey_rp.rp_id) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed parsing passkey rp id {}: {}",
                passkey_rp.rp_id, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };
    let user_handle = match web_auth::user_handle_for(&user) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed constructing passkey user handle for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };
    let passkey_name = match user.username.as_str().try_into() {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed constructing passkey username for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };
    let passkey_display_name = match user.username.as_str().try_into() {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed constructing passkey display name for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };
    let user_entity = PublicKeyCredentialUserEntity {
        name: passkey_name,
        id: (&user_handle).into(),
        display_name: Some(passkey_display_name),
    };
    let exclude_credentials = match web_auth::passkey_descriptors(&user) {
        Ok(value) => value,
        Err(error) => {
            warn!("failed decoding passkeys for {}: {}", user.username, error);
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };
    let (state, client_state) = match PublicKeyCredentialCreationOptions::second_factor(
        &rp_id,
        user_entity,
        exclude_credentials,
    )
    .start_ceremony()
    {
        Ok(values) => values,
        Err(error) => {
            warn!(
                "failed starting passkey registration for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };

    let registration_id = Uuid::new_v4().to_string();
    app_state.passkey_registrations.write().await.insert(
        registration_id.clone(),
        PendingPasskeyRegistration {
            user_id: user.id,
            auth_session_id: authenticated.auth_session.id.clone(),
            label: label.to_owned(),
            rp_id: passkey_rp.rp_id,
            origin: passkey_rp.origin,
            state,
        },
    );
    let options = match passkey_public_key_options(&client_state) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed serializing passkey registration options for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };

    Json(PasskeyRegistrationChallengeResponse {
        registration_id,
        options,
    })
    .into_response()
}

async fn finish_passkey_registration_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(request): Json<PasskeyFinishRegistrationRequest>,
) -> Response {
    let language = detect_language(&headers, request.lang.as_deref());
    let translations = language.translations();
    if authenticated.requires_password_reset {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            translations.settings_password_reset_required_message,
        );
    }
    let Some(pending) = app_state
        .passkey_registrations
        .write()
        .await
        .remove(&request.registration_id)
    else {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            translations.passkey_challenge_expired_message,
        );
    };
    if pending.user_id != authenticated.user.id {
        return json_error_response(StatusCode::UNAUTHORIZED, translations.login_error_invalid);
    }

    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return json_error_response(StatusCode::UNAUTHORIZED, translations.login_error_invalid);
    };
    let rp_id = match passkey_rp_id(&pending.rp_id) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed rebuilding passkey rp {} for registration: {}",
                pending.rp_id, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };
    let allowed_origin = match passkey_allowed_origin(&pending.origin) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed rebuilding passkey origin {} for registration: {}",
                pending.origin, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };
    let user_handle = match web_auth::user_handle_for(&user) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed constructing passkey user handle for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    };
    let registration: Registration = match serde_json::from_value(request.credential) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed decoding passkey registration payload for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_incomplete_response_message,
            );
        }
    };
    let verification_options: RegistrationVerificationOptions<
        '_,
        '_,
        DomainOrigin<'_, '_>,
        DomainOrigin<'_, '_>,
    > = RegistrationVerificationOptions {
        allowed_origins: std::slice::from_ref(&allowed_origin),
        ..RegistrationVerificationOptions::default()
    };
    let registered = match pending.state.verify(
        &rp_id,
        (&user_handle).into(),
        &registration,
        &verification_options,
    ) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed finishing passkey registration for {}: {}",
                authenticated.user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                passkey_registration_error_message(translations, &error),
            );
        }
    };
    let (
        credential_id,
        transports,
        _registered_user_handle,
        static_state,
        dynamic_state,
        _metadata,
    ) = registered.into_parts();
    let credential_id_owned = credential_id.into();
    let duplicate_on_self =
        match web_auth::user_has_passkey_credential_id(&user, &credential_id_owned) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    "failed decoding current passkeys for {}: {}",
                    user.username, error
                );
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    translations.passkey_registration_failed_message,
                );
            }
        };
    if duplicate_on_self {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            translations.passkey_registration_failed_message,
        );
    }
    match web_auth::passkey_registered_to_other_user(
        &app_state.meta_store,
        &user.id,
        &credential_id_owned,
    )
    .await
    {
        Ok(true) => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
        Ok(false) => {}
        Err(error) => {
            warn!(
                "failed checking duplicate passkeys for {}: {}",
                user.username, error
            );
            return json_error_response(
                StatusCode::BAD_REQUEST,
                translations.passkey_registration_failed_message,
            );
        }
    }
    if let Err(error) = web_auth::add_passkey_to_user(
        &app_state.meta_store,
        &mut user,
        &pending.label,
        credential_id,
        transports,
        static_state,
        dynamic_state,
    )
    .await
    {
        warn!("failed saving passkey for {}: {}", user.username, error);
        return json_error_response(
            StatusCode::BAD_REQUEST,
            translations.passkey_registration_failed_message,
        );
    }

    Json(PasskeyFinishResponse {
        redirect_to: security_settings_target(),
    })
    .into_response()
}

async fn delete_passkey_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(passkey_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    if authenticated.requires_password_reset {
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language
                    .translations()
                    .settings_password_reset_required_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to("/login").into_response();
    };

    match web_auth::remove_passkey_from_user(&app_state.meta_store, &mut user, &passkey_id).await {
        Ok(true) => {
            let mut refreshed = authenticated.clone();
            refreshed.user = user;
            match render_settings_page(
                &app_state,
                &refreshed,
                language,
                Some(PageBanner::success(
                    language.translations().passkey_deleted_message,
                )),
                &headers,
            )
            .await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            }
        }
        Ok(false) => match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language.translations().passkey_not_found_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        },
        Err(error) => match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        },
    }
}

async fn acknowledge_recovery_notice_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
) -> Response {
    app_state
        .recovery_notices
        .write()
        .await
        .remove(&authenticated.auth_session.id);
    Redirect::to(&security_settings_target()).into_response()
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
        return Redirect::to("/login").into_response();
    };

    let preferred_idle_timeout_minutes =
        match parse_user_idle_timeout_preference(&form.idle_timeout_minutes, &settings) {
            Ok(value) => value,
            Err(error) => {
                return match render_settings_page(
                    &app_state,
                    &authenticated,
                    language,
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

    user.security.preferred_idle_timeout_minutes = preferred_idle_timeout_minutes;
    user.updated_at_unix = Utc::now().timestamp();

    if let Err(error) = app_state.meta_store.save_user(&user).await {
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
            &headers,
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
        Some(PageBanner::success(
            language.translations().idle_timeout_updated_message,
        )),
        &headers,
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
    match render_totp_setup_page(&app_state, &authenticated, language, None, &headers).await {
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
    match form.action.as_deref() {
        Some("start_rotation") => {
            app_state.totp_setups.write().await.insert(
                authenticated.auth_session.id.clone(),
                build_pending_totp_setup(&authenticated.user.username, true),
            );
            return match render_totp_setup_page(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::success(
                    language.translations().totp_rotation_start_message,
                )),
                &headers,
            )
            .await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            };
        }
        Some("cancel_rotation") => {
            app_state
                .totp_setups
                .write()
                .await
                .remove(&authenticated.auth_session.id);
            return match render_totp_setup_page(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::success(
                    language.translations().totp_rotation_cancelled_message,
                )),
                &headers,
            )
            .await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            };
        }
        _ => {}
    }

    let code = form.code.as_deref().unwrap_or_default().trim();
    if code.is_empty() {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language.translations().totp_setup_enter_code_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let pending = {
        let mut setups = app_state.totp_setups.write().await;
        if authenticated.user.security.totp_enabled {
            match setups.get(&authenticated.auth_session.id).cloned() {
                Some(pending) => pending,
                None => {
                    return match render_totp_setup_page(
                        &app_state,
                        &authenticated,
                        language,
                        Some(PageBanner::error(
                            language.translations().totp_rotation_not_started_message,
                        )),
                        &headers,
                    )
                    .await
                    {
                        Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                        Err(status) => status.into_response(),
                    };
                }
            }
        } else {
            setups
                .entry(authenticated.auth_session.id.clone())
                .or_insert_with(|| build_pending_totp_setup(&authenticated.user.username, false))
                .clone()
        }
    };
    let confirmations_ready = form.confirm_saved_codes.as_deref() == Some("1")
        && (!pending.is_rotation
            || (form.confirm_replace_totp.as_deref() == Some("1")
                && form.confirm_replace_recovery.as_deref() == Some("1")));
    if !confirmations_ready {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language
                    .translations()
                    .totp_setup_confirm_checks_required_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
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
            Some(PageBanner::error(
                language.translations().totp_setup_code_mismatch_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let Some(master_key) = resolved_user_master_key(&app_state, &authenticated).await else {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language.translations().unlock_state_expired_message,
            )),
            &headers,
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
        return Redirect::to("/login").into_response();
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
            let mut refreshed = authenticated.clone();
            refreshed.user = user;
            refreshed.recovery_codes_remaining = pending.recovery_codes.len() as i64;
            refreshed.requires_totp_setup = false;
            match render_totp_setup_page(
                &app_state,
                &refreshed,
                language,
                Some(PageBanner::success(
                    language.translations().totp_updated_message,
                )),
                &headers,
            )
            .await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(error) => match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        },
    }
}

async fn logout_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let _language = detect_language(&headers, query.lang.as_deref());
    let mut response = Redirect::to("/login").into_response();
    let settings = app_state.system_settings.read().await.clone();
    let cookie_secure = effective_auth_cookie_secure(&settings, &headers);
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

    match set_cookie_header(&clear_auth_cookie(cookie_secure)) {
        Ok(cookie) => {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(status) => status.into_response(),
    }
}
