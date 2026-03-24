// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::web::shared::*;
use crate::web::telegram_workspace;

fn localized_session_error(
    error_kind: Option<SessionErrorKind>,
    translations: &crate::i18n::TranslationSet,
) -> Option<String> {
    let message = match error_kind? {
        SessionErrorKind::UnlockRequired => translations.session_worker_unlock_required_message,
        SessionErrorKind::UnlockFailed => translations.session_worker_unlock_failed_message,
        SessionErrorKind::Unauthorized => translations.session_worker_unauthorized_message,
        SessionErrorKind::LoadFailed => translations.session_worker_load_failed_message,
        SessionErrorKind::UpdateFailed => translations.session_worker_update_failed_message,
    };
    Some(message.to_owned())
}

fn localized_session_phone(phone: &str, translations: &crate::i18n::TranslationSet) -> String {
    let trimmed = phone.trim();
    if trimmed.is_empty() {
        translations.session_phone_unknown_label.to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn mask_session_phone(phone: &str) -> String {
    let digit_count = phone.chars().filter(|ch| ch.is_ascii_digit()).count();
    if digit_count <= 4 {
        return phone.to_owned();
    }

    let keep_start = if digit_count > 11 {
        5
    } else if digit_count > 7 {
        4
    } else {
        2
    };
    let keep_end = if digit_count > 7 { 4 } else { 2 };
    let mask_start = keep_start.min(digit_count.saturating_sub(keep_end));
    let mask_end = digit_count.saturating_sub(keep_end);
    if mask_start >= mask_end {
        return phone.to_owned();
    }

    let mut digit_index = 0usize;
    phone
        .chars()
        .map(|ch| {
            if ch.is_ascii_digit() {
                let current = digit_index;
                digit_index += 1;
                if current >= mask_start && current < mask_end {
                    '*'
                } else {
                    ch
                }
            } else {
                ch
            }
        })
        .collect()
}

fn build_workspace_session_view(
    session: SessionInfo,
    translations: &crate::i18n::TranslationSet,
) -> TelegramWorkspaceSessionView {
    let latest_message_at = session.latest_message().map(|message| {
        message
            .received_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string()
    });
    let now_unix = Utc::now().timestamp();
    let (latest_code, latest_code_at_unix, latest_code_expires_at_unix) =
        match session.latest_code_message() {
            Some(message) => {
                let latest_code_at_unix = message.received_at.timestamp();
                let latest_code_expires_at_unix =
                    latest_code_at_unix.saturating_add(TELEGRAM_OTP_VISIBILITY_SECONDS);
                let latest_code = (latest_code_expires_at_unix > now_unix)
                    .then(|| message.code.clone())
                    .flatten();
                (
                    latest_code,
                    Some(latest_code_at_unix),
                    Some(latest_code_expires_at_unix),
                )
            }
            None => (None, None, None),
        };
    let recent_messages = session
        .recent_messages()
        .into_iter()
        .map(|message| TelegramWorkspaceMessageView {
            received_at: message
                .received_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            text: message.text,
            code: message.code,
        })
        .collect();
    let phone = localized_session_phone(&session.phone, translations);
    let masked_phone = mask_session_phone(&phone);
    let session_file = session.session_file.display().to_string();
    let status = TelegramWorkspaceStatusView {
        kind: session.status.kind(),
        connected: session.status.is_connected(),
        error: localized_session_error(session.status.error_kind().copied(), translations),
    };

    TelegramWorkspaceSessionView {
        id: session.id,
        key: session.key,
        note: session.note,
        phone,
        masked_phone,
        session_file,
        status,
        latest_code,
        latest_message_at,
        latest_code_at_unix,
        latest_code_expires_at_unix,
        recent_messages,
    }
}

async fn build_workspace_snapshot(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
) -> TelegramWorkspaceSnapshot {
    let session_records = {
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
    let translations = language.translations();

    let total_count = session_records.len();
    let connected_count = session_records
        .iter()
        .filter(|session| matches!(session.status, SessionStatus::Connected))
        .count();
    let connecting_count = session_records
        .iter()
        .filter(|session| matches!(session.status, SessionStatus::Connecting))
        .count();
    let error_count = session_records
        .iter()
        .filter(|session| matches!(session.status, SessionStatus::Error(_)))
        .count();
    let sessions = session_records
        .into_iter()
        .map(|session| build_workspace_session_view(session, translations))
        .collect();

    TelegramWorkspaceSnapshot {
        total_count,
        connected_count,
        connecting_count,
        error_count,
        generated_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        sessions,
    }
}

pub(crate) async fn build_workspace_card(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
) -> PlatformWorkspaceCardView {
    let snapshot = build_workspace_snapshot(app_state, authenticated, language).await;
    let translations = language.translations();
    PlatformWorkspaceCardView {
        id: String::from("telegram"),
        name: translations.dashboard_nav_sessions.to_owned(),
        description: translations.dashboard_sessions_description.to_owned(),
        total_count: snapshot.total_count,
        connected_count: snapshot.connected_count,
        attention_count: snapshot.connecting_count + snapshot.error_count,
        workspace_href: telegram_workspace_href(language),
        setup_href: telegram_setup_href(language),
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(TELEGRAM_WORKSPACE_PATH, get(workspace_handler))
        .route(TELEGRAM_SNAPSHOT_API_PATH, get(workspace_snapshot_handler))
        .route("/api/dashboard/snapshot", get(workspace_snapshot_handler))
        .merge(telegram_workspace::routes())
}

pub(crate) async fn render_workspace_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, TELEGRAM_WORKSPACE_PATH);
    let snapshot = build_workspace_snapshot(app_state, authenticated, language).await;
    let attention_sessions = snapshot
        .sessions
        .iter()
        .filter(|session| session.status.kind != "connected")
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    let recent_activity_sessions = snapshot
        .sessions
        .iter()
        .take(12)
        .cloned()
        .collect::<Vec<_>>();
    let settings_page_href = settings_href(language);

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("current_username", &authenticated.user.username);
    context.insert("show_admin", &(authenticated.user.role == UserRole::Admin));
    context.insert("logout_action", "/logout");
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("setup_href", &telegram_setup_href(language));
    context.insert("settings_href", &settings_page_href);
    context.insert("admin_href", &admin_href(language));
    context.insert("settings_label", &translations.nav_settings_label);
    context.insert("admin_label", &translations.nav_admin_label);
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
        &format!("{}#users", admin_href(language)),
    );
    context.insert("banner", &banner);
    context.insert("sessions", &snapshot.sessions);
    context.insert("attention_sessions", &attention_sessions);
    context.insert("recent_activity_sessions", &recent_activity_sessions);
    context.insert("total_sessions", &snapshot.total_count);
    context.insert("connected_count", &snapshot.connected_count);
    context.insert("connecting_count", &snapshot.connecting_count);
    context.insert("error_count", &snapshot.error_count);
    context.insert(
        "attention_count",
        &(snapshot.connecting_count + snapshot.error_count),
    );
    context.insert("now", &snapshot.generated_at);
    context.insert("snapshot_api", &telegram_snapshot_api_href(language));
    context.insert(
        "telegram_workspace_incremental_refresh_seconds",
        &TELEGRAM_WORKSPACE_INCREMENTAL_SYNC_SECONDS,
    );
    context.insert(
        "telegram_workspace_full_refresh_seconds",
        &TELEGRAM_WORKSPACE_FULL_SYNC_SECONDS,
    );
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "telegram_workspace.html", &context)
}

async fn workspace_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let language = detect_language(&headers, query.lang.as_deref());
    render_workspace_page(&app_state, &authenticated, language, None, &headers).await
}

async fn workspace_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Json<TelegramWorkspaceSnapshot> {
    let language = detect_language(&headers, query.lang.as_deref());
    Json(build_workspace_snapshot(&app_state, &authenticated, language).await)
}

pub(crate) use telegram_workspace::{register_session_record, unlock_user_sessions};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_session_phone_hides_middle_digits_but_keeps_formatting() {
        assert_eq!(mask_session_phone("+86 138 0000 0000"), "+86 138 **** 0000");
        assert_eq!(mask_session_phone("+1 314 628 8470"), "+1 314 *** 8470");
        assert_eq!(mask_session_phone("未知"), "未知");
    }

    #[test]
    fn build_workspace_session_view_sets_visibility_expiry_for_fresh_codes() {
        let received_at = Utc::now() - TimeDelta::seconds(15);
        let view = build_workspace_session_view(
            SessionInfo {
                id: String::from("session-1"),
                user_id: String::from("user-1"),
                key: String::from("alpha"),
                note: String::new(),
                phone: String::from("+86 138 0000 0000"),
                session_file: PathBuf::from("sessions/alpha.session"),
                status: SessionStatus::Connected,
                messages: VecDeque::from([OtpMessage {
                    received_at,
                    text: String::from("Telegram code: 123456"),
                    code: Some(String::from("123456")),
                }]),
            },
            Language::ZhCn.translations(),
        );

        assert_eq!(view.latest_code.as_deref(), Some("123456"));
        assert_eq!(view.latest_code_at_unix, Some(received_at.timestamp()));
        assert_eq!(
            view.latest_code_expires_at_unix,
            Some(received_at.timestamp() + TELEGRAM_OTP_VISIBILITY_SECONDS)
        );
    }

    #[test]
    fn build_workspace_session_view_hides_expired_code_but_keeps_history() {
        let received_at = Utc::now() - TimeDelta::seconds(TELEGRAM_OTP_VISIBILITY_SECONDS + 5);
        let view = build_workspace_session_view(
            SessionInfo {
                id: String::from("session-1"),
                user_id: String::from("user-1"),
                key: String::from("alpha"),
                note: String::new(),
                phone: String::from("+86 138 0000 0000"),
                session_file: PathBuf::from("sessions/alpha.session"),
                status: SessionStatus::Connected,
                messages: VecDeque::from([OtpMessage {
                    received_at,
                    text: String::from("Telegram code: 123456"),
                    code: Some(String::from("123456")),
                }]),
            },
            Language::ZhCn.translations(),
        );

        assert_eq!(view.latest_code, None);
        assert_eq!(view.latest_code_at_unix, Some(received_at.timestamp()));
        assert_eq!(
            view.latest_code_expires_at_unix,
            Some(received_at.timestamp() + TELEGRAM_OTP_VISIBILITY_SECONDS)
        );
        assert_eq!(view.recent_messages[0].code.as_deref(), Some("123456"));
    }
}
