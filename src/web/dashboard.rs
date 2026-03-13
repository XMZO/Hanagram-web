// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::shared::*;

fn localized_session_error(
    error_kind: Option<SessionErrorKind>,
    translations: &crate::i18n::TranslationSet,
) -> Option<String> {
    let message = match error_kind? {
        SessionErrorKind::UnlockRequired => translations.session_worker_unlock_required_message,
        SessionErrorKind::TelegramApiMissing => translations.telegram_api_missing_message,
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

fn build_dashboard_session_view(
    session: SessionInfo,
    translations: &crate::i18n::TranslationSet,
) -> DashboardSessionView {
    let latest_message_at = session.latest_message().map(|message| {
        message
            .received_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string()
    });
    let latest_code_at_unix = session
        .latest_code_message()
        .map(|message| message.received_at.timestamp());
    let recent_messages = session
        .recent_messages()
        .into_iter()
        .map(|message| DashboardMessageView {
            received_at: message
                .received_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            text: message.text,
            code: message.code,
        })
        .collect();
    let phone = localized_session_phone(&session.phone, translations);
    let session_file = session.session_file.display().to_string();
    let status = DashboardStatusView {
        kind: session.status.kind(),
        connected: session.status.is_connected(),
        error: localized_session_error(session.status.error_kind().copied(), translations),
    };
    let latest_code = session.latest_code().map(str::to_owned);

    DashboardSessionView {
        id: session.id,
        key: session.key,
        note: session.note,
        phone,
        session_file,
        status,
        latest_code,
        latest_message_at,
        latest_code_at_unix,
        recent_messages,
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/dashboard/snapshot", get(dashboard_snapshot_handler))
}

async fn build_dashboard_snapshot(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
) -> DashboardSnapshot {
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
        .map(|session| build_dashboard_session_view(session, translations))
        .collect();

    DashboardSnapshot {
        total_count,
        connected_count,
        connecting_count,
        error_count,
        generated_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        sessions,
    }
}

pub(crate) async fn render_dashboard_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/");
    let snapshot = build_dashboard_snapshot(app_state, authenticated, language).await;
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
        .take(8)
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
    context.insert("setup_href", &setup_href(language));
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
    context.insert("snapshot_api", "/api/dashboard/snapshot");
    context.insert(
        "dashboard_incremental_refresh_seconds",
        &DASHBOARD_INCREMENTAL_SYNC_SECONDS,
    );
    context.insert(
        "dashboard_full_refresh_seconds",
        &DASHBOARD_FULL_SYNC_SECONDS,
    );
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "index.html", &context)
}

async fn index_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let language = detect_language(&headers, query.lang.as_deref());
    render_dashboard_page(&app_state, &authenticated, language, None, &headers).await
}

async fn dashboard_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Json<DashboardSnapshot> {
    let language = detect_language(&headers, query.lang.as_deref());
    Json(build_dashboard_snapshot(&app_state, &authenticated, language).await)
}
