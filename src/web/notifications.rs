// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::{admin, auth};
use super::shared::*;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/settings/notifications",
            get(notification_settings_page_handler),
        )
        .route("/settings/bot", post(save_bot_settings_handler))
}

pub(crate) async fn maybe_dispatch_bot_notification(
    meta_store: &MetaStoreHandle,
    http_client: &HttpClient,
    session: &SessionInfo,
    otp: &OtpMessage,
) {
    let Some(code) = otp.code.clone() else {
        return;
    };

    let settings = match meta_store.get_user_by_id(&session.user_id).await {
        Ok(Some(user)) => normalized_bot_settings(user.security.bot_notification_settings),
        Ok(None) => return,
        Err(error) => {
            warn!(
                "failed loading bot settings for user {}: {}",
                session.user_id, error
            );
            return;
        }
    };
    if !bot_settings_ready(&settings) {
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

fn current_user_bot_settings(user: &hanagram_web::store::UserRecord) -> BotNotificationSettings {
    normalized_bot_settings(user.security.bot_notification_settings.clone())
}

async fn render_notification_settings_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let bot_settings = current_user_bot_settings(&authenticated.user);
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
    return_to: Option<&str>,
) -> std::result::Result<Html<String>, StatusCode> {
    match return_to {
        Some("settings") => auth::render_settings_page(app_state, authenticated, language, banner).await,
        Some("admin") if authenticated.user.role == UserRole::Admin => {
            admin::render_admin_page(app_state, authenticated, language, banner).await
        }
        _ => render_notification_settings_page(app_state, authenticated, language, banner).await,
    }
}

fn authenticated_with_bot_settings(
    authenticated: &AuthenticatedSession,
    settings: BotNotificationSettings,
) -> AuthenticatedSession {
    let mut refreshed = authenticated.clone();
    refreshed.user.security.bot_notification_settings = settings;
    refreshed
}

async fn notification_settings_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    match render_notification_settings_page(&app_state, &authenticated, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn save_bot_settings_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<BotNotificationSettingsForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let return_to = form.return_to.as_deref();
    let settings = normalized_bot_settings(BotNotificationSettings {
        enabled: form.enabled.is_some(),
        bot_token: form.bot_token,
        chat_id: form.chat_id,
        template: form.template,
    });
    let preview_authenticated = authenticated_with_bot_settings(&authenticated, settings.clone());

    if settings.enabled && settings.bot_token.is_empty() {
        return match render_notification_workspace_page(
            &app_state,
            &preview_authenticated,
            language,
            Some(PageBanner::error(translations.bot_error_missing_token)),
            return_to,
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
            &preview_authenticated,
            language,
            Some(PageBanner::error(translations.bot_error_missing_chat_id)),
            return_to,
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
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    };
    user.security.bot_notification_settings = settings.clone();
    user.updated_at_unix = Utc::now().timestamp();

    if let Err(error) = app_state.meta_store.save_user(&user).await {
        warn!("failed saving per-user bot settings: {}", error);
        return match render_notification_workspace_page(
            &app_state,
            &preview_authenticated,
            language,
            Some(PageBanner::error(translations.bot_error_save)),
            return_to,
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let mut refreshed = authenticated.clone();
    refreshed.user = user;

    match render_notification_workspace_page(
        &app_state,
        &refreshed,
        language,
        Some(PageBanner::success(translations.bot_saved)),
        return_to,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
