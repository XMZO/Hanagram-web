// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::platforms::telegram;
use super::shared::*;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/", get(home_handler))
}

pub(crate) async fn render_dashboard_home_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/");
    let platforms = vec![telegram::build_workspace_card(app_state, authenticated, language).await];
    let settings_page_href = settings_href(language);
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("current_username", &authenticated.user.username);
    context.insert("show_admin", &(authenticated.user.role == UserRole::Admin));
    context.insert("logout_action", "/logout");
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
    context.insert("platforms", &platforms);
    context.insert("now", &now);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "dashboard_home.html", &context)
}

async fn home_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let language = detect_language(&headers, query.lang.as_deref());
    render_dashboard_home_page(&app_state, &authenticated, language, None, &headers).await
}
