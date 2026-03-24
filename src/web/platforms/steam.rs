// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::web::shared::*;

pub(crate) async fn build_workspace_card(
    _app_state: &AppState,
    _authenticated: &AuthenticatedSession,
    language: Language,
) -> PlatformWorkspaceCardView {
    let translations = language.translations();
    PlatformWorkspaceCardView {
        id: String::from("steam"),
        name: translations.steam_platform_name.to_owned(),
        description: translations.steam_platform_description.to_owned(),
        total_count: 0,
        connected_count: 0,
        attention_count: 0,
        workspace_href: steam_workspace_href(language),
        secondary_href: format!("{}#modules", steam_workspace_href(language)),
        secondary_label: translations
            .steam_workspace_secondary_action_label
            .to_owned(),
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route(STEAM_WORKSPACE_PATH, get(workspace_handler))
}

pub(crate) async fn render_workspace_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, STEAM_WORKSPACE_PATH);
    let settings_page_href = settings_href(language);
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("current_username", &authenticated.user.username);
    context.insert("show_admin", &(authenticated.user.role == UserRole::Admin));
    context.insert("logout_action", "/logout");
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("workspace_href", &steam_workspace_href(language));
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
    context.insert("now", &now);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "steam_workspace.html", &context)
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
