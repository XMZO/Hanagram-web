// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::platforms::steam as steam_platform;
use crate::web::middleware;
use crate::web::shared::*;

#[derive(Clone, Debug, Serialize)]
struct SteamAccountView {
    id: String,
    account_name: String,
    steam_id: Option<String>,
    storage_file: String,
    current_code: Option<String>,
    code_started_at_unix: Option<i64>,
    code_expires_at_unix: Option<i64>,
    encrypted_at_rest: bool,
    can_manage: bool,
    is_manual_entry: bool,
    is_uploaded_mafile: bool,
    is_legacy_mafile: bool,
    has_identity_secret: bool,
    has_confirmation_secret_material: bool,
    has_confirmation_session: bool,
    confirmation_ready: bool,
    imported_from: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    update_material_action: Option<String>,
    rename_action: Option<String>,
    delete_action: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SteamIssueView {
    storage_file: String,
    error: String,
}

#[derive(Clone, Debug, Serialize)]
struct SteamWorkspaceSnapshot {
    total_count: usize,
    ready_count: usize,
    managed_count: usize,
    encrypted_count: usize,
    confirmation_ready_count: usize,
    issue_count: usize,
    generated_at: String,
    generated_at_unix: i64,
    code_period_seconds: i64,
    accounts: Vec<SteamAccountView>,
    issues: Vec<SteamIssueView>,
}

#[derive(Clone, Debug, Serialize)]
struct SteamConfirmationView {
    id: String,
    nonce: String,
    creator_id: String,
    confirmation_type: u32,
    type_name: String,
    headline: String,
    summary: Vec<String>,
    icon: Option<String>,
    created_at: String,
    accept_action: String,
    deny_action: String,
}

#[derive(Clone, Debug, Serialize)]
struct SteamConfirmationAccountView {
    account_id: String,
    account_name: String,
    steam_id: Option<String>,
    confirmation_count: usize,
    error: Option<String>,
    confirmations: Vec<SteamConfirmationView>,
}

#[derive(Clone, Debug, Serialize)]
struct SteamConfirmationSnapshot {
    ready_account_count: usize,
    confirmation_count: usize,
    generated_at: String,
    accounts: Vec<SteamConfirmationAccountView>,
}

#[derive(Clone, Debug, Serialize)]
struct SteamActionResponse {
    ok: bool,
    message: String,
}

#[derive(Debug, Default, Deserialize)]
struct ManualSteamAccountForm {
    account_name: String,
    steam_id: String,
    shared_secret: String,
    identity_secret: String,
    device_id: String,
    steam_login_secure: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RenameSteamAccountForm {
    account_name: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateSteamMaterialForm {
    shared_secret: String,
    identity_secret: String,
    device_id: String,
    steam_login_secure: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamConfirmationActionForm {
    nonce: String,
    lang: Option<String>,
}

const STEAM_CODES_TAB_ID: &str = "codes";
const STEAM_MANAGE_TAB_ID: &str = "manage";

fn steam_accounts_dir(runtime: &RuntimeConfig, user_id: &str) -> PathBuf {
    runtime.users_dir.join(user_id).join("steam")
}

fn display_storage_path(base_dir: &Path, path: &Path) -> String {
    path.strip_prefix(base_dir)
        .map(|relative| {
            if relative.as_os_str().is_empty() {
                path.display().to_string()
            } else {
                relative.display().to_string()
            }
        })
        .unwrap_or_else(|_| path.display().to_string())
}

fn account_rename_action(account_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/rename")
}

fn account_delete_action(account_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/delete")
}

fn account_update_material_action(account_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/materials")
}

fn confirmation_accept_action(account_id: &str, confirmation_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/confirmations/{confirmation_id}/accept")
}

fn confirmation_deny_action(account_id: &str, confirmation_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/confirmations/{confirmation_id}/deny")
}

async fn build_workspace_snapshot(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
) -> SteamWorkspaceSnapshot {
    let base_dir = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let shared_master_key = middleware::resolved_user_master_key(app_state, authenticated).await;
    let (accounts, issues) = steam_platform::discover_accounts(
        &base_dir,
        shared_master_key
            .as_ref()
            .map(|value| value.as_ref().as_slice()),
    )
    .await;

    let generated_at_unix = Utc::now().timestamp().max(0);
    let code_started_at_unix = generated_at_unix
        .div_euclid(steam_platform::STEAM_GUARD_CODE_PERIOD_SECONDS)
        * steam_platform::STEAM_GUARD_CODE_PERIOD_SECONDS;
    let code_expires_at_unix =
        code_started_at_unix + steam_platform::STEAM_GUARD_CODE_PERIOD_SECONDS;

    let mut account_views = Vec::new();
    let mut issue_views = issues
        .into_iter()
        .map(|issue| SteamIssueView {
            storage_file: display_storage_path(&base_dir, &issue.storage_path),
            error: issue.error,
        })
        .collect::<Vec<_>>();

    for account in accounts {
        let current_code =
            match steam_platform::generate_guard_code(&account.shared_secret, generated_at_unix) {
                Ok(code) => Some(code),
                Err(error) => {
                    issue_views.push(SteamIssueView {
                        storage_file: display_storage_path(&base_dir, &account.storage_path),
                        error: error.to_string(),
                    });
                    None
                }
            };
        let can_manage = account.can_manage();
        let is_manual_entry =
            account.managed_origin == Some(steam_platform::SteamManagedAccountOrigin::ManualEntry);
        let is_uploaded_mafile = account.managed_origin
            == Some(steam_platform::SteamManagedAccountOrigin::UploadedMaFile);
        let is_legacy_mafile = matches!(
            account.source_kind,
            steam_platform::SteamAccountSourceKind::LegacyMaFile
        );
        let has_identity_secret = account.has_identity_secret();
        let has_confirmation_secret_material = account.has_confirmation_secret_material();
        let has_confirmation_session = account.has_confirmation_session();
        let confirmation_ready = account.confirmation_ready();
        let update_material_action =
            can_manage.then(|| account_update_material_action(&account.id));
        let rename_action = can_manage.then(|| account_rename_action(&account.id));
        let delete_action = can_manage.then(|| account_delete_action(&account.id));
        let code_started_at_unix_view = current_code.as_ref().map(|_| code_started_at_unix);
        let code_expires_at_unix_view = current_code.as_ref().map(|_| code_expires_at_unix);
        account_views.push(SteamAccountView {
            id: account.id.clone(),
            account_name: account.account_name,
            steam_id: account.steam_id.map(|value| value.to_string()),
            storage_file: display_storage_path(&base_dir, &account.storage_path),
            current_code,
            code_started_at_unix: code_started_at_unix_view,
            code_expires_at_unix: code_expires_at_unix_view,
            encrypted_at_rest: account.encrypted_at_rest,
            can_manage,
            is_manual_entry,
            is_uploaded_mafile,
            is_legacy_mafile,
            has_identity_secret,
            has_confirmation_secret_material,
            has_confirmation_session,
            confirmation_ready,
            imported_from: account.imported_from,
            created_at: account.created_at_unix.map(format_unix_timestamp),
            updated_at: account.updated_at_unix.map(format_unix_timestamp),
            update_material_action,
            rename_action,
            delete_action,
        });
    }

    account_views.sort_by(|left, right| {
        right
            .can_manage
            .cmp(&left.can_manage)
            .then_with(|| left.account_name.cmp(&right.account_name))
            .then_with(|| left.storage_file.cmp(&right.storage_file))
    });
    issue_views.sort_by(|left, right| left.storage_file.cmp(&right.storage_file));

    SteamWorkspaceSnapshot {
        total_count: account_views.len(),
        ready_count: account_views
            .iter()
            .filter(|account| account.current_code.is_some())
            .count(),
        managed_count: account_views
            .iter()
            .filter(|account| account.can_manage)
            .count(),
        encrypted_count: account_views
            .iter()
            .filter(|account| account.encrypted_at_rest)
            .count(),
        confirmation_ready_count: account_views
            .iter()
            .filter(|account| account.confirmation_ready)
            .count(),
        issue_count: issue_views.len(),
        generated_at: format_unix_timestamp(generated_at_unix),
        generated_at_unix,
        code_period_seconds: steam_platform::STEAM_GUARD_CODE_PERIOD_SECONDS,
        accounts: account_views,
        issues: issue_views,
    }
}

async fn build_confirmation_snapshot(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
) -> Result<SteamConfirmationSnapshot> {
    let base_dir = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let shared_master_key = middleware::resolved_user_master_key(app_state, authenticated)
        .await
        .context("user data is locked; sign in again to unlock it")?;
    let (accounts, _) =
        steam_platform::discover_accounts(&base_dir, Some(shared_master_key.as_ref().as_slice()))
            .await;
    let ready_accounts = accounts
        .into_iter()
        .filter(|account| account.can_manage() && account.confirmation_ready())
        .collect::<Vec<_>>();

    let mut account_views = Vec::new();
    let generated_at_unix = Utc::now().timestamp().max(0);
    let mut total_confirmations = 0usize;
    for account in ready_accounts {
        match steam_platform::fetch_confirmations(&app_state.http_client, &account).await {
            Ok(confirmations) => {
                let confirmation_views = confirmations
                    .into_iter()
                    .map(|confirmation| SteamConfirmationView {
                        accept_action: confirmation_accept_action(&account.id, &confirmation.id),
                        deny_action: confirmation_deny_action(&account.id, &confirmation.id),
                        id: confirmation.id,
                        nonce: confirmation.nonce,
                        creator_id: confirmation.creator_id,
                        confirmation_type: confirmation.confirmation_type,
                        type_name: confirmation.type_name,
                        headline: confirmation.headline,
                        summary: confirmation.summary,
                        icon: confirmation.icon,
                        created_at: format_unix_timestamp(confirmation.created_at_unix as i64),
                    })
                    .collect::<Vec<_>>();
                total_confirmations += confirmation_views.len();
                account_views.push(SteamConfirmationAccountView {
                    account_id: account.id,
                    account_name: account.account_name,
                    steam_id: account.steam_id.map(|value| value.to_string()),
                    confirmation_count: confirmation_views.len(),
                    error: None,
                    confirmations: confirmation_views,
                });
            }
            Err(error) => account_views.push(SteamConfirmationAccountView {
                account_id: account.id,
                account_name: account.account_name,
                steam_id: account.steam_id.map(|value| value.to_string()),
                confirmation_count: 0,
                error: Some(error.to_string()),
                confirmations: Vec::new(),
            }),
        }
    }
    account_views.sort_by(|left, right| left.account_name.cmp(&right.account_name));
    Ok(SteamConfirmationSnapshot {
        ready_account_count: account_views.len(),
        confirmation_count: total_confirmations,
        generated_at: format_unix_timestamp(generated_at_unix),
        accounts: account_views,
    })
}

pub(crate) async fn build_workspace_card(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
) -> PlatformWorkspaceCardView {
    let snapshot = build_workspace_snapshot(app_state, authenticated).await;
    let translations = language.translations();
    PlatformWorkspaceCardView {
        id: String::from("steam"),
        name: translations.steam_platform_name.to_owned(),
        description: translations.steam_platform_description.to_owned(),
        total_count: snapshot.total_count,
        connected_count: snapshot.ready_count,
        attention_count: snapshot.issue_count,
        workspace_href: steam_workspace_href(language),
        secondary_href: format!("{}#manage", steam_workspace_href(language)),
        secondary_label: translations.steam_manage_tab_label.to_owned(),
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(STEAM_WORKSPACE_PATH, get(workspace_handler))
        .route(STEAM_SNAPSHOT_API_PATH, get(workspace_snapshot_handler))
        .route(
            STEAM_CONFIRMATIONS_API_PATH,
            get(confirmations_snapshot_handler),
        )
        .route(STEAM_IMPORT_UPLOAD_PATH, post(import_mafile_handler))
        .route(
            STEAM_IMPORT_MANUAL_PATH,
            post(create_manual_account_handler),
        )
        .route(
            "/platforms/steam/accounts/{account_id}/materials",
            post(update_account_materials_handler),
        )
        .route(
            "/platforms/steam/accounts/{account_id}/rename",
            post(rename_account_handler),
        )
        .route(
            "/platforms/steam/accounts/{account_id}/delete",
            post(delete_account_handler),
        )
        .route(
            "/platforms/steam/accounts/{account_id}/confirmations/{confirmation_id}/accept",
            post(accept_confirmation_handler),
        )
        .route(
            "/platforms/steam/accounts/{account_id}/confirmations/{confirmation_id}/deny",
            post(deny_confirmation_handler),
        )
}

pub(crate) async fn render_workspace_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    default_tab: Option<&str>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, STEAM_WORKSPACE_PATH);
    let settings_page_href = settings_href(language);
    let snapshot = build_workspace_snapshot(app_state, authenticated).await;
    let scan_dir = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let managed_dir = steam_platform::managed_accounts_dir(&scan_dir);

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
    context.insert("default_tab", &default_tab.unwrap_or(STEAM_CODES_TAB_ID));
    context.insert("now", &snapshot.generated_at);
    context.insert("snapshot_api", &steam_snapshot_api_href(language));
    context.insert("confirmations_api", &steam_confirmations_api_href(language));
    context.insert(
        "steam_import_upload_action",
        &steam_import_upload_href(language),
    );
    context.insert(
        "steam_import_manual_action",
        &steam_import_manual_href(language),
    );
    context.insert("steam_accounts_dir", &scan_dir.display().to_string());
    context.insert("steam_managed_dir", &managed_dir.display().to_string());
    context.insert("total_accounts", &snapshot.total_count);
    context.insert("ready_accounts", &snapshot.ready_count);
    context.insert("managed_accounts", &snapshot.managed_count);
    context.insert("encrypted_accounts", &snapshot.encrypted_count);
    context.insert(
        "confirmation_ready_accounts",
        &snapshot.confirmation_ready_count,
    );
    context.insert("issue_count", &snapshot.issue_count);
    context.insert("snapshot", &snapshot);
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
    render_workspace_page(&app_state, &authenticated, language, None, None, &headers).await
}

async fn workspace_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Json<SteamWorkspaceSnapshot> {
    let _language = detect_language(&headers, query.lang.as_deref());
    Json(build_workspace_snapshot(&app_state, &authenticated).await)
}

async fn confirmations_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    match build_confirmation_snapshot(&app_state, &authenticated).await {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => {
            warn!("failed building Steam confirmation snapshot: {}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(SteamActionResponse {
                    ok: false,
                    message: language
                        .translations()
                        .steam_confirmations_load_failed_message
                        .to_owned(),
                }),
            )
                .into_response()
        }
    }
}

async fn import_mafile_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let mut language = detect_language(&headers, None);
    let mut account_name = String::new();
    let mut upload_name: Option<String> = None;
    let mut upload_bytes: Option<Vec<u8>> = None;

    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let field_name = field.name().unwrap_or_default().to_owned();
                match field_name.as_str() {
                    "lang" => {
                        if let Ok(raw) = field.text().await {
                            if let Some(parsed) = Language::parse(&raw) {
                                language = parsed;
                            }
                        }
                    }
                    "account_name" => {
                        account_name = field.text().await.unwrap_or_default();
                    }
                    "steam_file" => {
                        upload_name = field.file_name().map(str::to_owned);
                        upload_bytes = match field.bytes().await {
                            Ok(bytes) => Some(bytes.to_vec()),
                            Err(error) => {
                                warn!("failed reading uploaded Steam account file: {}", error);
                                return render_workspace_status(
                                    &app_state,
                                    &authenticated,
                                    language,
                                    Some(PageBanner::error(
                                        language.translations().steam_upload_read_error_message,
                                    )),
                                    Some(STEAM_MANAGE_TAB_ID),
                                    &headers,
                                    StatusCode::BAD_REQUEST,
                                )
                                .await;
                            }
                        };
                    }
                    _ => {}
                }
            }
            Ok(None) => break,
            Err(error) => {
                warn!("failed reading Steam multipart upload: {}", error);
                return render_workspace_status(
                    &app_state,
                    &authenticated,
                    language,
                    Some(PageBanner::error(
                        language.translations().steam_upload_read_error_message,
                    )),
                    Some(STEAM_MANAGE_TAB_ID),
                    &headers,
                    StatusCode::BAD_REQUEST,
                )
                .await;
            }
        }
    }

    let Some(file_bytes) = upload_bytes.filter(|value| !value.is_empty()) else {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language.translations().steam_upload_missing_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    };

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language.translations().session_data_locked_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::import_mafile_bytes(
        &steam_root,
        master_key.as_ref().as_slice(),
        upload_name.as_deref(),
        Some(account_name.as_str()),
        &file_bytes,
    )
    .await
    {
        Ok(_) => {
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::success(
                    language.translations().steam_upload_saved_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::OK,
            )
            .await
        }
        Err(error) => {
            warn!("failed importing uploaded Steam account: {}", error);
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(
                    language.translations().steam_upload_write_error_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

async fn create_manual_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<ManualSteamAccountForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    let steam_id = match form.steam_id.trim().parse::<u64>() {
        Ok(value) => value,
        Err(_) => {
            return render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(
                    translations.steam_invalid_steam_id_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::BAD_REQUEST,
            )
            .await;
        }
    };

    if form.shared_secret.trim().is_empty() {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_missing_shared_secret_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    if steam_platform::validate_shared_secret(&form.shared_secret).is_err() {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_invalid_shared_secret_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    if !form.identity_secret.trim().is_empty()
        && steam_platform::validate_identity_secret(&form.identity_secret).is_err()
    {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_invalid_identity_secret_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.session_data_locked_message)),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::create_manual_account(
        &steam_root,
        master_key.as_ref().as_slice(),
        steam_platform::ManualSteamAccountInput {
            account_name: form.account_name,
            steam_id,
            shared_secret: form.shared_secret,
            identity_secret: if form.identity_secret.trim().is_empty() {
                None
            } else {
                Some(form.identity_secret)
            },
            device_id: if form.device_id.trim().is_empty() {
                None
            } else {
                Some(form.device_id)
            },
            steam_login_secure: if form.steam_login_secure.trim().is_empty() {
                None
            } else {
                Some(form.steam_login_secure)
            },
        },
    )
    .await
    {
        Ok(_) => {
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::success(translations.steam_manual_saved_message)),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::OK,
            )
            .await
        }
        Err(error) => {
            warn!("failed storing manual Steam account: {}", error);
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(
                    translations.steam_manual_save_failed_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

async fn update_account_materials_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<UpdateSteamMaterialForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_account_missing_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::NOT_FOUND,
        )
        .await;
    }

    if form.shared_secret.trim().is_empty()
        && form.identity_secret.trim().is_empty()
        && form.device_id.trim().is_empty()
        && form.steam_login_secure.trim().is_empty()
    {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_materials_empty_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    if !form.shared_secret.trim().is_empty()
        && steam_platform::validate_shared_secret(&form.shared_secret).is_err()
    {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_invalid_shared_secret_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    if !form.identity_secret.trim().is_empty()
        && steam_platform::validate_identity_secret(&form.identity_secret).is_err()
    {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_invalid_identity_secret_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.session_data_locked_message)),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::update_managed_account_materials(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        steam_platform::UpdateSteamAccountInput {
            shared_secret: Some(form.shared_secret),
            identity_secret: Some(form.identity_secret),
            device_id: Some(form.device_id),
            steam_login_secure: Some(form.steam_login_secure),
        },
    )
    .await
    {
        Ok(true) => {
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::success(
                    translations.steam_materials_updated_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::OK,
            )
            .await
        }
        Ok(false) => {
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(
                    translations.steam_account_missing_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::NOT_FOUND,
            )
            .await
        }
        Err(error) => {
            warn!(
                "failed updating Steam materials for account {}: {}",
                account_id, error
            );
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(
                    translations.steam_materials_update_failed_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

async fn rename_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<RenameSteamAccountForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_account_missing_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    if form.account_name.trim().is_empty() {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.steam_rename_missing_message)),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.session_data_locked_message)),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::BAD_REQUEST,
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::rename_managed_account(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        &form.account_name,
    )
    .await
    {
        Ok(true) => {
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::success(translations.steam_renamed_message)),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::OK,
            )
            .await
        }
        Ok(false) => {
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(
                    translations.steam_account_missing_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::NOT_FOUND,
            )
            .await
        }
        Err(error) => {
            warn!("failed renaming Steam account {}: {}", account_id, error);
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(translations.steam_rename_failed_message)),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

async fn delete_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return render_workspace_status(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                translations.steam_account_missing_message,
            )),
            Some(STEAM_MANAGE_TAB_ID),
            &headers,
            StatusCode::NOT_FOUND,
        )
        .await;
    }

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::delete_managed_account(&steam_root, &account_id).await {
        Ok(true) => {
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::success(translations.steam_deleted_message)),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::OK,
            )
            .await
        }
        Ok(false) => {
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(
                    translations.steam_account_missing_message,
                )),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::NOT_FOUND,
            )
            .await
        }
        Err(error) => {
            warn!("failed deleting Steam account {}: {}", account_id, error);
            render_workspace_status(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(translations.steam_delete_failed_message)),
                Some(STEAM_MANAGE_TAB_ID),
                &headers,
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

async fn accept_confirmation_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath((account_id, confirmation_id)): AxumPath<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<SteamConfirmationActionForm>,
) -> Response {
    confirmation_action_handler(
        &app_state,
        &authenticated,
        language_from_headers_and_form(&headers, form.lang.as_deref()),
        &account_id,
        &confirmation_id,
        &form.nonce,
        true,
    )
    .await
}

async fn deny_confirmation_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath((account_id, confirmation_id)): AxumPath<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<SteamConfirmationActionForm>,
) -> Response {
    confirmation_action_handler(
        &app_state,
        &authenticated,
        language_from_headers_and_form(&headers, form.lang.as_deref()),
        &account_id,
        &confirmation_id,
        &form.nonce,
        false,
    )
    .await
}

fn language_from_headers_and_form(headers: &HeaderMap, lang: Option<&str>) -> Language {
    detect_language(headers, lang)
}

async fn confirmation_action_handler(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    account_id: &str,
    confirmation_id: &str,
    nonce: &str,
    accept: bool,
) -> Response {
    let translations = language.translations();
    if !steam_platform::is_valid_managed_account_id(account_id) || confirmation_id.trim().is_empty()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(SteamActionResponse {
                ok: false,
                message: translations.steam_account_missing_message.to_owned(),
            }),
        )
            .into_response();
    }
    if nonce.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(SteamActionResponse {
                ok: false,
                message: translations
                    .steam_confirmation_missing_nonce_message
                    .to_owned(),
            }),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(app_state, authenticated).await
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(SteamActionResponse {
                ok: false,
                message: translations.session_data_locked_message.to_owned(),
            }),
        )
            .into_response();
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let account = match steam_platform::load_managed_account(
        &steam_root,
        master_key.as_ref().as_slice(),
        account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(SteamActionResponse {
                    ok: false,
                    message: translations.steam_account_missing_message.to_owned(),
                }),
            )
                .into_response();
        }
        Err(error) => {
            warn!("failed loading Steam account {}: {}", account_id, error);
            return (
                StatusCode::BAD_REQUEST,
                Json(SteamActionResponse {
                    ok: false,
                    message: translations
                        .steam_confirmation_action_failed_message
                        .to_owned(),
                }),
            )
                .into_response();
        }
    };

    match steam_platform::respond_to_confirmation(
        &app_state.http_client,
        &account,
        confirmation_id,
        nonce,
        accept,
    )
    .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(SteamActionResponse {
                ok: true,
                message: if accept {
                    translations.steam_confirmation_accept_success_message
                } else {
                    translations.steam_confirmation_deny_success_message
                }
                .to_owned(),
            }),
        )
            .into_response(),
        Err(error) => {
            warn!(
                "failed handling Steam confirmation {} for account {}: {}",
                confirmation_id, account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(SteamActionResponse {
                    ok: false,
                    message: translations
                        .steam_confirmation_action_failed_message
                        .to_owned(),
                }),
            )
                .into_response()
        }
    }
}

async fn render_workspace_status(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    default_tab: Option<&str>,
    headers: &HeaderMap,
    status: StatusCode,
) -> Response {
    match render_workspace_page(
        app_state,
        authenticated,
        language,
        banner,
        default_tab,
        headers,
    )
    .await
    {
        Ok(html) => (status, html).into_response(),
        Err(status) => status.into_response(),
    }
}
