// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) async fn import_mafile_handler(
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
                                return redirect_with_workspace_banner(
                                    &app_state,
                                    &headers,
                                    PageBanner::error(
                                        language.translations().steam_upload_read_error_message,
                                    ),
                                    Some(STEAM_IMPORT_TAB_ID),
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
                return redirect_with_workspace_banner(
                    &app_state,
                    &headers,
                    PageBanner::error(language.translations().steam_upload_read_error_message),
                    Some(STEAM_IMPORT_TAB_ID),
                )
                .await;
            }
        }
    }

    let Some(file_bytes) = upload_bytes.filter(|value| !value.is_empty()) else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(language.translations().steam_upload_missing_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    };

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(language.translations().session_data_locked_message),
            Some(STEAM_IMPORT_TAB_ID),
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
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::success(language.translations().steam_upload_saved_message),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!("failed importing uploaded Steam account: {}", error);
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(language.translations().steam_upload_write_error_message),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await
        }
    }
}

pub(super) async fn create_manual_account_handler(
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
            return redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_invalid_steam_id_message),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await;
        }
    };

    if form.shared_secret.trim().is_empty() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_missing_shared_secret_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }
    if steam_platform::validate_shared_secret(&form.shared_secret).is_err() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_invalid_shared_secret_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }
    if !form.identity_secret.trim().is_empty()
        && steam_platform::validate_identity_secret(&form.identity_secret).is_err()
    {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_invalid_identity_secret_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.session_data_locked_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::create_manual_account(
        &steam_root,
        master_key.as_ref().as_slice(),
        steam_platform::ManualSteamAccountInput {
            account_name: form.account_name,
            steam_username: if form.steam_username.trim().is_empty() {
                None
            } else {
                Some(form.steam_username)
            },
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
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::success(translations.steam_manual_saved_message),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!("failed storing manual Steam account: {}", error);
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_manual_save_failed_message),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await
        }
    }
}

pub(super) async fn create_logged_in_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<CredentialSteamAccountForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.steam_username.trim().is_empty() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_login_missing_username_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }
    if form.steam_password.is_empty() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_login_missing_password_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }
    if form.shared_secret.trim().is_empty() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_missing_shared_secret_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }
    if steam_platform::validate_shared_secret(&form.shared_secret).is_err() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_invalid_shared_secret_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }
    if !form.identity_secret.trim().is_empty()
        && steam_platform::validate_identity_secret(&form.identity_secret).is_err()
    {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_invalid_identity_secret_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.session_data_locked_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::create_logged_in_account(
        &steam_root,
        master_key.as_ref().as_slice(),
        steam_platform::CredentialSteamAccountInput {
            account_name: form.account_name,
            steam_username: form.steam_username,
            steam_password: form.steam_password,
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
        },
    )
    .await
    {
        Ok(_) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::success(translations.steam_login_create_success_message),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!("failed creating credential Steam account: {}", error);
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(steam_login_failure_message(
                    translations,
                    &error,
                    translations.steam_login_create_failed_message,
                )),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await
        }
    }
}

pub(super) async fn login_managed_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<SteamAccountLoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_account_missing_message),
            Some(STEAM_ACCOUNTS_TAB_ID),
        )
        .await;
    }
    if form.steam_password.is_empty() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_login_missing_password_message),
            Some(STEAM_ACCOUNTS_TAB_ID),
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.session_data_locked_message),
            Some(STEAM_ACCOUNTS_TAB_ID),
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::login_managed_account_with_credentials(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        steam_platform::SteamCredentialLoginInput {
            steam_username: form.steam_username,
            steam_password: form.steam_password,
        },
    )
    .await
    {
        Ok(Some(_)) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::success(translations.steam_login_update_success_message),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
        Ok(None) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_account_missing_message),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!("failed reauthing Steam account {}: {}", account_id, error);
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(steam_login_failure_message(
                    translations,
                    &error,
                    translations.steam_login_update_failed_message,
                )),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
    }
}

pub(super) async fn update_account_materials_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<UpdateSteamMaterialForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_account_missing_message),
            Some(STEAM_SECURITY_TAB_ID),
        )
        .await;
    }

    if form.shared_secret.trim().is_empty()
        && form.steam_username.trim().is_empty()
        && form.identity_secret.trim().is_empty()
        && form.device_id.trim().is_empty()
        && form.steam_login_secure.trim().is_empty()
    {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_materials_empty_message),
            Some(STEAM_SECURITY_TAB_ID),
        )
        .await;
    }
    if !form.shared_secret.trim().is_empty()
        && steam_platform::validate_shared_secret(&form.shared_secret).is_err()
    {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_invalid_shared_secret_message),
            Some(STEAM_SECURITY_TAB_ID),
        )
        .await;
    }
    if !form.identity_secret.trim().is_empty()
        && steam_platform::validate_identity_secret(&form.identity_secret).is_err()
    {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_invalid_identity_secret_message),
            Some(STEAM_SECURITY_TAB_ID),
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.session_data_locked_message),
            Some(STEAM_SECURITY_TAB_ID),
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::update_managed_account_materials(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        steam_platform::UpdateSteamAccountInput {
            steam_username: Some(form.steam_username),
            shared_secret: Some(form.shared_secret),
            identity_secret: Some(form.identity_secret),
            device_id: Some(form.device_id),
            steam_login_secure: Some(form.steam_login_secure),
        },
    )
    .await
    {
        Ok(true) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::success(translations.steam_materials_updated_message),
                Some(STEAM_SECURITY_TAB_ID),
            )
            .await
        }
        Ok(false) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_account_missing_message),
                Some(STEAM_SECURITY_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!(
                "failed updating Steam materials for account {}: {}",
                account_id, error
            );
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_materials_update_failed_message),
                Some(STEAM_SECURITY_TAB_ID),
            )
            .await
        }
    }
}

pub(super) async fn rename_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<RenameSteamAccountForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_account_missing_message),
            Some(STEAM_ACCOUNTS_TAB_ID),
        )
        .await;
    }
    if form.account_name.trim().is_empty() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_rename_missing_message),
            Some(STEAM_ACCOUNTS_TAB_ID),
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.session_data_locked_message),
            Some(STEAM_ACCOUNTS_TAB_ID),
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
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::success(translations.steam_renamed_message),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
        Ok(false) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_account_missing_message),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!("failed renaming Steam account {}: {}", account_id, error);
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_rename_failed_message),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
    }
}

pub(super) async fn delete_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_account_missing_message),
            Some(STEAM_ACCOUNTS_TAB_ID),
        )
        .await;
    }

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::delete_managed_account(&steam_root, &account_id).await {
        Ok(true) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::success(translations.steam_deleted_message),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
        Ok(false) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_account_missing_message),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!("failed deleting Steam account {}: {}", account_id, error);
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(translations.steam_delete_failed_message),
                Some(STEAM_ACCOUNTS_TAB_ID),
            )
            .await
        }
    }
}

pub(super) async fn account_status_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<LangQuery>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_account_missing_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::fetch_security_info(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
    )
    .await
    {
        Ok(status) => Json(serde_json::json!({
            "ok": true,
            "status": status
        }))
        .into_response(),
        Err(error) => {
            warn!(
                "failed querying 2FA status for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_status_failed_message)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// TOTP URI / QR export handler
// ---------------------------------------------------------------------------

pub(super) async fn account_export_qr_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<LangQuery>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_account_missing_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let (accounts, _) =
        steam_platform::discover_accounts(&steam_root, Some(master_key.as_ref().as_slice())).await;

    let account = match accounts.into_iter().find(|a| a.id == account_id) {
        Some(a) => a,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_account_missing_message
                })),
            )
                .into_response();
        }
    };

    match steam_platform::generate_totp_uri(&account) {
        Ok(uri) => match render_qr_svg(&uri) {
            Ok(svg) => Json(serde_json::json!({
                "ok": true,
                "uri": uri,
                "svg": svg
            }))
            .into_response(),
            Err(error) => {
                warn!("QR rendering failed for account {}: {error}", account_id);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": translations.steam_export_qr_failed_message
                    })),
                )
                    .into_response()
            }
        },
        Err(error) => {
            warn!(
                "failed building otpauth URI for account {}: {error}",
                account_id
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_export_qr_failed_message
                })),
            )
                .into_response()
        }
    }
}

pub(super) fn steam_mafile_download_filename(
    account: &steam_platform::SteamGuardAccount,
) -> String {
    let raw = account
        .steam_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| account.account_name.clone());
    let mut filename = String::new();
    let mut pending_dash = false;

    for ch in raw.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            Some(ch)
        } else if ch.is_whitespace() {
            Some('-')
        } else {
            None
        };

        match mapped {
            Some('-') if filename.is_empty() || pending_dash => {}
            Some('-') => pending_dash = true,
            Some(ch) => {
                if pending_dash {
                    filename.push('-');
                    pending_dash = false;
                }
                filename.push(ch);
            }
            None => {}
        }
    }

    let filename = filename.trim_matches(['.', '_', '-']);
    if filename.is_empty() {
        String::from("steam-account.maFile")
    } else {
        format!("{filename}.maFile")
    }
}

pub(super) async fn account_export_mafile_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<LangQuery>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_account_missing_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let account = match steam_platform::load_managed_account(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
    )
    .await
    {
        Ok(Some(account)) => account,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_account_missing_message
                })),
            )
                .into_response();
        }
        Err(error) => {
            warn!("failed loading Steam account {}: {}", account_id, error);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_export_mafile_failed_message
                })),
            )
                .into_response();
        }
    };

    let bytes = match steam_platform::export_mafile_json_bytes(&account) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(
                "failed exporting maFile for account {}: {}",
                account_id, error
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_export_mafile_failed_message
                })),
            )
                .into_response();
        }
    };

    let filename = steam_mafile_download_filename(&account);
    let content_disposition = format!("attachment; filename=\"{filename}\"");
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    if let Ok(value) = HeaderValue::from_str(&content_disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

// ---------------------------------------------------------------------------
// Third-party guard import handler
// ---------------------------------------------------------------------------

pub(super) async fn import_winauth_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<SteamWinAuthImportForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.uri.trim().is_empty() {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.steam_import_winauth_invalid_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(translations.session_data_locked_message),
            Some(STEAM_IMPORT_TAB_ID),
        )
        .await;
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let display_name = if form.account_name.trim().is_empty() {
        None
    } else {
        Some(form.account_name.as_str())
    };

    match steam_platform::ingest_third_party_guard(
        &steam_root,
        master_key.as_ref().as_slice(),
        &form.uri,
        display_name,
    )
    .await
    {
        Ok(_) => {
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::success(translations.steam_import_winauth_success_message),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!("WinAuth import failed: {error}");
            redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(format!(
                    "{}: {error}",
                    translations.steam_import_winauth_failed_message
                )),
                Some(STEAM_IMPORT_TAB_ID),
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Batch trade confirmation handlers
// ---------------------------------------------------------------------------

pub(super) async fn account_proxy_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<SteamProxyForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_account_missing_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let storage_path = steam_platform::managed_account_storage_path(&steam_root, &account_id);
    let record =
        match steam_platform::load_stored_account(master_key.as_ref().as_slice(), &storage_path)
            .await
        {
            Ok(Some(r)) => r,
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": translations.steam_account_missing_message
                    })),
                )
                    .into_response();
            }
        };

    let proxy_url = if form.proxy_url.trim().is_empty() {
        None
    } else {
        Some(form.proxy_url.trim().to_owned())
    };

    let mut updated = record;
    updated.proxy_url = proxy_url;
    updated.updated_at_unix = Utc::now().timestamp();

    match steam_platform::persist_stored_account(
        master_key.as_ref().as_slice(),
        &storage_path,
        &updated,
    )
    .await
    {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "message": translations.steam_proxy_saved_message
        }))
        .into_response(),
        Err(error) => {
            warn!("failed saving proxy for account {}: {error}", account_id);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_proxy_save_failed_message
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Clock drift measurement handler
// ---------------------------------------------------------------------------
