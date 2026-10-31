// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) async fn approve_login_challenge_for_account(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    headers: &HeaderMap,
    language: Language,
    account_id: &str,
    challenge_url: &str,
) -> Response {
    let translations = language.translations();
    if !steam_platform::is_valid_managed_account_id(account_id) {
        return redirect_with_workspace_banner(
            app_state,
            headers,
            PageBanner::error(translations.steam_account_missing_message),
            Some(STEAM_APPROVALS_TAB_ID),
        )
        .await;
    }
    if challenge_url.trim().is_empty() {
        return redirect_with_workspace_banner(
            app_state,
            headers,
            PageBanner::error(translations.steam_link_approval_missing_message),
            Some(STEAM_APPROVALS_TAB_ID),
        )
        .await;
    }

    let Some(master_key) = middleware::resolved_user_master_key(app_state, authenticated).await
    else {
        return redirect_with_workspace_banner(
            app_state,
            headers,
            PageBanner::error(translations.session_data_locked_message),
            Some(STEAM_APPROVALS_TAB_ID),
        )
        .await;
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
            return redirect_with_workspace_banner(
                app_state,
                headers,
                PageBanner::error(translations.steam_account_missing_message),
                Some(STEAM_APPROVALS_TAB_ID),
            )
            .await;
        }
        Err(error) => {
            warn!(
                "failed loading Steam approval account {}: {}",
                account_id, error
            );
            return redirect_with_workspace_banner(
                app_state,
                headers,
                PageBanner::error(translations.steam_qr_approval_failed_message),
                Some(STEAM_APPROVALS_TAB_ID),
            )
            .await;
        }
    };

    let account = refresh_account_confirmation_session_if_needed(
        app_state,
        authenticated,
        master_key.as_ref().as_slice(),
        account,
        false,
    )
    .await;
    let result = match steam_platform::approve_login_challenge(&account, challenge_url).await {
        Err(_) if account.has_refreshable_session() => {
            let refreshed = refresh_account_confirmation_session_if_needed(
                app_state,
                authenticated,
                master_key.as_ref().as_slice(),
                account.clone(),
                true,
            )
            .await;
            match steam_platform::approve_login_challenge(&refreshed, challenge_url).await {
                Ok(()) => Ok(()),
                Err(retry_error) => Err(retry_error),
            }
        }
        other => other,
    };

    match result {
        Ok(()) => {
            redirect_with_workspace_banner(
                app_state,
                headers,
                PageBanner::success(translations.steam_qr_approval_success_message),
                Some(STEAM_APPROVALS_TAB_ID),
            )
            .await
        }
        Err(error) => {
            warn!(
                "failed approving Steam challenge for account {}: {}",
                account_id, error
            );
            redirect_with_workspace_banner(
                app_state,
                headers,
                PageBanner::error(steam_qr_failure_message(translations, &error)),
                Some(STEAM_APPROVALS_TAB_ID),
            )
            .await
        }
    }
}

pub(super) async fn approve_login_challenge_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<SteamQrApprovalForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());

    approve_login_challenge_for_account(
        &app_state,
        &authenticated,
        &headers,
        language,
        &form.account_id,
        &form.challenge_url,
    )
    .await
}

pub(super) async fn approve_login_challenge_upload_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let mut language = detect_language(&headers, None);
    let mut account_id = String::new();
    let mut image_bytes: Option<Vec<u8>> = None;

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
                    "account_id" => {
                        account_id = field.text().await.unwrap_or_default();
                    }
                    "challenge_image" => {
                        image_bytes = match field.bytes().await {
                            Ok(bytes) => Some(bytes.to_vec()),
                            Err(error) => {
                                warn!("failed reading Steam QR upload: {}", error);
                                return redirect_with_workspace_banner(
                                    &app_state,
                                    &headers,
                                    PageBanner::error(
                                        language
                                            .translations()
                                            .steam_qr_approval_read_error_message,
                                    ),
                                    Some(STEAM_APPROVALS_TAB_ID),
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
                warn!("failed reading Steam QR multipart upload: {}", error);
                return redirect_with_workspace_banner(
                    &app_state,
                    &headers,
                    PageBanner::error(language.translations().steam_qr_approval_read_error_message),
                    Some(STEAM_APPROVALS_TAB_ID),
                )
                .await;
            }
        }
    }

    let Some(file_bytes) = image_bytes.filter(|value| !value.is_empty()) else {
        return redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(language.translations().steam_qr_approval_missing_message),
            Some(STEAM_APPROVALS_TAB_ID),
        )
        .await;
    };

    let challenge_url = match steam_platform::extract_login_challenge_url_from_qr_image(&file_bytes)
    {
        Ok(url) => url,
        Err(error) => {
            warn!("failed decoding Steam QR upload: {}", error);
            return redirect_with_workspace_banner(
                &app_state,
                &headers,
                PageBanner::error(language.translations().steam_qr_approval_invalid_message),
                Some(STEAM_APPROVALS_TAB_ID),
            )
            .await;
        }
    };

    approve_login_challenge_for_account(
        &app_state,
        &authenticated,
        &headers,
        language,
        &account_id,
        &challenge_url,
    )
    .await
}

pub(super) async fn approve_login_approval_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath((account_id, client_id)): AxumPath<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<SteamApprovalActionForm>,
) -> Response {
    let language = language_from_headers_and_form(&headers, form.lang.as_deref());

    login_approval_action_handler(
        &app_state,
        &authenticated,
        language,
        &account_id,
        &client_id,
        true,
    )
    .await
}

pub(super) async fn deny_login_approval_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath((account_id, client_id)): AxumPath<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<SteamApprovalActionForm>,
) -> Response {
    login_approval_action_handler(
        &app_state,
        &authenticated,
        language_from_headers_and_form(&headers, form.lang.as_deref()),
        &account_id,
        &client_id,
        false,
    )
    .await
}

pub(super) async fn login_approval_action_handler(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    account_id: &str,
    client_id: &str,
    approve: bool,
) -> Response {
    let translations = language.translations();
    if !steam_platform::is_valid_managed_account_id(account_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(SteamActionResponse {
                ok: false,
                message: translations.steam_account_missing_message.to_owned(),
            }),
        )
            .into_response();
    }

    let client_id = match client_id.trim().parse::<u64>() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SteamActionResponse {
                    ok: false,
                    message: translations.steam_approval_action_failed_message.to_owned(),
                }),
            )
                .into_response();
        }
    };

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
            warn!(
                "failed loading Steam approval account {}: {}",
                account_id, error
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(SteamActionResponse {
                    ok: false,
                    message: translations.steam_approval_action_failed_message.to_owned(),
                }),
            )
                .into_response();
        }
    };

    let account = refresh_account_confirmation_session_if_needed(
        app_state,
        authenticated,
        master_key.as_ref().as_slice(),
        account,
        false,
    )
    .await;
    let result = match steam_platform::respond_to_login_approval(&account, client_id, approve).await
    {
        Err(_) if account.has_refreshable_session() => {
            let refreshed = refresh_account_confirmation_session_if_needed(
                app_state,
                authenticated,
                master_key.as_ref().as_slice(),
                account.clone(),
                true,
            )
            .await;
            steam_platform::respond_to_login_approval(&refreshed, client_id, approve).await
        }
        other => other,
    };

    match result {
        Ok(()) => (
            StatusCode::OK,
            Json(SteamActionResponse {
                ok: true,
                message: if approve {
                    translations.steam_approval_approve_success_message
                } else {
                    translations.steam_approval_deny_success_message
                }
                .to_owned(),
            }),
        )
            .into_response(),
        Err(error) => {
            warn!(
                "failed handling Steam login approval {} for account {}: {}",
                client_id, account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(SteamActionResponse {
                    ok: false,
                    message: translations.steam_approval_action_failed_message.to_owned(),
                }),
            )
                .into_response()
        }
    }
}
