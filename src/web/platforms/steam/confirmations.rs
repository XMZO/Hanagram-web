// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) async fn accept_confirmation_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath((account_id, confirmation_id)): AxumPath<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<SteamConfirmationActionForm>,
) -> Response {
    let language = language_from_headers_and_form(&headers, form.lang.as_deref());

    confirmation_action_handler(
        &app_state,
        &authenticated,
        language,
        &account_id,
        &confirmation_id,
        &form.nonce,
        true,
    )
    .await
}

pub(super) async fn deny_confirmation_handler(
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

pub(super) async fn confirmation_action_handler(
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

    let account = refresh_account_confirmation_session_if_needed(
        app_state,
        authenticated,
        master_key.as_ref().as_slice(),
        account,
        false,
    )
    .await;

    let result = match steam_platform::respond_to_confirmation(
        &app_state.http_client,
        &account,
        confirmation_id,
        nonce,
        accept,
    )
    .await
    {
        Err(error)
            if error.to_string().contains("no longer authorized")
                && steam_platform::confirmation_session_can_refresh(&account) =>
        {
            let refreshed = refresh_account_confirmation_session_if_needed(
                app_state,
                authenticated,
                master_key.as_ref().as_slice(),
                account.clone(),
                true,
            )
            .await;
            steam_platform::respond_to_confirmation(
                &app_state.http_client,
                &refreshed,
                confirmation_id,
                nonce,
                accept,
            )
            .await
        }
        other => other,
    };

    match result {
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

// ---------------------------------------------------------------------------
// Link authenticator for existing managed account
// ---------------------------------------------------------------------------

pub(super) async fn bulk_accept_confirmations_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());

    bulk_confirmation_action(
        &app_state,
        &authenticated,
        &headers,
        Some(language.code()),
        &account_id,
        true,
    )
    .await
}

pub(super) async fn bulk_deny_confirmations_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    bulk_confirmation_action(
        &app_state,
        &authenticated,
        &headers,
        form.lang.as_deref(),
        &account_id,
        false,
    )
    .await
}

pub(super) async fn bulk_confirmation_action(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    headers: &HeaderMap,
    lang: Option<&str>,
    account_id: &str,
    accept: bool,
) -> Response {
    let language = detect_language(headers, lang);
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(account_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_account_missing_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(app_state, authenticated).await
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
        account_id,
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
                    "message": translations.steam_bulk_action_failed_message
                })),
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

    let result = if accept {
        steam_platform::batch_approve_trades(&app_state.http_client, &account).await
    } else {
        steam_platform::batch_reject_trades(&app_state.http_client, &account).await
    };

    match result {
        Ok(count) => {
            let message = if accept {
                format!(
                    "{} ({})",
                    translations.steam_bulk_accept_success_message, count
                )
            } else {
                format!(
                    "{} ({})",
                    translations.steam_bulk_deny_success_message, count
                )
            };
            Json(serde_json::json!({
                "ok": true,
                "count": count,
                "message": message
            }))
            .into_response()
        }
        Err(error) => {
            warn!(
                "bulk {} for account {} failed: {error}",
                if accept { "accept" } else { "deny" },
                account_id
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_bulk_action_failed_message
                })),
            )
                .into_response()
        }
    }
}
