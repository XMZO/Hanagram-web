// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) fn steam_trade_restore_failure_message(
    translations: &crate::i18n::TranslationSet,
    error: &anyhow::Error,
) -> String {
    let message = error.to_string();
    if message.contains("not authorized") || message.contains("usable Steam web session") {
        translations
            .steam_trade_restore_session_missing_message
            .to_owned()
    } else if message.contains("no eligible protected trades") {
        translations
            .steam_trade_restore_unavailable_message
            .to_owned()
    } else {
        translations.steam_trade_restore_failed_message.to_owned()
    }
}

pub(super) async fn load_trade_restore_account(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    master_key: &[u8],
    account_id: &str,
) -> Result<Option<steam_platform::SteamGuardAccount>> {
    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let Some(account) =
        steam_platform::load_managed_account(&steam_root, master_key, account_id).await?
    else {
        return Ok(None);
    };
    Ok(Some(
        refresh_account_confirmation_session_if_needed(
            app_state,
            authenticated,
            master_key,
            account,
            false,
        )
        .await,
    ))
}

pub(super) async fn check_trade_restore_with_refresh(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    master_key: &[u8],
    account: steam_platform::SteamGuardAccount,
    language: Language,
) -> Result<steam_platform::SteamTradeRestoreStatus> {
    match steam_platform::check_trade_restore_status(
        &app_state.http_client,
        &account,
        language.code(),
    )
    .await
    {
        Err(error) if steam_platform::confirmation_session_can_refresh(&account) => {
            warn!(
                "Steam trade restore check failed before token refresh for account {}: {}",
                account.id, error
            );
            let refreshed = refresh_account_confirmation_session_if_needed(
                app_state,
                authenticated,
                master_key,
                account,
                true,
            )
            .await;
            steam_platform::check_trade_restore_status(
                &app_state.http_client,
                &refreshed,
                language.code(),
            )
            .await
        }
        other => other,
    }
}

pub(super) async fn revert_trade_restore_with_refresh(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    master_key: &[u8],
    account: steam_platform::SteamGuardAccount,
    language: Language,
) -> Result<steam_platform::SteamTradeRestoreOutcome> {
    match steam_platform::revert_eligible_trades(&app_state.http_client, &account, language.code())
        .await
    {
        Err(error) if steam_platform::confirmation_session_can_refresh(&account) => {
            warn!(
                "Steam trade restore revert failed before token refresh for account {}: {}",
                account.id, error
            );
            let refreshed = refresh_account_confirmation_session_if_needed(
                app_state,
                authenticated,
                master_key,
                account,
                true,
            )
            .await;
            steam_platform::revert_eligible_trades(
                &app_state.http_client,
                &refreshed,
                language.code(),
            )
            .await
        }
        other => other,
    }
}

pub(super) async fn trade_restore_status_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
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

    let account = match load_trade_restore_account(
        &app_state,
        &authenticated,
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
                    "message": translations.steam_trade_restore_failed_message
                })),
            )
                .into_response();
        }
    };

    match check_trade_restore_with_refresh(
        &app_state,
        &authenticated,
        master_key.as_ref().as_slice(),
        account,
        language,
    )
    .await
    {
        Ok(status) => Json(serde_json::json!({
            "ok": true,
            "can_revert": status.can_revert,
            "session_ready": status.session_ready,
            "message": if status.can_revert {
                translations.steam_trade_restore_ready_message
            } else {
                translations.steam_trade_restore_unavailable_message
            },
        }))
        .into_response(),
        Err(error) => {
            warn!(
                "failed checking Steam trade restore status for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": steam_trade_restore_failure_message(translations, &error)
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn trade_restore_revert_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<SteamTradeRestoreForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.confirm_phrase.trim() != translations.steam_trade_restore_confirm_phrase {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_trade_restore_invalid_confirm_message
            })),
        )
            .into_response();
    }

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

    let account = match load_trade_restore_account(
        &app_state,
        &authenticated,
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
                    "message": translations.steam_trade_restore_failed_message
                })),
            )
                .into_response();
        }
    };

    let account_name = account.account_name.clone();
    let steam_id = account.steam_id;
    let result = revert_trade_restore_with_refresh(
        &app_state,
        &authenticated,
        master_key.as_ref().as_slice(),
        account,
        language,
    )
    .await;

    match result {
        Ok(outcome) => {
            let _ = app_state
                .meta_store
                .record_audit(&NewAuditEntry {
                    action_type: "steam_trade_restore_revert".to_owned(),
                    actor_user_id: Some(authenticated.user.id.clone()),
                    subject_user_id: Some(authenticated.user.id.clone()),
                    ip_address: extract_client_ip(&headers),
                    success: true,
                    details_json: serde_json::json!({
                        "account_id": account_id,
                        "account_name": account_name,
                        "steam_id": steam_id,
                        "redir_present": outcome.redir.is_some(),
                    })
                    .to_string(),
                })
                .await;
            Json(serde_json::json!({
                "ok": true,
                "message": translations.steam_trade_restore_success_message,
                "redir": outcome.redir
            }))
            .into_response()
        }
        Err(error) => {
            warn!(
                "failed reverting Steam protected trades for account {}: {}",
                account_id, error
            );
            let _ = app_state
                .meta_store
                .record_audit(&NewAuditEntry {
                    action_type: "steam_trade_restore_revert".to_owned(),
                    actor_user_id: Some(authenticated.user.id.clone()),
                    subject_user_id: Some(authenticated.user.id.clone()),
                    ip_address: extract_client_ip(&headers),
                    success: false,
                    details_json: serde_json::json!({
                        "account_id": account_id,
                        "account_name": account_name,
                        "steam_id": steam_id,
                        "error": error.to_string(),
                    })
                    .to_string(),
                })
                .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": steam_trade_restore_failure_message(translations, &error)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy configuration handler
// ---------------------------------------------------------------------------

pub(super) async fn time_check_handler(
    State(app_state): State<AppState>,
    Extension(_authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Query(query): Query<LangQuery>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let translations = language.translations();

    match steam_platform::measure_clock_drift(&app_state.http_client).await {
        Ok((remote_ts, local_ts, drift)) => Json(serde_json::json!({
            "ok": true,
            "remote_time": remote_ts,
            "local_time": local_ts,
            "drift_seconds": drift
        }))
        .into_response(),
        Err(error) => {
            warn!("Steam time check failed: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_time_check_failed_message
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Phone status handler
// ---------------------------------------------------------------------------

pub(super) async fn account_phone_status_handler(
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
    match steam_platform::check_phone_status(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
    )
    .await
    {
        Ok(has_phone) => Json(serde_json::json!({
            "ok": true,
            "has_phone": has_phone
        }))
        .into_response(),
        Err(error) => {
            warn!(
                "failed querying phone status for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_phone_status_failed)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Emergency codes handlers
// ---------------------------------------------------------------------------

pub(super) async fn create_emergency_codes_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<SteamEmptyActionForm>,
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
    match steam_platform::create_emergency_codes(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
    )
    .await
    {
        Ok(codes) => Json(serde_json::json!({
            "ok": true,
            "codes": codes
        }))
        .into_response(),
        Err(error) => {
            warn!(
                "failed creating emergency codes for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_emergency_codes_failed)
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn destroy_emergency_codes_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<SteamEmptyActionForm>,
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
    match steam_platform::destroy_emergency_codes(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
    )
    .await
    {
        Ok(()) => Json(serde_json::json!({
            "ok": true
        }))
        .into_response(),
        Err(error) => {
            warn!(
                "failed destroying emergency codes for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_emergency_codes_failed)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Validate token handler
// ---------------------------------------------------------------------------

pub(super) async fn validate_token_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<SteamValidateTokenForm>,
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
    match steam_platform::validate_authenticator_token(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        form.code,
    )
    .await
    {
        Ok(valid) => Json(serde_json::json!({
            "ok": true,
            "valid": valid
        }))
        .into_response(),
        Err(error) => {
            warn!(
                "failed validating token for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_validate_token_failed)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Zero Trust Mode — middleware gateway (default-deny + allowlist)
// ---------------------------------------------------------------------------
