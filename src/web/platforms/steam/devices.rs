// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) fn build_session_device_snapshot(
    inventory: steam_platform::SteamSessionDeviceInventory,
) -> SteamSessionDeviceSnapshot {
    let devices = inventory
        .devices
        .into_iter()
        .map(|device| SteamSessionDeviceView {
            token_id: device.token_id.to_string(),
            device_label: device.device_label,
            platform_label: device.platform_label,
            location_label: device.location_label,
            first_seen_at: device.first_seen_at_unix.map(format_unix_timestamp),
            last_seen_at: device.last_seen_at_unix.map(format_unix_timestamp),
            is_current: device.is_current,
        })
        .collect::<Vec<_>>();

    SteamSessionDeviceSnapshot {
        current_token_id: inventory
            .current_token_id
            .map(|token_id| token_id.to_string()),
        device_count: devices.len(),
        devices,
    }
}

pub(super) async fn account_session_devices_handler(
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
    let account = match steam_platform::refresh_confirmation_session_if_needed(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        false,
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
            warn!(
                "failed preparing Steam login device inventory for account {}: {}",
                account_id, error
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_session_devices_load_failed_message)
                })),
            )
                .into_response();
        }
    };

    if !account.has_session_tokens() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_session_devices_unavailable_message
            })),
        )
            .into_response();
    }

    let inventory = match steam_platform::list_logged_in_devices(&account).await {
        Ok(inventory) => inventory,
        Err(error) if account.has_refreshable_session() => {
            warn!(
                "Steam login device inventory failed for account {}; retrying after refresh: {}",
                account_id, error
            );
            let refreshed = match steam_platform::refresh_confirmation_session_if_needed(
                &steam_root,
                master_key.as_ref().as_slice(),
                &account_id,
                true,
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
                Err(refresh_error) => {
                    warn!(
                        "failed refreshing Steam login device session for account {}: {}",
                        account_id, refresh_error
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": format!("{}: {refresh_error}", translations.steam_session_devices_load_failed_message)
                        })),
                    )
                        .into_response();
                }
            };

            match steam_platform::list_logged_in_devices(&refreshed).await {
                Ok(inventory) => inventory,
                Err(retry_error) => {
                    warn!(
                        "failed listing Steam login devices for account {} after refresh: {}",
                        account_id, retry_error
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": format!("{}: {retry_error}", translations.steam_session_devices_load_failed_message)
                        })),
                    )
                        .into_response();
                }
            }
        }
        Err(error) => {
            warn!(
                "failed listing Steam login devices for account {}: {}",
                account_id, error
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_session_devices_load_failed_message)
                })),
            )
                .into_response();
        }
    };

    Json(serde_json::json!({
        "ok": true,
        "snapshot": build_session_device_snapshot(inventory)
    }))
    .into_response()
}

pub(super) async fn revoke_account_session_devices_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<SteamSessionDeviceRevokeForm>,
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

    let selection = match form.scope.trim() {
        "token" => match form
            .token_id
            .as_deref()
            .and_then(|value| value.trim().parse::<u64>().ok())
        {
            Some(token_id) => steam_platform::SteamSessionDeviceSelection::Token(token_id),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": translations.steam_session_revoke_failed_message
                    })),
                )
                    .into_response();
            }
        },
        "others" => steam_platform::SteamSessionDeviceSelection::Others,
        "all" => steam_platform::SteamSessionDeviceSelection::All,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_session_revoke_failed_message
                })),
            )
                .into_response();
        }
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::revoke_logged_in_devices(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        selection,
    )
    .await
    {
        Ok(outcome) => {
            let base_message = if outcome.current_device_revoked {
                translations.steam_session_revoke_current_success_message
            } else {
                translations.steam_session_revoke_success_message
            };
            Json(serde_json::json!({
                "ok": true,
                "message": format!("{base_message} ({})", outcome.revoked_count),
                "current_device_revoked": outcome.current_device_revoked,
                "revoked_count": outcome.revoked_count
            }))
            .into_response()
        }
        Err(error) => {
            warn!(
                "failed revoking Steam login devices for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_session_revoke_failed_message)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Security profile handler
// ---------------------------------------------------------------------------
