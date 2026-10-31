// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) async fn build_workspace_snapshot(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    zero_trust_locked_ids: &std::collections::HashSet<String>,
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
        let account = match shared_master_key.as_ref() {
            Some(master_key) => {
                refresh_account_confirmation_session_if_needed(
                    app_state,
                    authenticated,
                    master_key.as_ref().as_slice(),
                    account,
                    false,
                )
                .await
            }
            None => account,
        };
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
        let has_session_tokens = account.has_session_tokens();
        let has_refreshable_session = account.has_refreshable_session();
        let login_approval_ready = account.login_approval_ready();
        let update_material_action =
            can_manage.then(|| account_update_material_action(&account.id));
        let rename_action = can_manage.then(|| account_rename_action(&account.id));
        let delete_action = can_manage.then(|| account_delete_action(&account.id));
        let login_action = can_manage.then(|| account_login_action(&account.id));
        let session_devices_api =
            (can_manage && has_session_tokens).then(|| account_session_devices_api(&account.id));
        let session_device_revoke_api = (can_manage && has_session_tokens)
            .then(|| account_session_device_revoke_api(&account.id));
        let code_started_at_unix_view = current_code.as_ref().map(|_| code_started_at_unix);
        let code_expires_at_unix_view = current_code.as_ref().map(|_| code_expires_at_unix);
        account_views.push(SteamAccountView {
            id: account.id.clone(),
            account_name: account.account_name,
            steam_username: account.steam_username.clone(),
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
            has_session_tokens,
            has_refreshable_session,
            login_approval_ready,
            imported_from: account.imported_from,
            created_at: account.created_at_unix.map(format_unix_timestamp),
            updated_at: account.updated_at_unix.map(format_unix_timestamp),
            update_material_action,
            rename_action,
            delete_action,
            login_action,
            has_revocation_code: account.revocation_code.is_some(),
            has_proxy: account
                .proxy_url
                .as_deref()
                .is_some_and(|v| !v.trim().is_empty()),
            proxy_url: account.proxy_url.clone(),
            session_devices_api,
            session_device_revoke_api,
            zero_trust_active: zero_trust_locked_ids.contains(&account.id),
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

pub(super) async fn build_confirmation_snapshot(
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
    let mut ready_accounts = Vec::new();
    for account in accounts {
        let account = refresh_account_confirmation_session_if_needed(
            app_state,
            authenticated,
            shared_master_key.as_ref().as_slice(),
            account,
            false,
        )
        .await;
        if account.can_manage() && account.confirmation_ready() {
            ready_accounts.push(account);
        }
    }

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
                let aid = account.id.clone();
                account_views.push(SteamConfirmationAccountView {
                    bulk_accept_action: bulk_accept_action(&aid),
                    bulk_deny_action: bulk_deny_action(&aid),
                    account_id: account.id,
                    account_name: account.account_name,
                    steam_id: account.steam_id.map(|value| value.to_string()),
                    confirmation_count: confirmation_views.len(),
                    error: None,
                    confirmations: confirmation_views,
                });
            }
            Err(error) => {
                let retryable = error.to_string().contains("no longer authorized")
                    && steam_platform::confirmation_session_can_refresh(&account);
                if retryable {
                    let refreshed = refresh_account_confirmation_session_if_needed(
                        app_state,
                        authenticated,
                        shared_master_key.as_ref().as_slice(),
                        account.clone(),
                        true,
                    )
                    .await;
                    match steam_platform::fetch_confirmations(&app_state.http_client, &refreshed)
                        .await
                    {
                        Ok(confirmations) => {
                            let confirmation_views = confirmations
                                .into_iter()
                                .map(|confirmation| SteamConfirmationView {
                                    accept_action: confirmation_accept_action(
                                        &refreshed.id,
                                        &confirmation.id,
                                    ),
                                    deny_action: confirmation_deny_action(
                                        &refreshed.id,
                                        &confirmation.id,
                                    ),
                                    id: confirmation.id,
                                    nonce: confirmation.nonce,
                                    creator_id: confirmation.creator_id,
                                    confirmation_type: confirmation.confirmation_type,
                                    type_name: confirmation.type_name,
                                    headline: confirmation.headline,
                                    summary: confirmation.summary,
                                    icon: confirmation.icon,
                                    created_at: format_unix_timestamp(
                                        confirmation.created_at_unix as i64,
                                    ),
                                })
                                .collect::<Vec<_>>();
                            total_confirmations += confirmation_views.len();
                            let aid = refreshed.id.clone();
                            account_views.push(SteamConfirmationAccountView {
                                bulk_accept_action: bulk_accept_action(&aid),
                                bulk_deny_action: bulk_deny_action(&aid),
                                account_id: refreshed.id,
                                account_name: refreshed.account_name,
                                steam_id: refreshed.steam_id.map(|value| value.to_string()),
                                confirmation_count: confirmation_views.len(),
                                error: None,
                                confirmations: confirmation_views,
                            });
                            continue;
                        }
                        Err(retry_error) => {
                            let aid = refreshed.id.clone();
                            account_views.push(SteamConfirmationAccountView {
                                bulk_accept_action: bulk_accept_action(&aid),
                                bulk_deny_action: bulk_deny_action(&aid),
                                account_id: refreshed.id,
                                account_name: refreshed.account_name,
                                steam_id: refreshed.steam_id.map(|value| value.to_string()),
                                confirmation_count: 0,
                                error: Some(retry_error.to_string()),
                                confirmations: Vec::new(),
                            });
                            continue;
                        }
                    }
                }

                let aid = account.id.clone();
                account_views.push(SteamConfirmationAccountView {
                    bulk_accept_action: bulk_accept_action(&aid),
                    bulk_deny_action: bulk_deny_action(&aid),
                    account_id: account.id,
                    account_name: account.account_name,
                    steam_id: account.steam_id.map(|value| value.to_string()),
                    confirmation_count: 0,
                    error: Some(error.to_string()),
                    confirmations: Vec::new(),
                })
            }
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

pub(super) async fn build_approval_snapshot(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
) -> Result<SteamApprovalSnapshot> {
    let base_dir = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    let shared_master_key = middleware::resolved_user_master_key(app_state, authenticated)
        .await
        .context("user data is locked; sign in again to unlock it")?;
    let (accounts, _) =
        steam_platform::discover_accounts(&base_dir, Some(shared_master_key.as_ref().as_slice()))
            .await;
    let mut ready_accounts = Vec::new();
    for account in accounts {
        let account = refresh_account_confirmation_session_if_needed(
            app_state,
            authenticated,
            shared_master_key.as_ref().as_slice(),
            account,
            false,
        )
        .await;
        if account.can_manage() && account.login_approval_ready() {
            ready_accounts.push(account);
        }
    }

    let generated_at_unix = Utc::now().timestamp().max(0);
    let mut total_approvals = 0usize;
    let mut account_views = Vec::new();
    for account in ready_accounts {
        match steam_platform::list_login_approvals(&account).await {
            Ok(approvals) => {
                let approval_views = approvals
                    .into_iter()
                    .map(|approval| SteamApprovalView {
                        approve_action: approval_allow_action(&account.id, &approval.client_id),
                        deny_action: approval_deny_action(&account.id, &approval.client_id),
                        client_id: approval.client_id,
                        ip: approval.ip,
                        geolocation: approval.geolocation,
                        city: approval.city,
                        state: approval.state,
                        country: approval.country,
                        platform_label: approval.platform_label,
                        device_label: approval.device_label,
                    })
                    .collect::<Vec<_>>();
                total_approvals += approval_views.len();
                account_views.push(SteamApprovalAccountView {
                    account_id: account.id,
                    account_name: account.account_name,
                    steam_username: account.steam_username,
                    steam_id: account.steam_id.map(|value| value.to_string()),
                    approval_count: approval_views.len(),
                    error: None,
                    approvals: approval_views,
                });
            }
            Err(error) => {
                if account.has_refreshable_session() {
                    let refreshed = refresh_account_confirmation_session_if_needed(
                        app_state,
                        authenticated,
                        shared_master_key.as_ref().as_slice(),
                        account.clone(),
                        true,
                    )
                    .await;
                    match steam_platform::list_login_approvals(&refreshed).await {
                        Ok(approvals) => {
                            let approval_views = approvals
                                .into_iter()
                                .map(|approval| SteamApprovalView {
                                    approve_action: approval_allow_action(
                                        &refreshed.id,
                                        &approval.client_id,
                                    ),
                                    deny_action: approval_deny_action(
                                        &refreshed.id,
                                        &approval.client_id,
                                    ),
                                    client_id: approval.client_id,
                                    ip: approval.ip,
                                    geolocation: approval.geolocation,
                                    city: approval.city,
                                    state: approval.state,
                                    country: approval.country,
                                    platform_label: approval.platform_label,
                                    device_label: approval.device_label,
                                })
                                .collect::<Vec<_>>();
                            total_approvals += approval_views.len();
                            account_views.push(SteamApprovalAccountView {
                                account_id: refreshed.id,
                                account_name: refreshed.account_name,
                                steam_username: refreshed.steam_username,
                                steam_id: refreshed.steam_id.map(|value| value.to_string()),
                                approval_count: approval_views.len(),
                                error: None,
                                approvals: approval_views,
                            });
                            continue;
                        }
                        Err(retry_error) => {
                            account_views.push(SteamApprovalAccountView {
                                account_id: refreshed.id,
                                account_name: refreshed.account_name,
                                steam_username: refreshed.steam_username,
                                steam_id: refreshed.steam_id.map(|value| value.to_string()),
                                approval_count: 0,
                                error: Some(retry_error.to_string()),
                                approvals: Vec::new(),
                            });
                            continue;
                        }
                    }
                }

                account_views.push(SteamApprovalAccountView {
                    account_id: account.id,
                    account_name: account.account_name,
                    steam_username: account.steam_username,
                    steam_id: account.steam_id.map(|value| value.to_string()),
                    approval_count: 0,
                    error: Some(error.to_string()),
                    approvals: Vec::new(),
                });
            }
        }
    }

    account_views.sort_by(|left, right| left.account_name.cmp(&right.account_name));
    Ok(SteamApprovalSnapshot {
        ready_account_count: account_views.len(),
        approval_count: total_approvals,
        generated_at: format_unix_timestamp(generated_at_unix),
        accounts: account_views,
    })
}

pub(super) async fn workspace_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let flash = read_flash_cookie(&headers);
    let banner = flash.as_ref().map(|flash| {
        if flash.kind == "error" {
            PageBanner::error(flash.message.clone())
        } else {
            PageBanner::success(flash.message.clone())
        }
    });
    let default_tab = flash
        .as_ref()
        .map(|flash| flash.default_tab.as_str())
        .or(Some(STEAM_CODES_TAB_ID));

    let mut response = match render_workspace_page(
        &app_state,
        &authenticated,
        language,
        banner,
        default_tab,
        &headers,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    };

    if flash.is_some() {
        let settings = app_state.system_settings.read().await.clone();
        if let Ok(cookie) = set_cookie_header(&clear_flash_cookie_value(
            effective_auth_cookie_secure(&settings, &headers),
        )) {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
    }

    response
}

pub(super) async fn workspace_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Json<SteamWorkspaceSnapshot> {
    let _language = detect_language(&headers, query.lang.as_deref());

    // Ensure zero trust state is loaded
    if let Some(mk) = middleware::resolved_user_master_key(&app_state, &authenticated).await {
        ensure_zero_trust_loaded(&app_state, &authenticated.user.id, mk.as_ref().as_slice()).await;
    }

    let zero_trust_locked_ids: std::collections::HashSet<String> = {
        let zt = app_state.zero_trust.read().await;
        zt.get(&authenticated.user.id)
            .map(|s| s.locked_accounts.keys().cloned().collect())
            .unwrap_or_default()
    };

    Json(build_workspace_snapshot(&app_state, &authenticated, &zero_trust_locked_ids).await)
}

pub(super) async fn approvals_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    match build_approval_snapshot(&app_state, &authenticated).await {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => {
            warn!("failed building Steam approval snapshot: {}", error);
            (
                StatusCode::BAD_REQUEST,
                Json(SteamActionResponse {
                    ok: false,
                    message: language
                        .translations()
                        .steam_approvals_load_failed_message
                        .to_owned(),
                }),
            )
                .into_response()
        }
    }
}

pub(super) async fn confirmations_snapshot_handler(
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
