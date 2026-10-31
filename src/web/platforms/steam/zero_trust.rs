// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

/// Axum middleware that enforces zero trust mode for all Steam routes.
///
/// When any of the user's Steam accounts are locked by zero trust, this
/// middleware blocks ALL requests except those on an explicit allowlist.
/// New handlers added in the future are automatically blocked — safe by default.
pub(crate) async fn zero_trust_guard(
    State(app_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // 1. Get authenticated session (inserted by require_login middleware)
    let Some(authenticated) = request.extensions().get::<AuthenticatedSession>().cloned() else {
        return next.run(request).await;
    };

    let locked_ids: HashSet<String> =
        match current_zero_trust_state(&app_state, &authenticated).await {
            Some(state) => state.locked_accounts.keys().cloned().collect(),
            None => return next.run(request).await,
        };

    // 4. Check allowlist
    let method = request.method().clone();
    let path = request.uri().path().to_owned();

    if is_zero_trust_allowed(&method, &path, &locked_ids) {
        return next.run(request).await;
    }

    // 5. Blocked — return appropriate response based on path type
    let headers = request.headers().clone();
    if path.starts_with("/api/") {
        let language = detect_language(&headers, None);
        let translations = language.translations();
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_zero_trust_operation_locked_message
            })),
        )
            .into_response()
    } else {
        let language = detect_language(&headers, None);
        redirect_with_workspace_banner(
            &app_state,
            &headers,
            PageBanner::error(
                language
                    .translations()
                    .steam_zero_trust_operation_locked_message,
            ),
            Some(STEAM_ACCOUNTS_TAB_ID),
        )
        .await
    }
}

/// Check whether a request is on the zero trust allowlist.
pub(super) fn is_zero_trust_allowed(
    method: &axum::http::Method,
    path: &str,
    locked_ids: &HashSet<String>,
) -> bool {
    // Zero trust endpoints — always allowed (activate, deactivate, status, sweep)
    if path.starts_with("/api/platforms/steam/zero-trust/") {
        return true;
    }

    // GET-only readonly endpoints — always allowed
    if *method == axum::http::Method::GET
        && (path == STEAM_WORKSPACE_PATH
            || path == STEAM_SNAPSHOT_API_PATH
            || path == STEAM_APPROVALS_API_PATH
            || path == STEAM_CONFIRMATIONS_API_PATH
            || path == STEAM_TIME_CHECK_API_PATH)
    {
        return true;
    }

    // Extract account_id from path (if present)
    let account_id = extract_account_id_from_path(path);

    // Account-specific paths: if the specific account is NOT locked, allow
    if let Some(ref id) = account_id {
        if !locked_ids.contains(id.as_str()) {
            return true;
        }
    }

    // Protective operations — these are allowed even for locked accounts
    // because zero trust actively uses them (deny confirmations, revoke devices, etc.)
    if is_protective_operation(method, path) {
        return true;
    }

    // Everything else is blocked (default-deny)
    false
}

/// Extract account_id from Steam route paths like:
///   /platforms/steam/accounts/{account_id}/...
///   /api/platforms/steam/accounts/{account_id}/...
pub(super) fn extract_account_id_from_path(path: &str) -> Option<String> {
    // Match both /platforms/steam/accounts/{id} and /api/platforms/steam/accounts/{id}
    let segments: Vec<&str> = path.split('/').collect();
    for (i, segment) in segments.iter().enumerate() {
        if *segment == "accounts" && i + 1 < segments.len() {
            let candidate = segments[i + 1];
            if !candidate.is_empty() {
                return Some(candidate.to_owned());
            }
        }
    }
    None
}

/// Check if the operation is a "protective" action allowed during zero trust.
pub(super) fn is_protective_operation(method: &axum::http::Method, path: &str) -> bool {
    if *method == axum::http::Method::GET {
        // Enumerate devices (sweep needs this)
        if path.ends_with("/devices") && path.contains("/accounts/") {
            return true;
        }
        // Account 2FA status (read-only, needed for monitoring)
        if path.ends_with("/status") && path.contains("/accounts/") {
            return true;
        }
        // Phone status (read-only)
        if path.ends_with("/phone-status") && path.contains("/accounts/") {
            return true;
        }
        return false;
    }

    if *method == axum::http::Method::POST {
        // Revoke devices
        if path.ends_with("/devices/revoke") && path.contains("/accounts/") {
            return true;
        }
        // Deny individual confirmation
        if path.contains("/confirmations/") && path.ends_with("/deny") {
            return true;
        }
        // Bulk deny confirmations
        if path.ends_with("/confirmations/deny-all") && path.contains("/accounts/") {
            return true;
        }
        // Deny login approval
        if path.contains("/approvals/") && path.ends_with("/deny") {
            return true;
        }
        return false;
    }

    false
}

// ---------------------------------------------------------------------------
// Zero Trust Mode — file persistence helpers
// ---------------------------------------------------------------------------

pub(super) fn zero_trust_file_path(runtime: &RuntimeConfig, user_id: &str) -> PathBuf {
    runtime
        .users_dir
        .join(user_id)
        .join("steam")
        .join("zero_trust.json")
}

pub(super) fn compute_zero_trust_hmac(master_key: &[u8], payload: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(master_key).expect("HMAC accepts any key length");
    mac.update(payload);
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

pub(super) fn verify_zero_trust_hmac(
    master_key: &[u8],
    payload: &[u8],
    expected_b64: &str,
) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(master_key).expect("HMAC accepts any key length");
    mac.update(payload);
    let expected = match base64::engine::general_purpose::STANDARD.decode(expected_b64) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    mac.verify_slice(&expected).is_ok()
}

pub(super) async fn persist_zero_trust_state(
    runtime: &RuntimeConfig,
    user_id: &str,
    state: &ZeroTrustUserState,
    master_key: &[u8],
) -> Result<()> {
    let path = zero_trust_file_path(runtime, user_id);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("failed creating zero trust state directory")?;
    }
    let state_json = serde_json::to_vec(state).context("failed serializing zero trust state")?;
    let signature = compute_zero_trust_hmac(master_key, &state_json);
    let file_content = serde_json::json!({
        "state": state,
        "signature": signature,
    });
    let encoded = serde_json::to_vec_pretty(&file_content)
        .context("failed encoding zero trust file content")?;
    tokio::fs::write(&path, encoded)
        .await
        .with_context(|| format!("failed writing {}", path.display()))
}

pub(super) async fn load_zero_trust_state(
    path: &std::path::Path,
    master_key: &[u8],
) -> Result<Option<ZeroTrustUserState>> {
    let raw = match tokio::fs::read(path).await {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("failed reading {}", path.display())),
    };

    let parsed: serde_json::Value =
        serde_json::from_slice(&raw).context("failed parsing zero trust file")?;

    let signature = parsed
        .get("signature")
        .and_then(|v| v.as_str())
        .context("zero trust file missing signature")?;

    let state_value = parsed
        .get("state")
        .context("zero trust file missing state")?;

    let state_bytes =
        serde_json::to_vec(state_value).context("failed re-serializing state for HMAC check")?;

    if !verify_zero_trust_hmac(master_key, &state_bytes, signature) {
        anyhow::bail!("zero trust file HMAC verification failed — possible tampering");
    }

    let state: ZeroTrustUserState = serde_json::from_value(state_value.clone())
        .context("failed deserializing zero trust state")?;
    Ok(Some(state))
}

/// Load zero trust state from disk into memory if not already present.
pub(super) async fn ensure_zero_trust_loaded(
    app_state: &AppState,
    user_id: &str,
    master_key: &[u8],
) {
    let already_loaded = {
        let zt = app_state.zero_trust.read().await;
        zt.contains_key(user_id)
    };
    if !already_loaded {
        let path = zero_trust_file_path(&app_state.runtime, user_id);
        if let Ok(Some(state)) = load_zero_trust_state(&path, master_key).await {
            if !state.locked_accounts.is_empty() {
                app_state
                    .zero_trust
                    .write()
                    .await
                    .insert(user_id.to_owned(), state);
            }
        }
    }
}

pub(super) async fn current_zero_trust_state(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
) -> Option<ZeroTrustUserState> {
    let in_memory = {
        let zt = app_state.zero_trust.read().await;
        zt.get(&authenticated.user.id)
            .filter(|state| !state.locked_accounts.is_empty())
            .cloned()
    };
    if in_memory.is_some() {
        return in_memory;
    }

    if let Some(master_key) = middleware::resolved_user_master_key(app_state, authenticated).await {
        ensure_zero_trust_loaded(
            app_state,
            &authenticated.user.id,
            master_key.as_ref().as_slice(),
        )
        .await;
    }

    let zt = app_state.zero_trust.read().await;
    zt.get(&authenticated.user.id)
        .filter(|state| !state.locked_accounts.is_empty())
        .cloned()
}

// ---------------------------------------------------------------------------
// Zero Trust Mode — handlers
// ---------------------------------------------------------------------------

pub(super) async fn zero_trust_activate_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<ZeroTrustActivateForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    // Validate confirm phrase
    if form.confirm_phrase.trim() != "CONFIRM" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_zero_trust_invalid_confirm_message
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

    // Resolve account IDs
    let account_ids: Vec<String> = if form.account_ids.trim() == "all" {
        steam_platform::list_managed_account_ids(&steam_root).await
    } else {
        form.account_ids
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    };

    if account_ids.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_zero_trust_activation_failed_message
            })),
        )
            .into_response();
    }

    // --- Phase 1: Lock accounts IMMEDIATELY, return fast ---
    let now = Utc::now().timestamp();
    let mut locked_accounts: HashMap<String, ZeroTrustAccountEntry> = HashMap::new();

    for account_id in &account_ids {
        locked_accounts.insert(
            account_id.clone(),
            ZeroTrustAccountEntry {
                activated_at_unix: now,
                activated_by_username: authenticated.user.username.clone(),
                initial_guard_state: None,
                initial_device_id: None,
            },
        );
    }

    let user_state = ZeroTrustUserState {
        locked_accounts: locked_accounts.clone(),
    };

    // Write to in-memory state
    {
        let mut zt = app_state.zero_trust.write().await;
        zt.insert(authenticated.user.id.clone(), user_state.clone());
    }

    let persist_result = tokio::time::timeout(
        Duration::from_secs(3),
        persist_zero_trust_state(
            &app_state.runtime,
            &authenticated.user.id,
            &user_state,
            master_key.as_ref().as_slice(),
        ),
    )
    .await;
    if let Some(error) = match persist_result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(anyhow::anyhow!(
            "timed out while persisting zero trust state"
        )),
    } {
        warn!(
            "failed persisting zero trust state for user {}: {}",
            authenticated.user.username, error
        );
        let mut zt = app_state.zero_trust.write().await;
        zt.remove(&authenticated.user.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_zero_trust_activation_failed_message
            })),
        )
            .into_response();
    }

    // --- Phase 2: Audit/sweep in background (non-blocking) ---
    let bg_app_state = app_state.clone();
    let bg_user_id = authenticated.user.id.clone();
    let bg_username = authenticated.user.username.clone();
    let bg_master_key: Vec<u8> = master_key.as_ref().to_vec();
    let bg_http_client = app_state.http_client.clone();
    let bg_account_ids = account_ids.clone();
    tokio::spawn(async move {
        let steam_root = steam_accounts_dir(&bg_app_state.runtime, &bg_user_id);

        let _ = bg_app_state
            .meta_store
            .record_audit(&NewAuditEntry {
                action_type: "steam_zero_trust_activate".to_owned(),
                actor_user_id: Some(bg_user_id.clone()),
                subject_user_id: Some(bg_user_id.clone()),
                ip_address: None,
                success: true,
                details_json: serde_json::json!({
                    "username": bg_username,
                    "locked_account_count": bg_account_ids.len(),
                    "account_ids": bg_account_ids.clone(),
                })
                .to_string(),
            })
            .await;

        for account_id in &bg_account_ids {
            // Fetch security info (with timeout)
            let (initial_guard_state, initial_device_id) = match tokio::time::timeout(
                Duration::from_secs(15),
                steam_platform::fetch_security_info(&steam_root, &bg_master_key, account_id),
            )
            .await
            {
                Ok(Ok(info)) => (Some(info.guard_state), Some(info.bound_device)),
                _ => (None, None),
            };

            // Update the entry with captured security info
            {
                let mut zt = bg_app_state.zero_trust.write().await;
                if let Some(user_state) = zt.get_mut(&bg_user_id) {
                    if let Some(entry) = user_state.locked_accounts.get_mut(account_id) {
                        entry.initial_guard_state = initial_guard_state;
                        entry.initial_device_id = initial_device_id.clone();
                    }
                }
            }

            // Execute the sweep
            let _ = steam_platform::execute_zero_trust_sweep(
                &steam_root,
                &bg_master_key,
                &bg_http_client,
                account_id,
                initial_guard_state,
                initial_device_id.as_deref(),
                true, // always skip emergency code rotation
            )
            .await;
        }

        // Re-persist state with updated security info
        let state_snapshot = {
            let zt = bg_app_state.zero_trust.read().await;
            zt.get(&bg_user_id).cloned()
        };
        if let Some(state) = state_snapshot {
            let _ = persist_zero_trust_state(
                &bg_app_state.runtime,
                &bg_user_id,
                &state,
                &bg_master_key,
            )
            .await;
        }

        info!(
            "zero trust background sweep completed for user {} ({} accounts)",
            bg_username,
            bg_account_ids.len()
        );
    });

    // Return immediately — the page will reload and show the zero trust banner,
    // and the periodic sweep polling will display ongoing results.
    Json(serde_json::json!({
        "ok": true,
        "message": translations.steam_zero_trust_activated_message,
    }))
    .into_response()
}

pub(super) async fn zero_trust_deactivate_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<ZeroTrustDeactivateForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    let _ = current_zero_trust_state(&app_state, &authenticated).await;

    // Validate confirm phrase
    if form.confirm_phrase.trim() != "CONFIRM" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_zero_trust_invalid_confirm_message
            })),
        )
            .into_response();
    }

    // Validate password
    if form.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_zero_trust_password_required_message
            })),
        )
            .into_response();
    }

    // Verify password against stored hash
    let stored_hash = match authenticated.user.security.password_hash.as_deref() {
        Some(hash) => hash.to_owned(),
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_zero_trust_password_invalid_message
                })),
            )
                .into_response();
        }
    };

    let settings = app_state.system_settings.read().await.clone();
    match verify_password(
        &form.password,
        &stored_hash,
        authenticated.user.security.password_argon_version,
        &settings.argon_policy,
    ) {
        Ok(PasswordVerification::Valid | PasswordVerification::ValidNeedsRehash) => {}
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_zero_trust_password_invalid_message
                })),
            )
                .into_response();
        }
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

    // If user has TOTP enabled, verify the TOTP code
    if authenticated.user.security.totp_enabled
        && authenticated.user.security.totp_secret_json.is_some()
    {
        let totp_secret = match web_auth::decrypt_user_totp_secret(
            &authenticated.user,
            master_key.as_ref().as_slice(),
        ) {
            Ok(secret) => secret,
            Err(error) => {
                warn!(
                    "failed decrypting zero trust deactivation TOTP secret for user {}: {}",
                    authenticated.user.username, error
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": translations.session_data_locked_message
                    })),
                )
                    .into_response();
            }
        };
        let totp_code = form.totp_code.as_deref().unwrap_or("").trim();
        if totp_code.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_zero_trust_totp_required_message
                })),
            )
                .into_response();
        }
        let now = Utc::now().timestamp();
        let used_steps = app_state
            .meta_store
            .list_recent_totp_steps(&authenticated.user.id, now.div_euclid(30) - 5)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        match verify_totp(totp_secret.as_str(), totp_code, now, 1, &used_steps) {
            Ok(TotpVerification::Valid { matched_step }) => {
                let _ = app_state
                    .meta_store
                    .mark_totp_step_used(&authenticated.user.id, matched_step)
                    .await;
                let _ = app_state
                    .meta_store
                    .prune_used_totp_steps(now.div_euclid(30) - 8)
                    .await;
            }
            Ok(TotpVerification::Replay) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": translations.steam_zero_trust_totp_replay_message
                    })),
                )
                    .into_response();
            }
            _ => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": translations.steam_zero_trust_totp_invalid_message
                    })),
                )
                    .into_response();
            }
        }
    }

    // Resolve which accounts to deactivate
    let requested_account_ids = form
        .account_ids
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("all");
    let accounts_to_remove: Vec<String> = if requested_account_ids == "all" {
        current_zero_trust_state(&app_state, &authenticated)
            .await
            .map(|state| state.locked_accounts.keys().cloned().collect())
            .unwrap_or_default()
    } else {
        requested_account_ids
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // Remove from in-memory state
    {
        let mut zt = app_state.zero_trust.write().await;
        if let Some(user_state) = zt.get_mut(&authenticated.user.id) {
            for account_id in &accounts_to_remove {
                user_state.locked_accounts.remove(account_id);
            }
            if user_state.locked_accounts.is_empty() {
                zt.remove(&authenticated.user.id);
            }
        }
    }

    // Update or delete persisted file
    let remaining_state = {
        let zt = app_state.zero_trust.read().await;
        zt.get(&authenticated.user.id).cloned()
    };

    let file_path = zero_trust_file_path(&app_state.runtime, &authenticated.user.id);
    match remaining_state {
        Some(state) if !state.locked_accounts.is_empty() => {
            if let Err(e) = persist_zero_trust_state(
                &app_state.runtime,
                &authenticated.user.id,
                &state,
                master_key.as_ref().as_slice(),
            )
            .await
            {
                warn!("failed persisting updated zero trust state: {e}");
            }
        }
        _ => {
            // All accounts removed, delete the file
            let _ = tokio::fs::remove_file(&file_path).await;
        }
    }

    // Audit log
    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: "steam_zero_trust_deactivate".to_owned(),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(authenticated.user.id.clone()),
            ip_address: None,
            success: true,
            details_json: serde_json::json!({
                "username": authenticated.user.username,
                "deactivated_account_count": accounts_to_remove.len(),
                "account_ids": accounts_to_remove,
            })
            .to_string(),
        })
        .await;

    Json(serde_json::json!({
        "ok": true,
        "message": translations.steam_zero_trust_deactivated_message,
    }))
    .into_response()
}

pub(super) async fn zero_trust_status_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let _language = detect_language(&headers, query.lang.as_deref());

    let (active, locked_accounts) = match current_zero_trust_state(&app_state, &authenticated).await
    {
        Some(state) => {
            let accounts: Vec<serde_json::Value> = state
                .locked_accounts
                .iter()
                .map(|(id, entry)| {
                    serde_json::json!({
                        "account_id": id,
                        "activated_at_unix": entry.activated_at_unix,
                        "activated_by_username": entry.activated_by_username,
                        "initial_guard_state": entry.initial_guard_state,
                        "initial_device_id": entry.initial_device_id,
                    })
                })
                .collect();
            (true, accounts)
        }
        _ => (false, Vec::new()),
    };

    Json(serde_json::json!({
        "active": active,
        "locked_accounts": locked_accounts,
    }))
    .into_response()
}

pub(super) async fn zero_trust_sweep_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    _headers: HeaderMap,
    Json(_form): Json<ZeroTrustSweepForm>,
) -> Response {
    // This endpoint is polled by the frontend to check zero trust status.
    // It does NOT run sweeps — the only sweep runs once in the background
    // when zero trust is first activated.
    let locked_accounts = match current_zero_trust_state(&app_state, &authenticated).await {
        Some(state) => state.locked_accounts,
        None => {
            return Json(serde_json::json!({
                "ok": true,
                "active": false,
                "locked_count": 0,
            }))
            .into_response();
        }
    };

    let locked_count = locked_accounts.len();
    let account_ids: Vec<String> = locked_accounts.keys().cloned().collect();

    Json(serde_json::json!({
        "ok": true,
        "active": true,
        "locked_count": locked_count,
        "account_ids": account_ids,
    }))
    .into_response()
}
