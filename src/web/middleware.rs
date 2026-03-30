// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::platforms;
use super::shared::*;

pub(crate) const LOGIN_REAUTH_UNLOCK_LOCATION: &str = "/login?reauth=unlock";

fn enforced_redirect_target(
    path: &str,
    requires_password_reset: bool,
    requires_recovery_ack: bool,
    requires_totp_setup: bool,
    recovery_codes_remaining: i64,
) -> Option<&'static str> {
    let allow_password_reset =
        path == "/settings" || path == "/settings/security/password" || path == "/logout";
    if requires_password_reset {
        if allow_password_reset {
            return None;
        }
        return Some("/settings#security");
    }

    let allow_recovery_ack =
        path == "/settings" || path == "/settings/security/recovery/ack" || path == "/logout";
    if requires_recovery_ack {
        if allow_recovery_ack {
            return None;
        }
        return Some("/settings#security");
    }

    let allow_totp_setup = path.starts_with("/settings/security/totp") || path == "/logout";
    if (requires_totp_setup || recovery_codes_remaining == 0) && !allow_totp_setup {
        return Some("/settings/security/totp/setup");
    }

    None
}

pub(crate) async fn require_login(
    State(app_state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let settings = app_state.system_settings.read().await.clone();
    let Some(authenticated) =
        resolve_authenticated_session(&app_state.meta_store, &settings, request.headers())
            .await
            .ok()
            .flatten()
    else {
        clear_invalid_cookie_state(&app_state, request.headers()).await;
        let location = match request.uri().query() {
            Some(query) if !query.is_empty() => format!("/login?{query}"),
            _ => String::from("/login"),
        };
        let mut response = Redirect::to(&location).into_response();
        if find_cookie(request.headers(), AUTH_COOKIE_NAME).is_some() {
            let cookie_secure = effective_auth_cookie_secure(&settings, request.headers());
            if let Ok(cookie) = set_cookie_header(&clear_auth_cookie(cookie_secure)) {
                response.headers_mut().insert(header::SET_COOKIE, cookie);
            }
        }
        return response;
    };

    if let Some(session_token) = find_cookie(request.headers(), AUTH_COOKIE_NAME) {
        let Some(master_key) = ensure_auth_session_master_key(
            &app_state,
            &authenticated.user.id,
            &authenticated.auth_session.id,
            session_token,
        )
        .await
        else {
            return revoke_auth_session_and_redirect_to_login(
                &app_state,
                &settings,
                request.headers(),
                &authenticated.auth_session,
                LOGIN_REAUTH_UNLOCK_LOCATION,
            )
            .await;
        };

        ensure_user_passkey_login_material(&app_state, &authenticated.user, &master_key).await;
    }

    let recovery_notice_pending = app_state
        .recovery_notices
        .read()
        .await
        .contains_key(&authenticated.auth_session.id);
    if let Some(target) = enforced_redirect_target(
        request.uri().path(),
        authenticated.requires_password_reset,
        recovery_notice_pending,
        authenticated.requires_totp_setup,
        authenticated.recovery_codes_remaining,
    ) {
        return Redirect::to(target).into_response();
    }

    request.extensions_mut().insert(authenticated);
    next.run(request).await
}

async fn ensure_user_passkey_login_material(
    app_state: &AppState,
    user: &UserRecord,
    master_key: &SharedMasterKey,
) {
    let current_payload = user.security.passkey_encrypted_master_key_json.as_deref();
    let passkey_login_key = app_state.passkey_login_key.as_ref().as_slice();
    let needs_refresh = current_payload.map_or(true, |payload| {
        platform_key::decrypt_master_key_for_passkey_login(passkey_login_key, payload).is_err()
    });
    if !needs_refresh {
        return;
    }

    let Some(mut fresh_user) = app_state
        .meta_store
        .get_user_by_id(&user.id)
        .await
        .ok()
        .flatten()
    else {
        return;
    };

    let needs_refresh = fresh_user
        .security
        .passkey_encrypted_master_key_json
        .as_deref()
        .map_or(true, |payload| {
            platform_key::decrypt_master_key_for_passkey_login(passkey_login_key, payload).is_err()
        });
    if !needs_refresh {
        return;
    }

    let wrapped_master_key = match platform_key::encrypt_master_key_for_passkey_login(
        passkey_login_key,
        master_key.as_ref().as_slice(),
    ) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                "failed wrapping passkey login material for {}: {}",
                fresh_user.username, error
            );
            return;
        }
    };
    fresh_user.security.passkey_encrypted_master_key_json = Some(wrapped_master_key);
    fresh_user.updated_at_unix = Utc::now().timestamp();

    if let Err(error) = app_state.meta_store.save_user(&fresh_user).await {
        warn!(
            "failed saving passkey login material for {}: {}",
            fresh_user.username, error
        );
    }
}

pub(crate) async fn sync_active_session_idle_timeouts(
    app_state: &AppState,
    settings: &SystemSettings,
) -> Result<()> {
    let users = app_state.meta_store.list_users().await?;
    for user in users {
        app_state
            .meta_store
            .set_idle_timeout_for_user_sessions(
                &user.id,
                effective_idle_timeout_minutes(&user, settings),
            )
            .await?;
    }
    Ok(())
}

pub(crate) async fn resolved_user_master_key(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
) -> Option<SharedMasterKey> {
    resolve_cached_user_master_key(
        app_state,
        &authenticated.user.id,
        &authenticated.auth_session.id,
    )
    .await
}

pub(crate) async fn resolve_cached_user_master_key(
    app_state: &AppState,
    user_id: &str,
    auth_session_id: &str,
) -> Option<SharedMasterKey> {
    if let Some(master_key) = app_state.user_keys.read().await.get(user_id).cloned() {
        return Some(master_key);
    }

    let master_key = app_state
        .unlock_cache
        .read()
        .await
        .get(auth_session_id)
        .cloned()?;
    app_state
        .user_keys
        .write()
        .await
        .insert(user_id.to_owned(), Arc::clone(&master_key));
    Some(master_key)
}

async fn cache_shared_user_master_key(
    app_state: &AppState,
    user_id: &str,
    auth_session_id: &str,
    shared_master_key: SharedMasterKey,
) {
    app_state
        .unlock_cache
        .write()
        .await
        .insert(auth_session_id.to_owned(), Arc::clone(&shared_master_key));
    app_state
        .user_keys
        .write()
        .await
        .insert(user_id.to_owned(), shared_master_key);
    platforms::telegram::unlock_user_sessions(app_state, user_id).await;
}

async fn persist_auth_session_master_key(
    app_state: &AppState,
    auth_session_id: &str,
    session_token: &str,
    master_key: &[u8],
) -> Result<()> {
    let payload_json = crate::web_auth::wrap_auth_session_master_key(session_token, master_key)?;
    app_state
        .meta_store
        .save_auth_session_unlock_material(auth_session_id, &payload_json)
        .await
}

pub(crate) async fn ensure_auth_session_master_key(
    app_state: &AppState,
    user_id: &str,
    auth_session_id: &str,
    session_token: &str,
) -> Option<SharedMasterKey> {
    if let Some(master_key) =
        resolve_cached_user_master_key(app_state, user_id, auth_session_id).await
    {
        match app_state
            .meta_store
            .load_auth_session_unlock_material(auth_session_id)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = persist_auth_session_master_key(
                    app_state,
                    auth_session_id,
                    session_token,
                    master_key.as_ref().as_slice(),
                )
                .await
                {
                    warn!(
                        "failed persisting auth session unlock material for {}: {}",
                        auth_session_id, error
                    );
                }
            }
            Err(error) => {
                warn!(
                    "failed checking auth session unlock material for {}: {}",
                    auth_session_id, error
                );
            }
        }
        return Some(master_key);
    }

    let payload_json = match app_state
        .meta_store
        .load_auth_session_unlock_material(auth_session_id)
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return None,
        Err(error) => {
            warn!(
                "failed loading auth session unlock material for {}: {}",
                auth_session_id, error
            );
            return None;
        }
    };
    let master_key =
        match crate::web_auth::unwrap_auth_session_master_key(session_token, &payload_json) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    "failed restoring auth session unlock material for {}: {}",
                    auth_session_id, error
                );
                if let Err(delete_error) = app_state
                    .meta_store
                    .delete_auth_session_unlock_material(auth_session_id)
                    .await
                {
                    warn!(
                        "failed deleting corrupted auth session unlock material for {}: {}",
                        auth_session_id, delete_error
                    );
                }
                return None;
            }
        };
    let shared_master_key = share_master_key(master_key);
    cache_shared_user_master_key(
        app_state,
        user_id,
        auth_session_id,
        Arc::clone(&shared_master_key),
    )
    .await;
    Some(shared_master_key)
}

pub(crate) async fn revoke_auth_session_and_redirect_to_login(
    app_state: &AppState,
    settings: &SystemSettings,
    headers: &HeaderMap,
    auth_session: &AuthSessionRecord,
    location: &str,
) -> Response {
    let _ = app_state
        .meta_store
        .revoke_auth_session(&auth_session.id)
        .await;
    clear_auth_session_sensitive_state(app_state, &auth_session.id).await;
    drop_user_master_key_if_no_active_sessions(app_state, &auth_session.user_id).await;

    let mut response = Redirect::to(location).into_response();
    let cookie_secure = effective_auth_cookie_secure(settings, headers);
    if let Ok(cookie) = set_cookie_header(&clear_auth_cookie(cookie_secure)) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

pub(crate) async fn cache_user_master_key(
    app_state: &AppState,
    user_id: &str,
    auth_session_id: &str,
    master_key: MasterKey,
) {
    let shared_master_key = share_master_key(master_key);
    cache_shared_user_master_key(app_state, user_id, auth_session_id, shared_master_key).await;
}

pub(crate) async fn cache_user_master_key_for_session(
    app_state: &AppState,
    user_id: &str,
    auth_session_id: &str,
    session_token: &str,
    master_key: MasterKey,
) {
    let shared_master_key = share_master_key(master_key);
    cache_shared_user_master_key(
        app_state,
        user_id,
        auth_session_id,
        Arc::clone(&shared_master_key),
    )
    .await;
    if let Err(error) = persist_auth_session_master_key(
        app_state,
        auth_session_id,
        session_token,
        shared_master_key.as_ref().as_slice(),
    )
    .await
    {
        warn!(
            "failed persisting auth session unlock material for {}: {}",
            auth_session_id, error
        );
    }
}

pub(crate) fn auth_session_is_active(auth_session: &AuthSessionRecord, now: i64) -> bool {
    if auth_session.revoked_at_unix.is_some() || auth_session.expires_at_unix <= now {
        return false;
    }

    match auth_session.idle_timeout_minutes {
        Some(0) | None => true,
        Some(idle_timeout_minutes) => {
            auth_session.last_seen_at_unix + i64::from(idle_timeout_minutes) * 60 > now
        }
    }
}

pub(crate) async fn clear_pending_flows_for_auth_session(
    app_state: &AppState,
    auth_session_id: &str,
) {
    app_state.totp_setups.write().await.remove(auth_session_id);
    app_state
        .steam_setups
        .write()
        .await
        .retain(|_, flow| flow.auth_session_id != auth_session_id);
    app_state
        .passkey_registrations
        .write()
        .await
        .retain(|_, flow| flow.auth_session_id != auth_session_id);
    app_state
        .recovery_notices
        .write()
        .await
        .remove(auth_session_id);
    app_state
        .phone_flows
        .write()
        .await
        .retain(|_, flow| flow.auth_session_id != auth_session_id);
    app_state
        .qr_flows
        .write()
        .await
        .retain(|_, flow| flow.auth_session_id != auth_session_id);
}

pub(crate) async fn clear_pending_flows_for_user(app_state: &AppState, user_id: &str) {
    app_state
        .passkey_registrations
        .write()
        .await
        .retain(|_, flow| flow.user_id != user_id);
    app_state
        .recovery_notices
        .write()
        .await
        .retain(|_, notice| notice.user_id != user_id);
    app_state
        .phone_flows
        .write()
        .await
        .retain(|_, flow| flow.user_id != user_id);
    app_state
        .qr_flows
        .write()
        .await
        .retain(|_, flow| flow.user_id != user_id);
    app_state
        .steam_setups
        .write()
        .await
        .retain(|_, flow| flow.user_id != user_id);
}

pub(crate) async fn clear_auth_session_sensitive_state(
    app_state: &AppState,
    auth_session_id: &str,
) {
    app_state.unlock_cache.write().await.remove(auth_session_id);
    if let Err(error) = app_state
        .meta_store
        .delete_auth_session_unlock_material(auth_session_id)
        .await
    {
        warn!(
            "failed deleting auth session unlock material for {}: {}",
            auth_session_id, error
        );
    }
    clear_pending_flows_for_auth_session(app_state, auth_session_id).await;
}

pub(crate) async fn drop_user_master_key_if_no_active_sessions(
    app_state: &AppState,
    user_id: &str,
) {
    let Ok(sessions) = app_state
        .meta_store
        .list_auth_sessions_for_user(user_id)
        .await
    else {
        return;
    };
    let now = Utc::now().timestamp();
    if sessions
        .iter()
        .any(|auth_session| auth_session_is_active(auth_session, now))
    {
        return;
    }

    {
        let mut unlock_cache = app_state.unlock_cache.write().await;
        for auth_session in &sessions {
            unlock_cache.remove(&auth_session.id);
        }
    }
    {
        let mut totp_setups = app_state.totp_setups.write().await;
        for auth_session in &sessions {
            totp_setups.remove(&auth_session.id);
        }
    }
    app_state.user_keys.write().await.remove(user_id);
    clear_pending_flows_for_user(app_state, user_id).await;
}

pub(crate) async fn clear_invalid_cookie_state(app_state: &AppState, headers: &HeaderMap) {
    let Some(token) = find_cookie(headers, AUTH_COOKIE_NAME) else {
        return;
    };
    let token_hash = hash_session_token(token);
    let Ok(Some(auth_session)) = app_state
        .meta_store
        .get_auth_session_by_token_hash(&token_hash)
        .await
    else {
        return;
    };

    let now = Utc::now().timestamp();
    if auth_session_is_active(&auth_session, now) {
        return;
    }

    if auth_session.revoked_at_unix.is_none() {
        let _ = app_state
            .meta_store
            .revoke_auth_session(&auth_session.id)
            .await;
    }
    clear_auth_session_sensitive_state(app_state, &auth_session.id).await;
    drop_user_master_key_if_no_active_sessions(app_state, &auth_session.user_id).await;
}

#[cfg(test)]
mod tests {
    use super::enforced_redirect_target;
    use crate::web::shared::TELEGRAM_WORKSPACE_PATH;

    #[test]
    fn password_reset_takes_precedence_over_totp_setup() {
        assert_eq!(
            enforced_redirect_target("/settings", true, false, true, 0),
            None
        );
        assert_eq!(
            enforced_redirect_target("/settings/security/password", true, false, true, 0),
            None
        );
        assert_eq!(
            enforced_redirect_target("/settings/security/totp/setup", true, false, true, 0),
            Some("/settings#security")
        );
        assert_eq!(
            enforced_redirect_target(TELEGRAM_WORKSPACE_PATH, true, false, true, 0),
            Some("/settings#security")
        );
    }

    #[test]
    fn recovery_notice_redirects_before_totp_setup() {
        assert_eq!(
            enforced_redirect_target("/settings", false, true, true, 5),
            None
        );
        assert_eq!(
            enforced_redirect_target("/settings/security/totp/setup", false, true, true, 5),
            Some("/settings#security")
        );
        assert_eq!(
            enforced_redirect_target(TELEGRAM_WORKSPACE_PATH, false, true, false, 5),
            Some("/settings#security")
        );
    }

    #[test]
    fn totp_redirect_applies_after_password_reset_is_cleared() {
        assert_eq!(
            enforced_redirect_target("/settings", false, false, true, 0),
            Some("/settings/security/totp/setup")
        );
        assert_eq!(
            enforced_redirect_target("/settings/security/totp/setup", false, false, true, 0),
            None
        );
    }
}
