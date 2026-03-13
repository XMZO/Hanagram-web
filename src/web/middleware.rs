// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::sessions;
use super::shared::*;

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

    let path = request.uri().path();
    let allow_password_reset =
        path == "/settings" || path == "/settings/security/password" || path == "/logout";
    if authenticated.requires_password_reset && !allow_password_reset {
        return Redirect::to("/settings#security").into_response();
    }

    let allow_totp_setup = path.starts_with("/settings/security/totp") || path == "/logout";
    if (authenticated.requires_totp_setup || authenticated.recovery_codes_remaining == 0)
        && !allow_totp_setup
    {
        return Redirect::to("/settings/security/totp/setup").into_response();
    }

    request.extensions_mut().insert(authenticated);
    next.run(request).await
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
    if let Some(master_key) = app_state
        .user_keys
        .read()
        .await
        .get(&authenticated.user.id)
        .cloned()
    {
        return Some(master_key);
    }

    app_state
        .unlock_cache
        .read()
        .await
        .get(&authenticated.auth_session.id)
        .cloned()
}

pub(crate) async fn cache_user_master_key(
    app_state: &AppState,
    user_id: &str,
    auth_session_id: &str,
    master_key: MasterKey,
) {
    let shared_master_key = share_master_key(master_key);
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
    sessions::unlock_user_sessions(app_state, user_id).await;
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
        .phone_flows
        .write()
        .await
        .retain(|_, flow| flow.user_id != user_id);
    app_state
        .qr_flows
        .write()
        .await
        .retain(|_, flow| flow.user_id != user_id);
}

pub(crate) async fn clear_auth_session_sensitive_state(
    app_state: &AppState,
    auth_session_id: &str,
) {
    app_state.unlock_cache.write().await.remove(auth_session_id);
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
