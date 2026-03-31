// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::platforms::steam as steam_platform;
use crate::web::middleware;
use crate::web::shared::*;

#[derive(Clone, Debug, Serialize)]
struct SteamAccountView {
    id: String,
    account_name: String,
    steam_username: Option<String>,
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
    has_session_tokens: bool,
    has_refreshable_session: bool,
    login_approval_ready: bool,
    imported_from: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    update_material_action: Option<String>,
    rename_action: Option<String>,
    delete_action: Option<String>,
    login_action: Option<String>,
    has_revocation_code: bool,
    has_proxy: bool,
    proxy_url: Option<String>,
    session_devices_api: Option<String>,
    session_device_revoke_api: Option<String>,
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
    bulk_accept_action: String,
    bulk_deny_action: String,
}

#[derive(Clone, Debug, Serialize)]
struct SteamConfirmationSnapshot {
    ready_account_count: usize,
    confirmation_count: usize,
    generated_at: String,
    accounts: Vec<SteamConfirmationAccountView>,
}

#[derive(Clone, Debug, Serialize)]
struct SteamApprovalView {
    client_id: String,
    ip: Option<String>,
    geolocation: Option<String>,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    platform_label: String,
    device_label: Option<String>,
    approve_action: String,
    deny_action: String,
}

#[derive(Clone, Debug, Serialize)]
struct SteamApprovalAccountView {
    account_id: String,
    account_name: String,
    steam_username: Option<String>,
    steam_id: Option<String>,
    approval_count: usize,
    error: Option<String>,
    approvals: Vec<SteamApprovalView>,
}

#[derive(Clone, Debug, Serialize)]
struct SteamApprovalSnapshot {
    ready_account_count: usize,
    approval_count: usize,
    generated_at: String,
    accounts: Vec<SteamApprovalAccountView>,
}

#[derive(Clone, Debug, Serialize)]
struct SteamSessionDeviceView {
    token_id: String,
    device_label: String,
    platform_label: String,
    location_label: Option<String>,
    first_seen_at: Option<String>,
    last_seen_at: Option<String>,
    is_current: bool,
}

#[derive(Clone, Debug, Serialize)]
struct SteamSessionDeviceSnapshot {
    current_token_id: Option<String>,
    device_count: usize,
    devices: Vec<SteamSessionDeviceView>,
}

#[derive(Clone, Debug, Serialize)]
struct SteamActionResponse {
    ok: bool,
    message: String,
}

#[derive(Debug, Default, Deserialize)]
struct ManualSteamAccountForm {
    account_name: String,
    steam_username: String,
    steam_id: String,
    shared_secret: String,
    identity_secret: String,
    device_id: String,
    steam_login_secure: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CredentialSteamAccountForm {
    account_name: String,
    steam_username: String,
    steam_password: String,
    shared_secret: String,
    identity_secret: String,
    device_id: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RenameSteamAccountForm {
    account_name: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamAccountLoginForm {
    steam_username: String,
    steam_password: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateSteamMaterialForm {
    steam_username: String,
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

#[derive(Debug, Default, Deserialize)]
struct SteamApprovalActionForm {
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamQrApprovalForm {
    account_id: String,
    challenge_url: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamSetupBeginForm {
    steam_username: String,
    steam_password: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamSetupLoginCodeForm {
    code: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamSetupPhoneNumberForm {
    phone_number: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamSetupPhoneVerifyForm {
    verification_code: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamSetupFinalizeForm {
    confirm_code: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamSetupTransferFinishForm {
    sms_code: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamRemoveAuthenticatorForm {
    revocation_code: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamWinAuthImportForm {
    uri: String,
    account_name: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamProxyForm {
    proxy_url: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamSessionDeviceRevokeForm {
    scope: String,
    token_id: Option<String>,
    lang: Option<String>,
}

const STEAM_CODES_TAB_ID: &str = "codes";
const STEAM_ACCOUNTS_TAB_ID: &str = "accounts";
const STEAM_IMPORT_TAB_ID: &str = "import";
const STEAM_SECURITY_TAB_ID: &str = "security";
const STEAM_DEVICES_TAB_ID: &str = "devices";
const STEAM_SETUP_TAB_ID: &str = "setup";
const STEAM_APPROVALS_TAB_ID: &str = "approvals";
const STEAM_CONFIRMATIONS_TAB_ID: &str = "confirmations";
const STEAM_ABOUT_TAB_ID: &str = "about";
const STEAM_FLASH_COOKIE_NAME: &str = "hanagram_steam_flash";
const STEAM_FLASH_COOKIE_MAX_AGE_SECONDS: i64 = 15;

#[derive(Debug, Deserialize, Serialize)]
struct SteamFlashCookie {
    kind: String,
    message: String,
    default_tab: String,
}

fn steam_accounts_dir(runtime: &RuntimeConfig, user_id: &str) -> PathBuf {
    runtime.users_dir.join(user_id).join("steam")
}

fn normalize_workspace_tab(tab: Option<&str>) -> &'static str {
    match tab {
        Some(STEAM_ACCOUNTS_TAB_ID) => STEAM_ACCOUNTS_TAB_ID,
        Some(STEAM_IMPORT_TAB_ID) => STEAM_IMPORT_TAB_ID,
        Some(STEAM_SECURITY_TAB_ID) => STEAM_SECURITY_TAB_ID,
        Some(STEAM_DEVICES_TAB_ID) => STEAM_DEVICES_TAB_ID,
        Some(STEAM_SETUP_TAB_ID) => STEAM_SETUP_TAB_ID,
        Some(STEAM_APPROVALS_TAB_ID) => STEAM_APPROVALS_TAB_ID,
        Some(STEAM_CONFIRMATIONS_TAB_ID) => STEAM_CONFIRMATIONS_TAB_ID,
        Some(STEAM_ABOUT_TAB_ID) => STEAM_ABOUT_TAB_ID,
        // Backward compat: old tab IDs redirect to new locations
        Some("manage") => STEAM_ACCOUNTS_TAB_ID,
        Some("issues") => STEAM_ABOUT_TAB_ID,
        _ => STEAM_CODES_TAB_ID,
    }
}

fn workspace_redirect_target(tab: Option<&str>) -> String {
    let tab = normalize_workspace_tab(tab);
    if tab == STEAM_CODES_TAB_ID {
        String::from(STEAM_WORKSPACE_PATH)
    } else {
        format!("{STEAM_WORKSPACE_PATH}#{tab}")
    }
}

fn build_flash_cookie_value(
    banner: &PageBanner,
    default_tab: Option<&str>,
    secure: bool,
) -> String {
    let payload = SteamFlashCookie {
        kind: banner.kind.to_owned(),
        message: banner.message.clone(),
        default_tab: normalize_workspace_tab(default_tab).to_owned(),
    };
    let encoded = serde_json::to_vec(&payload)
        .ok()
        .map(|value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value))
        .unwrap_or_default();
    let secure_fragment = if secure { "; Secure" } else { "" };
    format!(
        "{STEAM_FLASH_COOKIE_NAME}={encoded}; Path={STEAM_WORKSPACE_PATH}; HttpOnly; SameSite=Lax; Max-Age={STEAM_FLASH_COOKIE_MAX_AGE_SECONDS}{secure_fragment}"
    )
}

fn clear_flash_cookie_value(secure: bool) -> String {
    let secure_fragment = if secure { "; Secure" } else { "" };
    format!(
        "{STEAM_FLASH_COOKIE_NAME}=; Path={STEAM_WORKSPACE_PATH}; HttpOnly; SameSite=Lax; Max-Age=0{secure_fragment}"
    )
}

fn read_flash_cookie(headers: &HeaderMap) -> Option<SteamFlashCookie> {
    let raw = find_cookie(headers, STEAM_FLASH_COOKIE_NAME)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .ok()?;
    serde_json::from_slice::<SteamFlashCookie>(&decoded).ok()
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

fn account_login_action(account_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/login")
}

fn account_session_devices_api(account_id: &str) -> String {
    format!("/api/platforms/steam/accounts/{account_id}/devices")
}

fn account_session_device_revoke_api(account_id: &str) -> String {
    format!("/api/platforms/steam/accounts/{account_id}/devices/revoke")
}

async fn refresh_account_confirmation_session_if_needed(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    master_key: &[u8],
    account: steam_platform::SteamGuardAccount,
    force_refresh: bool,
) -> steam_platform::SteamGuardAccount {
    if !steam_platform::confirmation_session_can_refresh(&account) {
        return account;
    }
    if !force_refresh && !steam_platform::confirmation_session_should_refresh(&account) {
        return account;
    }

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::refresh_confirmation_session_if_needed(
        &steam_root,
        master_key,
        &account.id,
        force_refresh,
    )
    .await
    {
        Ok(Some(refreshed)) => refreshed,
        Ok(None) => account,
        Err(error) => {
            warn!(
                "failed refreshing Steam confirmation session for account {}: {}",
                account.id, error
            );
            account
        }
    }
}

fn confirmation_accept_action(account_id: &str, confirmation_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/confirmations/{confirmation_id}/accept")
}

fn confirmation_deny_action(account_id: &str, confirmation_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/confirmations/{confirmation_id}/deny")
}

fn approval_allow_action(account_id: &str, client_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/approvals/{client_id}/approve")
}

fn approval_deny_action(account_id: &str, client_id: &str) -> String {
    format!("{STEAM_WORKSPACE_PATH}/accounts/{account_id}/approvals/{client_id}/deny")
}

fn bulk_accept_action(account_id: &str) -> String {
    format!("/api/platforms/steam/accounts/{account_id}/confirmations/accept-all")
}

fn bulk_deny_action(account_id: &str) -> String {
    format!("/api/platforms/steam/accounts/{account_id}/confirmations/deny-all")
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
                .map_or(false, |v| !v.trim().is_empty()),
            proxy_url: account.proxy_url.clone(),
            session_devices_api,
            session_device_revoke_api,
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

async fn build_approval_snapshot(
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
        secondary_href: format!("{}#accounts", steam_workspace_href(language)),
        secondary_label: translations.steam_accounts_tab_label.to_owned(),
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(STEAM_WORKSPACE_PATH, get(workspace_handler))
        .route(STEAM_SNAPSHOT_API_PATH, get(workspace_snapshot_handler))
        .route(STEAM_APPROVALS_API_PATH, get(approvals_snapshot_handler))
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
            STEAM_IMPORT_LOGIN_PATH,
            post(create_logged_in_account_handler),
        )
        .route(
            STEAM_APPROVAL_CHALLENGE_PATH,
            post(approve_login_challenge_handler),
        )
        .route(
            STEAM_APPROVAL_CHALLENGE_UPLOAD_PATH,
            post(approve_login_challenge_upload_handler),
        )
        .route(
            "/platforms/steam/accounts/{account_id}/materials",
            post(update_account_materials_handler),
        )
        .route(
            "/platforms/steam/accounts/{account_id}/login",
            post(login_managed_account_handler),
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
        .route(
            "/platforms/steam/accounts/{account_id}/approvals/{client_id}/approve",
            post(approve_login_approval_handler),
        )
        .route(
            "/platforms/steam/accounts/{account_id}/approvals/{client_id}/deny",
            post(deny_login_approval_handler),
        )
        // Setup / Link authenticator
        .route(STEAM_SETUP_BEGIN_PATH, post(setup_begin_handler))
        .route(STEAM_SETUP_LOGIN_CODE_PATH, post(setup_login_code_handler))
        .route(STEAM_SETUP_RESUME_PATH, post(setup_resume_handler))
        .route(
            STEAM_SETUP_PHONE_BEGIN_PATH,
            post(setup_phone_begin_handler),
        )
        .route(
            STEAM_SETUP_PHONE_VERIFY_PATH,
            post(setup_phone_verify_handler),
        )
        .route(STEAM_SETUP_FINALIZE_PATH, post(setup_finalize_handler))
        .route(STEAM_SETUP_CANCEL_PATH, post(setup_cancel_handler))
        .route(
            STEAM_SETUP_TRANSFER_START_PATH,
            post(setup_transfer_start_handler),
        )
        .route(
            STEAM_SETUP_TRANSFER_FINISH_PATH,
            post(setup_transfer_finish_handler),
        )
        // Link authenticator for existing account
        .route(
            "/platforms/steam/accounts/{account_id}/authenticator/link",
            post(link_authenticator_for_account_handler),
        )
        // Remove authenticator
        .route(
            "/platforms/steam/accounts/{account_id}/authenticator/remove",
            post(remove_authenticator_handler),
        )
        // 2FA status query
        .route(
            "/api/platforms/steam/accounts/{account_id}/status",
            get(account_status_handler),
        )
        .route(
            "/api/platforms/steam/accounts/{account_id}/devices",
            get(account_session_devices_handler),
        )
        .route(
            "/api/platforms/steam/accounts/{account_id}/devices/revoke",
            post(revoke_account_session_devices_handler),
        )
        // QR export
        .route(
            "/api/platforms/steam/accounts/{account_id}/export/qr",
            get(account_export_qr_handler),
        )
        // WinAuth import
        .route(STEAM_IMPORT_WINAUTH_PATH, post(import_winauth_handler))
        // Bulk confirmations
        .route(
            "/api/platforms/steam/accounts/{account_id}/confirmations/accept-all",
            post(bulk_accept_confirmations_handler),
        )
        .route(
            "/api/platforms/steam/accounts/{account_id}/confirmations/deny-all",
            post(bulk_deny_confirmations_handler),
        )
        // Proxy settings
        .route(
            "/platforms/steam/accounts/{account_id}/proxy",
            post(account_proxy_handler),
        )
        // Time sync check
        .route(STEAM_TIME_CHECK_API_PATH, get(time_check_handler))
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
    let approval_ready_accounts = snapshot
        .accounts
        .iter()
        .filter(|account| account.can_manage && account.login_approval_ready)
        .cloned()
        .collect::<Vec<_>>();
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
    context.insert("default_tab", &normalize_workspace_tab(default_tab));
    context.insert("now", &snapshot.generated_at);
    context.insert("snapshot_api", &steam_snapshot_api_href(language));
    context.insert("approvals_api", &steam_approvals_api_href(language));
    context.insert("confirmations_api", &steam_confirmations_api_href(language));
    context.insert(
        "steam_import_upload_action",
        &steam_import_upload_href(language),
    );
    context.insert(
        "steam_import_manual_action",
        &steam_import_manual_href(language),
    );
    context.insert(
        "steam_import_login_action",
        &steam_import_login_href(language),
    );
    context.insert(
        "steam_approval_challenge_action",
        &steam_approval_challenge_href(language),
    );
    context.insert(
        "steam_approval_challenge_upload_action",
        &steam_approval_challenge_upload_href(language),
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
    context.insert("approval_ready_accounts", &approval_ready_accounts);
    context.insert("snapshot", &snapshot);
    context.insert("steam_setup_begin_action", STEAM_SETUP_BEGIN_PATH);
    context.insert("steam_setup_login_code_action", STEAM_SETUP_LOGIN_CODE_PATH);
    context.insert("steam_setup_resume_action", STEAM_SETUP_RESUME_PATH);
    context.insert(
        "steam_setup_phone_begin_action",
        STEAM_SETUP_PHONE_BEGIN_PATH,
    );
    context.insert(
        "steam_setup_phone_verify_action",
        STEAM_SETUP_PHONE_VERIFY_PATH,
    );
    context.insert("steam_setup_finalize_action", STEAM_SETUP_FINALIZE_PATH);
    context.insert("steam_setup_cancel_action", STEAM_SETUP_CANCEL_PATH);
    context.insert(
        "steam_setup_transfer_start_action",
        STEAM_SETUP_TRANSFER_START_PATH,
    );
    context.insert(
        "steam_setup_transfer_finish_action",
        STEAM_SETUP_TRANSFER_FINISH_PATH,
    );
    context.insert(
        "steam_import_winauth_action",
        &format!("{STEAM_IMPORT_WINAUTH_PATH}?lang={}", language.code()),
    );
    context.insert("steam_time_check_api", STEAM_TIME_CHECK_API_PATH);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "steam_workspace.html", &context)
}

async fn workspace_handler(
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

async fn workspace_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Json<SteamWorkspaceSnapshot> {
    let _language = detect_language(&headers, query.lang.as_deref());
    Json(build_workspace_snapshot(&app_state, &authenticated).await)
}

async fn approvals_snapshot_handler(
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

async fn redirect_with_workspace_banner(
    app_state: &AppState,
    headers: &HeaderMap,
    banner: PageBanner,
    default_tab: Option<&str>,
) -> Response {
    let settings = app_state.system_settings.read().await.clone();
    let secure = effective_auth_cookie_secure(&settings, headers);
    let mut response = Redirect::to(&workspace_redirect_target(default_tab)).into_response();
    if let Ok(cookie) = set_cookie_header(&build_flash_cookie_value(&banner, default_tab, secure)) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn steam_login_failure_message(
    translations: &crate::i18n::TranslationSet,
    error: &anyhow::Error,
    fallback: &'static str,
) -> String {
    let message = error.to_string();
    if message.contains("Steam username is required") {
        translations.steam_login_missing_username_message.to_owned()
    } else if message.contains("Steam password is required") {
        translations.steam_login_missing_password_message.to_owned()
    } else if message.contains("mobile confirmation on another device") {
        translations
            .steam_login_requires_other_confirmation_message
            .to_owned()
    } else if message.contains("email confirmation") || message.contains("email code") {
        translations.steam_login_requires_email_message.to_owned()
    } else {
        fallback.to_owned()
    }
}

fn steam_qr_failure_message(
    translations: &crate::i18n::TranslationSet,
    error: &anyhow::Error,
) -> String {
    let message = error.to_string();
    if message.contains("challenge URL is required") {
        translations.steam_link_approval_missing_message.to_owned()
    } else if message.contains("Invalid challenge URL")
        || message.contains("no Steam login challenge URL")
    {
        translations.steam_qr_approval_invalid_message.to_owned()
    } else {
        translations.steam_qr_approval_failed_message.to_owned()
    }
}

fn steam_setup_failure_message(
    language: Language,
    error: &anyhow::Error,
    fallback: &'static str,
) -> String {
    let translations = language.translations();
    let message = error.to_string();
    if message.contains("rate_limited") || message.contains("RateLimitExceeded") {
        translations.steam_setup_rate_limited_message.to_owned()
    } else if message.contains("bad_sms_code") {
        translations.steam_setup_bad_sms_code_message.to_owned()
    } else if message.contains("login_code_required") {
        translations
            .steam_setup_login_code_missing_message
            .to_owned()
    } else if message.contains("Steam Guard code was rejected")
        || message.contains("sign-in code was rejected")
    {
        translations
            .steam_setup_login_code_failed_message
            .to_owned()
    } else if message.contains("requires_email_login_confirmation") {
        translations.steam_login_requires_email_message.to_owned()
    } else if message.contains("requires_trusted_device_confirmation") {
        translations
            .steam_login_requires_other_confirmation_message
            .to_owned()
    } else if message.contains("requires_existing_guard_code") {
        translations
            .steam_setup_requires_existing_guard_code_message
            .to_owned()
    } else if message.contains("invalid_phone_number") {
        translations.steam_setup_invalid_phone_message.to_owned()
    } else if message.contains("phone_number_required") {
        translations
            .steam_setup_phone_number_missing_message
            .to_owned()
    } else if message.contains("no_phone") {
        translations.steam_setup_no_phone_message.to_owned()
    } else {
        fallback.to_owned()
    }
}

async fn find_pending_setup_id_for_user(app_state: &AppState, user_id: &str) -> Option<String> {
    let setups = app_state.steam_setups.read().await;
    setups
        .iter()
        .find(|(_, pending)| pending.user_id == user_id)
        .map(|(id, _)| id.clone())
}

async fn take_pending_setup_for_user(
    app_state: &AppState,
    user_id: &str,
) -> Option<(String, PendingSteamSetup)> {
    let setup_id = find_pending_setup_id_for_user(app_state, user_id).await?;
    let mut setups = app_state.steam_setups.write().await;
    let pending = setups.remove(&setup_id)?;
    Some((setup_id, pending))
}

async fn store_pending_setup(app_state: &AppState, setup_id: String, pending: PendingSteamSetup) {
    app_state
        .steam_setups
        .write()
        .await
        .insert(setup_id, pending);
}

async fn store_setup_login_code_prompt(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    setup_id: String,
    steam_username: String,
    login: steamguard::UserLogin<steamguard::transport::WebApiTransport>,
    transport: steamguard::transport::WebApiTransport,
    prompt: steam_platform::GuardLoginCodePrompt,
) -> Response {
    let code_kind = match prompt.kind {
        steam_platform::GuardLoginCodeKind::ExistingGuardCode => "device",
        steam_platform::GuardLoginCodeKind::EmailCode => "email",
    };
    let hint = prompt.hint.clone();
    store_pending_setup(
        app_state,
        setup_id.clone(),
        PendingSteamSetup {
            user_id: authenticated.user.id.clone(),
            auth_session_id: authenticated.auth_session.id.clone(),
            created_at: Utc::now().timestamp(),
            stage: SteamSetupStage::AwaitingLoginCode {
                login,
                transport,
                steam_username,
                prompt,
            },
        },
    )
    .await;

    Json(serde_json::json!({
        "ok": true,
        "step": "login_code",
        "setup_id": setup_id,
        "code_kind": code_kind,
        "hint": hint,
    }))
    .into_response()
}

async fn store_setup_outcome(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    setup_id: String,
    steam_username: String,
    outcome: steam_platform::GuardEnrollmentResult,
) -> Response {
    match outcome {
        steam_platform::GuardEnrollmentResult::Provisioned {
            guard_data,
            steam_timestamp,
            masked_phone,
            verify_channel,
            registrar,
        } => {
            let pending = PendingSteamSetup {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                created_at: Utc::now().timestamp(),
                stage: SteamSetupStage::AwaitingVerification {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    masked_phone: masked_phone.clone(),
                    verify_channel: verify_channel.clone(),
                    steam_username,
                },
            };
            store_pending_setup(app_state, setup_id.clone(), pending).await;

            Json(serde_json::json!({
                "ok": true,
                "step": "confirm",
                "setup_id": setup_id,
                "masked_phone": masked_phone,
                "verify_channel": verify_channel
            }))
            .into_response()
        }
        steam_platform::GuardEnrollmentResult::EmailConfirmationRequired { registrar } => {
            let pending = PendingSteamSetup {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                created_at: Utc::now().timestamp(),
                stage: SteamSetupStage::AwaitingAccountEmailConfirmation {
                    registrar,
                    steam_username,
                },
            };
            store_pending_setup(app_state, setup_id.clone(), pending).await;

            Json(serde_json::json!({
                "ok": true,
                "step": "email",
                "setup_id": setup_id
            }))
            .into_response()
        }
        steam_platform::GuardEnrollmentResult::PhoneRequired { registrar } => {
            let pending = PendingSteamSetup {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                created_at: Utc::now().timestamp(),
                stage: SteamSetupStage::AwaitingPhoneNumber {
                    registrar,
                    steam_username,
                },
            };
            store_pending_setup(app_state, setup_id.clone(), pending).await;

            Json(serde_json::json!({
                "ok": true,
                "step": "phone_number",
                "setup_id": setup_id
            }))
            .into_response()
        }
        steam_platform::GuardEnrollmentResult::DeviceConflict { registrar } => {
            let pending = PendingSteamSetup {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                created_at: Utc::now().timestamp(),
                stage: SteamSetupStage::AwaitingMigrationCode {
                    registrar,
                    steam_username,
                },
            };
            store_pending_setup(app_state, setup_id.clone(), pending).await;

            Json(serde_json::json!({
                "ok": true,
                "step": "transfer",
                "setup_id": setup_id
            }))
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

async fn create_logged_in_account_handler(
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

async fn login_managed_account_handler(
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

async fn approve_login_challenge_for_account(
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

async fn approve_login_challenge_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<SteamQrApprovalForm>,
) -> Response {
    approve_login_challenge_for_account(
        &app_state,
        &authenticated,
        &headers,
        detect_language(&headers, form.lang.as_deref()),
        &form.account_id,
        &form.challenge_url,
    )
    .await
}

async fn approve_login_challenge_upload_handler(
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

async fn approve_login_approval_handler(
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
        true,
    )
    .await
}

async fn deny_login_approval_handler(
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

fn language_from_headers_and_form(headers: &HeaderMap, lang: Option<&str>) -> Language {
    detect_language(headers, lang)
}

async fn login_approval_action_handler(
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

async fn link_authenticator_for_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
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

    // Clear any previous setup for this user.
    {
        let mut setups = app_state.steam_setups.write().await;
        setups.retain(|_, pending| pending.user_id != authenticated.user.id);
    }

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::enroll_guard_for_managed_account(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
    )
    .await
    {
        Ok((steam_username, outcome)) => {
            let setup_id = Uuid::new_v4().to_string();
            store_setup_outcome(
                &app_state,
                &authenticated,
                setup_id,
                steam_username,
                outcome,
            )
            .await
        }
        Err(error) => {
            warn!(
                "failed linking authenticator for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_setup_link_failed_message)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Guard enrollment handlers (fresh login flow)
// ---------------------------------------------------------------------------

async fn setup_begin_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupBeginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.steam_username.trim().is_empty() || form.steam_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_login_missing_username_message
            })),
        )
            .into_response();
    }

    let Some(_master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
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

    // Clear any previous setup for this user.
    {
        let mut setups = app_state.steam_setups.write().await;
        setups.retain(|_, pending| pending.user_id != authenticated.user.id);
    }

    let username = form.steam_username.clone();
    let password = form.steam_password.clone();
    match steam_platform::enroll_new_guard(username, password).await {
        Ok(steam_platform::GuardEnrollmentStartResult::Ready {
            steam_username,
            outcome,
        }) => {
            let setup_id = Uuid::new_v4().to_string();
            store_setup_outcome(
                &app_state,
                &authenticated,
                setup_id,
                steam_username,
                outcome,
            )
            .await
        }
        Ok(steam_platform::GuardEnrollmentStartResult::LoginCodeRequired {
            steam_username,
            login,
            transport,
            prompt,
        }) => {
            let setup_id = Uuid::new_v4().to_string();
            store_setup_login_code_prompt(
                &app_state,
                &authenticated,
                setup_id,
                steam_username,
                login,
                transport,
                prompt,
            )
            .await
        }
        Err(error) => {
            warn!("Steam setup begin failed: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_setup_link_failed_message)
                })),
            )
                .into_response()
        }
    }
}

async fn setup_login_code_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupLoginCodeForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_login_code_missing_message
            })),
        )
            .into_response();
    }

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingLoginCode {
            login,
            transport,
            steam_username,
            prompt,
        } => match steam_platform::continue_guard_enrollment_with_login_code(
            login, transport, prompt, form.code,
        )
        .await
        {
            Ok(steam_platform::GuardLoginCodeSubmitResult::Advanced(outcome)) => {
                store_setup_outcome(
                    &app_state,
                    &authenticated,
                    setup_id,
                    steam_username,
                    outcome,
                )
                .await
            }
            Ok(steam_platform::GuardLoginCodeSubmitResult::Retry {
                login,
                transport,
                prompt,
                error,
            }) => {
                warn!("Steam setup login-code verification failed: {error}");
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingLoginCode {
                            login,
                            transport,
                            steam_username,
                            prompt,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_login_code_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
            Err(error) => {
                warn!("Steam setup login-code task failed: {error}");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_login_code_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

async fn setup_resume_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingAccountEmailConfirmation {
            registrar,
            steam_username,
        } => match steam_platform::resume_guard_enrollment(registrar).await {
            Ok(steam_platform::GuardEnrollmentResult::EmailConfirmationRequired { registrar }) => {
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingAccountEmailConfirmation {
                            registrar,
                            steam_username,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": translations.steam_setup_email_confirm_pending_message
                    })),
                )
                    .into_response()
            }
            Ok(outcome) => {
                store_setup_outcome(
                    &app_state,
                    &authenticated,
                    setup_id,
                    steam_username,
                    outcome,
                )
                .await
            }
            Err(error) => {
                warn!("Steam setup email resume failed: {error}");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_link_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        SteamSetupStage::AwaitingPhoneEmailConfirmation {
            registrar,
            steam_username,
            confirmation_email_address,
            phone_number_formatted,
        } => match steam_platform::continue_guard_phone_link(&registrar).await {
            Ok(steam_platform::GuardPhoneEmailContinuation::StillWaiting { seconds_to_wait }) => {
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneEmailConfirmation {
                            registrar,
                            steam_username,
                            confirmation_email_address,
                            phone_number_formatted,
                        },
                    },
                )
                .await;
                let mut message = translations
                    .steam_setup_phone_email_pending_message
                    .to_owned();
                if let Some(wait_seconds) = seconds_to_wait {
                    message.push_str(" (");
                    message.push_str(&format_duration_for_display(
                        language,
                        i64::from(wait_seconds),
                    ));
                    message.push(')');
                }
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": message
                    })),
                )
                    .into_response()
            }
            Ok(steam_platform::GuardPhoneEmailContinuation::SmsSent) => {
                store_pending_setup(
                    &app_state,
                    setup_id.clone(),
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneCode {
                            registrar,
                            steam_username,
                            phone_number_formatted: phone_number_formatted.clone(),
                        },
                    },
                )
                .await;
                Json(serde_json::json!({
                    "ok": true,
                    "step": "phone_code",
                    "setup_id": setup_id,
                    "phone_number": phone_number_formatted
                }))
                .into_response()
            }
            Err(error) => {
                warn!("Steam phone email resume failed: {error}");
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneEmailConfirmation {
                            registrar,
                            steam_username,
                            confirmation_email_address,
                            phone_number_formatted,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_phone_begin_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

async fn setup_phone_begin_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupPhoneNumberForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.phone_number.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_phone_number_missing_message
            })),
        )
            .into_response();
    }

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingPhoneNumber {
            registrar,
            steam_username,
        } => match steam_platform::start_guard_phone_link(&registrar, form.phone_number).await {
            Ok(prompt) => {
                store_pending_setup(
                    &app_state,
                    setup_id.clone(),
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneEmailConfirmation {
                            registrar,
                            steam_username,
                            confirmation_email_address: prompt.confirmation_email_address.clone(),
                            phone_number_formatted: prompt.phone_number_formatted.clone(),
                        },
                    },
                )
                .await;
                Json(serde_json::json!({
                    "ok": true,
                    "step": "phone_email",
                    "setup_id": setup_id,
                    "phone_number": prompt.phone_number_formatted,
                    "confirmation_email": prompt.confirmation_email_address
                }))
                .into_response()
            }
            Err(error) => {
                warn!("Steam phone setup begin failed: {error}");
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneNumber {
                            registrar,
                            steam_username,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_phone_begin_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

async fn setup_phone_verify_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupPhoneVerifyForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.verification_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_bad_sms_code_message
            })),
        )
            .into_response();
    }

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingPhoneCode {
            registrar,
            steam_username,
            phone_number_formatted,
        } => match steam_platform::verify_guard_phone_link(registrar, form.verification_code).await
        {
            Ok(steam_platform::GuardPhoneVerificationResult::Advanced(outcome)) => {
                store_setup_outcome(
                    &app_state,
                    &authenticated,
                    setup_id,
                    steam_username,
                    outcome,
                )
                .await
            }
            Ok(steam_platform::GuardPhoneVerificationResult::Retry { registrar, error }) => {
                warn!("Steam phone verification failed: {error}");
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneCode {
                            registrar,
                            steam_username,
                            phone_number_formatted,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_phone_code_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
            Err(error) => {
                warn!("Steam phone verification failed: {error}");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_phone_code_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

async fn setup_finalize_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupFinalizeForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.confirm_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_missing_credentials_message
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

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingVerification {
            registrar,
            guard_data,
            steam_timestamp,
            steam_username,
            masked_phone,
            verify_channel,
            ..
        } => {
            let code = form.confirm_code.trim().to_owned();
            let username = steam_username.clone();

            let enrollment_result = tokio::task::spawn_blocking(move || {
                steam_platform::confirm_guard_enrollment(
                    registrar,
                    guard_data,
                    steam_timestamp,
                    code,
                )
            })
            .await;

            match enrollment_result {
                Ok(steam_platform::GuardFinalizeResult::Completed {
                    guard_data: enrolled_data,
                }) => {
                    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
                    match steam_platform::persist_enrolled_guard(
                        &steam_root,
                        master_key.as_ref().as_slice(),
                        &enrolled_data,
                        &username,
                    )
                    .await
                    {
                        Ok(saved) => {
                            let revocation_code = saved.revocation_code.clone().unwrap_or_default();
                            let account_id = saved.id.clone();

                            // Store completion state.
                            let complete = PendingSteamSetup {
                                user_id: authenticated.user.id.clone(),
                                auth_session_id: authenticated.auth_session.id.clone(),
                                created_at: Utc::now().timestamp(),
                                stage: SteamSetupStage::Complete,
                            };
                            app_state
                                .steam_setups
                                .write()
                                .await
                                .insert(setup_id, complete);

                            Json(serde_json::json!({
                                "ok": true,
                                "step": "complete",
                                "revocation_code": revocation_code,
                                "account_id": account_id
                            }))
                            .into_response()
                        }
                        Err(error) => {
                            warn!("Failed saving linked Steam account: {error}");
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({
                                    "ok": false,
                                    "message": translations.steam_setup_save_failed_message
                                })),
                            )
                                .into_response()
                        }
                    }
                }
                Ok(steam_platform::GuardFinalizeResult::Retry {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    error,
                }) => {
                    warn!("Steam setup finalize failed: {error}");
                    store_pending_setup(
                        &app_state,
                        setup_id,
                        PendingSteamSetup {
                            user_id: authenticated.user.id.clone(),
                            auth_session_id: authenticated.auth_session.id.clone(),
                            created_at: Utc::now().timestamp(),
                            stage: SteamSetupStage::AwaitingVerification {
                                registrar,
                                guard_data,
                                steam_timestamp,
                                masked_phone,
                                verify_channel,
                                steam_username,
                            },
                        },
                    )
                    .await;
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": steam_setup_failure_message(
                                language,
                                &error,
                                translations.steam_setup_finalize_failed_message,
                            )
                        })),
                    )
                        .into_response()
                }
                Err(join_error) => {
                    warn!("Steam setup finalize task panicked: {join_error}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": translations.steam_setup_finalize_failed_message
                        })),
                    )
                        .into_response()
                }
            }
        }
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

async fn setup_transfer_start_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingMigrationCode {
            registrar,
            steam_username,
        } => {
            let username = steam_username.clone();

            let result = tokio::task::spawn_blocking(move || {
                steam_platform::initiate_guard_migration(registrar)
            })
            .await;

            match result {
                Ok(steam_platform::GuardMigrationStartResult::AwaitingSms {
                    registrar: registrar_back,
                }) => {
                    let ready = PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingMigrationCode {
                            registrar: registrar_back,
                            steam_username: username,
                        },
                    };
                    app_state.steam_setups.write().await.insert(setup_id, ready);

                    Json(serde_json::json!({
                        "ok": true,
                        "step": "transfer_sms"
                    }))
                    .into_response()
                }
                Ok(steam_platform::GuardMigrationStartResult::PhoneRequired {
                    registrar: registrar_back,
                }) => {
                    store_pending_setup(
                        &app_state,
                        setup_id,
                        PendingSteamSetup {
                            user_id: authenticated.user.id.clone(),
                            auth_session_id: authenticated.auth_session.id.clone(),
                            created_at: Utc::now().timestamp(),
                            stage: SteamSetupStage::AwaitingPhoneNumber {
                                registrar: registrar_back,
                                steam_username: username,
                            },
                        },
                    )
                    .await;

                    Json(serde_json::json!({
                        "ok": true,
                        "step": "phone_number"
                    }))
                    .into_response()
                }
                Ok(steam_platform::GuardMigrationStartResult::Retry {
                    registrar: registrar_back,
                    error,
                }) => {
                    warn!("Steam transfer start failed: {error}");
                    store_pending_setup(
                        &app_state,
                        setup_id,
                        PendingSteamSetup {
                            user_id: authenticated.user.id.clone(),
                            auth_session_id: authenticated.auth_session.id.clone(),
                            created_at: Utc::now().timestamp(),
                            stage: SteamSetupStage::AwaitingMigrationCode {
                                registrar: registrar_back,
                                steam_username: username,
                            },
                        },
                    )
                    .await;
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": steam_setup_failure_message(
                                language,
                                &error,
                                translations.steam_setup_transfer_failed_message,
                            )
                        })),
                    )
                        .into_response()
                }
                Err(join_error) => {
                    warn!("Steam transfer start panicked: {join_error}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": translations.steam_setup_transfer_failed_message
                        })),
                    )
                        .into_response()
                }
            }
        }
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

async fn setup_transfer_finish_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupTransferFinishForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.sms_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_missing_credentials_message
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

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingMigrationCode {
            registrar,
            steam_username,
        } => {
            let migration_code = form.sms_code.trim().to_owned();
            let username = steam_username.clone();

            let result = tokio::task::spawn_blocking(move || {
                steam_platform::complete_guard_migration(registrar, migration_code)
            })
            .await;

            match result {
                Ok(steam_platform::GuardMigrationFinishResult::Completed {
                    guard_data: migrated_guard,
                }) => {
                    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
                    match steam_platform::persist_enrolled_guard(
                        &steam_root,
                        master_key.as_ref().as_slice(),
                        &migrated_guard,
                        &username,
                    )
                    .await
                    {
                        Ok(saved) => {
                            let revocation_code = saved.revocation_code.clone().unwrap_or_default();
                            let account_id = saved.id.clone();

                            let complete = PendingSteamSetup {
                                user_id: authenticated.user.id.clone(),
                                auth_session_id: authenticated.auth_session.id.clone(),
                                created_at: Utc::now().timestamp(),
                                stage: SteamSetupStage::Complete,
                            };
                            app_state
                                .steam_setups
                                .write()
                                .await
                                .insert(setup_id, complete);

                            Json(serde_json::json!({
                                "ok": true,
                                "step": "complete",
                                "revocation_code": revocation_code,
                                "account_id": account_id
                            }))
                            .into_response()
                        }
                        Err(error) => {
                            warn!("Failed saving transferred Steam account: {error}");
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({
                                    "ok": false,
                                    "message": translations.steam_setup_save_failed_message
                                })),
                            )
                                .into_response()
                        }
                    }
                }
                Ok(steam_platform::GuardMigrationFinishResult::Retry { registrar, error }) => {
                    warn!("Steam transfer finish failed: {error}");
                    store_pending_setup(
                        &app_state,
                        setup_id,
                        PendingSteamSetup {
                            user_id: authenticated.user.id.clone(),
                            auth_session_id: authenticated.auth_session.id.clone(),
                            created_at: Utc::now().timestamp(),
                            stage: SteamSetupStage::AwaitingMigrationCode {
                                registrar,
                                steam_username,
                            },
                        },
                    )
                    .await;
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": steam_setup_failure_message(
                                language,
                                &error,
                                translations.steam_setup_transfer_failed_message,
                            )
                        })),
                    )
                        .into_response()
                }
                Err(join_error) => {
                    warn!("Steam transfer finish panicked: {join_error}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": translations.steam_setup_transfer_failed_message
                        })),
                    )
                        .into_response()
                }
            }
        }
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

async fn setup_cancel_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    let _language = detect_language(&headers, form.lang.as_deref());

    let mut setups = app_state.steam_setups.write().await;
    let before = setups.len();
    setups.retain(|_, pending| pending.user_id != authenticated.user.id);
    let removed = before - setups.len();

    Json(serde_json::json!({
        "ok": true,
        "removed": removed
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Guard revocation handler
// ---------------------------------------------------------------------------

async fn remove_authenticator_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<SteamRemoveAuthenticatorForm>,
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

    if form.revocation_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_remove_missing_code_message
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
    match steam_platform::revoke_account_guard(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        form.revocation_code.trim().to_owned(),
    )
    .await
    {
        Ok(outcome) => {
            if outcome.revoked {
                Json(serde_json::json!({
                    "ok": true,
                    "message": translations.steam_remove_success_message
                }))
                .into_response()
            } else {
                let msg = if let Some(left) = outcome.tries_left {
                    format!(
                        "{} ({})",
                        translations.steam_remove_incorrect_code_message, left
                    )
                } else {
                    translations.steam_remove_incorrect_code_message.to_owned()
                };
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": msg,
                        "tries_left": outcome.tries_left
                    })),
                )
                    .into_response()
            }
        }
        Err(error) => {
            warn!(
                "guard revocation failed for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_remove_failed_message)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Logged-in device handlers
// ---------------------------------------------------------------------------

fn build_session_device_snapshot(
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

async fn account_session_devices_handler(
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

async fn revoke_account_session_devices_handler(
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

async fn account_status_handler(
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

async fn account_export_qr_handler(
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

// ---------------------------------------------------------------------------
// Third-party guard import handler
// ---------------------------------------------------------------------------

async fn import_winauth_handler(
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
                PageBanner::error(&format!(
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

async fn bulk_accept_confirmations_handler(
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
        true,
    )
    .await
}

async fn bulk_deny_confirmations_handler(
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

async fn bulk_confirmation_action(
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

// ---------------------------------------------------------------------------
// Proxy configuration handler
// ---------------------------------------------------------------------------

async fn account_proxy_handler(
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

async fn time_check_handler(
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
