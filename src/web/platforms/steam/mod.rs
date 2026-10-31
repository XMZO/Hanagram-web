// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::platforms::steam as steam_platform;
use crate::web::middleware;
use crate::web::shared::*;
use crate::web_auth;
use hanagram_web::security::{PasswordVerification, verify_password};
use hmac::{Hmac, Mac};
use sha2::Sha256;

mod accounts;
mod approvals;
mod confirmations;
mod devices;
mod setup;
mod snapshot;
mod tools;
mod zero_trust;

use accounts::*;
use approvals::*;
use confirmations::*;
use devices::*;
use setup::*;
use snapshot::*;
use tools::*;
pub(crate) use zero_trust::zero_trust_guard;
use zero_trust::*;

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
    zero_trust_active: bool,
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
struct SteamValidateTokenForm {
    code: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamTradeRestoreForm {
    confirm_phrase: String,
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamEmptyActionForm {
    lang: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SteamSessionDeviceRevokeForm {
    scope: String,
    token_id: Option<String>,
    lang: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZeroTrustActivateForm {
    account_ids: String,
    confirm_phrase: String,
    lang: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZeroTrustDeactivateForm {
    #[serde(default)]
    account_ids: Option<String>,
    confirm_phrase: String,
    password: String,
    #[serde(default, alias = "totp")]
    totp_code: Option<String>,
    lang: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZeroTrustSweepForm {
    #[serde(rename = "lang")]
    _lang: Option<String>,
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

pub(crate) async fn build_workspace_card(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
) -> PlatformWorkspaceCardView {
    // The workspace card doesn't need zero trust detail; pass an empty set.
    let snapshot =
        build_workspace_snapshot(app_state, authenticated, &std::collections::HashSet::new()).await;
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
        .route(
            "/api/platforms/steam/accounts/{account_id}/export/mafile",
            get(account_export_mafile_handler),
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
        // Phone status
        .route(
            "/api/platforms/steam/accounts/{account_id}/phone-status",
            get(account_phone_status_handler),
        )
        // Emergency codes
        .route(
            "/api/platforms/steam/accounts/{account_id}/emergency-codes",
            post(create_emergency_codes_handler),
        )
        .route(
            "/api/platforms/steam/accounts/{account_id}/emergency-codes/destroy",
            post(destroy_emergency_codes_handler),
        )
        // Validate token
        .route(
            "/api/platforms/steam/accounts/{account_id}/validate-token",
            post(validate_token_handler),
        )
        .route(
            "/api/platforms/steam/accounts/{account_id}/trade-restore",
            get(trade_restore_status_handler),
        )
        .route(
            "/api/platforms/steam/accounts/{account_id}/trade-restore/revert",
            post(trade_restore_revert_handler),
        )
        // Time sync check
        .route(STEAM_TIME_CHECK_API_PATH, get(time_check_handler))
        // Zero Trust Mode
        .route(
            STEAM_ZERO_TRUST_ACTIVATE_PATH,
            post(zero_trust_activate_handler),
        )
        .route(
            STEAM_ZERO_TRUST_DEACTIVATE_PATH,
            post(zero_trust_deactivate_handler),
        )
        .route(STEAM_ZERO_TRUST_STATUS_PATH, get(zero_trust_status_handler))
        .route(STEAM_ZERO_TRUST_SWEEP_PATH, post(zero_trust_sweep_handler))
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

    // Ensure zero trust state is loaded from disk if not yet in memory
    if let Some(mk) = middleware::resolved_user_master_key(app_state, authenticated).await {
        ensure_zero_trust_loaded(app_state, &authenticated.user.id, mk.as_ref().as_slice()).await;
    }

    // Collect zero-trust-locked account IDs so build_workspace_snapshot can populate them
    let zero_trust_locked_ids: std::collections::HashSet<String> = {
        let zt = app_state.zero_trust.read().await;
        zt.get(&authenticated.user.id)
            .map(|s| s.locked_accounts.keys().cloned().collect())
            .unwrap_or_default()
    };

    let snapshot = build_workspace_snapshot(app_state, authenticated, &zero_trust_locked_ids).await;

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

    // Zero Trust context injection (reuse the set collected earlier)
    let zero_trust_active_ids: Vec<String> = zero_trust_locked_ids.iter().cloned().collect();
    context.insert("zero_trust_active", &!zero_trust_active_ids.is_empty());
    context.insert("zero_trust_account_ids", &zero_trust_active_ids);
    context.insert("zero_trust_activate_api", STEAM_ZERO_TRUST_ACTIVATE_PATH);
    context.insert(
        "zero_trust_deactivate_api",
        STEAM_ZERO_TRUST_DEACTIVATE_PATH,
    );
    context.insert("zero_trust_status_api", STEAM_ZERO_TRUST_STATUS_PATH);
    context.insert("zero_trust_sweep_api", STEAM_ZERO_TRUST_SWEEP_PATH);

    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "steam_workspace.html", &context)
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

fn language_from_headers_and_form(headers: &HeaderMap, lang: Option<&str>) -> Language {
    detect_language(headers, lang)
}

#[cfg(test)]
mod tests {
    use super::ZeroTrustDeactivateForm;

    #[test]
    fn zero_trust_deactivate_form_accepts_legacy_totp_without_account_ids() {
        let form: ZeroTrustDeactivateForm = serde_json::from_value(serde_json::json!({
            "password": "temporary-password",
            "confirm_phrase": "CONFIRM",
            "totp": "123456"
        }))
        .expect("legacy deactivate payload should deserialize");

        assert_eq!(form.account_ids, None);
        assert_eq!(form.totp_code.as_deref(), Some("123456"));
        assert_eq!(form.confirm_phrase, "CONFIRM");
        assert_eq!(form.password, "temporary-password");
    }
}
