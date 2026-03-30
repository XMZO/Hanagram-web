// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use chrono::Utc;
use steamguard::ExposeSecret;
use hmac::{Hmac, Mac};
use image::ImageReader;
use rqrr::PreparedImage;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use steamguard::accountlinker::{
    AccountLinkError, AccountLinker, FinalizeLinkError, RemoveAuthenticatorError, TransferError,
};
use steamguard::phonelinker::{PhoneLinker, SetPhoneNumberError, VerifyPhoneError};
use steamguard::approver::Challenge;
use steamguard::protobufs::enums::ESessionPersistence;
use steamguard::protobufs::steammessages_auth_steamclient::{
    CAuthentication_GetAuthSessionInfo_Response, EAuthSessionGuardType, EAuthTokenPlatformType,
};
use steamguard::refresher::TokenRefresher;
use steamguard::steamapi::{AuthenticationClient, EResult, PhoneClient};
use steamguard::token::{Jwt as SteamJwt, Tokens as SteamTokens, TwoFactorSecret};
use steamguard::transport::WebApiTransport;
use steamguard::userlogin::UpdateAuthSessionError;
use steamguard::{
    DeviceDetails, LoginApprover, LoginError, SteamGuardAccount as VendorSteamGuardAccount,
    UserLogin,
};
use tokio::fs;
use tokio::task::spawn_blocking;
use tracing::warn;
use uuid::Uuid;

use hanagram_web::security::{EncryptedBlob, decrypt_bytes, encrypt_bytes};

pub(crate) const STEAM_GUARD_CODE_PERIOD_SECONDS: i64 = 30;
pub(crate) const STEAM_MANAGED_ACCOUNT_EXTENSION: &str = "steamguard";

const STEAM_GUARD_CODE_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const STEAM_MANAGED_SCHEMA_VERSION: u8 = 1;
const STEAM_MANAGED_PACK_PREFIX: &[u8] = b"hanagram-steam-pack:v1\0";
const STEAM_MANAGED_ZSTD_LEVEL: i32 = 9;
const STEAM_CONFIRMATION_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";
const STEAM_ACCESS_TOKEN_REFRESH_SKEW_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SteamManagedAccountOrigin {
    ManualEntry,
    UploadedMaFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SteamAccountSourceKind {
    Managed,
    LegacyMaFile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SteamWebSession {
    pub(crate) session_id: Option<String>,
    pub(crate) steam_login: Option<String>,
    pub(crate) steam_login_secure: Option<String>,
    pub(crate) web_cookie: Option<String>,
    pub(crate) oauth_token: Option<String>,
    pub(crate) access_token: Option<String>,
    pub(crate) refresh_token: Option<String>,
}

impl SteamWebSession {
    pub(crate) fn effective_confirmation_cookie(&self, steam_id: Option<u64>) -> Option<String> {
        if let Some(cookie) = self
            .steam_login_secure
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            return Some(cookie.trim().to_owned());
        }

        let access_token = self
            .access_token
            .as_deref()
            .filter(|value| !value.trim().is_empty())?;
        let steam_id = steam_id?;
        Some(format!("{steam_id}||{}", access_token.trim()))
    }

    fn refresh_token(&self) -> Option<&str> {
        self.refresh_token
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }

    fn access_token(&self) -> Option<&str> {
        self.access_token
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SteamGuardAccount {
    pub(crate) id: String,
    pub(crate) account_name: String,
    pub(crate) steam_username: Option<String>,
    pub(crate) steam_id: Option<u64>,
    pub(crate) shared_secret: String,
    pub(crate) identity_secret: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) session: Option<SteamWebSession>,
    pub(crate) storage_path: PathBuf,
    pub(crate) source_kind: SteamAccountSourceKind,
    pub(crate) managed_origin: Option<SteamManagedAccountOrigin>,
    pub(crate) imported_from: Option<String>,
    pub(crate) encrypted_at_rest: bool,
    pub(crate) created_at_unix: Option<i64>,
    pub(crate) updated_at_unix: Option<i64>,
    pub(crate) revocation_code: Option<String>,
    pub(crate) serial_number: Option<String>,
    pub(crate) token_gid: Option<String>,
    pub(crate) secret_1: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) proxy_url: Option<String>,
}

impl SteamGuardAccount {
    pub(crate) fn has_session_tokens(&self) -> bool {
        self.session
            .as_ref()
            .and_then(SteamWebSession::access_token)
            .is_some()
    }

    pub(crate) fn has_refreshable_session(&self) -> bool {
        self.can_manage()
            && self
                .session
                .as_ref()
                .and_then(SteamWebSession::refresh_token)
                .is_some()
    }

    pub(crate) fn login_approval_ready(&self) -> bool {
        self.steam_id.is_some() && self.has_session_tokens()
    }

    pub(crate) fn has_identity_secret(&self) -> bool {
        option_has_value(self.identity_secret.as_deref())
    }

    pub(crate) fn has_device_id(&self) -> bool {
        option_has_value(self.device_id.as_deref())
    }

    pub(crate) fn has_confirmation_secret_material(&self) -> bool {
        self.steam_id.is_some() && self.has_identity_secret() && self.has_device_id()
    }

    pub(crate) fn has_confirmation_session(&self) -> bool {
        self.session
            .as_ref()
            .and_then(|session| session.effective_confirmation_cookie(self.steam_id))
            .is_some()
    }

    pub(crate) fn confirmation_ready(&self) -> bool {
        self.has_confirmation_secret_material() && self.has_confirmation_session()
    }

    pub(crate) fn can_manage(&self) -> bool {
        matches!(self.source_kind, SteamAccountSourceKind::Managed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SteamGuardLoadIssue {
    pub(crate) storage_path: PathBuf,
    pub(crate) error: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManualSteamAccountInput {
    pub(crate) account_name: String,
    pub(crate) steam_username: Option<String>,
    pub(crate) steam_id: u64,
    pub(crate) shared_secret: String,
    pub(crate) identity_secret: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) steam_login_secure: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UpdateSteamAccountInput {
    pub(crate) steam_username: Option<String>,
    pub(crate) shared_secret: Option<String>,
    pub(crate) identity_secret: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) steam_login_secure: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialSteamAccountInput {
    pub(crate) account_name: String,
    pub(crate) steam_username: String,
    pub(crate) steam_password: String,
    pub(crate) shared_secret: String,
    pub(crate) identity_secret: Option<String>,
    pub(crate) device_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SteamCredentialLoginInput {
    pub(crate) steam_username: String,
    pub(crate) steam_password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SteamConfirmation {
    pub(crate) id: String,
    pub(crate) nonce: String,
    pub(crate) creator_id: String,
    pub(crate) confirmation_type: u32,
    pub(crate) type_name: String,
    pub(crate) headline: String,
    pub(crate) summary: Vec<String>,
    pub(crate) icon: Option<String>,
    pub(crate) created_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SteamLoginApproval {
    pub(crate) client_id: String,
    pub(crate) ip: Option<String>,
    pub(crate) geolocation: Option<String>,
    pub(crate) city: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) country: Option<String>,
    pub(crate) platform_label: String,
    pub(crate) device_label: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct StoredSteamWebSession {
    session_id: Option<String>,
    steam_login: Option<String>,
    steam_login_secure: Option<String>,
    web_cookie: Option<String>,
    oauth_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct StoredSteamAccount {
    pub(crate) schema_version: u8,
    pub(crate) id: String,
    pub(crate) account_name: String,
    #[serde(default)]
    pub(crate) steam_username: Option<String>,
    pub(crate) steam_id: Option<u64>,
    pub(crate) shared_secret: String,
    pub(crate) identity_secret: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) session: Option<StoredSteamWebSession>,
    pub(crate) imported_from: Option<String>,
    pub(crate) managed_origin: SteamManagedAccountOrigin,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
    #[serde(default)]
    pub(crate) revocation_code: Option<String>,
    #[serde(default)]
    pub(crate) serial_number: Option<String>,
    #[serde(default)]
    pub(crate) token_gid: Option<String>,
    #[serde(default)]
    pub(crate) secret_1: Option<String>,
    #[serde(default)]
    pub(crate) uri: Option<String>,
    #[serde(default)]
    pub(crate) proxy_url: Option<String>,
}

impl StoredSteamAccount {
    fn into_runtime(self, storage_path: PathBuf) -> SteamGuardAccount {
        SteamGuardAccount {
            id: self.id,
            account_name: self.account_name,
            steam_username: self.steam_username,
            steam_id: self.steam_id,
            shared_secret: self.shared_secret,
            identity_secret: self.identity_secret,
            device_id: self.device_id,
            session: self.session.map(|value| SteamWebSession {
                session_id: value.session_id,
                steam_login: value.steam_login,
                steam_login_secure: value.steam_login_secure,
                web_cookie: value.web_cookie,
                oauth_token: value.oauth_token,
                access_token: value.access_token,
                refresh_token: value.refresh_token,
            }),
            storage_path,
            source_kind: SteamAccountSourceKind::Managed,
            managed_origin: Some(self.managed_origin),
            imported_from: self.imported_from,
            encrypted_at_rest: true,
            created_at_unix: Some(self.created_at_unix),
            updated_at_unix: Some(self.updated_at_unix),
            revocation_code: self.revocation_code,
            serial_number: self.serial_number,
            token_gid: self.token_gid,
            secret_1: self.secret_1,
            uri: self.uri,
            proxy_url: self.proxy_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawSteamGuardAccount {
    #[serde(default)]
    account_name: String,
    #[serde(default)]
    shared_secret: String,
    #[serde(default)]
    identity_secret: String,
    #[serde(default)]
    device_id: String,
    #[serde(default, deserialize_with = "deserialize_optional_u64_from_any")]
    steamid: Option<u64>,
    #[serde(
        default,
        rename = "steam_id",
        deserialize_with = "deserialize_optional_u64_from_any"
    )]
    steam_id: Option<u64>,
    #[serde(default, rename = "Session")]
    session: Option<RawSteamSession>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSteamSession {
    #[serde(default, rename = "SessionID")]
    session_id: Option<String>,
    #[serde(default, rename = "SteamLogin")]
    steam_login: Option<String>,
    #[serde(default, rename = "SteamLoginSecure")]
    steam_login_secure: Option<String>,
    #[serde(default, rename = "WebCookie")]
    web_cookie: Option<String>,
    #[serde(default, rename = "OAuthToken")]
    oauth_token: Option<String>,
    #[serde(default, rename = "AccessToken")]
    access_token: Option<String>,
    #[serde(default, rename = "RefreshToken")]
    refresh_token: Option<String>,
    #[serde(
        default,
        rename = "SteamID",
        deserialize_with = "deserialize_optional_u64_from_any"
    )]
    steam_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SteamJwtClaims {
    #[serde(deserialize_with = "deserialize_u64_from_any")]
    sub: u64,
    #[serde(default, deserialize_with = "deserialize_optional_u64_from_any")]
    exp: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SteamQueryTimeEnvelope {
    response: SteamQueryTimeResponse,
}

#[derive(Debug, Deserialize)]
struct SteamQueryTimeResponse {
    #[serde(deserialize_with = "deserialize_u64_from_any")]
    server_time: u64,
}

#[derive(Debug, Deserialize)]
struct SteamConfirmationListResponse {
    success: bool,
    #[serde(default)]
    needauth: Option<bool>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    conf: Vec<RawSteamConfirmation>,
}

#[derive(Debug, Deserialize)]
struct RawSteamConfirmation {
    #[serde(rename = "type", deserialize_with = "deserialize_u32_from_any")]
    confirmation_type: u32,
    type_name: String,
    id: String,
    creator_id: String,
    nonce: String,
    #[serde(deserialize_with = "deserialize_u64_from_any")]
    creation_time: u64,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    headline: String,
    #[serde(default)]
    summary: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SteamConfirmationActionResponse {
    success: bool,
    #[serde(default)]
    needsauth: Option<bool>,
    #[serde(default)]
    message: Option<String>,
}

pub(crate) fn sanitize_account_name(raw: &str) -> String {
    let mut cleaned = String::new();
    let mut pending_space = false;

    for ch in raw.trim().chars().take(96) {
        let mapped = match ch {
            '/' | '\\' | ':' | '"' | '<' | '>' | '|' | '?' | '*' => Some(' '),
            _ if ch.is_control() => None,
            _ if ch.is_whitespace() => Some(' '),
            _ => Some(ch),
        };

        match mapped {
            Some(' ') => {
                if !cleaned.is_empty() {
                    pending_space = true;
                }
            }
            Some(ch) => {
                if pending_space {
                    cleaned.push(' ');
                    pending_space = false;
                }
                cleaned.push(ch);
            }
            None => {}
        }
    }

    let cleaned = cleaned.trim().to_owned();
    if cleaned.is_empty() {
        format!("steam-account-{}", Utc::now().timestamp())
    } else {
        cleaned
    }
}

fn extract_raw_steam_username(raw_account_name: &str) -> Option<String> {
    normalize_optional_string(Some(raw_account_name.to_owned()))
}

pub(crate) fn managed_accounts_dir(root_dir: &Path) -> PathBuf {
    root_dir.join("accounts")
}

pub(crate) async fn ensure_managed_accounts_dir(root_dir: &Path) -> Result<PathBuf> {
    let dir = managed_accounts_dir(root_dir);
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(dir)
}

pub(crate) fn managed_account_storage_path(root_dir: &Path, account_id: &str) -> PathBuf {
    managed_accounts_dir(root_dir).join(format!("{account_id}.{STEAM_MANAGED_ACCOUNT_EXTENSION}"))
}

pub(crate) fn is_valid_managed_account_id(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() <= 64
        && account_id
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ch == '-')
}

pub(crate) fn generate_guard_code(shared_secret_b64: &str, unix_time: i64) -> Result<String> {
    if unix_time < 0 {
        bail!("steam guard code requires a non-negative unix timestamp");
    }

    let secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(shared_secret_b64.trim())
        .context("failed to decode shared_secret as base64")?;
    let secret: [u8; 20] = secret_bytes
        .try_into()
        .map_err(|_| anyhow!("shared_secret must decode to exactly 20 bytes"))?;

    let time_bytes = (unix_time as u64 / STEAM_GUARD_CODE_PERIOD_SECONDS as u64).to_be_bytes();
    let mut mac =
        Hmac::<Sha1>::new_from_slice(&secret).context("failed to initialize steam guard hmac")?;
    mac.update(&time_bytes);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let mut code_point: i32 = (((digest[offset] & 0x7f) as i32) << 24)
        | ((digest[offset + 1] as i32) << 16)
        | ((digest[offset + 2] as i32) << 8)
        | (digest[offset + 3] as i32);

    let mut code = [0u8; 5];
    for character in &mut code {
        *character = STEAM_GUARD_CODE_ALPHABET
            [code_point.rem_euclid(STEAM_GUARD_CODE_ALPHABET.len() as i32) as usize];
        code_point /= STEAM_GUARD_CODE_ALPHABET.len() as i32;
    }

    String::from_utf8(code.to_vec()).context("steam guard code contained invalid utf-8")
}

pub(crate) fn generate_confirmation_key(
    identity_secret_b64: &str,
    unix_time: i64,
    tag: &str,
) -> Result<String> {
    if unix_time < 0 {
        bail!("confirmation key requires a non-negative unix timestamp");
    }

    let secret = base64::engine::general_purpose::STANDARD
        .decode(identity_secret_b64.trim())
        .context("failed to decode identity_secret as base64")?;
    let mut mac =
        Hmac::<Sha1>::new_from_slice(&secret).context("failed to initialize confirmation hmac")?;
    mac.update(&(unix_time as u64).to_be_bytes());
    mac.update(tag.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

pub(crate) fn generate_device_id_for_steam_id(steam_id: u64) -> String {
    let digest = Sha1::digest(steam_id.to_string().as_bytes());
    let hex = data_encoding::HEXLOWER.encode(digest.as_slice());
    format!(
        "android:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub(crate) async fn load_managed_account(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<Option<SteamGuardAccount>> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(record) = load_stored_account(master_key, &storage_path).await? else {
        return Ok(None);
    };
    Ok(Some(record.into_runtime(storage_path)))
}

pub(crate) async fn update_managed_account_materials(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    input: UpdateSteamAccountInput,
) -> Result<bool> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(mut record) = load_stored_account(master_key, &storage_path).await? else {
        return Ok(false);
    };

    if let Some(steam_username) = normalize_optional_string(input.steam_username) {
        record.steam_username = Some(steam_username);
    }
    if let Some(shared_secret) = normalize_optional_string(input.shared_secret) {
        validate_shared_secret(&shared_secret)?;
        record.shared_secret = shared_secret;
    }
    if let Some(identity_secret) = normalize_optional_string(input.identity_secret) {
        validate_identity_secret(&identity_secret)?;
        record.identity_secret = Some(identity_secret);
    }
    if let Some(device_id) = normalize_optional_string(input.device_id) {
        record.device_id = Some(device_id);
    } else if record.device_id.is_none() && record.identity_secret.is_some() {
        if let Some(steam_id) = record.steam_id {
            record.device_id = Some(generate_device_id_for_steam_id(steam_id));
        }
    }
    if let Some(steam_login_secure) = normalize_optional_string(input.steam_login_secure) {
        let session = record
            .session
            .get_or_insert_with(default_stored_web_session);
        session.steam_login_secure = Some(steam_login_secure);
    }

    record.updated_at_unix = Utc::now().timestamp();
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(true)
}

fn default_stored_web_session() -> StoredSteamWebSession {
    StoredSteamWebSession {
        session_id: None,
        steam_login: None,
        steam_login_secure: None,
        web_cookie: None,
        oauth_token: None,
        access_token: None,
        refresh_token: None,
    }
}

fn stored_web_session_mut(record: &mut StoredSteamAccount) -> &mut StoredSteamWebSession {
    record
        .session
        .get_or_insert_with(default_stored_web_session)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SteamCredentialLoginResult {
    steam_username: String,
    steam_id: u64,
    access_token: String,
    refresh_token: String,
}

fn build_blocking_steam_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(STEAM_CONFIRMATION_USER_AGENT)
        .build()
        .context("failed building blocking Steam client")
}

fn build_steam_mobile_device_details() -> DeviceDetails {
    DeviceDetails {
        friendly_name: String::from("Hanagram Web"),
        platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
        os_type: -500,
        gaming_device_type: 528,
    }
}

fn map_login_error(error: LoginError) -> anyhow::Error {
    match error {
        LoginError::BadCredentials => anyhow!("Steam username or password is incorrect"),
        LoginError::TooManyAttempts => anyhow!("Steam is rate limiting login attempts"),
        LoginError::SessionExpired => anyhow!("Steam login session expired before completion"),
        other => anyhow!("Steam credential login failed: {other}"),
    }
}

fn map_guard_submit_error(error: UpdateAuthSessionError) -> anyhow::Error {
    match error {
        UpdateAuthSessionError::IncorrectSteamGuardCode => {
            anyhow!("the generated Steam Guard code was rejected")
        }
        UpdateAuthSessionError::TooManyAttempts => {
            anyhow!("Steam rate limited Steam Guard submissions")
        }
        UpdateAuthSessionError::SessionExpired => anyhow!("Steam login session expired"),
        UpdateAuthSessionError::DuplicateRequest => {
            anyhow!("Steam login request was already approved elsewhere")
        }
        other => anyhow!("failed submitting Steam Guard code: {other}"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardSetupLoginGate {
    CanContinue,
    RequiresTrustedDeviceConfirmation,
    RequiresEmail,
    RequiresExistingGuardCode,
    Unsupported,
}

fn classify_guard_setup_login_gate<I>(confirmation_types: I) -> GuardSetupLoginGate
where
    I: IntoIterator<Item = EAuthSessionGuardType>,
{
    let mut has_guardless_flow = false;
    let mut has_device_code = false;
    let mut requires_device_confirmation = false;
    let mut requires_email = false;
    let mut saw_any = false;

    for confirmation_type in confirmation_types {
        saw_any = true;
        match confirmation_type {
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => {
                has_guardless_flow = true;
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                has_device_code = true;
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                requires_device_confirmation = true;
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
            | EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
                requires_email = true;
            }
            _ => {}
        }
    }

    if has_guardless_flow || !saw_any {
        return GuardSetupLoginGate::CanContinue;
    }
    if has_device_code {
        return GuardSetupLoginGate::RequiresExistingGuardCode;
    }
    if requires_device_confirmation {
        return GuardSetupLoginGate::RequiresTrustedDeviceConfirmation;
    }
    if requires_email {
        return GuardSetupLoginGate::RequiresEmail;
    }
    GuardSetupLoginGate::Unsupported
}

fn ensure_guard_setup_login_can_continue<I>(confirmation_types: I) -> Result<()>
where
    I: IntoIterator<Item = EAuthSessionGuardType>,
{
    match classify_guard_setup_login_gate(confirmation_types) {
        GuardSetupLoginGate::CanContinue => Ok(()),
        GuardSetupLoginGate::RequiresTrustedDeviceConfirmation => {
            bail!("requires_trusted_device_confirmation")
        }
        GuardSetupLoginGate::RequiresEmail => bail!("requires_email_login_confirmation"),
        GuardSetupLoginGate::RequiresExistingGuardCode => {
            bail!("requires_existing_guard_code")
        }
        GuardSetupLoginGate::Unsupported => bail!("unsupported_login_confirmation_method"),
    }
}

async fn perform_credential_login(
    shared_secret: String,
    steam_username: String,
    steam_password: String,
) -> Result<SteamCredentialLoginResult> {
    spawn_blocking(move || {
        let username = steam_username.trim().to_owned();
        ensure!(!username.is_empty(), "Steam username is required");
        ensure!(
            !steam_password.is_empty(),
            "Steam password is required for credential login"
        );

        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let shared_secret = TwoFactorSecret::parse_shared_secret(shared_secret.trim().to_owned())
            .context("failed parsing Steam shared_secret")?;

        let mut vendor_account = VendorSteamGuardAccount::new();
        vendor_account.account_name = username.clone();
        vendor_account.shared_secret = shared_secret;

        let mut login = UserLogin::new(transport.clone(), build_steam_mobile_device_details());
        let confirmation_methods = login
            .begin_auth_via_credentials(&username, &steam_password)
            .map_err(map_login_error)?;

        let has_guardless_flow = confirmation_methods.iter().any(|method| {
            method.confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_None
        });
        let has_device_code = confirmation_methods.iter().any(|method| {
            method.confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
        });
        let requires_device_confirmation = confirmation_methods.iter().any(|method| {
            method.confirmation_type
                == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation
        });
        let requires_email_code = confirmation_methods.iter().any(|method| {
            method.confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
        });
        let requires_email_confirmation = confirmation_methods.iter().any(|method| {
            method.confirmation_type
                == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation
        });

        if !has_guardless_flow {
            if has_device_code {
                let server_time = steamguard::steamapi::get_server_time(transport.clone())
                    .context("failed querying Steam server time for credential login")?
                    .server_time();
                let guard_code = vendor_account.generate_code(server_time);
                match login.submit_steam_guard_code(
                    EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
                    guard_code,
                ) {
                    Ok(_) | Err(UpdateAuthSessionError::DuplicateRequest) => {}
                    Err(error) => return Err(map_guard_submit_error(error)),
                }
            } else if requires_device_confirmation {
                bail!("Steam requested mobile confirmation on another device for this login");
            } else if requires_email_code {
                bail!("Steam requested an email code for this login");
            } else if requires_email_confirmation {
                bail!("Steam requested email confirmation for this login");
            } else if !confirmation_methods.is_empty() {
                bail!("Steam requested an unsupported login confirmation method");
            }
        }

        let tokens = login
            .poll_until_tokens()
            .context("failed polling Steam for credential login tokens")?;
        let steam_id = tokens
            .access_token()
            .decode()
            .context("failed decoding Steam access token")?
            .steam_id();

        Ok::<SteamCredentialLoginResult, anyhow::Error>(SteamCredentialLoginResult {
            steam_username: username,
            steam_id,
            access_token: tokens.access_token().expose_secret().to_owned(),
            refresh_token: tokens.refresh_token().expose_secret().to_owned(),
        })
    })
    .await
    .context("Steam credential login task failed")?
}

fn apply_credential_login_result(
    record: &mut StoredSteamAccount,
    login_result: &SteamCredentialLoginResult,
) {
    record.steam_username = Some(login_result.steam_username.clone());
    record.steam_id = Some(login_result.steam_id);
    if record.device_id.is_none() && record.identity_secret.is_some() {
        record.device_id = Some(generate_device_id_for_steam_id(login_result.steam_id));
    }

    let session = stored_web_session_mut(record);
    session.access_token = Some(login_result.access_token.clone());
    session.refresh_token = Some(login_result.refresh_token.clone());
}

pub(crate) async fn create_logged_in_account(
    root_dir: &Path,
    master_key: &[u8],
    input: CredentialSteamAccountInput,
) -> Result<SteamGuardAccount> {
    ensure_managed_accounts_dir(root_dir).await?;
    validate_shared_secret(&input.shared_secret)?;

    let identity_secret = normalize_optional_string(input.identity_secret);
    if let Some(secret) = identity_secret.as_deref() {
        validate_identity_secret(secret)?;
    }

    let login_result = perform_credential_login(
        input.shared_secret.trim().to_owned(),
        input.steam_username,
        input.steam_password,
    )
    .await?;

    let display_name = if input.account_name.trim().is_empty() {
        login_result.steam_username.as_str()
    } else {
        input.account_name.as_str()
    };
    let now = Utc::now().timestamp();
    let mut record = StoredSteamAccount {
        schema_version: STEAM_MANAGED_SCHEMA_VERSION,
        id: Uuid::new_v4().to_string(),
        account_name: sanitize_account_name(display_name),
        steam_username: Some(login_result.steam_username.clone()),
        steam_id: Some(login_result.steam_id),
        shared_secret: input.shared_secret.trim().to_owned(),
        identity_secret,
        device_id: normalize_optional_string(input.device_id),
        session: None,
        imported_from: Some(String::from("credential-login")),
        managed_origin: SteamManagedAccountOrigin::ManualEntry,
        created_at_unix: now,
        updated_at_unix: now,
        revocation_code: None,
        serial_number: None,
        token_gid: None,
        secret_1: None,
        uri: None,
        proxy_url: None,
    };
    apply_credential_login_result(&mut record, &login_result);

    let storage_path = managed_account_storage_path(root_dir, &record.id);
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(record.into_runtime(storage_path))
}

pub(crate) async fn login_managed_account_with_credentials(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    input: SteamCredentialLoginInput,
) -> Result<Option<SteamGuardAccount>> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(mut record) = load_stored_account(master_key, &storage_path).await? else {
        return Ok(None);
    };

    let steam_username = normalize_optional_string(Some(input.steam_username))
        .or_else(|| record.steam_username.clone())
        .context("Steam username is required")?;
    let login_result = perform_credential_login(
        record.shared_secret.clone(),
        steam_username,
        input.steam_password,
    )
    .await?;

    apply_credential_login_result(&mut record, &login_result);
    record.updated_at_unix = Utc::now().timestamp();
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(Some(record.into_runtime(storage_path)))
}

fn build_vendor_account(account: &SteamGuardAccount) -> Result<VendorSteamGuardAccount> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID for login approvals")?;
    let shared_secret =
        TwoFactorSecret::parse_shared_secret(account.shared_secret.trim().to_owned())
            .context("failed parsing Steam shared_secret for login approvals")?;

    let mut vendor_account = VendorSteamGuardAccount::new();
    vendor_account.account_name = account
        .steam_username
        .clone()
        .unwrap_or_else(|| account.account_name.clone());
    vendor_account.steam_id = steam_id;
    vendor_account.shared_secret = shared_secret;
    Ok(vendor_account)
}

fn build_vendor_tokens(account: &SteamGuardAccount) -> Result<SteamTokens> {
    let session = account
        .session
        .as_ref()
        .context("Steam account is missing session material")?;
    let access_token = session
        .access_token()
        .context("Steam account is missing an access token")?
        .to_owned();
    let refresh_token = session.refresh_token().unwrap_or_default().to_owned();
    Ok(SteamTokens::new(
        SteamJwt::from(access_token),
        SteamJwt::from(refresh_token),
    ))
}

fn login_approval_platform_label(platform_type: EAuthTokenPlatformType) -> &'static str {
    match platform_type {
        EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient => "Steam Client",
        EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser => "Web Browser",
        EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp => "Mobile App",
        _ => "Unknown",
    }
}

fn build_login_approval(
    client_id: u64,
    session: &CAuthentication_GetAuthSessionInfo_Response,
) -> SteamLoginApproval {
    SteamLoginApproval {
        client_id: client_id.to_string(),
        ip: normalize_optional_string(Some(session.ip().to_owned())),
        geolocation: normalize_optional_string(Some(session.geoloc().to_owned())),
        city: normalize_optional_string(Some(session.city().to_owned())),
        state: normalize_optional_string(Some(session.state().to_owned())),
        country: normalize_optional_string(Some(session.country().to_owned())),
        platform_label: login_approval_platform_label(session.platform_type()).to_owned(),
        device_label: normalize_optional_string(Some(session.device_friendly_name().to_owned())),
    }
}

pub(crate) async fn list_login_approvals(
    account: &SteamGuardAccount,
) -> Result<Vec<SteamLoginApproval>> {
    let vendor_account = build_vendor_account(account)?;
    let vendor_tokens = build_vendor_tokens(account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let approver = LoginApprover::new(transport, &vendor_tokens);
        let client_ids = approver
            .list_auth_sessions()
            .context("failed listing Steam login approvals")?;

        let mut approvals = Vec::with_capacity(client_ids.len());
        for client_id in client_ids {
            let session = approver
                .get_auth_session_info(client_id)
                .with_context(|| format!("failed loading Steam approval session {client_id}"))?;
            approvals.push(build_login_approval(client_id, &session));
        }

        let _ = vendor_account;
        Ok::<Vec<SteamLoginApproval>, anyhow::Error>(approvals)
    })
    .await
    .context("Steam login approval listing task failed")?
}

pub(crate) async fn respond_to_login_approval(
    account: &SteamGuardAccount,
    client_id: u64,
    approve: bool,
) -> Result<()> {
    let vendor_account = build_vendor_account(account)?;
    let vendor_tokens = build_vendor_tokens(account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let mut approver = LoginApprover::new(transport, &vendor_tokens);
        let challenge = Challenge::new(1, client_id);
        if approve {
            approver
                .approve(
                    &vendor_account,
                    challenge,
                    ESessionPersistence::k_ESessionPersistence_Persistent,
                )
                .context("failed approving Steam login session")?;
        } else {
            approver
                .deny(&vendor_account, challenge)
                .context("failed denying Steam login session")?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Steam login approval action task failed")?
}

pub(crate) async fn approve_login_challenge(
    account: &SteamGuardAccount,
    challenge_url: &str,
) -> Result<()> {
    let vendor_account = build_vendor_account(account)?;
    let vendor_tokens = build_vendor_tokens(account)?;
    let challenge_url = challenge_url.trim().to_owned();
    ensure!(!challenge_url.is_empty(), "Steam challenge URL is required");

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let mut approver = LoginApprover::new(transport, &vendor_tokens);
        approver
            .approve_from_challenge_url(
                &vendor_account,
                challenge_url,
                ESessionPersistence::k_ESessionPersistence_Persistent,
            )
            .context("failed approving Steam QR login challenge")?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Steam QR approval task failed")?
}

pub(crate) fn extract_login_challenge_url_from_qr_image(raw_bytes: &[u8]) -> Result<String> {
    let image = ImageReader::new(Cursor::new(raw_bytes))
        .with_guessed_format()
        .context("failed reading Steam QR image format")?
        .decode()
        .context("failed decoding Steam QR image")?
        .to_luma8();
    let mut prepared = PreparedImage::prepare(image);
    for grid in prepared.detect_grids() {
        let (_, text) = grid.decode().context("failed decoding Steam QR image")?;
        if text.contains("s.team") {
            return Ok(text);
        }
    }
    bail!("no Steam login challenge URL was found in the QR image")
}

pub(crate) async fn query_steam_server_time(http_client: &reqwest::Client) -> Result<i64> {
    match query_steam_server_time_via_client(http_client).await {
        Ok(server_time) => Ok(server_time),
        Err(primary_error) => {
            warn!(
                error = %primary_error,
                "Steam server time query failed on shared client; retrying with a dedicated client"
            );

            let dedicated_client = reqwest::Client::builder()
                .user_agent(STEAM_CONFIRMATION_USER_AGENT)
                .build()
                .context("failed building dedicated Steam server time client")?;
            match query_steam_server_time_via_client(&dedicated_client).await {
                Ok(server_time) => Ok(server_time),
                Err(secondary_error) => {
                    let fallback_time = Utc::now().timestamp().max(0);
                    warn!(
                        error = %secondary_error,
                        fallback_time,
                        "Steam server time query failed again; falling back to local unix time"
                    );
                    Ok(fallback_time)
                }
            }
        }
    }
}

async fn query_steam_server_time_via_client(http_client: &reqwest::Client) -> Result<i64> {
    let response = http_client
        .post("https://api.steampowered.com/ITwoFactorService/QueryTime/v0001/?format=json")
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .send()
        .await
        .context("failed querying Steam server time")?;
    let response = response
        .error_for_status()
        .context("Steam server time endpoint returned an error")?;
    let payload: SteamQueryTimeEnvelope = response
        .json()
        .await
        .context("failed decoding Steam server time response")?;
    Ok(payload.response.server_time as i64)
}

pub(crate) async fn fetch_confirmations(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
) -> Result<Vec<SteamConfirmation>> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let time = query_steam_server_time(http_client).await?;
    let query = build_confirmation_query(account, "conf", time)?;
    let cookie_header = build_confirmation_cookie_header(account, steam_id)?;
    let response = http_client
        .get("https://steamcommunity.com/mobileconf/getlist")
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .header(reqwest::header::COOKIE, cookie_header)
        .query(&query)
        .send()
        .await
        .context("failed fetching Steam confirmations")?;
    let response = response
        .error_for_status()
        .context("Steam confirmation list endpoint returned an error")?;
    let payload: SteamConfirmationListResponse = response
        .json()
        .await
        .context("failed decoding Steam confirmation list")?;
    if payload.needauth.unwrap_or(false) {
        bail!("Steam confirmation session is no longer authorized");
    }
    if !payload.success {
        bail!(
            "{}",
            payload
                .message
                .unwrap_or_else(|| String::from("Steam confirmation list request failed"))
        );
    }

    Ok(payload
        .conf
        .into_iter()
        .map(|confirmation| SteamConfirmation {
            id: confirmation.id,
            nonce: confirmation.nonce,
            creator_id: confirmation.creator_id,
            confirmation_type: confirmation.confirmation_type,
            type_name: confirmation.type_name,
            headline: confirmation.headline,
            summary: confirmation.summary,
            icon: normalize_optional_string(confirmation.icon),
            created_at_unix: confirmation.creation_time,
        })
        .collect())
}

pub(crate) async fn respond_to_confirmation(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
    confirmation_id: &str,
    nonce: &str,
    accept: bool,
) -> Result<()> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let time = query_steam_server_time(http_client).await?;
    let mut query = build_confirmation_query(account, "conf", time)?;
    query.push((
        String::from("op"),
        String::from(if accept { "allow" } else { "cancel" }),
    ));
    query.push((String::from("cid"), confirmation_id.trim().to_owned()));
    query.push((String::from("ck"), nonce.trim().to_owned()));

    let cookie_header = build_confirmation_cookie_header(account, steam_id)?;
    let response = http_client
        .get("https://steamcommunity.com/mobileconf/ajaxop")
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .header(reqwest::header::COOKIE, cookie_header)
        .header(reqwest::header::ORIGIN, "https://steamcommunity.com")
        .query(&query)
        .send()
        .await
        .context("failed sending Steam confirmation action")?;
    let response = response
        .error_for_status()
        .context("Steam confirmation action endpoint returned an error")?;
    let payload: SteamConfirmationActionResponse = response
        .json()
        .await
        .context("failed decoding Steam confirmation action response")?;
    if payload.needsauth.unwrap_or(false) {
        bail!("Steam confirmation session is no longer authorized");
    }
    if !payload.success {
        bail!(
            "{}",
            payload
                .message
                .unwrap_or_else(|| String::from("Steam confirmation action failed"))
        );
    }
    Ok(())
}

pub(crate) async fn create_manual_account(
    root_dir: &Path,
    master_key: &[u8],
    input: ManualSteamAccountInput,
) -> Result<SteamGuardAccount> {
    ensure_managed_accounts_dir(root_dir).await?;

    validate_shared_secret(&input.shared_secret)?;
    let identity_secret = normalize_optional_string(input.identity_secret);
    if let Some(secret) = identity_secret.as_deref() {
        validate_identity_secret(secret)?;
    }

    let account_name = sanitize_account_name(&input.account_name);
    let device_id = normalize_optional_string(input.device_id).or_else(|| {
        identity_secret
            .as_ref()
            .map(|_| generate_device_id_for_steam_id(input.steam_id))
    });
    let steam_login_secure = normalize_optional_string(input.steam_login_secure);
    let now = Utc::now().timestamp();
    let record = StoredSteamAccount {
        schema_version: STEAM_MANAGED_SCHEMA_VERSION,
        id: Uuid::new_v4().to_string(),
        account_name,
        steam_username: normalize_optional_string(input.steam_username),
        steam_id: Some(input.steam_id),
        shared_secret: input.shared_secret.trim().to_owned(),
        identity_secret,
        device_id,
        session: steam_login_secure.map(|value| {
            let mut session = default_stored_web_session();
            session.steam_login_secure = Some(value);
            session
        }),
        imported_from: Some(String::from("manual-entry")),
        managed_origin: SteamManagedAccountOrigin::ManualEntry,
        created_at_unix: now,
        updated_at_unix: now,
        revocation_code: None,
        serial_number: None,
        token_gid: None,
        secret_1: None,
        uri: None,
        proxy_url: None,
    };
    let storage_path = managed_account_storage_path(root_dir, &record.id);
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(record.into_runtime(storage_path))
}

pub(crate) async fn import_mafile_bytes(
    root_dir: &Path,
    master_key: &[u8],
    file_name: Option<&str>,
    display_name_override: Option<&str>,
    raw_bytes: &[u8],
) -> Result<SteamGuardAccount> {
    ensure_managed_accounts_dir(root_dir).await?;

    let placeholder = file_name.unwrap_or("uploaded.maFile");
    let parsed = parse_account_bytes(raw_bytes, Path::new(placeholder))?;
    validate_shared_secret(&parsed.shared_secret)?;
    if let Some(secret) = parsed.identity_secret.as_deref() {
        validate_identity_secret(secret)?;
    }

    let now = Utc::now().timestamp();
    let record = StoredSteamAccount {
        schema_version: STEAM_MANAGED_SCHEMA_VERSION,
        id: Uuid::new_v4().to_string(),
        account_name: sanitize_account_name(
            display_name_override
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(&parsed.account_name),
        ),
        steam_username: parsed.steam_username.clone(),
        steam_id: parsed.steam_id,
        shared_secret: parsed.shared_secret,
        identity_secret: parsed.identity_secret,
        device_id: parsed.device_id,
        session: parsed.session.map(|value| StoredSteamWebSession {
            session_id: normalize_optional_string(value.session_id),
            steam_login: normalize_optional_string(value.steam_login),
            steam_login_secure: normalize_optional_string(value.steam_login_secure),
            web_cookie: normalize_optional_string(value.web_cookie),
            oauth_token: normalize_optional_string(value.oauth_token),
            access_token: normalize_optional_string(value.access_token),
            refresh_token: normalize_optional_string(value.refresh_token),
        }),
        imported_from: file_name
            .and_then(|value| Path::new(value).file_name().and_then(|name| name.to_str()))
            .map(str::to_owned),
        managed_origin: SteamManagedAccountOrigin::UploadedMaFile,
        created_at_unix: now,
        updated_at_unix: now,
        revocation_code: None,
        serial_number: None,
        token_gid: None,
        secret_1: None,
        uri: None,
        proxy_url: None,
    };
    let storage_path = managed_account_storage_path(root_dir, &record.id);
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(record.into_runtime(storage_path))
}

pub(crate) async fn rename_managed_account(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    next_name: &str,
) -> Result<bool> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(mut record) = load_stored_account(master_key, &storage_path).await? else {
        return Ok(false);
    };
    let sanitized = sanitize_account_name(next_name);
    if sanitized == record.account_name {
        return Ok(true);
    }
    record.account_name = sanitized;
    record.updated_at_unix = Utc::now().timestamp();
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(true)
}

pub(crate) async fn delete_managed_account(root_dir: &Path, account_id: &str) -> Result<bool> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    match fs::remove_file(&storage_path).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed deleting {}", storage_path.display()))
        }
    }
}

pub(crate) async fn discover_accounts(
    root_dir: &Path,
    master_key: Option<&[u8]>,
) -> (Vec<SteamGuardAccount>, Vec<SteamGuardLoadIssue>) {
    let mut account_files = Vec::new();
    if collect_account_files_recursive(root_dir.to_path_buf(), &mut account_files)
        .await
        .is_err()
    {
        return (
            Vec::new(),
            vec![SteamGuardLoadIssue {
                storage_path: root_dir.to_path_buf(),
                error: format!(
                    "failed scanning {} for Steam Guard account files",
                    root_dir.display()
                ),
            }],
        );
    }

    account_files.sort();
    let mut accounts = Vec::new();
    let mut issues = Vec::new();
    for path in account_files {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase());

        match extension.as_deref() {
            Some("mafile") => match load_legacy_account(&path).await {
                Ok(account) => accounts.push(account),
                Err(error) => issues.push(SteamGuardLoadIssue {
                    storage_path: path,
                    error: error.to_string(),
                }),
            },
            Some(STEAM_MANAGED_ACCOUNT_EXTENSION) => {
                let Some(master_key) = master_key else {
                    issues.push(SteamGuardLoadIssue {
                        storage_path: path,
                        error: String::from(
                            "managed Steam accounts are locked; sign in again to unlock them",
                        ),
                    });
                    continue;
                };
                match load_managed_runtime_account(master_key, &path).await {
                    Ok(account) => accounts.push(account),
                    Err(error) => issues.push(SteamGuardLoadIssue {
                        storage_path: path,
                        error: error.to_string(),
                    }),
                }
            }
            _ => {}
        }
    }

    accounts.sort_by(|left, right| {
        right
            .can_manage()
            .cmp(&left.can_manage())
            .then_with(|| left.account_name.cmp(&right.account_name))
            .then_with(|| left.storage_path.cmp(&right.storage_path))
    });
    issues.sort_by(|left, right| left.storage_path.cmp(&right.storage_path));
    (accounts, issues)
}

async fn load_legacy_account(path: &Path) -> Result<SteamGuardAccount> {
    let raw_bytes = fs::read(path)
        .await
        .with_context(|| format!("failed reading Steam Guard file {}", path.display()))?;
    parse_account_bytes(&raw_bytes, path)
}

async fn load_managed_runtime_account(master_key: &[u8], path: &Path) -> Result<SteamGuardAccount> {
    let record = load_stored_account(master_key, path)
        .await?
        .ok_or_else(|| anyhow!("managed Steam account file is missing"))?;
    Ok(record.into_runtime(path.to_path_buf()))
}

fn parse_account_bytes(raw_bytes: &[u8], path: &Path) -> Result<SteamGuardAccount> {
    let parsed: RawSteamGuardAccount = serde_json::from_slice(raw_bytes)
        .with_context(|| format!("failed parsing Steam Guard file {}", path.display()))?;
    let steam_username = extract_raw_steam_username(&parsed.account_name);

    let account_name = if parsed.account_name.trim().is_empty() {
        path.file_stem()
            .and_then(|value| value.to_str())
            .map(str::to_owned)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| String::from("steam-account"))
    } else {
        sanitize_account_name(&parsed.account_name)
    };

    if parsed.shared_secret.trim().is_empty() {
        bail!("{} is missing shared_secret", path.display());
    }

    Ok(SteamGuardAccount {
        id: path.display().to_string(),
        account_name,
        steam_username,
        steam_id: parsed
            .steamid
            .or(parsed.steam_id)
            .or_else(|| parsed.session.as_ref().and_then(derive_session_steam_id)),
        shared_secret: parsed.shared_secret.trim().to_owned(),
        identity_secret: normalize_optional_string(Some(parsed.identity_secret)),
        device_id: normalize_optional_string(Some(parsed.device_id)),
        session: parsed.session.map(|session| SteamWebSession {
            session_id: normalize_optional_string(session.session_id),
            steam_login: normalize_optional_string(session.steam_login),
            steam_login_secure: normalize_optional_string(session.steam_login_secure),
            web_cookie: normalize_optional_string(session.web_cookie),
            oauth_token: normalize_optional_string(session.oauth_token),
            access_token: normalize_optional_string(session.access_token),
            refresh_token: normalize_optional_string(session.refresh_token),
        }),
        storage_path: path.to_path_buf(),
        source_kind: SteamAccountSourceKind::LegacyMaFile,
        managed_origin: None,
        imported_from: path
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_owned),
        encrypted_at_rest: false,
        created_at_unix: None,
        updated_at_unix: None,
        revocation_code: None,
        serial_number: None,
        token_gid: None,
        secret_1: None,
        uri: None,
        proxy_url: None,
    })
}

pub(crate) fn validate_shared_secret(shared_secret: &str) -> Result<()> {
    generate_guard_code(shared_secret, 0).map(|_| ())
}

pub(crate) fn validate_identity_secret(identity_secret: &str) -> Result<()> {
    generate_confirmation_key(identity_secret, 0, "conf").map(|_| ())
}

fn build_confirmation_query(
    account: &SteamGuardAccount,
    tag: &str,
    unix_time: i64,
) -> Result<Vec<(String, String)>> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let identity_secret = account
        .identity_secret
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .context("Steam account is missing identity_secret")?;
    let device_id = account
        .device_id
        .as_deref()
        .map(str::to_owned)
        .or_else(|| Some(generate_device_id_for_steam_id(steam_id)))
        .context("Steam account is missing device_id")?;
    Ok(vec![
        (String::from("p"), device_id),
        (String::from("a"), steam_id.to_string()),
        (
            String::from("k"),
            generate_confirmation_key(identity_secret, unix_time, tag)?,
        ),
        (String::from("t"), unix_time.to_string()),
        (String::from("m"), String::from("react")),
        (String::from("tag"), tag.to_owned()),
    ])
}

fn build_confirmation_cookie_header(account: &SteamGuardAccount, steam_id: u64) -> Result<String> {
    let steam_login_secure = account
        .session
        .as_ref()
        .and_then(|session| session.effective_confirmation_cookie(Some(steam_id)))
        .context("Steam account is missing a usable confirmation session")?;
    Ok(format!(
        "dob=; steamid={steam_id}; steamLoginSecure={steam_login_secure}"
    ))
}

pub(crate) fn confirmation_session_can_refresh(account: &SteamGuardAccount) -> bool {
    account.has_refreshable_session()
}

pub(crate) fn confirmation_session_should_refresh(account: &SteamGuardAccount) -> bool {
    let Some(session) = account.session.as_ref() else {
        return false;
    };
    if session.refresh_token().is_none() {
        return false;
    }

    match session.access_token() {
        Some(access_token) => access_token_expires_soon(access_token, Utc::now().timestamp()),
        None => true,
    }
}

pub(crate) async fn refresh_confirmation_session_if_needed(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    force_refresh: bool,
) -> Result<Option<SteamGuardAccount>> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(mut record) = load_stored_account(master_key, &storage_path).await? else {
        return Ok(None);
    };

    let Some(session) = record.session.as_mut() else {
        return Ok(Some(record.into_runtime(storage_path)));
    };

    let Some(refresh_token) = session
        .refresh_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
    else {
        return Ok(Some(record.into_runtime(storage_path)));
    };

    let needs_refresh = match session
        .access_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(access_token) => access_token_expires_soon(access_token, Utc::now().timestamp()),
        None => true,
    };
    if !force_refresh && !needs_refresh {
        return Ok(Some(record.into_runtime(storage_path)));
    }

    let steam_id = record
        .steam_id
        .or_else(|| derive_stored_session_steam_id(session))
        .context(
            "Steam account is missing SteamID and could not derive one from stored session tokens",
        )?;
    let current_access_token = session
        .access_token
        .as_deref()
        .unwrap_or_default()
        .to_owned();
    let refreshed_access_token =
        refresh_access_token_from_refresh_token(steam_id, current_access_token, refresh_token)
            .await?;

    session.access_token = Some(refreshed_access_token);
    record.steam_id = Some(steam_id);
    record.updated_at_unix = Utc::now().timestamp();
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(Some(record.into_runtime(storage_path)))
}

fn derive_session_steam_id(session: &RawSteamSession) -> Option<u64> {
    session
        .steam_id
        .or_else(|| {
            session
                .access_token
                .as_deref()
                .and_then(steam_id_from_jwt_unverified)
        })
        .or_else(|| {
            session
                .refresh_token
                .as_deref()
                .and_then(steam_id_from_jwt_unverified)
        })
}

fn steam_id_from_jwt_unverified(token: &str) -> Option<u64> {
    steam_jwt_claims_unverified(token).map(|claims| claims.sub)
}

fn derive_stored_session_steam_id(session: &StoredSteamWebSession) -> Option<u64> {
    session
        .access_token
        .as_deref()
        .and_then(steam_id_from_jwt_unverified)
        .or_else(|| {
            session
                .refresh_token
                .as_deref()
                .and_then(steam_id_from_jwt_unverified)
        })
}

fn access_token_expires_soon(token: &str, now_unix: i64) -> bool {
    steam_jwt_claims_unverified(token)
        .and_then(|claims| claims.exp)
        .map(|exp| exp as i64 <= now_unix + STEAM_ACCESS_TOKEN_REFRESH_SKEW_SECONDS)
        .unwrap_or(false)
}

fn steam_jwt_claims_unverified(token: &str) -> Option<SteamJwtClaims> {
    let mut parts = token.trim().split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    serde_json::from_slice::<SteamJwtClaims>(&decoded).ok()
}

async fn refresh_access_token_from_refresh_token(
    steam_id: u64,
    current_access_token: String,
    refresh_token: String,
) -> Result<String> {
    spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .user_agent(STEAM_CONFIRMATION_USER_AGENT)
            .build()
            .context("failed building blocking Steam auth client")?;
        let transport = WebApiTransport::new(client);
        let auth_client = AuthenticationClient::new(transport);
        let mut refresher = TokenRefresher::new(auth_client);
        let tokens = SteamTokens::new(
            SteamJwt::from(current_access_token),
            SteamJwt::from(refresh_token),
        );
        let refreshed = refresher
            .refresh(steam_id, &tokens)
            .context("failed refreshing Steam access token from refresh token")?;
        Ok::<String, anyhow::Error>(refreshed.expose_secret().to_owned())
    })
    .await
    .context("Steam access token refresh task failed")?
}

fn normalize_optional_string<T>(value: Option<T>) -> Option<String>
where
    T: Into<String>,
{
    value.and_then(|value| {
        let trimmed = value.into().trim().to_owned();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn option_has_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

fn deserialize_u64_from_any<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("expected unsigned integer")),
        serde_json::Value::String(raw) => raw
            .trim()
            .parse::<u64>()
            .map_err(|_| serde::de::Error::custom("expected u64-compatible string")),
        other => Err(serde::de::Error::custom(format!(
            "unsupported u64 value: {other}"
        ))),
    }
}

fn deserialize_u32_from_any<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_u64_from_any(deserializer)?;
    u32::try_from(value).map_err(|_| serde::de::Error::custom("value did not fit into u32"))
}

fn deserialize_optional_u64_from_any<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("expected unsigned integer"))
            .map(Some),
        serde_json::Value::String(raw) => raw
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("expected u64-compatible string")),
        other => Err(serde::de::Error::custom(format!(
            "unsupported steam id value: {other}"
        ))),
    }
}

async fn collect_account_files_recursive(dir: PathBuf, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut stack = vec![dir];
    while let Some(current_dir) = stack.pop() {
        let mut entries = match fs::read_dir(&current_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed reading {}", current_dir.display()));
            }
        };

        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("failed enumerating {}", current_dir.display()))?
        {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .await
                .with_context(|| format!("failed reading file type for {}", path.display()))?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.to_ascii_lowercase());
            if matches!(
                extension.as_deref(),
                Some("mafile") | Some(STEAM_MANAGED_ACCOUNT_EXTENSION)
            ) {
                files.push(path);
            }
        }
    }
    Ok(())
}

pub(crate) async fn persist_stored_account(
    master_key: &[u8],
    storage_path: &Path,
    record: &StoredSteamAccount,
) -> Result<()> {
    let encoded = serde_json::to_vec(record).context("failed to encode managed Steam account")?;
    let packed = pack_managed_storage_bytes(&encoded)?;
    let payload = encrypt_bytes(master_key, packed.as_slice())?;
    let encrypted =
        serde_json::to_vec(&payload).context("failed to encode encrypted Steam account")?;
    fs::write(storage_path, encrypted)
        .await
        .with_context(|| format!("failed writing {}", storage_path.display()))
}

pub(crate) async fn load_stored_account(
    master_key: &[u8],
    storage_path: &Path,
) -> Result<Option<StoredSteamAccount>> {
    let raw = match fs::read(storage_path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed reading {}", storage_path.display()));
        }
    };
    let payload: EncryptedBlob =
        serde_json::from_slice(&raw).context("failed decoding encrypted Steam account")?;
    let decrypted = decrypt_bytes(master_key, &payload)?;
    let unpacked = unpack_managed_storage_bytes(decrypted.as_slice())?;
    let record: StoredSteamAccount = serde_json::from_slice(unpacked.as_slice())
        .context("failed decoding managed Steam account")?;
    if record.schema_version != STEAM_MANAGED_SCHEMA_VERSION {
        bail!(
            "unsupported Steam account schema version {}",
            record.schema_version
        );
    }
    Ok(Some(record))
}

fn pack_managed_storage_bytes(plaintext: &[u8]) -> Result<Vec<u8>> {
    let compressed = zstd::stream::encode_all(Cursor::new(plaintext), STEAM_MANAGED_ZSTD_LEVEL)
        .context("failed compressing Steam account payload")?;
    if compressed.len() + STEAM_MANAGED_PACK_PREFIX.len() + 16 >= plaintext.len() {
        return Ok(plaintext.to_vec());
    }

    let mut packed = Vec::with_capacity(STEAM_MANAGED_PACK_PREFIX.len() + compressed.len());
    packed.extend_from_slice(STEAM_MANAGED_PACK_PREFIX);
    packed.extend_from_slice(&compressed);
    Ok(packed)
}

fn unpack_managed_storage_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    let Some(compressed) = raw.strip_prefix(STEAM_MANAGED_PACK_PREFIX) else {
        return Ok(raw.to_vec());
    };
    zstd::stream::decode_all(Cursor::new(compressed))
        .context("failed decompressing Steam account payload")
}

// ---------------------------------------------------------------------------
// Guard enrollment (provision new 2FA or migrate existing)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) enum GuardEnrollmentResult {
    Provisioned {
        registrar: AccountLinker<WebApiTransport>,
        guard_data: VendorSteamGuardAccount,
        steam_timestamp: u64,
        masked_phone: String,
        verify_channel: String,
    },
    EmailConfirmationRequired {
        registrar: AccountLinker<WebApiTransport>,
    },
    PhoneRequired {
        registrar: AccountLinker<WebApiTransport>,
    },
    DeviceConflict {
        registrar: AccountLinker<WebApiTransport>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct GuardPhoneLinkPrompt {
    pub(crate) confirmation_email_address: String,
    pub(crate) phone_number_formatted: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum GuardPhoneEmailContinuation {
    StillWaiting { seconds_to_wait: Option<u32> },
    SmsSent,
}

#[derive(Debug)]
pub(crate) enum GuardPhoneVerificationResult {
    Advanced(GuardEnrollmentResult),
    Retry {
        registrar: AccountLinker<WebApiTransport>,
        error: anyhow::Error,
    },
}

#[derive(Debug)]
pub(crate) enum GuardFinalizeResult {
    Completed {
        guard_data: VendorSteamGuardAccount,
    },
    Retry {
        registrar: AccountLinker<WebApiTransport>,
        guard_data: VendorSteamGuardAccount,
        steam_timestamp: u64,
        error: anyhow::Error,
    },
}

#[derive(Debug)]
pub(crate) enum GuardMigrationStartResult {
    AwaitingSms {
        registrar: AccountLinker<WebApiTransport>,
    },
    PhoneRequired {
        registrar: AccountLinker<WebApiTransport>,
    },
    Retry {
        registrar: AccountLinker<WebApiTransport>,
        error: anyhow::Error,
    },
}

#[derive(Debug)]
pub(crate) enum GuardMigrationFinishResult {
    Completed {
        guard_data: VendorSteamGuardAccount,
    },
    Retry {
        registrar: AccountLinker<WebApiTransport>,
        error: anyhow::Error,
    },
}

/// Resolve the enrollment attempt from an `AccountLinker` into a typed result.
fn resolve_enrollment(
    mut registrar: AccountLinker<WebApiTransport>,
) -> Result<GuardEnrollmentResult> {
    match registrar.link() {
        Ok(provision) => {
            let verify_channel = match provision.confirm_type() {
                steamguard::accountlinker::AccountLinkConfirmType::SMS => "sms",
                steamguard::accountlinker::AccountLinkConfirmType::Email => "email",
                _ => "unknown",
            }
            .to_owned();
            let steam_timestamp = provision.server_time();
            let masked_phone = provision.phone_number_hint().to_owned();
            let guard_data = provision.into_account();
            Ok(GuardEnrollmentResult::Provisioned {
                guard_data,
                steam_timestamp,
                masked_phone,
                verify_channel,
                registrar,
            })
        }
        Err(AccountLinkError::MustConfirmEmail) => {
            Ok(GuardEnrollmentResult::EmailConfirmationRequired { registrar })
        }
        Err(AccountLinkError::MustProvidePhoneNumber) => {
            Ok(GuardEnrollmentResult::PhoneRequired { registrar })
        }
        Err(AccountLinkError::AuthenticatorPresent) => {
            Ok(GuardEnrollmentResult::DeviceConflict { registrar })
        }
        Err(e) => Err(e.into()),
    }
}

pub(crate) async fn resume_guard_enrollment(
    registrar: AccountLinker<WebApiTransport>,
) -> Result<GuardEnrollmentResult> {
    spawn_blocking(move || resolve_enrollment(registrar))
        .await
        .context("guard enrollment resume task panicked")?
}

fn build_phone_linker(tokens: SteamTokens) -> Result<PhoneLinker<WebApiTransport>> {
    let client = build_blocking_steam_client()?;
    let transport = WebApiTransport::new(client);
    Ok(PhoneLinker::new(PhoneClient::new(transport), tokens))
}

fn map_phone_set_error(error: SetPhoneNumberError) -> anyhow::Error {
    match error {
        SetPhoneNumberError::UnknownEResult(EResult::RateLimitExceeded) => anyhow!("rate_limited"),
        SetPhoneNumberError::UnknownEResult(result) => {
            anyhow!("failed setting Steam phone number: {result:?}")
        }
        SetPhoneNumberError::TransportError(inner) => inner.into(),
    }
}

fn map_phone_verify_error(error: VerifyPhoneError) -> anyhow::Error {
    match error {
        VerifyPhoneError::UnknownEResult(EResult::SMSCodeFailed) => anyhow!("bad_sms_code"),
        VerifyPhoneError::UnknownEResult(EResult::RateLimitExceeded) => anyhow!("rate_limited"),
        VerifyPhoneError::UnknownEResult(result) => {
            anyhow!("failed verifying Steam phone number: {result:?}")
        }
        VerifyPhoneError::TransportError(inner) => inner.into(),
    }
}

pub(crate) async fn start_guard_phone_link(
    registrar: &AccountLinker<WebApiTransport>,
    phone_number_raw: String,
) -> Result<GuardPhoneLinkPrompt> {
    let tokens = registrar.tokens().clone();
    spawn_blocking(move || {
        let trimmed = phone_number_raw.trim();
        ensure!(!trimmed.is_empty(), "phone_number_required");
        let parsed = phonenumber::parse(None, trimmed).map_err(|_| anyhow!("invalid_phone_number"))?;
        let linker = build_phone_linker(tokens)?;
        let response = linker
            .set_account_phone_number(parsed)
            .map_err(map_phone_set_error)?;
        Ok::<GuardPhoneLinkPrompt, anyhow::Error>(GuardPhoneLinkPrompt {
            confirmation_email_address: response.confirmation_email_address().to_owned(),
            phone_number_formatted: response.phone_number_formatted().to_owned(),
        })
    })
    .await
    .context("Steam phone setup task panicked")?
}

pub(crate) async fn continue_guard_phone_link(
    registrar: &AccountLinker<WebApiTransport>,
) -> Result<GuardPhoneEmailContinuation> {
    let tokens = registrar.tokens().clone();
    spawn_blocking(move || {
        let linker = build_phone_linker(tokens)?;
        let waiting = linker.is_account_waiting_for_email_confirmation()?;
        if waiting.is_some() {
            return Ok::<GuardPhoneEmailContinuation, anyhow::Error>(
                GuardPhoneEmailContinuation::StillWaiting {
                    seconds_to_wait: waiting,
                },
            );
        }
        linker
            .send_phone_verification_code(0)
            .map_err(|error| match error.downcast::<steamguard::transport::TransportError>() {
                Ok(transport_error) => anyhow!(transport_error.to_string()),
                Err(other) => {
                    let message = other.to_string();
                    if message.contains("RateLimitExceeded") {
                        anyhow!("rate_limited")
                    } else {
                        anyhow!("failed sending Steam phone verification code: {message}")
                    }
                }
            })?;
        Ok::<GuardPhoneEmailContinuation, anyhow::Error>(GuardPhoneEmailContinuation::SmsSent)
    })
    .await
    .context("Steam phone email confirmation task panicked")?
}

pub(crate) async fn verify_guard_phone_link(
    registrar: AccountLinker<WebApiTransport>,
    verification_code: String,
) -> Result<GuardPhoneVerificationResult> {
    spawn_blocking(move || {
        let code = verification_code.trim().to_owned();
        ensure!(!code.is_empty(), "phone_verification_code_required");
        let linker = build_phone_linker(registrar.tokens().clone())?;
        if let Err(error) = linker
            .verify_account_phone_with_code(code)
            .map_err(map_phone_verify_error)
        {
            return Ok(GuardPhoneVerificationResult::Retry { registrar, error });
        }
        Ok(GuardPhoneVerificationResult::Advanced(resolve_enrollment(
            registrar,
        )?))
    })
    .await
    .context("Steam phone verification task panicked")?
}

/// Authenticate to Steam and request a new guard enrollment.
pub(crate) async fn enroll_new_guard(
    steam_username: String,
    steam_password: String,
) -> Result<(String, GuardEnrollmentResult)> {
    spawn_blocking(move || {
        let username = steam_username.trim().to_owned();
        ensure!(!username.is_empty(), "Steam username is required");
        ensure!(!steam_password.is_empty(), "Steam password is required");

        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);

        let mut login = UserLogin::new(transport.clone(), build_steam_mobile_device_details());
        let guard_methods = login
            .begin_auth_via_credentials(&username, &steam_password)
            .map_err(map_login_error)?;
        ensure_guard_setup_login_can_continue(
            guard_methods.iter().map(|method| method.confirmation_type),
        )?;

        let tokens = login
            .poll_until_tokens()
            .context("could not obtain session tokens during guard enrollment")?;

        let registrar = AccountLinker::new(transport, tokens);
        let outcome = resolve_enrollment(registrar)?;
        Ok((username, outcome))
    })
    .await
    .context("guard enrollment task panicked")?
}

/// Enroll a guard on an existing managed account using its stored session tokens.
pub(crate) async fn enroll_guard_for_managed_account(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<(String, GuardEnrollmentResult)> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let record = load_stored_account(master_key, &storage_path)
        .await?
        .context("account not found")?;

    let session = record.session.as_ref().context("no session on account")?;
    let access_jwt = session
        .access_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("no access token")?
        .to_owned();
    let refresh_jwt = session
        .refresh_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("no refresh token")?
        .to_owned();
    let display_name = record
        .steam_username
        .clone()
        .unwrap_or_else(|| record.account_name.clone());

    spawn_blocking(move || {
        let tokens = SteamTokens::new(SteamJwt::from(access_jwt), SteamJwt::from(refresh_jwt));
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let registrar = AccountLinker::new(transport, tokens);

        let outcome = resolve_enrollment(registrar)?;
        Ok((display_name, outcome))
    })
    .await
    .context("managed account guard enrollment task panicked")?
}

const GUARD_VERIFY_ATTEMPTS: usize = 5;

/// Submit the user-provided verification code to complete the guard enrollment.
pub(crate) fn confirm_guard_enrollment(
    mut registrar: AccountLinker<WebApiTransport>,
    mut guard_data: VendorSteamGuardAccount,
    mut steam_timestamp: u64,
    verification_code: String,
) -> GuardFinalizeResult {
    let mut remaining = GUARD_VERIFY_ATTEMPTS;
    loop {
        match registrar.finalize(steam_timestamp, &mut guard_data, verification_code.clone()) {
            Ok(()) => return GuardFinalizeResult::Completed { guard_data },
            Err(FinalizeLinkError::WantMore { server_time }) if remaining > 1 => {
                steam_timestamp = server_time;
                remaining -= 1;
            }
            Err(FinalizeLinkError::WantMore { .. }) => {
                return GuardFinalizeResult::Retry {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    error: anyhow!("guard enrollment verification exhausted"),
                };
            }
            Err(FinalizeLinkError::BadSmsCode) => {
                return GuardFinalizeResult::Retry {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    error: anyhow!("bad_sms_code"),
                };
            }
            Err(error) => {
                return GuardFinalizeResult::Retry {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    error: error.into(),
                };
            }
        }
    }
}

/// Request Steam to start migrating an existing guard to this device.
pub(crate) fn initiate_guard_migration(
    mut registrar: AccountLinker<WebApiTransport>,
) -> GuardMigrationStartResult {
    match registrar.transfer_start() {
        Ok(()) => GuardMigrationStartResult::AwaitingSms { registrar },
        Err(TransferError::GenericFailure) => GuardMigrationStartResult::PhoneRequired { registrar },
        Err(error) => GuardMigrationStartResult::Retry {
            registrar,
            error: error.into(),
        },
    }
}

/// Finish the guard migration by providing the SMS verification code.
pub(crate) fn complete_guard_migration(
    mut registrar: AccountLinker<WebApiTransport>,
    code: String,
) -> GuardMigrationFinishResult {
    match registrar.transfer_finish(code) {
        Ok(guard_data) => GuardMigrationFinishResult::Completed { guard_data },
        Err(TransferError::BadSmsCode) => GuardMigrationFinishResult::Retry {
            registrar,
            error: anyhow!("bad_sms_code"),
        },
        Err(error) => GuardMigrationFinishResult::Retry {
            registrar,
            error: error.into(),
        },
    }
}

/// Persist a newly enrolled/migrated guard into our encrypted storage format.
pub(crate) async fn persist_enrolled_guard(
    root_dir: &Path,
    master_key: &[u8],
    guard_data: &VendorSteamGuardAccount,
    steam_username: &str,
) -> Result<SteamGuardAccount> {
    ensure_managed_accounts_dir(root_dir).await?;

    let secret_b64 = base64::engine::general_purpose::STANDARD
        .encode(guard_data.shared_secret.expose_secret());
    validate_shared_secret(&secret_b64)?;

    let tokens = guard_data
        .tokens
        .as_ref()
        .context("guard enrollment did not provide usable Steam session tokens")?;

    let now = Utc::now().timestamp();
    let record = StoredSteamAccount {
        schema_version: STEAM_MANAGED_SCHEMA_VERSION,
        id: Uuid::new_v4().to_string(),
        account_name: sanitize_account_name(&guard_data.account_name),
        steam_username: Some(steam_username.to_owned()),
        steam_id: Some(guard_data.steam_id),
        shared_secret: secret_b64,
        identity_secret: Some(guard_data.identity_secret.expose_secret().to_owned()),
        device_id: Some(guard_data.device_id.clone()),
        session: Some(StoredSteamWebSession {
            session_id: None,
            steam_login: None,
            steam_login_secure: None,
            web_cookie: None,
            oauth_token: None,
            access_token: Some(tokens.access_token().expose_secret().to_owned()),
            refresh_token: Some(tokens.refresh_token().expose_secret().to_owned()),
        }),
        imported_from: Some(String::from("guard-enrollment")),
        managed_origin: SteamManagedAccountOrigin::ManualEntry,
        created_at_unix: now,
        updated_at_unix: now,
        revocation_code: Some(guard_data.revocation_code.expose_secret().to_owned()),
        serial_number: Some(guard_data.serial_number.clone()),
        token_gid: Some(guard_data.token_gid.clone()),
        secret_1: Some(guard_data.secret_1.expose_secret().to_owned()),
        uri: Some(guard_data.uri.expose_secret().to_owned()),
        proxy_url: None,
    };
    let storage_path = managed_account_storage_path(root_dir, &record.id);
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(record.into_runtime(storage_path))
}

// ---------------------------------------------------------------------------
// Guard revocation
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct GuardRevocationOutcome {
    pub(crate) revoked: bool,
    pub(crate) tries_left: Option<u32>,
}

/// Revoke the guard on a managed account using the recovery code.
pub(crate) async fn revoke_account_guard(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    recovery_code: String,
) -> Result<GuardRevocationOutcome> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(record) = load_stored_account(master_key, &storage_path).await? else {
        bail!("account not found");
    };

    let session = record.session.as_ref().context("no session on account")?;
    let access_jwt = session
        .access_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("session lacks access token for guard revocation")?
        .to_owned();
    let refresh_jwt = session
        .refresh_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("session lacks refresh token for guard revocation")?
        .to_owned();

    let outcome = spawn_blocking(move || {
        let tokens = SteamTokens::new(SteamJwt::from(access_jwt), SteamJwt::from(refresh_jwt));
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let registrar = AccountLinker::new(transport, tokens);

        match registrar.remove_authenticator(Some(&recovery_code)) {
            Ok(()) => Ok(GuardRevocationOutcome {
                revoked: true,
                tries_left: None,
            }),
            Err(RemoveAuthenticatorError::IncorrectRevocationCode {
                attempts_remaining,
            }) => Ok(GuardRevocationOutcome {
                revoked: false,
                tries_left: Some(attempts_remaining),
            }),
            Err(RemoveAuthenticatorError::MissingRevocationCode) => {
                bail!("missing_revocation_code")
            }
            Err(e) => Err(e.into()),
        }
    })
    .await
    .context("guard revocation task panicked")??;

    if outcome.revoked {
        delete_managed_account(root_dir, account_id).await?;
    }

    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Account security profile
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AccountSecurityInfo {
    pub(crate) guard_state: u32,
    pub(crate) protection_mode: u32,
    pub(crate) guard_type: u32,
    pub(crate) email_verified: bool,
    pub(crate) bound_device: String,
    pub(crate) enrolled_at: u32,
    pub(crate) remaining_revoke_tries: u32,
    pub(crate) schema_ver: u32,
}

/// Fetch the current guard / 2FA security profile for a managed account.
pub(crate) async fn fetch_security_info(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<AccountSecurityInfo> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let record = load_stored_account(master_key, &storage_path)
        .await?
        .context("account not found")?;
    let session = record.session.as_ref().context("no session on account")?;
    let access_jwt = session
        .access_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("session lacks access token")?
        .to_owned();
    let refresh_jwt = session
        .refresh_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("session lacks refresh token")?
        .to_owned();
    let steam_id = record.steam_id.context("no steam_id on account")?;
    let shared_secret = record.shared_secret.clone();

    spawn_blocking(move || {
        let tokens = SteamTokens::new(SteamJwt::from(access_jwt), SteamJwt::from(refresh_jwt));
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);

        let mut stub = VendorSteamGuardAccount::new();
        stub.steam_id = steam_id;
        stub.shared_secret =
            TwoFactorSecret::parse_shared_secret(shared_secret).context("bad shared_secret")?;

        let registrar = AccountLinker::new(transport, tokens);
        let resp = registrar
            .query_status(&stub)
            .map_err(|e| anyhow!("security profile query failed: {e:?}"))?;

        Ok(AccountSecurityInfo {
            guard_state: resp.state(),
            protection_mode: resp.steamguard_scheme(),
            guard_type: resp.authenticator_type(),
            email_verified: resp.email_validated(),
            bound_device: resp.device_identifier().to_owned(),
            enrolled_at: resp.time_created(),
            remaining_revoke_tries: resp.revocation_attempts_remaining(),
            schema_ver: resp.version(),
        })
    })
    .await
    .context("security profile query task panicked")?
}

// ---------------------------------------------------------------------------
// TOTP export URI
// ---------------------------------------------------------------------------

/// Build an `otpauth://` URI suitable for QR code rendering or manual import.
pub(crate) fn generate_totp_uri(account: &SteamGuardAccount) -> Result<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(account.shared_secret.trim())
        .context("shared_secret is not valid base64")?;
    let encoded_secret = data_encoding::BASE32_NOPAD.encode(&raw);
    let encoded_label = percent_encoding::utf8_percent_encode(
        &account.account_name,
        percent_encoding::NON_ALPHANUMERIC,
    );
    Ok(format!(
        "otpauth://totp/Steam:{encoded_label}?secret={encoded_secret}&issuer=Steam&digits=5&period=30&algorithm=SHA1"
    ))
}

// ---------------------------------------------------------------------------
// Third-party guard import (WinAuth / otpauth URI)
// ---------------------------------------------------------------------------

/// Embedded JSON payload inside a third-party otpauth:// URI (e.g. WinAuth export).
#[derive(Debug, Deserialize)]
struct ThirdPartyGuardPayload {
    #[serde(default)]
    shared_secret: String,
    #[serde(default)]
    identity_secret: String,
    #[serde(default, alias = "deviceid")]
    device_id: String,
    #[serde(default, alias = "steamid")]
    steam_id: String,
    #[serde(default)]
    revocation_code: String,
    #[serde(default)]
    serial_number: String,
    #[serde(default)]
    token_gid: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    secret_1: String,
    #[serde(default)]
    account_name: String,
}

/// Parse a third-party otpauth:// URI, extract the embedded guard material, and persist it.
pub(crate) async fn ingest_third_party_guard(
    root_dir: &Path,
    master_key: &[u8],
    raw_uri: &str,
    display_name_override: Option<&str>,
) -> Result<SteamGuardAccount> {
    let input = raw_uri.trim();
    ensure!(input.starts_with("otpauth://"), "expected otpauth:// scheme");

    // Extract the `data` query param which holds a percent-encoded JSON blob.
    let qs = input
        .split_once('?')
        .map(|(_, q)| q)
        .context("URI has no query parameters")?;
    let payload_json: String = qs
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "data")
        .map(|(_, v)| {
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned()
        })
        .context("URI is missing the embedded data parameter")?;

    let payload: ThirdPartyGuardPayload =
        serde_json::from_str(&payload_json).context("embedded data is not valid JSON")?;

    ensure!(
        !payload.shared_secret.trim().is_empty(),
        "embedded shared_secret is empty"
    );
    validate_shared_secret(payload.shared_secret.trim())?;
    let id_secret = normalize_optional_string(Some(payload.identity_secret));
    if let Some(s) = id_secret.as_deref() {
        validate_identity_secret(s)?;
    }

    let sid: Option<u64> = payload.steam_id.parse().ok();
    let dev_id =
        normalize_optional_string(Some(payload.device_id)).or_else(|| sid.map(generate_device_id_for_steam_id));

    let name = display_name_override
        .filter(|v| !v.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| normalize_optional_string(Some(payload.account_name)))
        .unwrap_or_else(|| String::from("third-party-import"));

    ensure_managed_accounts_dir(root_dir).await?;

    let now = Utc::now().timestamp();
    let record = StoredSteamAccount {
        schema_version: STEAM_MANAGED_SCHEMA_VERSION,
        id: Uuid::new_v4().to_string(),
        account_name: sanitize_account_name(&name),
        steam_username: None,
        steam_id: sid,
        shared_secret: payload.shared_secret.trim().to_owned(),
        identity_secret: id_secret,
        device_id: dev_id,
        session: None,
        imported_from: Some(String::from("third-party-uri")),
        managed_origin: SteamManagedAccountOrigin::UploadedMaFile,
        created_at_unix: now,
        updated_at_unix: now,
        revocation_code: normalize_optional_string(Some(payload.revocation_code)),
        serial_number: normalize_optional_string(Some(payload.serial_number)),
        token_gid: normalize_optional_string(Some(payload.token_gid)),
        secret_1: normalize_optional_string(Some(payload.secret_1)),
        uri: normalize_optional_string(Some(payload.uri)),
        proxy_url: None,
    };
    let storage_path = managed_account_storage_path(root_dir, &record.id);
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(record.into_runtime(storage_path))
}

// ---------------------------------------------------------------------------
// Batch trade confirmation operations
// ---------------------------------------------------------------------------

/// Approve every pending trade confirmation for the given account. Returns count of successes.
pub(crate) async fn batch_approve_trades(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
) -> Result<usize> {
    let pending = fetch_confirmations(http_client, account).await?;
    let mut approved = 0usize;
    for item in &pending {
        match respond_to_confirmation(http_client, account, &item.id, &item.nonce, true).await {
            Ok(()) => approved += 1,
            Err(e) => warn!("could not approve trade {}: {e}", item.id),
        }
    }
    Ok(approved)
}

/// Reject every pending trade confirmation for the given account. Returns count of successes.
pub(crate) async fn batch_reject_trades(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
) -> Result<usize> {
    let pending = fetch_confirmations(http_client, account).await?;
    let mut rejected = 0usize;
    for item in &pending {
        match respond_to_confirmation(http_client, account, &item.id, &item.nonce, false).await {
            Ok(()) => rejected += 1,
            Err(e) => warn!("could not reject trade {}: {e}", item.id),
        }
    }
    Ok(rejected)
}

// ---------------------------------------------------------------------------
// Proxied HTTP client helper
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) fn create_proxied_http_client(
    proxy_url: Option<&str>,
) -> Result<reqwest::blocking::Client> {
    let mut builder =
        reqwest::blocking::Client::builder().user_agent(STEAM_CONFIRMATION_USER_AGENT);
    if let Some(url) = proxy_url.filter(|v| !v.trim().is_empty()) {
        builder = builder.proxy(
            reqwest::Proxy::all(url.trim())
                .with_context(|| format!("malformed proxy address: {url}"))?,
        );
    }
    builder.build().context("could not construct HTTP client")
}

// ---------------------------------------------------------------------------
// Clock drift measurement
// ---------------------------------------------------------------------------

/// Query the Steam server clock and compare with local time. Returns `(remote, local, drift)`.
pub(crate) async fn measure_clock_drift(
    http_client: &reqwest::Client,
) -> Result<(i64, i64, i64)> {
    let local = Utc::now().timestamp();
    let remote = query_steam_server_time(http_client).await?;
    Ok((remote, local, remote - local))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_guard_code_matches_reference_sample() {
        let code = generate_guard_code("zvIayp3JPvtvX/QGHqsqKBk/44s=", 1_616_374_841)
            .expect("steam guard code should generate");
        assert_eq!(code, "2F9J5");
    }

    #[test]
    fn generate_confirmation_key_matches_reference_sample() {
        let key = generate_confirmation_key("GQP46b73Ws7gr8GmZFR0sDuau5c=", 1_617_591_917, "conf")
            .expect("confirmation key should generate");
        assert_eq!(key, "NaL8EIMhfy/7vBounJ0CvpKbrPk=");
    }

    #[test]
    fn guard_setup_login_gate_allows_guardless_sign_in() {
        assert_eq!(
            classify_guard_setup_login_gate([
                EAuthSessionGuardType::k_EAuthSessionGuardType_None,
            ]),
            GuardSetupLoginGate::CanContinue
        );
    }

    #[test]
    fn guard_setup_login_gate_blocks_existing_guard_code_requirement() {
        assert_eq!(
            classify_guard_setup_login_gate([
                EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
            ]),
            GuardSetupLoginGate::RequiresExistingGuardCode
        );
    }

    #[test]
    fn guard_setup_login_gate_blocks_email_confirmation_requirement() {
        assert_eq!(
            classify_guard_setup_login_gate([
                EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation,
            ]),
            GuardSetupLoginGate::RequiresEmail
        );
    }

    #[test]
    fn parse_account_file_accepts_standard_mafile() {
        let path = PathBuf::from("tests/fixtures/steam/compat/1-account/1234.maFile");
        let raw = std::fs::read(&path).expect("fixture should be readable");
        let account = parse_account_bytes(&raw, &path).expect("maFile should parse");

        assert_eq!(account.account_name, "example");
        assert_eq!(account.steam_username.as_deref(), Some("example"));
        assert_eq!(account.steam_id, Some(1234));
        assert_eq!(account.shared_secret, "zvIayp3JPvtvX/QGHqsqKBk/44s=");
        assert_eq!(account.identity_secret.as_deref(), Some("kjsdlwowiqe="));
        assert!(account.has_confirmation_secret_material());
    }

    #[test]
    fn parse_account_file_accepts_steamv2_style_mafile() {
        let path = PathBuf::from("tests/fixtures/steam/compat/steamv2/sample.maFile");
        let raw = std::fs::read(&path).expect("fixture should be readable");
        let account = parse_account_bytes(&raw, &path).expect("steamv2 maFile should parse");

        assert_eq!(account.account_name, "afarihm");
        assert_eq!(account.steam_username.as_deref(), Some("afarihm"));
        assert_eq!(account.steam_id, Some(76_561_199_441_992_970));
        assert_eq!(
            account.identity_secret.as_deref(),
            Some("f62XbJcml4r1j3NcFm0GGTtmcXw=")
        );
    }

    #[test]
    fn parse_account_file_accepts_access_token_confirmation_session() {
        let raw = br#"{
            "account_name": "token-session",
            "shared_secret": "zvIayp3JPvtvX/QGHqsqKBk/44s=",
            "identity_secret": "GQP46b73Ws7gr8GmZFR0sDuau5c=",
            "device_id": "android:63e01aa8-e99c-42c4-ef4c-e78bd041f129",
            "Session": {
                "AccessToken": "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInI6MTRCM18yMkZEQjg0RF9BMjJDRCIsICJzdWIiOiAiNzY1NjExOTk0NDE5OTI5NzAiLCAiYXVkIjogWyAid2ViIiwgIm1vYmlsZSIgXSwgImV4cCI6IDE2OTE3NTc5MzUsICJuYmYiOiAxNjgzMDMxMDUxLCAiaWF0IjogMTY5MTY3MTA1MSwgImp0aSI6ICIxNTI1XzIyRkRCOUJBXzZBRDkwIiwgIm9hdCI6IDE2OTE2NzEwNTEsICJwZXIiOiAwLCAiaXBfc3ViamVjdCI6ICIxMDQuMjQ2LjEyNS4xNDEiLCAiaXBfY29uZmlybWVyIjogIjEwNC4yNDYuMTI1LjE0MSIgfQ.ncqc5TpVlD05lnZvy8c3Bkx70gXDvQQXN0iG5Z4mOLgY_rwasXIJXnR-X4JczT8PmZ2v5cisW5VRHAdfsz_8CA",
                "RefreshToken": "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTE1NTcwNjg5MiIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTcwNTAxMTk1NSwgIm5iZiI6IDE2Nzg0NjQ4MzcsICJpYXQiOiAxNjg3MTA0ODM3LCAianRpIjogIjE4QzVfMjJCM0Y0MzFfQ0RGNkEiLCAib2F0IjogMTY4NzEwNDgzNywgInBlciI6IDEsICJpcF9zdWJqZWN0IjogIjY5LjEyMC4xMzYuMTI0IiwgImlwX2NvbmZpcm1lciI6ICI2OS4xMjAuMTM2LjEyNCIgfQ.7p5TPj9pGQbxIzWDDNCSP9OkKYSeDnWBE8E-M8hUrxOEPCW0XwrbDUrh199RzjPDw"
            }
        }"#;
        let path = PathBuf::from("tokenized.maFile");
        let account = parse_account_bytes(raw, &path).expect("tokenized maFile should parse");

        assert_eq!(account.steam_id, Some(76_561_199_441_992_970));
        assert!(account.has_confirmation_secret_material());
        assert!(account.has_confirmation_session());
        assert!(account.confirmation_ready());
        assert_eq!(
            account
                .session
                .as_ref()
                .and_then(|session| session.access_token.as_deref()),
            Some(
                "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInI6MTRCM18yMkZEQjg0RF9BMjJDRCIsICJzdWIiOiAiNzY1NjExOTk0NDE5OTI5NzAiLCAiYXVkIjogWyAid2ViIiwgIm1vYmlsZSIgXSwgImV4cCI6IDE2OTE3NTc5MzUsICJuYmYiOiAxNjgzMDMxMDUxLCAiaWF0IjogMTY5MTY3MTA1MSwgImp0aSI6ICIxNTI1XzIyRkRCOUJBXzZBRDkwIiwgIm9hdCI6IDE2OTE2NzEwNTEsICJwZXIiOiAwLCAiaXBfc3ViamVjdCI6ICIxMDQuMjQ2LjEyNS4xNDEiLCAiaXBfY29uZmlybWVyIjogIjEwNC4yNDYuMTI1LjE0MSIgfQ.ncqc5TpVlD05lnZvy8c3Bkx70gXDvQQXN0iG5Z4mOLgY_rwasXIJXnR-X4JczT8PmZ2v5cisW5VRHAdfsz_8CA"
            )
        );
    }

    #[test]
    fn build_confirmation_cookie_header_falls_back_to_access_token() {
        let account = SteamGuardAccount {
            id: String::from("demo"),
            account_name: String::from("token-cookie"),
            steam_username: None,
            steam_id: Some(76_561_199_441_992_970),
            shared_secret: String::from("zvIayp3JPvtvX/QGHqsqKBk/44s="),
            identity_secret: Some(String::from("GQP46b73Ws7gr8GmZFR0sDuau5c=")),
            device_id: Some(String::from("android:63e01aa8-e99c-42c4-ef4c-e78bd041f129")),
            session: Some(SteamWebSession {
                session_id: None,
                steam_login: None,
                steam_login_secure: None,
                web_cookie: None,
                oauth_token: None,
                access_token: Some(String::from("access-token-value")),
                refresh_token: Some(String::from("refresh-token-value")),
            }),
            storage_path: PathBuf::from("demo"),
            source_kind: SteamAccountSourceKind::Managed,
            managed_origin: Some(SteamManagedAccountOrigin::UploadedMaFile),
            imported_from: Some(String::from("tokenized.maFile")),
            encrypted_at_rest: true,
            created_at_unix: Some(0),
            updated_at_unix: Some(0),
            revocation_code: None,
            serial_number: None,
            token_gid: None,
            secret_1: None,
            uri: None,
            proxy_url: None,
        };

        let cookie = build_confirmation_cookie_header(&account, 76_561_199_441_992_970)
            .expect("access token should produce a confirmation cookie");
        assert_eq!(
            cookie,
            "dob=; steamid=76561199441992970; steamLoginSecure=76561199441992970||access-token-value"
        );
    }

    #[test]
    fn sanitize_account_name_keeps_unicode() {
        assert_eq!(sanitize_account_name("中文 steam 🚀"), "中文 steam 🚀");
        assert_eq!(sanitize_account_name("中文/会话:*"), "中文 会话");
    }

    #[tokio::test]
    async fn managed_account_round_trips_encrypted() {
        let temp_root = std::env::temp_dir().join(format!("hanagram-steam-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_root)
            .await
            .expect("temporary steam dir should be created");
        let master_key = [7u8; 32];
        let created = create_manual_account(
            &temp_root,
            &master_key,
            ManualSteamAccountInput {
                account_name: String::from("Demo Steam"),
                steam_username: Some(String::from("demo_login")),
                steam_id: 76_561_197_960_265_728,
                shared_secret: String::from("zvIayp3JPvtvX/QGHqsqKBk/44s="),
                identity_secret: Some(String::from("GQP46b73Ws7gr8GmZFR0sDuau5c=")),
                device_id: None,
                steam_login_secure: Some(String::from("cookie-value")),
            },
        )
        .await
        .expect("manual account should be stored");

        let (accounts, issues) = discover_accounts(&temp_root, Some(&master_key)).await;
        assert!(issues.is_empty());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_name, "Demo Steam");
        assert_eq!(accounts[0].steam_username.as_deref(), Some("demo_login"));
        assert_eq!(accounts[0].id, created.id);
        assert!(accounts[0].encrypted_at_rest);
        assert!(accounts[0].confirmation_ready());

        let raw = fs::read(managed_account_storage_path(&temp_root, &created.id))
            .await
            .expect("encrypted file should exist");
        assert!(!String::from_utf8_lossy(&raw).contains("Demo Steam"));

        fs::remove_dir_all(&temp_root)
            .await
            .expect("temporary steam dir should be deleted");
    }

    #[tokio::test]
    async fn managed_account_materials_update_derives_confirmation_ready_fields() {
        let temp_root = std::env::temp_dir().join(format!("hanagram-steam-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_root)
            .await
            .expect("temporary steam dir should be created");
        let master_key = [9u8; 32];
        let created = create_manual_account(
            &temp_root,
            &master_key,
            ManualSteamAccountInput {
                account_name: String::from("Updater"),
                steam_username: None,
                steam_id: 76_561_197_960_265_728,
                shared_secret: String::from("zvIayp3JPvtvX/QGHqsqKBk/44s="),
                identity_secret: None,
                device_id: None,
                steam_login_secure: None,
            },
        )
        .await
        .expect("manual account should be stored");

        let updated = update_managed_account_materials(
            &temp_root,
            &master_key,
            &created.id,
            UpdateSteamAccountInput {
                steam_username: Some(String::from("updater_login")),
                shared_secret: None,
                identity_secret: Some(String::from("GQP46b73Ws7gr8GmZFR0sDuau5c=")),
                device_id: None,
                steam_login_secure: Some(String::from("76561197960265728||cookie-value")),
            },
        )
        .await
        .expect("managed account materials should update");
        assert!(updated);

        let account = load_managed_account(&temp_root, &master_key, &created.id)
            .await
            .expect("managed account should load")
            .expect("managed account should still exist");
        assert_eq!(account.steam_username.as_deref(), Some("updater_login"));
        assert_eq!(
            account.identity_secret.as_deref(),
            Some("GQP46b73Ws7gr8GmZFR0sDuau5c=")
        );
        assert_eq!(
            account.device_id.as_deref(),
            Some("android:63e01aa8-e99c-42c4-ef4c-e78bd041f129")
        );
        assert_eq!(
            account
                .session
                .as_ref()
                .and_then(|session| session.steam_login_secure.as_deref()),
            Some("76561197960265728||cookie-value")
        );
        assert!(account.confirmation_ready());

        fs::remove_dir_all(&temp_root)
            .await
            .expect("temporary steam dir should be deleted");
    }

    #[tokio::test]
    async fn imported_mafile_with_access_token_round_trips_encrypted() {
        let temp_root = std::env::temp_dir().join(format!("hanagram-steam-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_root)
            .await
            .expect("temporary steam dir should be created");
        let master_key = [5u8; 32];
        let raw = br#"{
            "account_name": "token-import",
            "shared_secret": "zvIayp3JPvtvX/QGHqsqKBk/44s=",
            "identity_secret": "GQP46b73Ws7gr8GmZFR0sDuau5c=",
            "device_id": "android:63e01aa8-e99c-42c4-ef4c-e78bd041f129",
            "Session": {
                "SteamID": 76561199441992970,
                "AccessToken": "imported-access-token",
                "RefreshToken": "imported-refresh-token"
            }
        }"#;

        let imported =
            import_mafile_bytes(&temp_root, &master_key, Some("tokenized.maFile"), None, raw)
                .await
                .expect("tokenized maFile should import");
        assert!(imported.confirmation_ready());
        assert_eq!(imported.steam_username.as_deref(), Some("token-import"));

        let loaded = load_managed_account(&temp_root, &master_key, &imported.id)
            .await
            .expect("managed account should load")
            .expect("managed account should exist");
        assert!(loaded.confirmation_ready());
        assert_eq!(loaded.steam_username.as_deref(), Some("token-import"));
        assert_eq!(
            loaded
                .session
                .as_ref()
                .and_then(|session| session.access_token.as_deref()),
            Some("imported-access-token")
        );
        assert_eq!(
            loaded
                .session
                .as_ref()
                .and_then(|session| session.refresh_token.as_deref()),
            Some("imported-refresh-token")
        );

        fs::remove_dir_all(&temp_root)
            .await
            .expect("temporary steam dir should be deleted");
    }

    #[tokio::test]
    async fn persist_enrolled_guard_keeps_real_tokens() {
        let temp_root = std::env::temp_dir().join(format!("hanagram-steam-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_root)
            .await
            .expect("temporary steam dir should be created");
        let master_key = [3u8; 32];

        let mut guard = VendorSteamGuardAccount::new();
        guard.account_name = String::from("linked-account");
        guard.steam_id = 76_561_199_441_992_970;
        guard.serial_number = String::from("serial");
        guard.revocation_code = String::from("R12345").into();
        guard.shared_secret =
            TwoFactorSecret::parse_shared_secret(String::from("zvIayp3JPvtvX/QGHqsqKBk/44s="))
                .expect("shared_secret should parse");
        guard.token_gid = String::from("token-gid");
        guard.identity_secret = String::from("GQP46b73Ws7gr8GmZFR0sDuau5c=").into();
        guard.uri = String::from("otpauth://totp/Steam:linked-account?secret=ASDF&issuer=Steam")
            .into();
        guard.device_id = String::from("android:63e01aa8-e99c-42c4-ef4c-e78bd041f129");
        guard.secret_1 = String::from("secret-1").into();
        guard.set_tokens(SteamTokens::new(
            SteamJwt::from(String::from("access-token")),
            SteamJwt::from(String::from("refresh-token")),
        ));

        let persisted = persist_enrolled_guard(&temp_root, &master_key, &guard, "linked_login")
            .await
            .expect("enrolled guard should persist");
        let loaded = load_managed_account(&temp_root, &master_key, &persisted.id)
            .await
            .expect("managed account should load")
            .expect("managed account should exist");

        assert_eq!(loaded.steam_username.as_deref(), Some("linked_login"));
        assert_eq!(
            loaded
                .session
                .as_ref()
                .and_then(|session| session.access_token.as_deref()),
            Some("access-token")
        );
        assert_eq!(
            loaded
                .session
                .as_ref()
                .and_then(|session| session.refresh_token.as_deref()),
            Some("refresh-token")
        );

        fs::remove_dir_all(&temp_root)
            .await
            .expect("temporary steam dir should be deleted");
    }
}
