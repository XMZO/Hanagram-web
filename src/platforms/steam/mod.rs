// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use image::ImageReader;
use rqrr::PreparedImage;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use steamguard::ExposeSecret;
use steamguard::accountlinker::{
    AccountLinkError, AccountLinker, FinalizeLinkError, RemoveAuthenticatorError, TransferError,
};
use steamguard::approver::Challenge;
use steamguard::phonelinker::{PhoneLinker, SetPhoneNumberError, VerifyPhoneError};
use steamguard::protobufs::enums::ESessionPersistence;
use steamguard::protobufs::service_phone::CPhone_AccountPhoneStatus_Request;
use steamguard::protobufs::service_twofactor::{
    CTwoFactor_CreateEmergencyCodes_Request, CTwoFactor_DestroyEmergencyCodes_Request,
    CTwoFactor_ValidateToken_Request,
};
use steamguard::protobufs::steammessages_auth_steamclient::{
    CAuthentication_GetAuthSessionInfo_Response, CAuthentication_RefreshToken_Enumerate_Request,
    CAuthentication_RefreshToken_Revoke_Request, CAuthenticationSupport_RevokeToken_Request,
    EAuthSessionGuardType, EAuthTokenPlatformType, EAuthTokenRevokeAction,
};
use steamguard::refresher::TokenRefresher;
use steamguard::steamapi::{AuthenticationClient, EResult, PhoneClient, TwoFactorClient};
use steamguard::token::{Jwt as SteamJwt, Tokens as SteamTokens, TwoFactorSecret};
use steamguard::transport::{Transport, WebApiTransport};
use steamguard::userlogin::UpdateAuthSessionError;
use steamguard::{
    DeviceDetails, LoginApprover, LoginError, SteamGuardAccount as VendorSteamGuardAccount,
    UserLogin,
};
use tokio::fs;
use tokio::task::spawn_blocking;
use tracing::{info, warn};
use uuid::Uuid;

use hanagram_web::security::{EncryptedBlob, decrypt_bytes, encrypt_bytes};

mod accounts;
mod codes;
mod confirmations;
mod devices;
mod guard;
mod login;
mod network;
mod trade_restore;
mod zero_trust;

pub(crate) use accounts::*;
pub(crate) use codes::*;
pub(crate) use confirmations::*;
pub(crate) use devices::*;
pub(crate) use guard::*;
pub(crate) use login::*;
pub(crate) use network::*;
pub(crate) use trade_restore::*;
pub(crate) use zero_trust::*;

pub(crate) const STEAM_GUARD_CODE_PERIOD_SECONDS: i64 = 30;
pub(crate) const STEAM_MANAGED_ACCOUNT_EXTENSION: &str = "steamguard";

const STEAM_GUARD_CODE_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const STEAM_MANAGED_SCHEMA_VERSION: u8 = 1;
const STEAM_MANAGED_PACK_PREFIX: &[u8] = b"hanagram-steam-pack:v1\0";
const STEAM_MANAGED_ZSTD_LEVEL: i32 = 9;
const STEAM_CONFIRMATION_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";
const STEAM_HELP_BASE_URL: &str = "https://help.steampowered.com";
const STEAM_ACCESS_TOKEN_REFRESH_SKEW_SECONDS: i64 = 300;
const STEAM_DEVICE_REVOKE_VERIFICATION_ATTEMPTS: usize = 4;
const STEAM_DEVICE_REVOKE_VERIFICATION_DELAY: Duration = Duration::from_millis(400);

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SteamSessionDevice {
    pub(crate) token_id: u64,
    pub(crate) device_label: String,
    pub(crate) platform_label: String,
    pub(crate) location_label: Option<String>,
    pub(crate) first_seen_at_unix: Option<i64>,
    pub(crate) last_seen_at_unix: Option<i64>,
    pub(crate) is_current: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SteamSessionDeviceInventory {
    pub(crate) current_token_id: Option<u64>,
    pub(crate) devices: Vec<SteamSessionDevice>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SteamSessionDeviceSelection {
    Token(u64),
    Others,
    All,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SteamSessionRevokeOutcome {
    pub(crate) revoked_count: usize,
    pub(crate) current_device_revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SteamTradeRestoreStatus {
    pub(crate) can_revert: bool,
    pub(crate) session_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SteamTradeRestoreOutcome {
    pub(crate) redir: Option<String>,
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

impl SteamConfirmationActionResponse {
    fn into_result(self) -> Result<()> {
        if self.needsauth.unwrap_or(false) {
            bail!("Steam confirmation session is no longer authorized");
        }
        if !self.success {
            bail!(
                "{}",
                self.message
                    .unwrap_or_else(|| String::from("Steam confirmation action failed"))
            );
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct SteamHelpRevertResponse {
    #[serde(deserialize_with = "deserialize_bool_from_any")]
    success: bool,
    #[serde(default)]
    redir: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SteamCredentialLoginResult {
    steam_username: String,
    steam_id: u64,
    access_token: String,
    refresh_token: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardSetupLoginGate {
    CanContinue,
    RequiresTrustedDeviceConfirmation,
    RequiresEmailConfirmation,
    RequiresEmailCode,
    RequiresExistingGuardCode,
    Unsupported,
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardLoginCodeKind {
    ExistingGuardCode,
    EmailCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardLoginCodePrompt {
    pub(crate) kind: GuardLoginCodeKind,
    pub(crate) hint: Option<String>,
}

#[derive(Debug)]
pub(crate) enum GuardEnrollmentStartResult {
    Ready {
        steam_username: String,
        outcome: GuardEnrollmentResult,
    },
    LoginCodeRequired {
        steam_username: String,
        login: UserLogin<WebApiTransport>,
        transport: WebApiTransport,
        prompt: GuardLoginCodePrompt,
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
pub(crate) enum GuardLoginCodeSubmitResult {
    Advanced(GuardEnrollmentResult),
    Retry {
        login: UserLogin<WebApiTransport>,
        transport: WebApiTransport,
        prompt: GuardLoginCodePrompt,
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

const GUARD_VERIFY_ATTEMPTS: usize = 5;

#[derive(Debug)]
pub(crate) struct GuardRevocationOutcome {
    pub(crate) revoked: bool,
    pub(crate) tries_left: Option<u32>,
}

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

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ZeroTrustSweepResult {
    pub(crate) confirmations_rejected: usize,
    pub(crate) approvals_denied: usize,
    pub(crate) devices_revoked: usize,
    pub(crate) emergency_codes_rotated: bool,
    pub(crate) guard_state_changed: bool,
    pub(crate) device_id_changed: bool,
    pub(crate) errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_qr_luma(payload: &str) -> image::GrayImage {
        let code = qrcodegen::QrCode::encode_text(payload, qrcodegen::QrCodeEcc::Medium)
            .expect("payload should fit in a QR code");
        let scale = 8_i32;
        let border = 4_i32;
        let side = ((code.size() + border * 2) * scale) as u32;
        image::GrayImage::from_fn(side, side, |x, y| {
            let module_x = x as i32 / scale - border;
            let module_y = y as i32 / scale - border;
            if code.get_module(module_x, module_y) {
                image::Luma([0])
            } else {
                image::Luma([255])
            }
        })
    }

    #[test]
    fn qr_screenshot_decoding_supports_common_formats() {
        let url = "https://s.team/q/1/1234567890123456789";
        let luma = render_qr_luma(url);
        for format in [
            image::ImageFormat::Png,
            image::ImageFormat::Jpeg,
            image::ImageFormat::Gif,
            image::ImageFormat::Bmp,
            image::ImageFormat::WebP,
        ] {
            let mut encoded = Cursor::new(Vec::new());
            let pixels = image::DynamicImage::ImageLuma8(luma.clone()).to_rgba8();
            let pixels = if format == image::ImageFormat::Jpeg || format == image::ImageFormat::Bmp
            {
                image::DynamicImage::ImageRgba8(pixels).to_rgb8().into()
            } else {
                image::DynamicImage::ImageRgba8(pixels)
            };
            pixels
                .write_to(&mut encoded, format)
                .unwrap_or_else(|error| panic!("encoding {format:?} failed: {error}"));
            let decoded = extract_login_challenge_url_from_qr_image(encoded.get_ref())
                .unwrap_or_else(|error| panic!("decoding {format:?} failed: {error}"));
            assert_eq!(decoded, url, "{format:?}");
        }
    }

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
    fn bulk_confirmation_request_includes_every_id_and_nonce() {
        let account = parse_account_bytes(
            br#"{
                "account_name": "bulk-test",
                "steamid": "76561197960265728",
                "shared_secret": "zvIayp3JPvtvX/QGHqsqKBk/44s=",
                "identity_secret": "GQP46b73Ws7gr8GmZFR0sDuau5c=",
                "device_id": "android:bulk-test",
                "Session": { "SteamLoginSecure": "76561197960265728||test-cookie" }
            }"#,
            Path::new("bulk-test.maFile"),
        )
        .expect("test account should parse");
        let pending: Vec<_> = (1..=128)
            .map(|index| SteamConfirmation {
                id: index.to_string(),
                nonce: (index + 1000).to_string(),
                creator_id: index.to_string(),
                confirmation_type: 2,
                type_name: String::from("Trade"),
                headline: String::new(),
                summary: Vec::new(),
                icon: None,
                created_at_unix: 0,
            })
            .collect();
        let client = reqwest::Client::new();

        for accept in [true, false] {
            let request =
                build_bulk_confirmation_request(&client, &account, &pending, accept, 1_617_591_917)
                    .expect("bulk request should build");
            assert_eq!(request.method(), reqwest::Method::POST);
            assert_eq!(
                request.url().as_str(),
                "https://steamcommunity.com/mobileconf/multiajaxop"
            );
            assert_eq!(
                request.headers()[reqwest::header::CONTENT_TYPE],
                "application/x-www-form-urlencoded; charset=UTF-8"
            );
            assert_eq!(
                request.headers()[reqwest::header::COOKIE],
                "dob=; steamid=76561197960265728; steamLoginSecure=76561197960265728||test-cookie"
            );
            let body = std::str::from_utf8(request.body().unwrap().as_bytes().unwrap())
                .expect("form body should be UTF-8");
            let form_url = reqwest::Url::parse(&format!("http://localhost/?{body}"))
                .expect("form should decode");
            let params: Vec<_> = form_url.query_pairs().into_owned().collect();
            let values = |name: &str| -> Vec<&str> {
                params
                    .iter()
                    .filter(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
                    .collect()
            };
            assert_eq!(values("op"), [if accept { "allow" } else { "cancel" }]);
            assert_eq!(values("tag"), ["conf"]);
            assert_eq!(values("t"), ["1617591917"]);
            assert_eq!(values("k"), ["NaL8EIMhfy/7vBounJ0CvpKbrPk="]);
            assert_eq!(
                values("cid[]"),
                pending
                    .iter()
                    .map(|item| item.id.as_str())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                values("ck[]"),
                pending
                    .iter()
                    .map(|item| item.nonce.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn confirmation_action_response_propagates_failures() {
        for (payload, expected_error) in [
            (serde_json::json!({ "success": true }), None),
            (
                serde_json::json!({ "success": false, "message": "Rate limit exceeded" }),
                Some("Rate limit exceeded"),
            ),
            (
                serde_json::json!({ "success": false }),
                Some("Steam confirmation action failed"),
            ),
            (
                serde_json::json!({ "success": false, "needsauth": true }),
                Some("Steam confirmation session is no longer authorized"),
            ),
        ] {
            let response: SteamConfirmationActionResponse =
                serde_json::from_value(payload).expect("action response should deserialize");
            let result = response.into_result();
            match expected_error {
                Some(message) => assert_eq!(result.unwrap_err().to_string(), message),
                None => assert!(result.is_ok()),
            }
        }
    }

    #[test]
    fn guard_setup_login_gate_allows_guardless_sign_in() {
        assert_eq!(
            classify_guard_setup_login_gate([EAuthSessionGuardType::k_EAuthSessionGuardType_None,]),
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
    fn guard_setup_login_gate_blocks_email_code_requirement() {
        assert_eq!(
            classify_guard_setup_login_gate([
                EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
            ]),
            GuardSetupLoginGate::RequiresEmailCode
        );
    }

    #[test]
    fn guard_setup_login_gate_blocks_email_confirmation_requirement() {
        assert_eq!(
            classify_guard_setup_login_gate([
                EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation,
            ]),
            GuardSetupLoginGate::RequiresEmailConfirmation
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

        let help_cookie =
            build_help_cookie_header(&account, 76_561_199_441_992_970, Some("session-id"))
                .expect("access token should produce a Steam Help cookie");
        assert_eq!(
            help_cookie,
            "sessionid=session-id; steamid=76561199441992970; steamLoginSecure=76561199441992970%7C%7Caccess-token-value"
        );
    }

    #[test]
    fn steam_help_language_path_matches_steam_support_urls() {
        assert_eq!(steam_help_language_path("zh-CN"), "zh-cn");
        assert_eq!(steam_help_language_path("zh-cn"), "zh-cn");
        assert_eq!(steam_help_language_path("en-US"), "en");
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
        guard.uri =
            String::from("otpauth://totp/Steam:linked-account?secret=ASDF&issuer=Steam").into();
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

    #[test]
    fn ordered_selected_session_tokens_keeps_current_last() {
        let inventory = SteamSessionDeviceInventory {
            current_token_id: Some(22),
            devices: vec![
                SteamSessionDevice {
                    token_id: 11,
                    device_label: String::from("Browser"),
                    platform_label: String::from("Web Browser"),
                    location_label: None,
                    first_seen_at_unix: None,
                    last_seen_at_unix: Some(200),
                    is_current: false,
                },
                SteamSessionDevice {
                    token_id: 22,
                    device_label: String::from("Current"),
                    platform_label: String::from("Mobile App"),
                    location_label: None,
                    first_seen_at_unix: None,
                    last_seen_at_unix: Some(300),
                    is_current: true,
                },
                SteamSessionDevice {
                    token_id: 33,
                    device_label: String::from("Desktop"),
                    platform_label: String::from("Steam Client"),
                    location_label: None,
                    first_seen_at_unix: None,
                    last_seen_at_unix: Some(100),
                    is_current: false,
                },
            ],
        };

        let all = ordered_selected_session_tokens(&inventory, SteamSessionDeviceSelection::All)
            .expect("all devices should be selectable");
        assert_eq!(all, vec![11, 33, 22]);

        let others =
            ordered_selected_session_tokens(&inventory, SteamSessionDeviceSelection::Others)
                .expect("other devices should be selectable");
        assert_eq!(others, vec![11, 33]);
    }

    #[test]
    fn build_refresh_token_revoke_signature_uses_decimal_token_id() {
        let shared_secret_bytes: [u8; 20] = base64::engine::general_purpose::STANDARD
            .decode("zvIayp3JPvtvX/QGHqsqKBk/44s=")
            .expect("shared_secret should decode")
            .try_into()
            .expect("shared_secret should be 20 bytes");

        let signature =
            build_refresh_token_revoke_signature(&shared_secret_bytes, 11_961_540_867_365_273)
                .expect("signature should build");

        assert_eq!(
            data_encoding::HEXLOWER.encode(&signature),
            "45b65591b60097b69df1f2885535004d0c889534426d1a5d91bfce4bba7c35b4"
        );
    }

    #[test]
    fn revoke_verification_accepts_expected_session_loss_results() {
        assert!(revoke_verification_accepts_session_loss(
            EResult::AccessDenied
        ));
        assert!(revoke_verification_accepts_session_loss(
            EResult::NotLoggedOn
        ));
        assert!(revoke_verification_accepts_session_loss(EResult::Revoked));
        assert!(!revoke_verification_accepts_session_loss(
            EResult::InvalidParam
        ));
        assert!(!revoke_verification_accepts_session_loss(EResult::Fail));
    }

    #[test]
    fn clear_stored_session_material_removes_saved_tokens() {
        let mut record = StoredSteamAccount {
            schema_version: STEAM_MANAGED_SCHEMA_VERSION,
            id: String::from("demo"),
            account_name: String::from("Demo"),
            steam_username: Some(String::from("demo_login")),
            steam_id: Some(76_561_197_960_265_728),
            shared_secret: String::from("zvIayp3JPvtvX/QGHqsqKBk/44s="),
            identity_secret: None,
            device_id: None,
            session: Some(StoredSteamWebSession {
                session_id: Some(String::from("session-id")),
                steam_login: Some(String::from("steam-login")),
                steam_login_secure: Some(String::from("steam-login-secure")),
                web_cookie: Some(String::from("web-cookie")),
                oauth_token: Some(String::from("oauth-token")),
                access_token: Some(String::from("access-token")),
                refresh_token: Some(String::from("refresh-token")),
            }),
            imported_from: None,
            managed_origin: SteamManagedAccountOrigin::ManualEntry,
            created_at_unix: 0,
            updated_at_unix: 0,
            revocation_code: None,
            serial_number: None,
            token_gid: None,
            secret_1: None,
            uri: None,
            proxy_url: None,
        };

        clear_stored_session_material(&mut record);
        assert!(record.session.is_none());
    }
}
