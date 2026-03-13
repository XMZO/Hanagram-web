// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, ensure};
use axum::http::{HeaderMap, header};
use base64::Engine;
use chrono::Utc;
use hanagram_web::security::{
    ArgonPolicy, EncryptedBlob, MasterKey, PasswordVerification, RECOVERY_CODE_COUNT,
    SensitiveString, SharedSensitiveString, TOTP_PERIOD_SECONDS, TotpVerification, build_totp_uri,
    decrypt_bytes, encrypt_bytes, evaluate_password_strength, generate_master_key,
    generate_recovery_codes, generate_session_token, generate_totp_secret, hash_password,
    hash_recovery_code, hash_session_token, into_sensitive_string, random_bytes,
    share_sensitive_string, unwrap_master_key, verify_password, verify_recovery_code, verify_totp,
    wrap_master_key,
};
use hanagram_web::store::{
    AuthSessionRecord, MetaStore, NewAuditEntry, StoredPasskey, SystemSettings, UserRecord,
    UserRole,
};
use serde_json::json;
use uuid::Uuid;
use webauthn_rp::bin::{Decode, Encode};
use webauthn_rp::request::PublicKeyCredentialDescriptor;
use webauthn_rp::request::register::UserHandle;
use webauthn_rp::response::register::{
    CompressedPubKey, DynamicState, StaticState, UncompressedPubKey,
};
use webauthn_rp::response::{AuthTransports, CredentialId};

use crate::i18n::Language;

pub const AUTH_COOKIE_NAME: &str = "hanagram_auth";
pub const LANGUAGE_COOKIE_NAME: &str = "hanagram_lang";
pub const AUTH_AUDIT_LOGIN_SUCCESS: &str = "login_success";
pub const AUTH_AUDIT_LOGIN_FAILURE: &str = "login_failure";
pub const AUTH_AUDIT_REGISTER: &str = "user_registered";
pub const AUTH_AUDIT_PASSWORD_CHANGED: &str = "password_changed";
pub const AUTH_AUDIT_TOTP_UPDATED: &str = "totp_updated";
pub const AUTH_AUDIT_PASSKEY_ADDED: &str = "passkey_added";
pub const AUTH_AUDIT_PASSKEY_REMOVED: &str = "passkey_removed";
pub const AUTH_AUDIT_RECOVERY_CODES_ROTATED: &str = "recovery_codes_rotated";
pub const LOGIN_METHOD_PASSWORD_ONLY: &str = "password_only";
pub const LOGIN_METHOD_PASSWORD_TOTP: &str = "password_totp";
pub const LOGIN_METHOD_PASSWORD_RECOVERY: &str = "password_recovery_code";
pub const LOGIN_METHOD_PASSWORD_PASSKEY: &str = "password_passkey";

#[derive(Clone, Debug)]
pub struct AuthenticatedSession {
    pub user: UserRecord,
    pub auth_session: AuthSessionRecord,
    pub recovery_codes_remaining: i64,
    pub requires_totp_setup: bool,
    pub requires_password_reset: bool,
}

pub struct RegistrationResult {
    pub user: UserRecord,
    pub auth_session: AuthSessionRecord,
    pub session_token: String,
    pub master_key: MasterKey,
}

pub struct LoginResult {
    pub auth_session: AuthSessionRecord,
    pub session_token: String,
    pub master_key: MasterKey,
    pub requires_totp_setup: bool,
    pub requires_password_reset: bool,
    pub recovery_notice_codes: Option<Vec<SharedSensitiveString>>,
}

pub struct TotpSetupMaterial {
    pub secret: SharedSensitiveString,
    pub otp_auth_uri: SharedSensitiveString,
    pub recovery_codes: Vec<SharedSensitiveString>,
}

pub struct PasskeyLoginChallenge {
    pub user: UserRecord,
    pub master_key: MasterKey,
    pub requires_totp_setup: bool,
    pub requires_password_reset: bool,
}

struct VerifiedPrimaryLogin {
    user: UserRecord,
    master_key: MasterKey,
    requires_totp_setup: bool,
    requires_password_reset: bool,
}

#[derive(Debug)]
pub enum LoginError {
    InvalidCredentials,
    MissingSecondFactor,
    InvalidSecondFactor,
    LockedUntil(i64),
}

const STORED_PASSKEY_VERSION: u8 = 1;

pub(crate) type StoredPasskeyStaticState =
    StaticState<CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>>;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct StoredPasskeyMaterial {
    version: u8,
    credential_id_b64: String,
    transports: u8,
    static_state_b64: String,
    dynamic_state_b64: String,
}

struct DecodedStoredPasskey {
    credential_id: CredentialId<Vec<u8>>,
    transports: AuthTransports,
    static_state_b64: String,
    static_state: StoredPasskeyStaticState,
    dynamic_state: DynamicState,
}

pub(crate) struct PasskeyAuthenticationMaterial {
    pub(crate) label: String,
    pub(crate) credential_id: CredentialId<Vec<u8>>,
    pub(crate) static_state: StoredPasskeyStaticState,
    pub(crate) dynamic_state: DynamicState,
}

pub async fn register_user(
    store: &MetaStore,
    settings: &SystemSettings,
    username: &str,
    password: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<RegistrationResult> {
    let username = normalize_username(username)?;
    let existing_user = store
        .get_user_by_username(&username)
        .await
        .context("failed checking for existing username")?;
    let reactivated_existing_user = existing_user.is_some();

    let mut user = if let Some(existing_user) = existing_user {
        ensure!(
            existing_user.security.password_hash.is_none(),
            "username already exists"
        );
        existing_user
    } else {
        let is_first_user = store.count_users().await? == 0;
        let role = if is_first_user {
            UserRole::Admin
        } else {
            UserRole::User
        };
        UserRecord::new(username.clone(), role)
    };
    let strength = evaluate_password_strength(
        password,
        &settings.password_strength_rules,
        user.role == UserRole::Admin,
    );
    ensure!(strength.valid, strength.reasons.join("; "));

    let argon_policy = settings.argon_policy.clone();
    let master_key = initialize_user_credentials(&mut user, password, &argon_policy)?;
    store.save_user(&user).await?;

    let session_token = generate_session_token();
    let auth_session = issue_session_token(
        store,
        settings,
        &user,
        &session_token,
        ip_address,
        user_agent,
    )
    .await?;

    store
        .record_audit(&NewAuditEntry {
            action_type: String::from(AUTH_AUDIT_REGISTER),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: ip_address.map(str::to_owned),
            success: true,
            details_json: json!({
                "username": user.username,
                "role": match user.role { UserRole::Admin => "admin", UserRole::User => "user" },
                "reactivated_existing_user": reactivated_existing_user
            })
            .to_string(),
        })
        .await?;

    Ok(RegistrationResult {
        user,
        auth_session,
        session_token,
        master_key,
    })
}

pub fn initialize_user_credentials(
    user: &mut UserRecord,
    password: &str,
    argon_policy: &ArgonPolicy,
) -> Result<MasterKey> {
    let password_hash = hash_password(password, argon_policy)?;
    let kek_salt = random_bytes(16);
    let master_key = generate_master_key();
    let wrapped_master_key =
        wrap_master_key(password, &kek_salt, argon_policy, master_key.as_slice())?;

    user.security.password_hash = Some(password_hash);
    user.security.password_argon_version = argon_policy.version;
    user.security.kek_salt_b64 =
        Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&kek_salt));
    user.security.encrypted_master_key_json = Some(
        serde_json::to_string(&wrapped_master_key)
            .context("failed to encode wrapped master key payload")?,
    );
    user.security.password_needs_reset = false;
    user.security.login_failures = 0;
    user.security.lockout_level = 0;
    user.security.locked_until_unix = None;
    user.updated_at_unix = Utc::now().timestamp();
    Ok(master_key)
}

async fn verify_primary_credentials(
    store: &MetaStore,
    settings: &SystemSettings,
    username: &str,
    password: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    login_method: Option<&str>,
) -> Result<VerifiedPrimaryLogin, LoginError> {
    let Some(mut user) = store
        .get_user_by_username(
            &normalize_username(username).map_err(|_| LoginError::InvalidCredentials)?,
        )
        .await
        .map_err(|_| LoginError::InvalidCredentials)?
    else {
        audit_login_failure(
            store,
            None,
            username,
            ip_address,
            user_agent,
            "user_not_found",
            login_method,
            None,
        )
        .await;
        return Err(LoginError::InvalidCredentials);
    };

    let now = Utc::now().timestamp();
    if let Some(locked_until) = user.security.locked_until_unix {
        if locked_until > now {
            audit_login_failure(
                store,
                Some(&user.id),
                &user.username,
                ip_address,
                user_agent,
                "account_locked",
                login_method,
                None,
            )
            .await;
            return Err(LoginError::LockedUntil(locked_until));
        }
    }

    let Some(stored_hash) = user.security.password_hash.clone() else {
        audit_login_failure(
            store,
            Some(&user.id),
            &user.username,
            ip_address,
            user_agent,
            "password_not_set",
            login_method,
            None,
        )
        .await;
        return Err(LoginError::InvalidCredentials);
    };

    match verify_password(
        password,
        &stored_hash,
        user.security.password_argon_version,
        &settings.argon_policy,
    )
    .map_err(|_| LoginError::InvalidCredentials)?
    {
        PasswordVerification::Invalid => {
            register_failed_login(
                store,
                settings,
                &mut user,
                ip_address,
                user_agent,
                login_method,
            )
            .await;
            return Err(LoginError::InvalidCredentials);
        }
        PasswordVerification::ValidNeedsRehash => {
            user.security.password_hash = Some(
                hash_password(password, &settings.argon_policy)
                    .map_err(|_| LoginError::InvalidCredentials)?,
            );
            user.security.password_argon_version = settings.argon_policy.version;
        }
        PasswordVerification::Valid => {}
    }

    let master_key = load_user_master_key(&user, password, &settings.argon_policy)
        .map_err(|_| LoginError::InvalidCredentials)?;

    Ok(VerifiedPrimaryLogin {
        requires_totp_setup: settings
            .totp_policy
            .applies_to(user.role == UserRole::Admin)
            && !user.security.totp_enabled,
        requires_password_reset: user.security.password_needs_reset,
        user,
        master_key,
    })
}

async fn complete_login(
    store: &MetaStore,
    settings: &SystemSettings,
    verified: VerifiedPrimaryLogin,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    login_method: &'static str,
    passkey_label: Option<&str>,
    recovery_codes_rotated: bool,
) -> Result<LoginResult, LoginError> {
    let mut user = verified.user;
    let session_token = generate_session_token();
    let auth_session = issue_session_token(
        store,
        settings,
        &user,
        &session_token,
        ip_address,
        user_agent,
    )
    .await
    .map_err(|_| LoginError::InvalidCredentials)?;

    reset_successful_login_state(store, &mut user, ip_address).await;
    audit_login_success(
        store,
        &user,
        ip_address,
        user_agent,
        verified.requires_totp_setup,
        login_method,
        passkey_label,
        recovery_codes_rotated,
    )
    .await;

    Ok(LoginResult {
        auth_session,
        session_token,
        master_key: verified.master_key,
        requires_totp_setup: verified.requires_totp_setup,
        requires_password_reset: verified.requires_password_reset,
        recovery_notice_codes: None,
    })
}

fn encode_passkey(
    credential_id: CredentialId<&[u8]>,
    transports: AuthTransports,
    static_state: StaticState<UncompressedPubKey<'_>>,
    dynamic_state: DynamicState,
) -> Result<String> {
    let static_state_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        static_state
            .encode()
            .expect("static state encoding is infallible"),
    );
    let dynamic_state_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        dynamic_state
            .encode()
            .expect("dynamic state encoding is infallible"),
    );
    let credential_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        credential_id
            .encode()
            .expect("credential id encoding is infallible"),
    );
    serde_json::to_string(&StoredPasskeyMaterial {
        version: STORED_PASSKEY_VERSION,
        credential_id_b64,
        transports: transports
            .encode()
            .expect("transport encoding is infallible"),
        static_state_b64,
        dynamic_state_b64,
    })
    .context("failed to encode stored passkey")
}

fn decode_passkey(record: &StoredPasskey) -> Result<DecodedStoredPasskey> {
    let material: StoredPasskeyMaterial =
        serde_json::from_str(&record.credential_json).context("failed to parse stored passkey")?;
    ensure!(
        material.version == STORED_PASSKEY_VERSION,
        "unsupported stored passkey version"
    );

    let static_state_b64 = material.static_state_b64.clone();
    let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(material.credential_id_b64)
        .context("failed to decode stored passkey credential id")?;
    let static_state_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(static_state_b64.as_str())
        .context("failed to decode stored passkey static state")?;
    let dynamic_state_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(material.dynamic_state_b64)
        .context("failed to decode stored passkey dynamic state")?;
    let dynamic_state_bytes: [u8; 7] = dynamic_state_bytes
        .try_into()
        .map_err(|_| anyhow!("stored passkey dynamic state has invalid length"))?;

    Ok(DecodedStoredPasskey {
        credential_id: CredentialId::decode(credential_id_bytes)
            .context("failed to decode stored passkey credential id")?,
        transports: AuthTransports::decode(material.transports)
            .context("failed to decode stored passkey transports")?,
        static_state_b64,
        static_state: StoredPasskeyStaticState::decode(static_state_bytes.as_slice())
            .context("failed to decode stored passkey static state")?,
        dynamic_state: DynamicState::decode(dynamic_state_bytes)
            .context("failed to decode stored passkey dynamic state")?,
    })
}

fn passkey_descriptor(decoded: &DecodedStoredPasskey) -> PublicKeyCredentialDescriptor<Vec<u8>> {
    PublicKeyCredentialDescriptor {
        id: decoded.credential_id.clone(),
        transports: decoded.transports,
    }
}

pub(crate) fn user_handle_for(user: &UserRecord) -> Result<UserHandle<Vec<u8>>> {
    UserHandle::try_from(user.id.as_bytes().to_vec()).context("failed to construct user handle")
}

pub(crate) fn passkey_descriptors(
    user: &UserRecord,
) -> Result<Vec<PublicKeyCredentialDescriptor<Vec<u8>>>> {
    user.security
        .passkeys
        .iter()
        .map(decode_passkey)
        .map(|result| result.map(|decoded| passkey_descriptor(&decoded)))
        .collect()
}

pub(crate) fn user_has_passkey_credential_id(
    user: &UserRecord,
    credential_id: &CredentialId<Vec<u8>>,
) -> Result<bool> {
    for record in &user.security.passkeys {
        if decode_passkey(record)?.credential_id == credential_id.clone() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn passkey_authentication_material(
    user: &UserRecord,
    credential_id: &CredentialId<Vec<u8>>,
) -> Result<Option<PasskeyAuthenticationMaterial>> {
    for record in &user.security.passkeys {
        let decoded = decode_passkey(record)?;
        if decoded.credential_id == credential_id.clone() {
            return Ok(Some(PasskeyAuthenticationMaterial {
                label: record.label.clone(),
                credential_id: decoded.credential_id,
                static_state: decoded.static_state,
                dynamic_state: decoded.dynamic_state,
            }));
        }
    }
    Ok(None)
}

fn hash_shared_recovery_codes(recovery_codes: &[SharedSensitiveString]) -> Result<Vec<String>> {
    let mut recovery_code_hashes = Vec::with_capacity(recovery_codes.len());
    for code in recovery_codes {
        recovery_code_hashes.push(hash_recovery_code(
            code.as_ref().as_str(),
            &ArgonPolicy::minimum(),
        )?);
    }
    Ok(recovery_code_hashes)
}

pub async fn rotate_recovery_codes(
    store: &MetaStore,
    user: &UserRecord,
    reason: &str,
) -> Result<Vec<SharedSensitiveString>> {
    let recovery_codes = generate_recovery_codes(RECOVERY_CODE_COUNT)
        .into_iter()
        .map(into_sensitive_string)
        .map(share_sensitive_string)
        .collect::<Vec<_>>();
    let recovery_code_hashes = hash_shared_recovery_codes(&recovery_codes)?;
    store
        .replace_recovery_codes(&user.id, &recovery_code_hashes)
        .await?;
    store
        .record_audit(&NewAuditEntry {
            action_type: String::from(AUTH_AUDIT_RECOVERY_CODES_ROTATED),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: None,
            success: true,
            details_json: json!({
                "username": user.username,
                "reason": reason,
                "recovery_codes": recovery_codes.len(),
            })
            .to_string(),
        })
        .await?;
    Ok(recovery_codes)
}

pub async fn add_passkey_to_user(
    store: &MetaStore,
    user: &mut UserRecord,
    label: &str,
    credential_id: CredentialId<&[u8]>,
    transports: AuthTransports,
    static_state: StaticState<UncompressedPubKey<'_>>,
    dynamic_state: DynamicState,
) -> Result<()> {
    let normalized_label = label.trim();
    ensure!(
        !normalized_label.is_empty(),
        "passkey label cannot be empty"
    );
    let encoded = encode_passkey(credential_id, transports, static_state, dynamic_state)?;
    let passkey_id = Uuid::new_v4().to_string();
    user.security.passkeys.push(StoredPasskey {
        id: passkey_id,
        label: normalized_label.to_owned(),
        credential_json: encoded,
        created_at_unix: Utc::now().timestamp(),
        last_used_at_unix: None,
    });
    user.updated_at_unix = Utc::now().timestamp();
    store.save_user(user).await?;
    store
        .record_audit(&NewAuditEntry {
            action_type: String::from(AUTH_AUDIT_PASSKEY_ADDED),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: None,
            success: true,
            details_json: json!({
                "username": user.username,
                "label": normalized_label,
                "passkey_count": user.security.passkeys.len(),
            })
            .to_string(),
        })
        .await?;
    Ok(())
}

pub async fn remove_passkey_from_user(
    store: &MetaStore,
    user: &mut UserRecord,
    passkey_id: &str,
) -> Result<bool> {
    let original_len = user.security.passkeys.len();
    let removed = user
        .security
        .passkeys
        .iter()
        .find(|record| record.id == passkey_id)
        .map(|record| record.label.clone());
    user.security
        .passkeys
        .retain(|record| record.id != passkey_id);
    if user.security.passkeys.len() == original_len {
        return Ok(false);
    }
    user.updated_at_unix = Utc::now().timestamp();
    store.save_user(user).await?;
    store
        .record_audit(&NewAuditEntry {
            action_type: String::from(AUTH_AUDIT_PASSKEY_REMOVED),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: None,
            success: true,
            details_json: json!({
                "username": user.username,
                "label": removed,
                "passkey_count": user.security.passkeys.len(),
            })
            .to_string(),
        })
        .await?;
    Ok(true)
}

pub async fn passkey_registered_to_other_user(
    store: &MetaStore,
    current_user_id: &str,
    credential_id: &CredentialId<Vec<u8>>,
) -> Result<bool> {
    let users = store.list_users().await?;
    for user in users {
        if user.id == current_user_id {
            continue;
        }
        if user_has_passkey_credential_id(&user, credential_id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn update_user_passkey_usage(
    user: &mut UserRecord,
    credential_id: &CredentialId<Vec<u8>>,
    dynamic_state: DynamicState,
) -> Result<Option<String>> {
    for record in &mut user.security.passkeys {
        let decoded = decode_passkey(record)?;
        if decoded.credential_id == credential_id.clone() {
            let dynamic_state_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                dynamic_state
                    .encode()
                    .expect("dynamic state encoding is infallible"),
            );
            record.credential_json = serde_json::to_string(&StoredPasskeyMaterial {
                version: STORED_PASSKEY_VERSION,
                credential_id_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                    decoded
                        .credential_id
                        .encode()
                        .expect("credential id encoding is infallible"),
                ),
                transports: decoded
                    .transports
                    .encode()
                    .expect("transport encoding is infallible"),
                static_state_b64: decoded.static_state_b64,
                dynamic_state_b64,
            })
            .context("failed to encode updated stored passkey")?;
            record.last_used_at_unix = Some(Utc::now().timestamp());
            return Ok(Some(record.label.clone()));
        }
    }
    Ok(None)
}

pub async fn authenticate_user(
    store: &MetaStore,
    settings: &SystemSettings,
    username: &str,
    password: &str,
    mfa_code: Option<&str>,
    recovery_code: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<LoginResult, LoginError> {
    let attempted_login_method = if recovery_code.is_some_and(|value| !value.trim().is_empty()) {
        LOGIN_METHOD_PASSWORD_RECOVERY
    } else if mfa_code.is_some_and(|value| !value.trim().is_empty()) {
        LOGIN_METHOD_PASSWORD_TOTP
    } else {
        LOGIN_METHOD_PASSWORD_ONLY
    };
    let verified = verify_primary_credentials(
        store,
        settings,
        username,
        password,
        ip_address,
        user_agent,
        Some(attempted_login_method),
    )
    .await?;
    let now = Utc::now().timestamp();
    if verified.user.security.totp_enabled {
        let secret = decrypt_user_totp_secret(&verified.user, verified.master_key.as_slice())
            .map_err(|_| LoginError::InvalidSecondFactor)?;
        let recent_steps = store
            .list_recent_totp_steps(&verified.user.id, now.div_euclid(TOTP_PERIOD_SECONDS) - 2)
            .await
            .map_err(|_| LoginError::InvalidSecondFactor)?;
        let used_steps = recent_steps.into_iter().collect::<HashSet<_>>();
        let mut recovery_notice_codes = None;
        let mut login_method = LOGIN_METHOD_PASSWORD_ONLY;

        if let Some(code) = mfa_code.filter(|value| !value.trim().is_empty()) {
            match verify_totp(secret.as_str(), code, now, 1, &used_steps)
                .map_err(|_| LoginError::InvalidSecondFactor)?
            {
                TotpVerification::Valid { matched_step } => {
                    store
                        .mark_totp_step_used(&verified.user.id, matched_step)
                        .await
                        .map_err(|_| LoginError::InvalidSecondFactor)?;
                    store
                        .prune_used_totp_steps(now.div_euclid(TOTP_PERIOD_SECONDS) - 8)
                        .await
                        .ok();
                    login_method = LOGIN_METHOD_PASSWORD_TOTP;
                }
                TotpVerification::Replay | TotpVerification::Invalid => {}
            }
        }

        if login_method == LOGIN_METHOD_PASSWORD_ONLY {
            if let Some(candidate) = recovery_code.filter(|value| !value.trim().is_empty()) {
                let recovery_codes = store
                    .list_active_recovery_code_hashes(&verified.user.id)
                    .await
                    .map_err(|_| LoginError::InvalidSecondFactor)?;
                for (code_id, code_hash) in recovery_codes {
                    if verify_recovery_code(candidate, &code_hash)
                        .map_err(|_| LoginError::InvalidSecondFactor)?
                    {
                        store
                            .mark_recovery_code_used(&code_id)
                            .await
                            .map_err(|_| LoginError::InvalidSecondFactor)?;
                        recovery_notice_codes = Some(
                            rotate_recovery_codes(store, &verified.user, "recovery_code_login")
                                .await
                                .map_err(|_| LoginError::InvalidSecondFactor)?,
                        );
                        login_method = LOGIN_METHOD_PASSWORD_RECOVERY;
                        break;
                    }
                }
            }
        }

        if login_method == LOGIN_METHOD_PASSWORD_ONLY {
            audit_login_failure(
                store,
                Some(&verified.user.id),
                &verified.user.username,
                ip_address,
                user_agent,
                "second_factor_required",
                Some(attempted_login_method),
                None,
            )
            .await;
            return Err(if mfa_code.is_some() || recovery_code.is_some() {
                LoginError::InvalidSecondFactor
            } else {
                LoginError::MissingSecondFactor
            });
        }

        let mut login_result = complete_login(
            store,
            settings,
            verified,
            ip_address,
            user_agent,
            login_method,
            None,
            recovery_notice_codes.is_some(),
        )
        .await?;
        login_result.recovery_notice_codes = recovery_notice_codes;
        return Ok(login_result);
    }

    complete_login(
        store,
        settings,
        verified,
        ip_address,
        user_agent,
        LOGIN_METHOD_PASSWORD_ONLY,
        None,
        false,
    )
    .await
}

pub async fn begin_passkey_login(
    store: &MetaStore,
    settings: &SystemSettings,
    username: &str,
    password: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<PasskeyLoginChallenge, LoginError> {
    let verified = verify_primary_credentials(
        store,
        settings,
        username,
        password,
        ip_address,
        user_agent,
        Some(LOGIN_METHOD_PASSWORD_PASSKEY),
    )
    .await?;
    if passkey_descriptors(&verified.user)
        .map_err(|_| LoginError::InvalidSecondFactor)?
        .is_empty()
    {
        audit_login_failure(
            store,
            Some(&verified.user.id),
            &verified.user.username,
            ip_address,
            user_agent,
            "passkey_not_configured",
            Some(LOGIN_METHOD_PASSWORD_PASSKEY),
            None,
        )
        .await;
        return Err(LoginError::MissingSecondFactor);
    }

    Ok(PasskeyLoginChallenge {
        user: verified.user,
        master_key: verified.master_key,
        requires_totp_setup: verified.requires_totp_setup,
        requires_password_reset: verified.requires_password_reset,
    })
}

pub async fn authenticate_user_with_passkey(
    store: &MetaStore,
    settings: &SystemSettings,
    user: UserRecord,
    master_key: MasterKey,
    requires_totp_setup: bool,
    requires_password_reset: bool,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    passkey_label: Option<&str>,
) -> Result<LoginResult, LoginError> {
    complete_login(
        store,
        settings,
        VerifiedPrimaryLogin {
            user,
            master_key,
            requires_totp_setup,
            requires_password_reset,
        },
        ip_address,
        user_agent,
        LOGIN_METHOD_PASSWORD_PASSKEY,
        passkey_label,
        false,
    )
    .await
}

pub async fn resolve_authenticated_session(
    store: &MetaStore,
    settings: &SystemSettings,
    headers: &HeaderMap,
) -> Result<Option<AuthenticatedSession>> {
    let Some(token) = find_cookie(headers, AUTH_COOKIE_NAME) else {
        return Ok(None);
    };
    let token_hash = hash_session_token(token);
    let Some(auth_session) = store.get_auth_session_by_token_hash(&token_hash).await? else {
        return Ok(None);
    };

    let now = Utc::now().timestamp();
    if auth_session.revoked_at_unix.is_some() || auth_session.expires_at_unix <= now {
        return Ok(None);
    }
    if let Some(idle_timeout) = auth_session.idle_timeout_minutes {
        if idle_timeout != 0 {
            let idle_cutoff = auth_session.last_seen_at_unix + i64::from(idle_timeout) * 60;
            if idle_cutoff <= now {
                return Ok(None);
            }
        }
    }

    let Some(user) = store.get_user_by_id(&auth_session.user_id).await? else {
        return Ok(None);
    };

    store
        .touch_auth_session(&auth_session.id, now, extract_client_ip(headers).as_deref())
        .await
        .ok();
    let recovery_codes_remaining = store
        .count_active_recovery_codes(&user.id)
        .await
        .unwrap_or(0);
    let requires_totp_setup = settings
        .totp_policy
        .applies_to(user.role == UserRole::Admin)
        && !user.security.totp_enabled;
    let requires_password_reset = user.security.password_needs_reset;

    Ok(Some(AuthenticatedSession {
        user,
        auth_session,
        recovery_codes_remaining,
        requires_totp_setup,
        requires_password_reset,
    }))
}

pub async fn change_password(
    store: &MetaStore,
    settings: &SystemSettings,
    user: &mut UserRecord,
    current_password: &str,
    new_password: &str,
) -> Result<MasterKey> {
    let strength = evaluate_password_strength(
        new_password,
        &settings.password_strength_rules,
        user.role == UserRole::Admin,
    );
    ensure!(strength.valid, strength.reasons.join("; "));

    let master_key = load_user_master_key(user, current_password, &settings.argon_policy)?;
    let new_hash = hash_password(new_password, &settings.argon_policy)?;
    let new_salt = random_bytes(16);
    let wrapped_master_key = wrap_master_key(
        new_password,
        &new_salt,
        &settings.argon_policy,
        master_key.as_slice(),
    )?;

    user.security.password_hash = Some(new_hash);
    user.security.password_argon_version = settings.argon_policy.version;
    user.security.kek_salt_b64 =
        Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&new_salt));
    user.security.encrypted_master_key_json =
        Some(serde_json::to_string(&wrapped_master_key).context("failed to encode wrapped key")?);
    user.security.password_needs_reset = false;
    user.updated_at_unix = Utc::now().timestamp();
    store.save_user(user).await?;
    store
        .record_audit(&NewAuditEntry {
            action_type: String::from(AUTH_AUDIT_PASSWORD_CHANGED),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: None,
            success: true,
            details_json: json!({ "username": user.username }).to_string(),
        })
        .await?;

    Ok(master_key)
}

pub async fn save_totp_setup(
    store: &MetaStore,
    user: &mut UserRecord,
    master_key: &[u8],
    secret: &str,
    recovery_codes: &[SharedSensitiveString],
) -> Result<()> {
    let encrypted_secret = encrypt_bytes(master_key, secret.as_bytes())?;
    let recovery_code_hashes = hash_shared_recovery_codes(recovery_codes)?;

    user.security.totp_secret_json =
        Some(serde_json::to_string(&encrypted_secret).context("failed to encode totp secret")?);
    user.security.totp_enabled = true;
    user.updated_at_unix = Utc::now().timestamp();
    store.save_user(user).await?;
    store
        .replace_recovery_codes(&user.id, &recovery_code_hashes)
        .await?;
    store
        .record_audit(&NewAuditEntry {
            action_type: String::from(AUTH_AUDIT_TOTP_UPDATED),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: None,
            success: true,
            details_json: json!({
                "username": user.username,
                "recovery_codes": recovery_codes.len()
            })
            .to_string(),
        })
        .await?;
    Ok(())
}

pub fn build_totp_setup_material(username: &str) -> TotpSetupMaterial {
    let secret = share_sensitive_string(into_sensitive_string(generate_totp_secret()));
    let recovery_codes = generate_recovery_codes(RECOVERY_CODE_COUNT)
        .into_iter()
        .map(into_sensitive_string)
        .map(share_sensitive_string)
        .collect();
    let otp_auth_uri = share_sensitive_string(into_sensitive_string(build_totp_uri(
        "Hanagram Web",
        username,
        secret.as_ref().as_str(),
    )));

    TotpSetupMaterial {
        secret,
        otp_auth_uri,
        recovery_codes,
    }
}

pub fn build_auth_cookie(token: &str, max_age_seconds: i64, secure: bool) -> String {
    let secure_fragment = if secure { "; Secure" } else { "" };
    format!(
        "{AUTH_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_seconds}{secure_fragment}"
    )
}

pub fn clear_auth_cookie(secure: bool) -> String {
    let secure_fragment = if secure { "; Secure" } else { "" };
    format!("{AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure_fragment}")
}

pub fn build_language_cookie(language: Language, secure: bool) -> String {
    let secure_fragment = if secure { "; Secure" } else { "" };
    format!(
        "{LANGUAGE_COOKIE_NAME}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000{secure_fragment}",
        language.code()
    )
}

pub fn effective_auth_cookie_secure(settings: &SystemSettings, headers: &HeaderMap) -> bool {
    settings.cookie_secure && request_uses_https(headers)
}

pub fn request_uses_https(headers: &HeaderMap) -> bool {
    if header_has_https_value(headers, "x-forwarded-proto") {
        return true;
    }
    if header_has_https_value(headers, "x-forwarded-ssl") {
        return true;
    }
    if header_has_https_value(headers, "front-end-https") {
        return true;
    }

    if let Some(value) = headers
        .get("forwarded")
        .and_then(|value| value.to_str().ok())
    {
        for entry in value.split(',') {
            for segment in entry.split(';') {
                let Some((key, raw_value)) = segment.trim().split_once('=') else {
                    continue;
                };
                if key.trim().eq_ignore_ascii_case("proto")
                    && raw_value
                        .trim()
                        .trim_matches('"')
                        .eq_ignore_ascii_case("https")
                {
                    return true;
                }
            }
        }
    }

    header_scheme_is_https(headers, header::ORIGIN)
        || header_scheme_is_https(headers, header::REFERER)
}

fn header_has_https_value(headers: &HeaderMap, header_name: &str) -> bool {
    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.split(',').any(|segment| {
                let normalized = segment.trim();
                normalized.eq_ignore_ascii_case("https") || normalized.eq_ignore_ascii_case("on")
            })
        })
        .unwrap_or(false)
}

fn header_scheme_is_https(headers: &HeaderMap, header_name: header::HeaderName) -> bool {
    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("https://")
        })
        .unwrap_or(false)
}

pub fn normalize_username(raw: &str) -> Result<String> {
    let normalized = raw
        .trim()
        .chars()
        .filter_map(|ch| {
            if ch.is_ascii_alphanumeric() {
                Some(ch.to_ascii_lowercase())
            } else if matches!(ch, '-' | '_' | '.') {
                Some(ch)
            } else {
                None
            }
        })
        .collect::<String>();

    ensure!(!normalized.is_empty(), "username cannot be empty");
    ensure!(
        normalized.len() >= 3,
        "username must be at least 3 characters"
    );
    Ok(normalized)
}

pub fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    for header_name in ["cf-connecting-ip", "x-forwarded-for", "x-real-ip"] {
        let Some(value) = headers.get(header_name) else {
            continue;
        };
        let Ok(raw) = value.to_str() else {
            continue;
        };
        let candidate = raw
            .split(',')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(candidate) = candidate {
            return Some(candidate.to_owned());
        }
    }

    None
}

pub fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub fn find_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;

    cookies.split(';').find_map(|cookie| {
        let (cookie_name, cookie_value) = cookie.trim().split_once('=')?;
        if cookie_name == name {
            Some(cookie_value)
        } else {
            None
        }
    })
}

pub fn load_user_master_key(
    user: &UserRecord,
    password: &str,
    argon_policy: &ArgonPolicy,
) -> Result<MasterKey> {
    let wrapped_master_key = user
        .security
        .encrypted_master_key_json
        .as_deref()
        .context("user is missing an encrypted master key")?;
    let salt = user
        .security
        .kek_salt_b64
        .as_deref()
        .context("user is missing a kek salt")?;
    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(salt)
        .context("failed to decode kek salt")?;
    let wrapped_master_key = serde_json::from_str::<EncryptedBlob>(wrapped_master_key)
        .context("failed to parse wrapped master key")?;

    unwrap_master_key(password, &salt, argon_policy, &wrapped_master_key)
}

pub fn decrypt_user_totp_secret(user: &UserRecord, master_key: &[u8]) -> Result<SensitiveString> {
    let payload = user
        .security
        .totp_secret_json
        .as_deref()
        .context("user does not have an encrypted totp secret")?;
    let payload = serde_json::from_str::<EncryptedBlob>(payload)
        .context("failed to parse totp secret payload")?;
    let plaintext = decrypt_bytes(master_key, &payload)?;
    let secret = String::from_utf8(plaintext.as_slice().to_vec())
        .map_err(|error| anyhow!("invalid utf-8 totp secret: {error}"))?;
    Ok(into_sensitive_string(secret))
}

async fn issue_session_token(
    store: &MetaStore,
    settings: &SystemSettings,
    user: &UserRecord,
    token: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuthSessionRecord> {
    let expires_at = Utc::now().timestamp() + i64::from(settings.session_absolute_ttl_hours) * 3600;
    let idle_timeout_minutes = effective_idle_timeout_minutes(user, settings);
    store
        .create_auth_session(
            &user.id,
            &hash_session_token(token),
            ip_address,
            user_agent,
            expires_at,
            idle_timeout_minutes,
        )
        .await
}

fn effective_idle_timeout_minutes(user: &UserRecord, settings: &SystemSettings) -> Option<u32> {
    match (
        user.security.preferred_idle_timeout_minutes,
        settings.max_idle_timeout_minutes,
    ) {
        (Some(0), None) => Some(0),
        (Some(0), Some(maximum)) => Some(maximum),
        (Some(minutes), Some(maximum)) => Some(minutes.min(maximum)),
        (Some(minutes), None) => Some(minutes),
        (None, system_default) => system_default,
    }
}

async fn register_failed_login(
    store: &MetaStore,
    settings: &SystemSettings,
    user: &mut UserRecord,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    login_method: Option<&str>,
) {
    user.security.login_failures = user.security.login_failures.saturating_add(1);
    let delay = hanagram_web::security::next_lockout_delay(
        user.security.login_failures,
        &settings.lockout_policy,
    );
    user.security.lockout_level = user.security.login_failures;
    user.security.locked_until_unix = if delay > 0 {
        Some(Utc::now().timestamp() + i64::try_from(delay).unwrap_or(i64::MAX))
    } else {
        None
    };
    user.updated_at_unix = Utc::now().timestamp();
    let _ = store.save_user(user).await;
    audit_login_failure(
        store,
        Some(&user.id),
        &user.username,
        ip_address,
        user_agent,
        "invalid_password",
        login_method,
        None,
    )
    .await;
}

async fn reset_successful_login_state(
    store: &MetaStore,
    user: &mut UserRecord,
    ip_address: Option<&str>,
) {
    user.security.login_failures = 0;
    user.security.lockout_level = 0;
    user.security.locked_until_unix = None;
    if let Some(ip_address) = ip_address {
        user.security.last_login_ip = Some(ip_address.to_owned());
    }
    user.updated_at_unix = Utc::now().timestamp();
    let _ = store.save_user(user).await;
}

async fn audit_login_failure(
    store: &MetaStore,
    user_id: Option<&str>,
    username: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    reason: &str,
    login_method: Option<&str>,
    passkey_label: Option<&str>,
) {
    let _ = store
        .record_audit(&NewAuditEntry {
            action_type: String::from(AUTH_AUDIT_LOGIN_FAILURE),
            actor_user_id: user_id.map(str::to_owned),
            subject_user_id: user_id.map(str::to_owned),
            ip_address: ip_address.map(str::to_owned),
            success: false,
            details_json: json!({
                "username": username,
                "reason": reason,
                "login_method": login_method,
                "passkey_label": passkey_label,
                "user_agent": user_agent
            })
            .to_string(),
        })
        .await;
}

pub async fn record_login_failure(
    store: &MetaStore,
    user_id: Option<&str>,
    username: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    reason: &str,
    login_method: Option<&str>,
    passkey_label: Option<&str>,
) {
    audit_login_failure(
        store,
        user_id,
        username,
        ip_address,
        user_agent,
        reason,
        login_method,
        passkey_label,
    )
    .await;
}

async fn audit_login_success(
    store: &MetaStore,
    user: &UserRecord,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    requires_totp_setup: bool,
    login_method: &str,
    passkey_label: Option<&str>,
    recovery_codes_rotated: bool,
) {
    let details = json!({
        "username": user.username,
        "login_method": login_method,
        "passkey_label": passkey_label,
        "requires_totp_setup": requires_totp_setup,
        "new_ip": ip_address.is_some() && user.security.last_login_ip.as_deref() != ip_address,
        "recovery_codes_rotated": recovery_codes_rotated,
        "user_agent": user_agent,
    });
    let _ = store
        .record_audit(&NewAuditEntry {
            action_type: String::from(AUTH_AUDIT_LOGIN_SUCCESS),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: ip_address.map(str::to_owned),
            success: true,
            details_json: details.to_string(),
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hanagram_web::store::{SystemSettings, UserRole};

    #[tokio::test]
    async fn register_user_reactivates_existing_passwordless_account() {
        let store = MetaStore::open_memory()
            .await
            .expect("metadata store should open");
        let settings = SystemSettings::default();

        let original_user = UserRecord::new("alice", UserRole::Admin);
        let original_user_id = original_user.id.clone();
        store
            .save_user(&original_user)
            .await
            .expect("placeholder user should save");

        let result = register_user(
            &store,
            &settings,
            "alice",
            "ResetPassword!42",
            Some("127.0.0.1"),
            Some("test-agent"),
        )
        .await
        .expect("registration should succeed");

        assert_eq!(result.user.id, original_user_id);
        assert_eq!(result.user.role, UserRole::Admin);
        assert!(result.user.security.password_hash.is_some());
        assert!(result.user.security.encrypted_master_key_json.is_some());
    }

    #[test]
    fn effective_idle_timeout_keeps_never_without_cap() {
        let settings = SystemSettings::default();
        let mut user = UserRecord::new("idle-user", UserRole::User);
        user.security.preferred_idle_timeout_minutes = Some(0);

        assert_eq!(effective_idle_timeout_minutes(&user, &settings), Some(0));
    }

    #[test]
    fn effective_idle_timeout_clamps_to_system_cap() {
        let mut settings = SystemSettings::default();
        settings.max_idle_timeout_minutes = Some(60);
        let mut user = UserRecord::new("idle-user", UserRole::User);
        user.security.preferred_idle_timeout_minutes = Some(480);

        assert_eq!(effective_idle_timeout_minutes(&user, &settings), Some(60));
    }

    #[test]
    fn find_cookie_extracts_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            axum::http::HeaderValue::from_static(
                "theme=light; hanagram_auth=session-token; other=value",
            ),
        );

        assert_eq!(
            find_cookie(&headers, AUTH_COOKIE_NAME),
            Some("session-token")
        );
    }

    #[test]
    fn find_cookie_rejects_missing_cookie() {
        let mut headers = HeaderMap::new();

        assert_eq!(find_cookie(&headers, AUTH_COOKIE_NAME), None);

        headers.insert(
            header::COOKIE,
            axum::http::HeaderValue::from_static("other=value"),
        );

        assert_eq!(find_cookie(&headers, AUTH_COOKIE_NAME), None);
    }

    #[test]
    fn effective_auth_cookie_secure_disables_secure_flag_for_plain_http() {
        let settings = SystemSettings::default();
        let headers = HeaderMap::new();

        assert!(!effective_auth_cookie_secure(&settings, &headers));
    }

    #[test]
    fn effective_auth_cookie_secure_respects_forwarded_https() {
        let settings = SystemSettings::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-proto",
            axum::http::HeaderValue::from_static("https"),
        );

        assert!(effective_auth_cookie_secure(&settings, &headers));
    }
}
