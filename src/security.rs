// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::collections::HashSet;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub const TOTP_PERIOD_SECONDS: i64 = 30;
pub const TOTP_DIGITS: u32 = 6;
pub const RECOVERY_CODE_COUNT: usize = 5;
const AES_GCM_NONCE_BYTES: usize = 12;
const MASTER_KEY_BYTES: usize = 32;
const DEFAULT_PASSWORD_MIN_LENGTH: usize = 12;
const RECOVERY_CODE_SEGMENTS: usize = 3;
const RECOVERY_CODE_SEGMENT_LENGTH: usize = 4;
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPolicy {
    AlwaysPublic,
    AdminOnly,
    AdminSelectable,
}

impl Default for RegistrationPolicy {
    fn default() -> Self {
        Self::AdminOnly
    }
}

impl RegistrationPolicy {
    pub fn allows_public_registration(self, admin_toggle_open: bool) -> bool {
        match self {
            Self::AlwaysPublic => true,
            Self::AdminOnly => false,
            Self::AdminSelectable => admin_toggle_open,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    AdminExempt,
    Disabled,
    AllUsers,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        Self::AllUsers
    }
}

impl EnforcementMode {
    pub fn applies_to(self, is_admin: bool) -> bool {
        match self {
            Self::AdminExempt => !is_admin,
            Self::Disabled => false,
            Self::AllUsers => true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArgonPolicy {
    pub version: i64,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl Default for ArgonPolicy {
    fn default() -> Self {
        Self::minimum()
    }
}

impl ArgonPolicy {
    pub fn minimum() -> Self {
        Self {
            version: 1,
            memory_kib: 64 * 1024,
            iterations: 3,
            lanes: 2,
        }
    }

    pub fn raised(self, version: i64, memory_kib: u32, iterations: u32, lanes: u32) -> Self {
        Self {
            version: version.max(self.version),
            memory_kib: memory_kib.max(self.memory_kib),
            iterations: iterations.max(self.iterations),
            lanes: lanes.max(self.lanes),
        }
    }

    fn params(&self) -> Result<Params> {
        Params::new(
            self.memory_kib,
            self.iterations,
            self.lanes,
            Some(MASTER_KEY_BYTES),
        )
        .map_err(|error| anyhow!("invalid argon2 policy: {error}"))
    }

    fn argon2(&self) -> Result<Argon2<'static>> {
        Ok(Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            self.params()?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PasswordStrengthRules {
    pub mode: EnforcementMode,
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_number: bool,
    pub require_symbol: bool,
}

impl Default for PasswordStrengthRules {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::AllUsers,
            min_length: DEFAULT_PASSWORD_MIN_LENGTH,
            require_uppercase: true,
            require_lowercase: true,
            require_number: true,
            require_symbol: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PasswordStrengthOutcome {
    pub valid: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LockoutPolicy {
    pub threshold: u32,
    pub base_delay_seconds: u64,
    pub max_delay_seconds: u64,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            threshold: 5,
            base_delay_seconds: 5,
            max_delay_seconds: 300,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedBlob {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordVerification {
    Valid,
    ValidNeedsRehash,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpVerification {
    Valid { matched_step: i64 },
    Invalid,
    Replay,
}

pub fn hash_password(password: &str, policy: &ArgonPolicy) -> Result<String> {
    ensure!(!password.is_empty(), "password cannot be empty");
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = policy.argon2()?;

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow!("password hashing failed: {error}"))
}

pub fn verify_password(
    password: &str,
    phc_hash: &str,
    stored_version: i64,
    current_policy: &ArgonPolicy,
) -> Result<PasswordVerification> {
    let parsed = PasswordHash::new(phc_hash).context("stored password hash is invalid")?;
    let verified = Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();

    if !verified {
        return Ok(PasswordVerification::Invalid);
    }

    if stored_version < current_policy.version {
        Ok(PasswordVerification::ValidNeedsRehash)
    } else {
        Ok(PasswordVerification::Valid)
    }
}

pub fn evaluate_password_strength(
    password: &str,
    rules: &PasswordStrengthRules,
    is_admin: bool,
) -> PasswordStrengthOutcome {
    if !rules.mode.applies_to(is_admin) {
        return PasswordStrengthOutcome {
            valid: true,
            reasons: Vec::new(),
        };
    }

    let mut reasons = Vec::new();

    if password.chars().count() < rules.min_length {
        reasons.push(format!("password must be at least {} characters", rules.min_length));
    }
    if rules.require_uppercase && !password.chars().any(|ch| ch.is_ascii_uppercase()) {
        reasons.push(String::from("password must contain an uppercase letter"));
    }
    if rules.require_lowercase && !password.chars().any(|ch| ch.is_ascii_lowercase()) {
        reasons.push(String::from("password must contain a lowercase letter"));
    }
    if rules.require_number && !password.chars().any(|ch| ch.is_ascii_digit()) {
        reasons.push(String::from("password must contain a number"));
    }
    if rules.require_symbol && !password.chars().any(|ch| !ch.is_ascii_alphanumeric()) {
        reasons.push(String::from("password must contain a symbol"));
    }

    PasswordStrengthOutcome {
        valid: reasons.is_empty(),
        reasons,
    }
}

pub fn next_lockout_delay(failure_count: u32, policy: &LockoutPolicy) -> u64 {
    if failure_count < policy.threshold {
        return 0;
    }

    let exponent = failure_count.saturating_sub(policy.threshold);
    let multiplier = 1_u64.checked_shl(exponent.min(31)).unwrap_or(u64::MAX);
    policy
        .base_delay_seconds
        .saturating_mul(multiplier)
        .min(policy.max_delay_seconds)
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn generate_master_key() -> [u8; MASTER_KEY_BYTES] {
    let mut key = [0_u8; MASTER_KEY_BYTES];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn derive_kek(password: &str, salt: &[u8], policy: &ArgonPolicy) -> Result<[u8; 32]> {
    ensure!(!salt.is_empty(), "kek salt cannot be empty");
    let argon2 = policy.argon2()?;
    let mut output = [0_u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|error| anyhow!("argon2 key derivation failed: {error}"))?;
    Ok(output)
}

pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|error| anyhow!("invalid aes key: {error}"))?;
    let nonce = random_bytes(AES_GCM_NONCE_BYTES);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|error| anyhow!("aes-gcm encryption failed: {error}"))?;

    Ok(EncryptedBlob {
        nonce_b64: encode_base64_urlsafe(&nonce),
        ciphertext_b64: encode_base64_urlsafe(&ciphertext),
    })
}

pub fn decrypt_bytes(key: &[u8; 32], blob: &EncryptedBlob) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|error| anyhow!("invalid aes key: {error}"))?;
    let nonce = decode_base64_urlsafe(&blob.nonce_b64)?;
    ensure!(
        nonce.len() == AES_GCM_NONCE_BYTES,
        "invalid aes-gcm nonce length {}",
        nonce.len()
    );
    let ciphertext = decode_base64_urlsafe(&blob.ciphertext_b64)?;

    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|error| anyhow!("aes-gcm decryption failed: {error}"))
}

pub fn wrap_master_key(
    password: &str,
    salt: &[u8],
    policy: &ArgonPolicy,
    master_key: &[u8; 32],
) -> Result<EncryptedBlob> {
    let kek = derive_kek(password, salt, policy)?;
    encrypt_bytes(&kek, master_key)
}

pub fn unwrap_master_key(
    password: &str,
    salt: &[u8],
    policy: &ArgonPolicy,
    wrapped_key: &EncryptedBlob,
) -> Result<[u8; 32]> {
    let kek = derive_kek(password, salt, policy)?;
    let plaintext = decrypt_bytes(&kek, wrapped_key)?;
    let master_key: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow!("wrapped master key had an unexpected length"))?;
    Ok(master_key)
}

pub fn generate_totp_secret() -> String {
    BASE32_NOPAD.encode(&random_bytes(20))
}

pub fn build_totp_uri(issuer: &str, account_name: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&period={}&digits={}",
        percent_encode_component(issuer),
        percent_encode_component(account_name),
        secret,
        percent_encode_component(issuer),
        TOTP_PERIOD_SECONDS,
        TOTP_DIGITS
    )
}

pub fn totp_code_at(secret: &str, timestamp: i64) -> Result<String> {
    let step = timestamp.div_euclid(TOTP_PERIOD_SECONDS);
    totp_code_for_step(secret, step)
}

pub fn verify_totp(
    secret: &str,
    code: &str,
    timestamp: i64,
    allowed_drift_steps: i64,
    used_steps: &HashSet<i64>,
) -> Result<TotpVerification> {
    let normalized = normalize_numeric_code(code)?;
    let current_step = timestamp.div_euclid(TOTP_PERIOD_SECONDS);

    for offset in -allowed_drift_steps..=allowed_drift_steps {
        let candidate_step = current_step + offset;
        if totp_code_for_step(secret, candidate_step)? == normalized {
            if used_steps.contains(&candidate_step) {
                return Ok(TotpVerification::Replay);
            }

            return Ok(TotpVerification::Valid {
                matched_step: candidate_step,
            });
        }
    }

    Ok(TotpVerification::Invalid)
}

pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let raw = (0..(RECOVERY_CODE_SEGMENTS * RECOVERY_CODE_SEGMENT_LENGTH))
                .map(|_| {
                    let index = (OsRng.next_u32() as usize) % RECOVERY_ALPHABET.len();
                    RECOVERY_ALPHABET[index] as char
                })
                .collect::<String>();

            (0..RECOVERY_CODE_SEGMENTS)
                .map(|segment| {
                    let start = segment * RECOVERY_CODE_SEGMENT_LENGTH;
                    let end = start + RECOVERY_CODE_SEGMENT_LENGTH;
                    raw[start..end].to_string()
                })
                .collect::<Vec<_>>()
                .join("-")
        })
        .collect()
}

pub fn normalize_recovery_code(raw: &str) -> String {
    raw.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

pub fn hash_recovery_code(code: &str, policy: &ArgonPolicy) -> Result<String> {
    let normalized = normalize_recovery_code(code);
    ensure!(!normalized.is_empty(), "recovery code cannot be empty");
    hash_password(&normalized, policy)
}

pub fn verify_recovery_code(code: &str, phc_hash: &str) -> Result<bool> {
    let normalized = normalize_recovery_code(code);
    ensure!(!normalized.is_empty(), "recovery code cannot be empty");

    let parsed = PasswordHash::new(phc_hash).context("stored recovery code hash is invalid")?;
    Ok(Argon2::default()
        .verify_password(normalized.as_bytes(), &parsed)
        .is_ok())
}

pub fn generate_session_token() -> String {
    encode_base64_urlsafe(&random_bytes(32))
}

pub fn hash_session_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    encode_hex(digest.as_slice())
}

fn totp_code_for_step(secret: &str, step: i64) -> Result<String> {
    let normalized_secret = secret.trim().to_ascii_uppercase();
    let secret_bytes = BASE32_NOPAD
        .decode(normalized_secret.as_bytes())
        .map_err(|error| anyhow!("invalid totp secret: {error}"))?;

    let mut mac = <HmacSha1 as Mac>::new_from_slice(&secret_bytes)
        .map_err(|error| anyhow!("invalid totp key: {error}"))?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = usize::from(digest[19] & 0x0f);
    let binary = ((u32::from(digest[offset] & 0x7f)) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10_u32.pow(TOTP_DIGITS);
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = TOTP_DIGITS as usize
    ))
}

fn normalize_numeric_code(raw: &str) -> Result<String> {
    let normalized = raw
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if normalized.len() != TOTP_DIGITS as usize {
        bail!("totp code must be exactly {TOTP_DIGITS} digits");
    }
    Ok(normalized)
}

fn encode_base64_urlsafe(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_base64_urlsafe(raw: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|error| anyhow!("failed to decode base64 payload: {error}"))
}

fn encode_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(LUT[usize::from(byte >> 4)] as char);
        out.push(LUT[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn percent_encode_component(raw: &str) -> String {
    let mut encoded = String::new();
    for byte in raw.as_bytes() {
        let ch = char::from(*byte);
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            encoded.push(ch);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{:02X}", byte));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_policy_supports_admin_toggle() {
        assert!(RegistrationPolicy::AlwaysPublic.allows_public_registration(false));
        assert!(!RegistrationPolicy::AdminOnly.allows_public_registration(true));
        assert!(RegistrationPolicy::AdminSelectable.allows_public_registration(true));
        assert!(!RegistrationPolicy::AdminSelectable.allows_public_registration(false));
    }

    #[test]
    fn password_strength_rules_can_exempt_admin() {
        let rules = PasswordStrengthRules {
            mode: EnforcementMode::AdminExempt,
            ..Default::default()
        };

        assert!(evaluate_password_strength("weak", &rules, true).valid);
        assert!(!evaluate_password_strength("weak", &rules, false).valid);
    }

    #[test]
    fn password_hash_round_trip_supports_rehash_detection() {
        let old_policy = ArgonPolicy::minimum();
        let next_policy = old_policy.clone().raised(2, 96 * 1024, 4, 2);
        let hash = hash_password("CorrectHorseBatteryStaple!1", &old_policy)
            .expect("password hashing should succeed");

        assert_eq!(
            verify_password("CorrectHorseBatteryStaple!1", &hash, old_policy.version, &old_policy)
                .expect("password verification should succeed"),
            PasswordVerification::Valid
        );
        assert_eq!(
            verify_password("CorrectHorseBatteryStaple!1", &hash, old_policy.version, &next_policy)
                .expect("password verification should succeed"),
            PasswordVerification::ValidNeedsRehash
        );
        assert_eq!(
            verify_password("wrong", &hash, old_policy.version, &next_policy)
                .expect("password verification should succeed"),
            PasswordVerification::Invalid
        );
    }

    #[test]
    fn aes_gcm_round_trip_keeps_plaintext_intact() {
        let key = generate_master_key();
        let encrypted =
            encrypt_bytes(&key, b"hanagram").expect("aes-gcm encryption should succeed");
        let decrypted =
            decrypt_bytes(&key, &encrypted).expect("aes-gcm decryption should succeed");

        assert_eq!(decrypted, b"hanagram");
    }

    #[test]
    fn wrapped_master_key_can_be_unwrapped() {
        let policy = ArgonPolicy::minimum();
        let salt = random_bytes(16);
        let master_key = generate_master_key();
        let wrapped = wrap_master_key("MyStrongPassword!9", &salt, &policy, &master_key)
            .expect("master key wrapping should succeed");
        let unwrapped = unwrap_master_key("MyStrongPassword!9", &salt, &policy, &wrapped)
            .expect("master key unwrapping should succeed");

        assert_eq!(unwrapped, master_key);
    }

    #[test]
    fn totp_codes_verify_and_prevent_replay() {
        let secret = generate_totp_secret();
        let timestamp = 1_710_000_000;
        let code = totp_code_at(&secret, timestamp).expect("totp generation should succeed");
        let used_steps = HashSet::new();

        assert_eq!(
            verify_totp(&secret, &code, timestamp, 1, &used_steps)
                .expect("totp verification should succeed"),
            TotpVerification::Valid {
                matched_step: timestamp.div_euclid(TOTP_PERIOD_SECONDS)
            }
        );

        let replayed = HashSet::from([timestamp.div_euclid(TOTP_PERIOD_SECONDS)]);
        assert_eq!(
            verify_totp(&secret, &code, timestamp, 1, &replayed)
                .expect("totp verification should succeed"),
            TotpVerification::Replay
        );
    }

    #[test]
    fn totp_uri_contains_expected_otpauth_prefix() {
        let uri = build_totp_uri("Hanagram Web", "alice@example.com", "ABCDEF123456");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=Hanagram%20Web"));
    }

    #[test]
    fn recovery_codes_are_hashed_without_storing_plaintext() {
        let policy = ArgonPolicy::minimum();
        let codes = generate_recovery_codes(RECOVERY_CODE_COUNT);
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);

        let hash =
            hash_recovery_code(&codes[0], &policy).expect("recovery code hashing should succeed");
        assert!(
            verify_recovery_code(&codes[0], &hash)
                .expect("recovery code verification should succeed")
        );
        assert!(
            !verify_recovery_code("WRONG-CODE", &hash)
                .expect("recovery code verification should succeed")
        );
    }

    #[test]
    fn session_tokens_are_random_and_hashed() {
        let first = generate_session_token();
        let second = generate_session_token();

        assert_ne!(first, second);
        assert_eq!(hash_session_token(&first).len(), 64);
    }

    #[test]
    fn lockout_policy_grows_exponentially_after_threshold() {
        let policy = LockoutPolicy {
            threshold: 3,
            base_delay_seconds: 5,
            max_delay_seconds: 60,
        };

        assert_eq!(next_lockout_delay(2, &policy), 0);
        assert_eq!(next_lockout_delay(3, &policy), 5);
        assert_eq!(next_lockout_delay(4, &policy), 10);
        assert_eq!(next_lockout_delay(8, &policy), 60);
    }
}
