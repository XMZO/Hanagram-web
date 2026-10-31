// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

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

pub(crate) fn export_mafile_json_bytes(account: &SteamGuardAccount) -> Result<Vec<u8>> {
    let uri = match account
        .uri
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => value.to_owned(),
        None => generate_totp_uri(account)?,
    };
    let session = account.session.as_ref();
    let session_value = if session.is_some() || account.steam_id.is_some() {
        serde_json::json!({
            "SteamID": account.steam_id,
            "AccessToken": session.and_then(|value| value.access_token.clone()),
            "RefreshToken": session.and_then(|value| value.refresh_token.clone()),
            "SessionID": session.and_then(|value| value.session_id.clone()),
            "SteamLogin": session.and_then(|value| value.steam_login.clone()),
            "SteamLoginSecure": session.and_then(|value| value.steam_login_secure.clone()),
            "WebCookie": session.and_then(|value| value.web_cookie.clone()),
            "OAuthToken": session.and_then(|value| value.oauth_token.clone()),
        })
    } else {
        serde_json::Value::Null
    };
    let payload = serde_json::json!({
        "shared_secret": account.shared_secret.clone(),
        "serial_number": account.serial_number.clone().unwrap_or_default(),
        "revocation_code": account.revocation_code.clone().unwrap_or_default(),
        "uri": uri,
        "server_time": 0,
        "account_name": account.account_name.clone(),
        "token_gid": account.token_gid.clone().unwrap_or_default(),
        "identity_secret": account.identity_secret.clone().unwrap_or_default(),
        "secret_1": account.secret_1.clone().unwrap_or_default(),
        "status": 0,
        "device_id": account.device_id.clone().unwrap_or_default(),
        "fully_enrolled": true,
        "Session": session_value,
    });

    serde_json::to_vec_pretty(&payload).context("failed encoding maFile export")
}

// ---------------------------------------------------------------------------
// Third-party guard import (WinAuth / otpauth URI)
// ---------------------------------------------------------------------------

/// Parse a third-party otpauth:// URI, extract the embedded guard material, and persist it.
pub(crate) async fn ingest_third_party_guard(
    root_dir: &Path,
    master_key: &[u8],
    raw_uri: &str,
    display_name_override: Option<&str>,
) -> Result<SteamGuardAccount> {
    let input = raw_uri.trim();
    ensure!(
        input.starts_with("otpauth://"),
        "expected otpauth:// scheme"
    );

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
    let dev_id = normalize_optional_string(Some(payload.device_id))
        .or_else(|| sid.map(generate_device_id_for_steam_id));

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
