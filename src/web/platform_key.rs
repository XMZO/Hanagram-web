// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine;
use hanagram_web::security::{
    EncryptedBlob, MasterKey, decrypt_bytes, encrypt_bytes, generate_master_key,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const PASSKEY_LOGIN_KEY_VERSION: u8 = 1;

#[derive(Debug, Deserialize, Serialize)]
struct StoredPasskeyLoginKey {
    version: u8,
    key_b64: String,
}

pub(crate) async fn load_or_create_passkey_login_key(path: &Path) -> Result<MasterKey> {
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => decode_passkey_login_key(&raw),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = generate_master_key();
            let encoded = encode_passkey_login_key(key.as_slice())?;
            tokio::fs::write(path, encoded)
                .await
                .with_context(|| format!("failed writing {}", path.display()))?;
            Ok(key)
        }
        Err(error) => Err(error).with_context(|| format!("failed reading {}", path.display())),
    }
}

pub(crate) fn encrypt_master_key_for_passkey_login(
    passkey_login_key: &[u8],
    master_key: &[u8],
) -> Result<String> {
    let encrypted = encrypt_bytes(passkey_login_key, master_key)?;
    serde_json::to_string(&encrypted).context("failed to encode passkey login master key")
}

pub(crate) fn decrypt_master_key_for_passkey_login(
    passkey_login_key: &[u8],
    payload_json: &str,
) -> Result<MasterKey> {
    let payload: EncryptedBlob = serde_json::from_str(payload_json)
        .context("failed to parse passkey login master key payload")?;
    let plaintext = decrypt_bytes(passkey_login_key, &payload)?;
    let master_key: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("passkey login master key payload had an unexpected length"))?;
    Ok(zeroize::Zeroizing::new(master_key))
}

fn encode_passkey_login_key(key: &[u8]) -> Result<String> {
    Ok(serde_json::to_string(&StoredPasskeyLoginKey {
        version: PASSKEY_LOGIN_KEY_VERSION,
        key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
    })
    .context("failed to encode passkey login key")?)
}

fn decode_passkey_login_key(raw: &str) -> Result<MasterKey> {
    let payload: StoredPasskeyLoginKey =
        serde_json::from_str(raw).context("failed to parse passkey login key")?;
    ensure!(
        payload.version == PASSKEY_LOGIN_KEY_VERSION,
        "unsupported passkey login key version"
    );

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.key_b64)
        .context("failed to decode passkey login key bytes")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("passkey login key had an unexpected length"))?;
    Ok(zeroize::Zeroizing::new(key))
}
