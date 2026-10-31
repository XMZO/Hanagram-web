// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

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

pub(super) fn extract_raw_steam_username(raw_account_name: &str) -> Option<String> {
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

pub(super) fn default_stored_web_session() -> StoredSteamWebSession {
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

pub(super) fn stored_web_session_mut(
    record: &mut StoredSteamAccount,
) -> &mut StoredSteamWebSession {
    record
        .session
        .get_or_insert_with(default_stored_web_session)
}

pub(super) fn clear_stored_session_material(record: &mut StoredSteamAccount) {
    if let Some(session) = record.session.as_mut() {
        session.session_id = None;
        session.steam_login = None;
        session.steam_login_secure = None;
        session.web_cookie = None;
        session.oauth_token = None;
        session.access_token = None;
        session.refresh_token = None;
    }
    record.session = None;
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

pub(super) async fn load_legacy_account(path: &Path) -> Result<SteamGuardAccount> {
    let raw_bytes = fs::read(path)
        .await
        .with_context(|| format!("failed reading Steam Guard file {}", path.display()))?;
    parse_account_bytes(&raw_bytes, path)
}

pub(super) async fn load_managed_runtime_account(
    master_key: &[u8],
    path: &Path,
) -> Result<SteamGuardAccount> {
    let record = load_stored_account(master_key, path)
        .await?
        .ok_or_else(|| anyhow!("managed Steam account file is missing"))?;
    Ok(record.into_runtime(path.to_path_buf()))
}

pub(super) fn parse_account_bytes(raw_bytes: &[u8], path: &Path) -> Result<SteamGuardAccount> {
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

pub(super) fn normalize_optional_string<T>(value: Option<T>) -> Option<String>
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

pub(super) fn option_has_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

pub(super) fn deserialize_u64_from_any<'de, D>(
    deserializer: D,
) -> std::result::Result<u64, D::Error>
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

pub(super) fn deserialize_u32_from_any<'de, D>(
    deserializer: D,
) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_u64_from_any(deserializer)?;
    u32::try_from(value).map_err(|_| serde::de::Error::custom("value did not fit into u32"))
}

pub(super) fn deserialize_bool_from_any<'de, D>(
    deserializer: D,
) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Bool(value) => Ok(value),
        serde_json::Value::Number(number) => number
            .as_u64()
            .map(|value| value != 0)
            .ok_or_else(|| serde::de::Error::custom("expected bool-compatible number")),
        serde_json::Value::String(raw) => {
            let raw = raw.trim();
            if raw.eq_ignore_ascii_case("true") || raw == "1" {
                Ok(true)
            } else if raw.eq_ignore_ascii_case("false") || raw == "0" {
                Ok(false)
            } else {
                Err(serde::de::Error::custom("expected bool-compatible string"))
            }
        }
        other => Err(serde::de::Error::custom(format!(
            "unsupported bool value: {other}"
        ))),
    }
}

pub(super) fn deserialize_optional_u64_from_any<'de, D>(
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

pub(super) async fn collect_account_files_recursive(
    dir: PathBuf,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
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

pub(super) fn pack_managed_storage_bytes(plaintext: &[u8]) -> Result<Vec<u8>> {
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

pub(super) fn unpack_managed_storage_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    let Some(compressed) = raw.strip_prefix(STEAM_MANAGED_PACK_PREFIX) else {
        return Ok(raw.to_vec());
    };
    zstd::stream::decode_all(Cursor::new(compressed))
        .context("failed decompressing Steam account payload")
}

// ---------------------------------------------------------------------------
// Guard enrollment (provision new 2FA or migrate existing)
// ---------------------------------------------------------------------------

/// List all managed account IDs for a steam root directory.
pub(crate) async fn list_managed_account_ids(root_dir: &Path) -> Vec<String> {
    let managed_dir = managed_accounts_dir(root_dir);
    let mut ids = Vec::new();
    let mut entries = match fs::read_dir(&managed_dir).await {
        Ok(entries) => entries,
        Err(_) => return ids,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path
            .extension()
            .and_then(|v| v.to_str())
            .map(|v| v.eq_ignore_ascii_case(STEAM_MANAGED_ACCOUNT_EXTENSION))
            == Some(true)
        {
            if let Some(stem) = path.file_stem().and_then(|v| v.to_str()) {
                ids.push(stem.to_owned());
            }
        }
    }
    ids
}
