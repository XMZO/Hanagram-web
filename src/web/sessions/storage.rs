// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::io::Cursor;

use crate::web::middleware;
use crate::web::shared::*;

use super::runtime::register_session_record;

const PACKED_SESSION_PREFIX: &[u8] = b"hanagram-session-pack:v1\0";
const SESSION_ZSTD_LEVEL: i32 = 9;

fn user_sessions_dir(runtime: &RuntimeConfig, user_id: &str) -> PathBuf {
    runtime.users_dir.join(user_id)
}

pub(crate) fn session_storage_path(
    runtime: &RuntimeConfig,
    user_id: &str,
    session_id: &str,
) -> PathBuf {
    user_sessions_dir(runtime, user_id).join(format!("{session_id}.session"))
}

pub(crate) async fn ensure_user_sessions_dir(
    runtime: &RuntimeConfig,
    user_id: &str,
) -> Result<PathBuf> {
    let dir = user_sessions_dir(runtime, user_id);
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(dir)
}

fn encrypt_session_text_field(
    raw_value: &str,
    master_key: &[u8],
    prefix: &str,
    field_name: &str,
) -> Result<String> {
    if raw_value.is_empty() {
        return Ok(String::new());
    }
    let payload = encrypt_bytes(master_key, raw_value.as_bytes())?;
    let encoded = serde_json::to_string(&payload)
        .with_context(|| format!("failed to encode encrypted {field_name}"))?;
    Ok(format!("{prefix}{encoded}"))
}

fn decrypt_session_text_field(
    raw_value: &str,
    master_key: &[u8],
    prefix: &str,
    field_name: &str,
) -> Result<(String, bool)> {
    if raw_value.is_empty() {
        return Ok((String::new(), false));
    }
    let Some(payload) = raw_value.strip_prefix(prefix) else {
        return Ok((raw_value.to_owned(), true));
    };
    let payload: EncryptedBlob = serde_json::from_str(payload)
        .with_context(|| format!("failed to decode encrypted {field_name}"))?;
    let plaintext = decrypt_bytes(master_key, &payload)?;
    let value = String::from_utf8(plaintext.to_vec())
        .with_context(|| format!("{field_name} was not valid utf-8"))?;
    Ok((value, false))
}

fn encrypt_session_key(session_key: &str, master_key: &[u8]) -> Result<String> {
    encrypt_session_text_field(
        session_key,
        master_key,
        SESSION_KEY_PREFIX,
        "session key payload",
    )
}

fn decrypt_session_key(raw_session_key: &str, master_key: &[u8]) -> Result<(String, bool)> {
    decrypt_session_text_field(
        raw_session_key,
        master_key,
        SESSION_KEY_PREFIX,
        "session key payload",
    )
}

fn encrypt_session_note(note: &str, master_key: &[u8]) -> Result<String> {
    encrypt_session_text_field(note, master_key, SESSION_NOTE_PREFIX, "session note")
}

fn decrypt_session_note(raw_note: &str, master_key: &[u8]) -> Result<(String, bool)> {
    decrypt_session_text_field(raw_note, master_key, SESSION_NOTE_PREFIX, "session note")
}

pub(crate) async fn persist_session_record(
    app_state: &AppState,
    record: &SessionRecord,
) -> Result<()> {
    let master_key = app_state
        .user_keys
        .read()
        .await
        .get(&record.user_id)
        .cloned()
        .context("user data is locked; sign in again to unlock it")?;
    let mut encrypted_record = record.clone();
    encrypted_record.session_key =
        encrypt_session_key(&record.session_key, master_key.as_ref().as_slice())?;
    encrypted_record.note = encrypt_session_note(&record.note, master_key.as_ref().as_slice())?;
    app_state
        .meta_store
        .save_session_record(&encrypted_record)
        .await
}

pub(crate) async fn hydrate_session_record(
    app_state: &AppState,
    record: &mut SessionRecord,
) -> Result<()> {
    let Some(master_key) = app_state
        .user_keys
        .read()
        .await
        .get(&record.user_id)
        .cloned()
    else {
        record.session_key = Path::new(&record.storage_path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| record.storage_path.clone());
        record.note.clear();
        return Ok(());
    };
    let (session_key_value, key_was_legacy_plaintext) =
        decrypt_session_key(&record.session_key, master_key.as_ref().as_slice())?;
    let (note, note_was_legacy_plaintext) =
        decrypt_session_note(&record.note, master_key.as_ref().as_slice())?;
    record.session_key = session_key_value;
    record.note = note;
    if key_was_legacy_plaintext || note_was_legacy_plaintext {
        persist_session_record(app_state, record).await?;
    }
    Ok(())
}

fn decrypt_session_storage_bytes(master_key: &[u8], raw: &[u8]) -> Result<(SensitiveBytes, bool)> {
    match serde_json::from_slice::<EncryptedBlob>(raw) {
        Ok(payload) => Ok((
            unpack_session_storage_bytes(decrypt_bytes(master_key, &payload)?.as_slice())?,
            false,
        )),
        Err(_) => Ok((into_sensitive_bytes(raw.to_vec()), true)),
    }
}

fn pack_session_storage_bytes(plaintext: &[u8]) -> Result<SensitiveBytes> {
    let compressed = zstd::stream::encode_all(Cursor::new(plaintext), SESSION_ZSTD_LEVEL)
        .context("failed compressing session payload")?;
    if compressed.len() + PACKED_SESSION_PREFIX.len() + 16 >= plaintext.len() {
        return Ok(into_sensitive_bytes(plaintext.to_vec()));
    }

    let mut packed = Vec::with_capacity(PACKED_SESSION_PREFIX.len() + compressed.len());
    packed.extend_from_slice(PACKED_SESSION_PREFIX);
    packed.extend_from_slice(&compressed);
    Ok(into_sensitive_bytes(packed))
}

fn unpack_session_storage_bytes(raw: &[u8]) -> Result<SensitiveBytes> {
    let Some(compressed) = raw.strip_prefix(PACKED_SESSION_PREFIX) else {
        return Ok(into_sensitive_bytes(raw.to_vec()));
    };
    let decompressed = zstd::stream::decode_all(Cursor::new(compressed))
        .context("failed decompressing session payload")?;
    Ok(into_sensitive_bytes(decompressed))
}

async fn write_encrypted_session_bytes(
    master_key: &[u8],
    encrypted_path: &Path,
    plaintext: &[u8],
) -> Result<()> {
    let packed = pack_session_storage_bytes(plaintext)?;
    let payload = encrypt_bytes(master_key, packed.as_slice())?;
    let encoded =
        serde_json::to_vec(&payload).context("failed to encode encrypted session payload")?;
    tokio::fs::write(encrypted_path, encoded)
        .await
        .with_context(|| format!("failed writing {}", encrypted_path.display()))
}

async fn read_decrypted_session_bytes(
    master_key: &[u8],
    encrypted_path: &Path,
) -> Result<SensitiveBytes> {
    let raw = tokio::fs::read(encrypted_path)
        .await
        .with_context(|| format!("failed reading {}", encrypted_path.display()))?;
    let (plaintext, was_legacy_plaintext) = decrypt_session_storage_bytes(master_key, &raw)?;
    if was_legacy_plaintext {
        write_encrypted_session_bytes(master_key, encrypted_path, plaintext.as_slice()).await?;
    }
    Ok(plaintext)
}

pub(crate) async fn load_persisted_session(
    master_key: &[u8],
    encrypted_path: &Path,
) -> Result<LoadedSession> {
    let plaintext = read_decrypted_session_bytes(master_key, encrypted_path).await?;
    let loaded =
        load_session(plaintext.as_slice()).context("failed to decode stored session payload")?;
    if loaded.needs_persist {
        persist_loaded_session(master_key, encrypted_path, &loaded.session).await?;
    }
    Ok(loaded.session)
}

pub(crate) async fn persist_loaded_session(
    master_key: &[u8],
    encrypted_path: &Path,
    session: &LoadedSession,
) -> Result<()> {
    let plaintext = serialize_session(session)?;
    write_encrypted_session_bytes(master_key, encrypted_path, plaintext.as_slice()).await
}

pub(crate) async fn save_new_session_record(
    app_state: &AppState,
    user_id: &str,
    session_id: &str,
    session_name: &str,
    session: &LoadedSession,
) -> Result<SessionRecord> {
    let master_key = app_state
        .user_keys
        .read()
        .await
        .get(user_id)
        .cloned()
        .context("user data is locked; sign in again to unlock it")?;
    let session_path = session_storage_path(&app_state.runtime, user_id, session_id);
    persist_loaded_session(master_key.as_ref().as_slice(), &session_path, session).await?;

    let record = SessionRecord::new(
        user_id.to_owned(),
        session_name.to_owned(),
        session_path.display().to_string(),
    );
    let mut record = record;
    record.id = session_id.to_owned();
    persist_session_record(app_state, &record).await?;
    register_session_record(app_state, record.clone()).await;
    Ok(record)
}

pub(crate) async fn load_owned_session_record(
    app_state: &AppState,
    user_id: &str,
    session_id: &str,
) -> Result<Option<SessionRecord>> {
    let Some(record) = app_state
        .meta_store
        .get_session_record_by_id(session_id)
        .await?
    else {
        return Ok(None);
    };
    if record.user_id != user_id {
        return Ok(None);
    }
    let mut record = record;
    if let Err(error) = hydrate_session_record(app_state, &mut record).await {
        warn!(
            "failed hydrating owned session note for {}: {}",
            record.id, error
        );
        record.note.clear();
    }
    Ok(Some(record))
}

pub(crate) async fn export_owned_session_file(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    session_id: &str,
    language: Language,
) -> Response {
    let translations = language.translations();
    let session =
        match load_owned_session_record(app_state, &authenticated.user.id, session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for export: {}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let Some(session) = session else {
        return (
            StatusCode::NOT_FOUND,
            String::from(translations.dashboard_session_missing),
        )
            .into_response();
    };
    let Some(master_key) = middleware::resolved_user_master_key(app_state, authenticated).await
    else {
        return (
            StatusCode::LOCKED,
            String::from(translations.session_data_locked_message),
        )
            .into_response();
    };

    let session_path = PathBuf::from(&session.storage_path);
    match load_persisted_session(master_key.as_ref().as_slice(), &session_path).await {
        Ok(loaded_session) => match export_sqlite_session_bytes(&loaded_session) {
            Ok(bytes) => {
                let mut response = bytes.as_slice().to_vec().into_response();
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
                match HeaderValue::from_str(&format!(
                    "attachment; filename=\"{}.session\"",
                    session.session_key
                )) {
                    Ok(value) => {
                        response
                            .headers_mut()
                            .insert(header::CONTENT_DISPOSITION, value);
                        response
                    }
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
            Err(error) => {
                warn!(
                    "failed exporting sqlite session file {}: {}",
                    session_path.display(),
                    error
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from(translations.export_file_error_message),
                )
                    .into_response()
            }
        },
        Err(error) => {
            warn!(
                "failed reading session file {} for export: {}",
                session_path.display(),
                error
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from(translations.export_file_error_message),
            )
                .into_response()
        }
    }
}

pub(crate) async fn finalize_pending_session(
    app_state: &AppState,
    user_id: &str,
    session_id: &str,
    session_name: &str,
    final_path: &Path,
    session_data: &[u8],
) -> Result<()> {
    let master_key = app_state
        .user_keys
        .read()
        .await
        .get(user_id)
        .cloned()
        .context("user data is locked; sign in again to unlock it")?;
    let loaded = load_session(session_data).context("failed to decode pending session payload")?;
    persist_loaded_session(master_key.as_ref().as_slice(), final_path, &loaded.session).await?;

    let mut record = SessionRecord::new(
        user_id.to_owned(),
        session_name.to_owned(),
        final_path.display().to_string(),
    );
    record.id = session_id.to_owned();
    persist_session_record(app_state, &record).await?;
    register_session_record(app_state, record).await;
    Ok(())
}

pub(crate) async fn remove_file_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_session_storage_bytes_round_trips_encrypted_payload() {
        let master_key = [7_u8; 32];
        let plaintext = b"telegram-session-sqlite";
        let payload = encrypt_bytes(&master_key, plaintext).expect("encrypt payload");
        let encoded = serde_json::to_vec(&payload).expect("encode encrypted payload");

        let (decrypted, was_legacy_plaintext) =
            decrypt_session_storage_bytes(&master_key, &encoded).expect("decrypt payload");

        assert_eq!(decrypted.as_slice(), plaintext);
        assert!(!was_legacy_plaintext);
    }

    #[test]
    fn decrypt_session_storage_bytes_accepts_legacy_plaintext() {
        let master_key = [9_u8; 32];
        let plaintext = b"legacy-session";

        let (decrypted, was_legacy_plaintext) =
            decrypt_session_storage_bytes(&master_key, plaintext).expect("accept legacy payload");

        assert_eq!(decrypted.as_slice(), plaintext);
        assert!(was_legacy_plaintext);
    }

    #[test]
    fn encrypt_session_metadata_round_trips_and_accepts_legacy_plaintext() {
        let master_key = [11_u8; 32];
        let encrypted_key =
            encrypt_session_key("primary-account", &master_key).expect("encrypt session key");
        let (decrypted_key, key_was_legacy_plaintext) =
            decrypt_session_key(&encrypted_key, &master_key).expect("decrypt session key");
        assert_eq!(decrypted_key, "primary-account");
        assert!(!key_was_legacy_plaintext);

        let encrypted = encrypt_session_note("Primary phone", &master_key).expect("encrypt note");

        let (decrypted, was_legacy_plaintext) =
            decrypt_session_note(&encrypted, &master_key).expect("decrypt note");
        assert_eq!(decrypted, "Primary phone");
        assert!(!was_legacy_plaintext);

        let (legacy_decrypted, legacy_plaintext) =
            decrypt_session_note("legacy note", &master_key).expect("accept legacy note");
        assert_eq!(legacy_decrypted, "legacy note");
        assert!(legacy_plaintext);
    }

    #[test]
    fn packed_session_storage_round_trips_compressed_payloads() {
        let plaintext = vec![b'A'; 8 * 1024];
        let packed = pack_session_storage_bytes(&plaintext).expect("pack session payload");
        assert!(packed.len() < plaintext.len());

        let unpacked =
            unpack_session_storage_bytes(packed.as_slice()).expect("unpack session payload");
        assert_eq!(unpacked.as_slice(), plaintext.as_slice());
    }
}
