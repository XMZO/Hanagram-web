// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use chrono::Utc;

use crate::security::{
    ArgonPolicy, generate_master_key, hash_password, random_bytes, wrap_master_key,
};
use crate::store::{MetaStore, UserRecord};

#[derive(Debug)]
pub struct ResetAccountResult {
    pub auth_session_ids: Vec<String>,
    pub session_record_ids: Vec<String>,
    pub temporary_password: String,
}

#[derive(Debug)]
pub struct DeleteAccountResult {
    pub auth_session_ids: Vec<String>,
    pub session_record_ids: Vec<String>,
}

pub fn clear_user_credentials(user: &mut UserRecord) {
    user.security.password_hash = None;
    user.security.password_argon_version = 0;
    user.security.kek_salt_b64 = None;
    user.security.encrypted_master_key_json = None;
    user.security.passkey_encrypted_master_key_json = None;
    user.security.totp_secret_json = None;
    user.security.totp_enabled = false;
    user.security.password_needs_reset = true;
    user.security.login_failures = 0;
    user.security.lockout_level = 0;
    user.security.locked_until_unix = None;
    user.security.last_login_ip = None;
    user.security.preferred_idle_timeout_minutes = None;
    user.security.bot_notification_settings = Default::default();
    user.security.passkeys.clear();
    user.updated_at_unix = Utc::now().timestamp();
}

fn build_temporary_password() -> String {
    let entropy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes(48));
    format!("Hanagram!{entropy}Aa9")
}

fn assign_password_credentials(
    user: &mut UserRecord,
    password: &str,
    argon_policy: &ArgonPolicy,
) -> Result<()> {
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
    user.security.passkey_encrypted_master_key_json = None;
    user.updated_at_unix = Utc::now().timestamp();
    Ok(())
}

async fn purge_user_account_state(
    store: &MetaStore,
    user_id: &str,
    users_dir: &Path,
) -> Result<(Vec<String>, Vec<String>)> {
    let auth_sessions = store.list_auth_sessions_for_user(user_id).await?;
    let session_records = store.list_session_records_for_user(user_id).await?;

    for auth_session in &auth_sessions {
        store
            .delete_auth_session_unlock_material(&auth_session.id)
            .await?;
    }
    store.revoke_all_auth_sessions_for_user(user_id).await?;
    store.replace_recovery_codes(user_id, &[]).await?;
    store.clear_used_totp_steps_for_user(user_id).await?;

    for session_record in &session_records {
        store.delete_session_record(&session_record.id).await?;
        remove_file_if_exists(Path::new(&session_record.storage_path)).await?;
    }

    remove_dir_all_if_exists(&users_dir.join(user_id)).await?;

    Ok((
        auth_sessions
            .into_iter()
            .map(|session| session.id)
            .collect(),
        session_records
            .into_iter()
            .map(|record| record.id)
            .collect(),
    ))
}

pub async fn reset_user_account(
    store: &MetaStore,
    user: &mut UserRecord,
    users_dir: &Path,
    argon_policy: &ArgonPolicy,
) -> Result<ResetAccountResult> {
    let (auth_session_ids, session_record_ids) =
        purge_user_account_state(store, &user.id, users_dir).await?;
    clear_user_credentials(user);
    let temporary_password = build_temporary_password();
    assign_password_credentials(user, &temporary_password, argon_policy)?;
    user.security.password_needs_reset = true;
    store.save_user(user).await?;

    Ok(ResetAccountResult {
        auth_session_ids,
        session_record_ids,
        temporary_password,
    })
}

pub async fn delete_user_account(
    store: &MetaStore,
    user: &UserRecord,
    users_dir: &Path,
) -> Result<DeleteAccountResult> {
    let (auth_session_ids, session_record_ids) =
        purge_user_account_state(store, &user.id, users_dir).await?;
    store.delete_user(&user.id).await?;

    Ok(DeleteAccountResult {
        auth_session_ids,
        session_record_ids,
    })
}

async fn remove_file_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed removing {}", path.display())),
    }
}

async fn remove_dir_all_if_exists(path: &PathBuf) -> Result<()> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{ArgonPolicy, PasswordVerification, verify_password};
    use crate::store::{SessionRecord, UserRole};
    use uuid::Uuid;

    #[tokio::test]
    async fn reset_user_account_rotates_to_temporary_password_and_clears_disk_state() {
        let store = MetaStore::open_memory()
            .await
            .expect("metadata store should open");
        let users_dir = std::env::temp_dir().join(format!("hanagram-reset-{}", Uuid::new_v4()));

        let mut user = UserRecord::new("reset-me", UserRole::User);
        user.security.password_hash = Some(String::from("hash"));
        user.security.password_argon_version = 1;
        user.security.kek_salt_b64 = Some(String::from("salt"));
        user.security.encrypted_master_key_json = Some(String::from("wrapped"));
        user.security.totp_secret_json = Some(String::from("totp"));
        user.security.totp_enabled = true;
        user.security.last_login_ip = Some(String::from("127.0.0.1"));
        user.security.preferred_idle_timeout_minutes = Some(30);
        user.security.bot_notification_settings.enabled = true;
        user.security.bot_notification_settings.bot_token = String::from("bot-token");
        user.security.passkeys.push(crate::store::StoredPasskey {
            id: String::from("passkey-1"),
            label: String::from("My Passkey"),
            credential_json: String::from("{}"),
            created_at_unix: Utc::now().timestamp(),
            last_used_at_unix: None,
        });
        store.save_user(&user).await.expect("user should save");

        store
            .replace_recovery_codes(&user.id, &[String::from("hash-a"), String::from("hash-b")])
            .await
            .expect("recovery codes should save");
        store
            .mark_totp_step_used(&user.id, 42)
            .await
            .expect("totp step should save");
        let auth_session = store
            .create_auth_session(
                &user.id,
                "token-hash",
                Some("127.0.0.1"),
                Some("test-agent"),
                Utc::now().timestamp() + 3600,
                Some(30),
            )
            .await
            .expect("auth session should save");
        store
            .save_auth_session_unlock_material(&auth_session.id, r#"{"wrapped":"value"}"#)
            .await
            .expect("unlock material should save");

        let user_dir = users_dir.join(&user.id);
        tokio::fs::create_dir_all(&user_dir)
            .await
            .expect("user directory should be created");
        let session_path = user_dir.join("alpha.session");
        tokio::fs::write(&session_path, b"session-bytes")
            .await
            .expect("session file should be written");

        let session_record =
            SessionRecord::new(user.id.clone(), "alpha", session_path.display().to_string());
        store
            .save_session_record(&session_record)
            .await
            .expect("session record should save");

        let argon_policy = ArgonPolicy::minimum();
        let result = reset_user_account(&store, &mut user, &users_dir, &argon_policy)
            .await
            .expect("reset should succeed");

        assert_eq!(result.auth_session_ids.len(), 1);
        assert_eq!(result.session_record_ids.len(), 1);
        assert!(user.security.password_hash.is_some());
        assert!(user.security.password_needs_reset);
        assert!(!user.security.totp_enabled);
        assert!(user.security.last_login_ip.is_none());
        assert!(user.security.preferred_idle_timeout_minutes.is_none());
        assert!(!user.security.bot_notification_settings.enabled);
        assert!(user.security.bot_notification_settings.bot_token.is_empty());
        assert!(user.security.passkeys.is_empty());

        let saved_user = store
            .get_user_by_id(&user.id)
            .await
            .expect("user lookup should succeed")
            .expect("user should still exist");
        let password_hash = saved_user
            .security
            .password_hash
            .clone()
            .expect("temporary password hash should exist");
        assert_eq!(
            verify_password(
                &result.temporary_password,
                &password_hash,
                saved_user.security.password_argon_version,
                &argon_policy,
            )
            .expect("temporary password should verify"),
            PasswordVerification::Valid
        );
        assert_eq!(
            store
                .count_active_recovery_codes(&user.id)
                .await
                .expect("count should load"),
            0
        );
        assert!(
            store
                .list_recent_totp_steps(&user.id, 0)
                .await
                .expect("totp steps should load")
                .is_empty()
        );
        assert!(
            store
                .list_session_records_for_user(&user.id)
                .await
                .expect("session records should load")
                .is_empty()
        );
        assert!(
            store
                .load_auth_session_unlock_material(&result.auth_session_ids[0])
                .await
                .expect("unlock material should load")
                .is_none()
        );
        assert!(!session_path.exists());
        assert!(!user_dir.exists());
    }

    #[tokio::test]
    async fn delete_user_account_removes_user_and_disk_state() {
        let store = MetaStore::open_memory()
            .await
            .expect("metadata store should open");
        let users_dir = std::env::temp_dir().join(format!("hanagram-delete-{}", Uuid::new_v4()));

        let mut user = UserRecord::new("delete-me", UserRole::User);
        user.security.password_hash = Some(String::from("hash"));
        store.save_user(&user).await.expect("user should save");

        store
            .create_auth_session(
                &user.id,
                "token-hash",
                Some("127.0.0.1"),
                Some("test-agent"),
                Utc::now().timestamp() + 3600,
                Some(30),
            )
            .await
            .expect("auth session should save");

        let user_dir = users_dir.join(&user.id);
        tokio::fs::create_dir_all(&user_dir)
            .await
            .expect("user directory should be created");
        let session_path = user_dir.join("beta.session");
        tokio::fs::write(&session_path, b"session-bytes")
            .await
            .expect("session file should be written");

        let session_record =
            SessionRecord::new(user.id.clone(), "beta", session_path.display().to_string());
        store
            .save_session_record(&session_record)
            .await
            .expect("session record should save");

        let result = delete_user_account(&store, &user, &users_dir)
            .await
            .expect("delete should succeed");

        assert_eq!(result.auth_session_ids.len(), 1);
        assert_eq!(result.session_record_ids.len(), 1);
        assert!(
            store
                .get_user_by_id(&user.id)
                .await
                .expect("user lookup should succeed")
                .is_none()
        );
        assert!(!session_path.exists());
        assert!(!user_dir.exists());
    }
}
