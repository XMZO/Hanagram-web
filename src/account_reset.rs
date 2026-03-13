// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::store::{MetaStore, UserRecord};

#[derive(Debug)]
pub struct ResetAccountResult {
    pub auth_session_ids: Vec<String>,
    pub session_record_ids: Vec<String>,
}

pub fn clear_user_credentials(user: &mut UserRecord) {
    user.security.password_hash = None;
    user.security.password_argon_version = 0;
    user.security.kek_salt_b64 = None;
    user.security.encrypted_master_key_json = None;
    user.security.totp_secret_json = None;
    user.security.totp_enabled = false;
    user.security.password_needs_reset = true;
    user.security.login_failures = 0;
    user.security.lockout_level = 0;
    user.security.locked_until_unix = None;
    user.security.last_login_ip = None;
    user.security.preferred_idle_timeout_minutes = None;
    user.security.bot_notification_settings = Default::default();
    user.updated_at_unix = Utc::now().timestamp();
}

pub async fn reset_user_account(
    store: &MetaStore,
    user: &mut UserRecord,
    users_dir: &Path,
) -> Result<ResetAccountResult> {
    let auth_sessions = store.list_auth_sessions_for_user(&user.id).await?;
    let session_records = store.list_session_records_for_user(&user.id).await?;

    store.revoke_all_auth_sessions_for_user(&user.id).await?;
    store.replace_recovery_codes(&user.id, &[]).await?;
    store.clear_used_totp_steps_for_user(&user.id).await?;

    for session_record in &session_records {
        store.delete_session_record(&session_record.id).await?;
        remove_file_if_exists(Path::new(&session_record.storage_path)).await?;
    }

    remove_dir_all_if_exists(&users_dir.join(&user.id)).await?;
    clear_user_credentials(user);
    store.save_user(user).await?;

    Ok(ResetAccountResult {
        auth_session_ids: auth_sessions
            .into_iter()
            .map(|session| session.id)
            .collect(),
        session_record_ids: session_records
            .into_iter()
            .map(|record| record.id)
            .collect(),
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
    use crate::store::{SessionRecord, UserRole};
    use uuid::Uuid;

    #[tokio::test]
    async fn reset_user_account_clears_credentials_and_disk_state() {
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
        store.save_user(&user).await.expect("user should save");

        store
            .replace_recovery_codes(&user.id, &[String::from("hash-a"), String::from("hash-b")])
            .await
            .expect("recovery codes should save");
        store
            .mark_totp_step_used(&user.id, 42)
            .await
            .expect("totp step should save");
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

        let result = reset_user_account(&store, &mut user, &users_dir)
            .await
            .expect("reset should succeed");

        assert_eq!(result.auth_session_ids.len(), 1);
        assert_eq!(result.session_record_ids.len(), 1);
        assert!(user.security.password_hash.is_none());
        assert!(!user.security.totp_enabled);
        assert!(user.security.last_login_ip.is_none());
        assert!(user.security.preferred_idle_timeout_minutes.is_none());
        assert!(!user.security.bot_notification_settings.enabled);
        assert!(user.security.bot_notification_settings.bot_token.is_empty());

        let saved_user = store
            .get_user_by_id(&user.id)
            .await
            .expect("user lookup should succeed")
            .expect("user should still exist");
        assert!(saved_user.security.password_hash.is_none());
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
        assert!(!session_path.exists());
        assert!(!user_dir.exists());
    }
}
