// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use libsql::{Builder, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::security::{
    ArgonPolicy, EnforcementMode, LockoutPolicy, PasswordStrengthRules, RegistrationPolicy,
};

const SYSTEM_SETTINGS_KEY: &str = "system_settings";
const SCHEMA_VERSION_KEY: &str = "schema_version";
const APP_SCHEMA_VERSION: i64 = 2;
const INCOMPATIBLE_SCHEMA_MESSAGE: &str = "existing metadata database schema is incompatible with this build; delete .hanagram/app.db and restart";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TelegramApiSettings {
    pub api_id: Option<i32>,
    pub api_hash: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BotNotificationSettings {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
    pub template: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct StoredPasskey {
    pub id: String,
    pub label: String,
    pub credential_json: String,
    pub created_at_unix: i64,
    pub last_used_at_unix: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct SystemSettings {
    pub registration_policy: RegistrationPolicy,
    pub public_registration_open: bool,
    pub totp_policy: EnforcementMode,
    pub password_strength_policy: EnforcementMode,
    pub password_strength_rules: PasswordStrengthRules,
    pub lockout_policy: LockoutPolicy,
    pub audit_detail_limit: u32,
    pub session_absolute_ttl_hours: u32,
    pub cookie_secure: bool,
    pub max_idle_timeout_minutes: Option<u32>,
    pub argon_policy: ArgonPolicy,
    pub telegram_api: TelegramApiSettings,
}

impl Default for SystemSettings {
    fn default() -> Self {
        Self {
            registration_policy: RegistrationPolicy::AdminOnly,
            public_registration_open: false,
            totp_policy: EnforcementMode::AllUsers,
            password_strength_policy: EnforcementMode::AllUsers,
            password_strength_rules: PasswordStrengthRules::default(),
            lockout_policy: LockoutPolicy::default(),
            audit_detail_limit: 500,
            session_absolute_ttl_hours: 24,
            cookie_secure: true,
            max_idle_timeout_minutes: None,
            argon_policy: ArgonPolicy::minimum(),
            telegram_api: TelegramApiSettings::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            _ => Err(anyhow!("unsupported user role {raw}")),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct UserSecurityState {
    pub password_hash: Option<String>,
    pub password_argon_version: i64,
    pub kek_salt_b64: Option<String>,
    pub encrypted_master_key_json: Option<String>,
    pub totp_secret_json: Option<String>,
    pub totp_enabled: bool,
    pub password_needs_reset: bool,
    pub login_failures: u32,
    pub lockout_level: u32,
    pub locked_until_unix: Option<i64>,
    pub ban_active: bool,
    pub banned_until_unix: Option<i64>,
    pub ban_reason: Option<String>,
    pub last_login_ip: Option<String>,
    pub preferred_idle_timeout_minutes: Option<u32>,
    pub bot_notification_settings: BotNotificationSettings,
    pub passkeys: Vec<StoredPasskey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub security: UserSecurityState,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl UserRecord {
    pub fn new(username: impl Into<String>, role: UserRole) -> Self {
        let now = now_unix();
        Self {
            id: Uuid::new_v4().to_string(),
            username: username.into(),
            role,
            security: UserSecurityState::default(),
            created_at_unix: now,
            updated_at_unix: now,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEntry {
    pub action_type: String,
    pub actor_user_id: Option<String>,
    pub subject_user_id: Option<String>,
    pub ip_address: Option<String>,
    pub success: bool,
    pub created_at_unix: i64,
    pub details_json: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewAuditEntry {
    pub action_type: String,
    pub actor_user_id: Option<String>,
    pub subject_user_id: Option<String>,
    pub ip_address: Option<String>,
    pub success: bool,
    pub details_json: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRollup {
    pub action_type: String,
    pub total_count: i64,
    pub updated_at_unix: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthSessionRecord {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub last_seen_at_unix: i64,
    pub idle_timeout_minutes: Option<u32>,
    pub revoked_at_unix: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionRecord {
    pub id: String,
    pub user_id: String,
    pub session_key: String,
    pub storage_path: String,
    pub note: String,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl SessionRecord {
    pub fn new(
        user_id: impl Into<String>,
        session_key: impl Into<String>,
        storage_path: impl Into<String>,
    ) -> Self {
        let now = now_unix();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            session_key: session_key.into(),
            storage_path: storage_path.into(),
            note: String::new(),
            created_at_unix: now,
            updated_at_unix: now,
        }
    }
}

pub struct MetaStore {
    db: libsql::Database,
}

impl MetaStore {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Builder::new_local(path).build().await?;
        let store = Self { db };
        store.initialize().await?;
        Ok(store)
    }

    pub async fn open_memory() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("hanagram-meta-{}.sqlite", Uuid::new_v4()));
        let db = Builder::new_local(path).build().await?;
        let store = Self { db };
        store.initialize().await?;
        Ok(store)
    }

    pub async fn load_system_settings(&self) -> Result<SystemSettings> {
        let conn = self.connection()?;
        let mut statement = conn
            .prepare("SELECT value_json FROM metadata WHERE key = ?1 LIMIT 1")
            .await?;
        match statement.query_row([SYSTEM_SETTINGS_KEY]).await {
            Ok(row) => {
                let value: String = row
                    .get(0)
                    .context("failed to decode system settings json")?;
                serde_json::from_str(&value).context("failed to parse system settings json")
            }
            Err(libsql::Error::QueryReturnedNoRows) => {
                let defaults = SystemSettings::default();
                self.save_system_settings(&defaults).await?;
                Ok(defaults)
            }
            Err(error) => Err(error).context("failed reading system settings"),
        }
    }

    pub async fn save_system_settings(&self, settings: &SystemSettings) -> Result<()> {
        let conn = self.connection()?;
        let value =
            serde_json::to_string(settings).context("failed to encode system settings json")?;
        conn.execute(
            "INSERT INTO metadata (key, value_json) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            libsql::params![SYSTEM_SETTINGS_KEY, value],
        )
        .await
        .context("failed writing system settings")?;
        Ok(())
    }

    pub async fn count_users(&self) -> Result<i64> {
        let conn = self.connection()?;
        let mut statement = conn.prepare("SELECT COUNT(*) FROM users").await?;
        let row = statement
            .query_row(())
            .await
            .context("failed counting users")?;
        row.get(0).context("failed to decode user count")
    }

    pub async fn save_user(&self, user: &UserRecord) -> Result<()> {
        let conn = self.connection()?;
        if user.role == UserRole::Admin {
            let mut statement = conn
                .prepare("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?1")
                .await?;
            let row = statement
                .query_row([user.id.clone()])
                .await
                .context("failed checking for an existing admin user")?;
            let existing_admins: i64 =
                row.get(0).context("failed decoding existing admin count")?;
            anyhow::ensure!(existing_admins == 0, "only one admin account is allowed");
        }
        let payload_json =
            serde_json::to_string(&user.security).context("failed to encode user payload")?;
        conn.execute(
            "INSERT INTO users (id, username, role, payload_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                username = excluded.username,
                role = excluded.role,
                payload_json = excluded.payload_json,
                updated_at = excluded.updated_at",
            libsql::params![
                user.id.clone(),
                user.username.clone(),
                user.role.as_str(),
                payload_json,
                user.created_at_unix,
                user.updated_at_unix
            ],
        )
        .await
        .context("failed saving user")?;
        Ok(())
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<UserRecord>> {
        self.load_one_user(
            "SELECT id, username, role, payload_json, created_at, updated_at
             FROM users WHERE username = ?1 LIMIT 1",
            [username],
        )
        .await
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserRecord>> {
        self.load_one_user(
            "SELECT id, username, role, payload_json, created_at, updated_at
             FROM users WHERE id = ?1 LIMIT 1",
            [user_id],
        )
        .await
    }

    pub async fn list_users(&self) -> Result<Vec<UserRecord>> {
        let conn = self.connection()?;
        let statement = conn
            .prepare(
                "SELECT id, username, role, payload_json, created_at, updated_at
                 FROM users
                 ORDER BY created_at ASC, username ASC",
            )
            .await?;
        let mut rows = statement.query(()).await?;
        let mut users = Vec::new();

        while let Some(row) = rows.next().await? {
            users.push(decode_user_row(&row)?);
        }

        Ok(users)
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute("DELETE FROM users WHERE id = ?1", [user_id])
            .await
            .context("failed deleting user")?;
        Ok(())
    }

    pub async fn record_audit(&self, entry: &NewAuditEntry) -> Result<()> {
        let conn = self.connection()?;
        let now = now_unix();

        conn.execute(
            "INSERT INTO audit_logs (
                action_type,
                actor_user_id,
                subject_user_id,
                ip_address,
                success,
                created_at,
                details_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            libsql::params![
                entry.action_type.clone(),
                entry.actor_user_id.clone(),
                entry.subject_user_id.clone(),
                entry.ip_address.clone(),
                if entry.success { 1_i64 } else { 0_i64 },
                now,
                entry.details_json.clone()
            ],
        )
        .await
        .context("failed writing audit log entry")?;

        let detail_limit = self.load_system_settings().await?.audit_detail_limit;
        self.enforce_audit_retention(detail_limit).await
    }

    pub async fn create_auth_session(
        &self,
        user_id: &str,
        token_hash: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        expires_at_unix: i64,
        idle_timeout_minutes: Option<u32>,
    ) -> Result<AuthSessionRecord> {
        let conn = self.connection()?;
        let now = now_unix();
        let record = AuthSessionRecord {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_owned(),
            token_hash: token_hash.to_owned(),
            ip_address: ip_address.map(str::to_owned),
            user_agent: user_agent.map(str::to_owned),
            issued_at_unix: now,
            expires_at_unix,
            last_seen_at_unix: now,
            idle_timeout_minutes,
            revoked_at_unix: None,
        };

        conn.execute(
            "INSERT INTO auth_sessions (
                id, user_id, token_hash, ip_address, user_agent, issued_at, expires_at, last_seen_at, idle_timeout_minutes, revoked_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            libsql::params![
                record.id.clone(),
                record.user_id.clone(),
                record.token_hash.clone(),
                record.ip_address.clone(),
                record.user_agent.clone(),
                record.issued_at_unix,
                record.expires_at_unix,
                record.last_seen_at_unix,
                record.idle_timeout_minutes.map(i64::from),
                record.revoked_at_unix
            ],
        )
        .await
        .context("failed creating auth session")?;

        Ok(record)
    }

    pub async fn get_auth_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<AuthSessionRecord>> {
        self.load_one_auth_session(
            "SELECT id, user_id, token_hash, ip_address, user_agent, issued_at, expires_at, last_seen_at, idle_timeout_minutes, revoked_at
             FROM auth_sessions
             WHERE token_hash = ?1
             LIMIT 1",
            [token_hash],
        )
        .await
    }

    pub async fn get_auth_session_by_id(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthSessionRecord>> {
        self.load_one_auth_session(
            "SELECT id, user_id, token_hash, ip_address, user_agent, issued_at, expires_at, last_seen_at, idle_timeout_minutes, revoked_at
             FROM auth_sessions
             WHERE id = ?1
             LIMIT 1",
            [session_id],
        )
        .await
    }

    pub async fn list_auth_sessions_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<AuthSessionRecord>> {
        let conn = self.connection()?;
        let statement = conn
            .prepare(
                "SELECT id, user_id, token_hash, ip_address, user_agent, issued_at, expires_at, last_seen_at, idle_timeout_minutes, revoked_at
                 FROM auth_sessions
                 WHERE user_id = ?1
                 ORDER BY issued_at DESC, id DESC",
            )
            .await?;
        let mut rows = statement.query([user_id]).await?;
        let mut records = Vec::new();

        while let Some(row) = rows.next().await? {
            records.push(decode_auth_session_row(&row)?);
        }

        Ok(records)
    }

    pub async fn touch_auth_session(
        &self,
        session_id: &str,
        last_seen_at_unix: i64,
        ip_address: Option<&str>,
    ) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "UPDATE auth_sessions
             SET last_seen_at = ?2,
                 ip_address = COALESCE(?3, ip_address)
             WHERE id = ?1",
            libsql::params![session_id, last_seen_at_unix, ip_address.map(str::to_owned)],
        )
        .await
        .context("failed touching auth session")?;
        Ok(())
    }

    pub async fn revoke_auth_session(&self, session_id: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "UPDATE auth_sessions
             SET revoked_at = ?2
             WHERE id = ?1 AND revoked_at IS NULL",
            libsql::params![session_id, now_unix()],
        )
        .await
        .context("failed revoking auth session")?;
        Ok(())
    }

    pub async fn revoke_other_auth_sessions(
        &self,
        user_id: &str,
        keep_session_id: &str,
    ) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "UPDATE auth_sessions
             SET revoked_at = ?3
             WHERE user_id = ?1 AND id != ?2 AND revoked_at IS NULL",
            libsql::params![user_id, keep_session_id, now_unix()],
        )
        .await
        .context("failed revoking other auth sessions")?;
        Ok(())
    }

    pub async fn revoke_all_auth_sessions_for_user(&self, user_id: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "UPDATE auth_sessions
             SET revoked_at = ?2
             WHERE user_id = ?1 AND revoked_at IS NULL",
            libsql::params![user_id, now_unix()],
        )
        .await
        .context("failed revoking all auth sessions for user")?;
        Ok(())
    }

    pub async fn set_idle_timeout_for_user_sessions(
        &self,
        user_id: &str,
        idle_timeout_minutes: Option<u32>,
    ) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "UPDATE auth_sessions
             SET idle_timeout_minutes = ?2
             WHERE user_id = ?1 AND revoked_at IS NULL",
            libsql::params![user_id, idle_timeout_minutes.map(i64::from)],
        )
        .await
        .context("failed updating user auth session idle timeout")?;
        Ok(())
    }

    pub async fn replace_recovery_codes(
        &self,
        user_id: &str,
        code_hashes: &[String],
    ) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "DELETE FROM user_recovery_codes WHERE user_id = ?1",
            [user_id],
        )
        .await
        .context("failed deleting existing recovery codes")?;

        let now = now_unix();
        for code_hash in code_hashes {
            conn.execute(
                "INSERT INTO user_recovery_codes (id, user_id, code_hash, created_at, used_at)
                 VALUES (?1, ?2, ?3, ?4, NULL)",
                libsql::params![
                    Uuid::new_v4().to_string(),
                    user_id.to_owned(),
                    code_hash.clone(),
                    now
                ],
            )
            .await
            .context("failed inserting recovery code")?;
        }

        Ok(())
    }

    pub async fn list_active_recovery_code_hashes(
        &self,
        user_id: &str,
    ) -> Result<Vec<(String, String)>> {
        let conn = self.connection()?;
        let statement = conn
            .prepare(
                "SELECT id, code_hash
                 FROM user_recovery_codes
                 WHERE user_id = ?1 AND used_at IS NULL
                 ORDER BY created_at ASC, id ASC",
            )
            .await?;
        let mut rows = statement.query([user_id]).await?;
        let mut codes = Vec::new();

        while let Some(row) = rows.next().await? {
            let id: String = row.get(0).context("failed to decode recovery code id")?;
            let code_hash: String = row.get(1).context("failed to decode recovery code hash")?;
            codes.push((id, code_hash));
        }

        Ok(codes)
    }

    pub async fn count_active_recovery_codes(&self, user_id: &str) -> Result<i64> {
        let conn = self.connection()?;
        let mut statement = conn
            .prepare(
                "SELECT COUNT(*)
                 FROM user_recovery_codes
                 WHERE user_id = ?1 AND used_at IS NULL",
            )
            .await?;
        let row = statement
            .query_row([user_id])
            .await
            .context("failed counting active recovery codes")?;
        row.get(0)
            .context("failed decoding active recovery code count")
    }

    pub async fn mark_recovery_code_used(&self, recovery_code_id: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "UPDATE user_recovery_codes
             SET used_at = ?2
             WHERE id = ?1 AND used_at IS NULL",
            libsql::params![recovery_code_id, now_unix()],
        )
        .await
        .context("failed marking recovery code as used")?;
        Ok(())
    }

    pub async fn list_recent_totp_steps(&self, user_id: &str, min_step: i64) -> Result<Vec<i64>> {
        let conn = self.connection()?;
        let statement = conn
            .prepare(
                "SELECT time_step
                 FROM used_totp_steps
                 WHERE user_id = ?1 AND time_step >= ?2
                 ORDER BY time_step DESC",
            )
            .await?;
        let mut rows = statement
            .query(libsql::params![user_id.to_owned(), min_step])
            .await?;
        let mut steps = Vec::new();

        while let Some(row) = rows.next().await? {
            steps.push(row.get(0).context("failed to decode used totp step")?);
        }

        Ok(steps)
    }

    pub async fn mark_totp_step_used(&self, user_id: &str, time_step: i64) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "INSERT INTO used_totp_steps (user_id, time_step, consumed_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id, time_step) DO NOTHING",
            libsql::params![user_id.to_owned(), time_step, now_unix()],
        )
        .await
        .context("failed recording totp step")?;
        Ok(())
    }

    pub async fn prune_used_totp_steps(&self, min_step: i64) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "DELETE FROM used_totp_steps WHERE time_step < ?1",
            [min_step],
        )
        .await
        .context("failed pruning old totp steps")?;
        Ok(())
    }

    pub async fn clear_used_totp_steps_for_user(&self, user_id: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute("DELETE FROM used_totp_steps WHERE user_id = ?1", [user_id])
            .await
            .context("failed clearing used totp steps for user")?;
        Ok(())
    }

    pub async fn save_session_record(&self, record: &SessionRecord) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "INSERT INTO session_records (id, user_id, session_key, storage_path, note, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                session_key = excluded.session_key,
                storage_path = excluded.storage_path,
                note = excluded.note,
                updated_at = excluded.updated_at",
            libsql::params![
                record.id.clone(),
                record.user_id.clone(),
                record.session_key.clone(),
                record.storage_path.clone(),
                record.note.clone(),
                record.created_at_unix,
                record.updated_at_unix
            ],
        )
        .await
        .context("failed saving session record")?;
        Ok(())
    }

    pub async fn get_session_record_by_id(&self, record_id: &str) -> Result<Option<SessionRecord>> {
        self.load_one_session_record(
            "SELECT id, user_id, session_key, storage_path, note, created_at, updated_at
             FROM session_records
             WHERE id = ?1
             LIMIT 1",
            [record_id],
        )
        .await
    }

    pub async fn get_session_record_by_user_and_key(
        &self,
        user_id: &str,
        session_key: &str,
    ) -> Result<Option<SessionRecord>> {
        self.load_one_session_record(
            "SELECT id, user_id, session_key, storage_path, note, created_at, updated_at
             FROM session_records
             WHERE user_id = ?1 AND session_key = ?2
             LIMIT 1",
            libsql::params![user_id.to_owned(), session_key.to_owned()],
        )
        .await
    }

    pub async fn list_session_records_for_user(&self, user_id: &str) -> Result<Vec<SessionRecord>> {
        let conn = self.connection()?;
        let statement = conn
            .prepare(
                "SELECT id, user_id, session_key, storage_path, note, created_at, updated_at
                 FROM session_records
                 WHERE user_id = ?1
                 ORDER BY updated_at DESC, session_key ASC",
            )
            .await?;
        let mut rows = statement.query([user_id]).await?;
        let mut records = Vec::new();

        while let Some(row) = rows.next().await? {
            records.push(decode_session_record_row(&row)?);
        }

        Ok(records)
    }

    pub async fn list_all_session_records(&self) -> Result<Vec<SessionRecord>> {
        let conn = self.connection()?;
        let statement = conn
            .prepare(
                "SELECT id, user_id, session_key, storage_path, note, created_at, updated_at
                 FROM session_records
                 ORDER BY created_at ASC, session_key ASC",
            )
            .await?;
        let mut rows = statement.query(()).await?;
        let mut records = Vec::new();

        while let Some(row) = rows.next().await? {
            records.push(decode_session_record_row(&row)?);
        }

        Ok(records)
    }

    pub async fn delete_session_record(&self, record_id: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute("DELETE FROM session_records WHERE id = ?1", [record_id])
            .await
            .context("failed deleting session record")?;
        Ok(())
    }

    pub async fn list_audit_logs(&self) -> Result<Vec<AuditEntry>> {
        let conn = self.connection()?;
        let statement = conn
            .prepare(
                "SELECT action_type, actor_user_id, subject_user_id, ip_address, success, created_at, details_json
                 FROM audit_logs
                 ORDER BY created_at DESC, rowid DESC",
            )
            .await?;
        let mut rows = statement.query(()).await?;
        let mut logs = Vec::new();

        while let Some(row) = rows.next().await? {
            logs.push(AuditEntry {
                action_type: row.get(0).context("failed to decode audit action type")?,
                actor_user_id: row.get(1).context("failed to decode audit actor user id")?,
                subject_user_id: row
                    .get(2)
                    .context("failed to decode audit subject user id")?,
                ip_address: row.get(3).context("failed to decode audit ip")?,
                success: {
                    let value: i64 = row.get(4).context("failed to decode audit success flag")?;
                    value != 0
                },
                created_at_unix: row.get(5).context("failed to decode audit timestamp")?,
                details_json: row.get(6).context("failed to decode audit details json")?,
            });
        }

        Ok(logs)
    }

    pub async fn list_audit_rollups(&self) -> Result<Vec<AuditRollup>> {
        let conn = self.connection()?;
        let statement = conn
            .prepare(
                "SELECT action_type, total_count, updated_at
                 FROM audit_rollups
                 ORDER BY updated_at DESC, action_type ASC",
            )
            .await?;
        let mut rows = statement.query(()).await?;
        let mut rollups = Vec::new();

        while let Some(row) = rows.next().await? {
            rollups.push(AuditRollup {
                action_type: row.get(0).context("failed to decode rollup action type")?,
                total_count: row.get(1).context("failed to decode rollup count")?,
                updated_at_unix: row.get(2).context("failed to decode rollup timestamp")?,
            });
        }

        Ok(rollups)
    }

    async fn initialize(&self) -> Result<()> {
        let conn = self.connection()?;
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;

        conn.execute(SCHEMA_STATEMENTS[0], ())
            .await
            .with_context(|| {
                format!("failed running schema statement: {}", SCHEMA_STATEMENTS[0])
            })?;
        self.ensure_schema_version().await?;

        for statement in &SCHEMA_STATEMENTS[1..] {
            conn.execute(statement, ())
                .await
                .with_context(|| format!("failed running schema statement: {statement}"))?;
        }

        self.ensure_single_admin().await?;

        if self
            .load_system_settings()
            .await
            .context("failed to bootstrap default system settings")?
            .audit_detail_limit
            == 0
        {
            self.save_system_settings(&SystemSettings::default())
                .await?;
        }

        Ok(())
    }

    async fn ensure_schema_version(&self) -> Result<()> {
        let conn = self.connection()?;
        let mut statement = conn
            .prepare("SELECT value_json FROM metadata WHERE key = ?1 LIMIT 1")
            .await?;
        match statement.query_row([SCHEMA_VERSION_KEY]).await {
            Ok(row) => {
                let value: String = row.get(0).context("failed to decode schema version json")?;
                let version: i64 =
                    serde_json::from_str(&value).context("failed to parse schema version json")?;
                anyhow::ensure!(version == APP_SCHEMA_VERSION, INCOMPATIBLE_SCHEMA_MESSAGE);
                Ok(())
            }
            Err(libsql::Error::QueryReturnedNoRows) => {
                if self.has_legacy_schema().await? {
                    anyhow::bail!(INCOMPATIBLE_SCHEMA_MESSAGE);
                }

                let encoded = serde_json::to_string(&APP_SCHEMA_VERSION)
                    .context("failed to encode schema version")?;
                conn.execute(
                    "INSERT INTO metadata (key, value_json) VALUES (?1, ?2)",
                    libsql::params![SCHEMA_VERSION_KEY, encoded],
                )
                .await
                .context("failed writing schema version")?;
                Ok(())
            }
            Err(error) => Err(error).context("failed reading schema version"),
        }
    }

    async fn has_legacy_schema(&self) -> Result<bool> {
        let conn = self.connection()?;
        let mut statement = conn
            .prepare(
                "SELECT COUNT(*)
                 FROM sqlite_master
                 WHERE name IN (
                    'users',
                    'auth_sessions',
                    'user_recovery_codes',
                    'used_totp_steps',
                    'session_records',
                    'audit_logs',
                    'audit_rollups'
                 )",
            )
            .await?;
        let row = statement
            .query_row(())
            .await
            .context("failed checking existing schema objects")?;
        let count: i64 = row
            .get(0)
            .context("failed decoding existing schema object count")?;
        Ok(count > 0)
    }

    async fn ensure_single_admin(&self) -> Result<()> {
        let conn = self.connection()?;
        let mut statement = conn
            .prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            .await?;
        let row = statement
            .query_row(())
            .await
            .context("failed counting admin users")?;
        let admin_count: i64 = row.get(0).context("failed decoding admin user count")?;
        anyhow::ensure!(
            admin_count <= 1,
            "metadata database contains multiple admin users; delete .hanagram/app.db and restart"
        );
        Ok(())
    }

    async fn enforce_audit_retention(&self, detail_limit: u32) -> Result<()> {
        if detail_limit == 0 {
            return Ok(());
        }

        let conn = self.connection()?;
        let mut count_statement = conn.prepare("SELECT COUNT(*) FROM audit_logs").await?;
        let count_row = count_statement
            .query_row(())
            .await
            .context("failed counting audit logs")?;
        let audit_count: i64 = count_row
            .get(0)
            .context("failed to decode audit log count")?;
        let overflow = audit_count - i64::from(detail_limit);
        if overflow <= 0 {
            return Ok(());
        }

        let oldest_statement = conn
            .prepare(
                "SELECT rowid, action_type
                 FROM audit_logs
                 ORDER BY created_at ASC, rowid ASC
                 LIMIT ?1",
            )
            .await?;
        let mut rows = oldest_statement.query([overflow]).await?;
        let mut archived_rows = Vec::new();

        while let Some(row) = rows.next().await? {
            let rowid: i64 = row.get(0).context("failed to decode audit rowid")?;
            let action_type: String = row.get(1).context("failed to decode audit action type")?;
            archived_rows.push((rowid, action_type));
        }

        let now = now_unix();
        for (rowid, action_type) in archived_rows {
            conn.execute(
                "INSERT INTO audit_rollups (action_type, total_count, updated_at)
                 VALUES (?1, 1, ?2)
                 ON CONFLICT(action_type) DO UPDATE SET
                    total_count = audit_rollups.total_count + 1,
                    updated_at = excluded.updated_at",
                libsql::params![action_type, now],
            )
            .await
            .context("failed updating audit rollup")?;
            conn.execute("DELETE FROM audit_logs WHERE rowid = ?1", [rowid])
                .await
                .context("failed deleting archived audit detail row")?;
        }

        Ok(())
    }

    async fn load_one_user<T>(&self, sql: &str, params: T) -> Result<Option<UserRecord>>
    where
        T: libsql::params::IntoParams,
    {
        let conn = self.connection()?;
        let mut statement = conn.prepare(sql).await?;

        match statement.query_row(params).await {
            Ok(row) => Ok(Some(decode_user_row(&row)?)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error).context("failed reading user row"),
        }
    }

    async fn load_one_auth_session<T>(
        &self,
        sql: &str,
        params: T,
    ) -> Result<Option<AuthSessionRecord>>
    where
        T: libsql::params::IntoParams,
    {
        let conn = self.connection()?;
        let mut statement = conn.prepare(sql).await?;

        match statement.query_row(params).await {
            Ok(row) => Ok(Some(decode_auth_session_row(&row)?)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error).context("failed reading auth session row"),
        }
    }

    async fn load_one_session_record<T>(
        &self,
        sql: &str,
        params: T,
    ) -> Result<Option<SessionRecord>>
    where
        T: libsql::params::IntoParams,
    {
        let conn = self.connection()?;
        let mut statement = conn.prepare(sql).await?;

        match statement.query_row(params).await {
            Ok(row) => Ok(Some(decode_session_record_row(&row)?)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error).context("failed reading session record row"),
        }
    }

    fn connection(&self) -> Result<Connection> {
        self.db
            .connect()
            .map_err(|error| anyhow!("failed to open metadata connection: {error}"))
    }
}

const SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE UNIQUE INDEX IF NOT EXISTS users_single_admin_role_idx
     ON users(role)
     WHERE role = 'admin'",
    "CREATE TABLE IF NOT EXISTS auth_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        ip_address TEXT,
        user_agent TEXT,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        idle_timeout_minutes INTEGER,
        revoked_at INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )",
    "CREATE TABLE IF NOT EXISTS user_recovery_codes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        used_at INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )",
    "CREATE TABLE IF NOT EXISTS used_totp_steps (
        user_id TEXT NOT NULL,
        time_step INTEGER NOT NULL,
        consumed_at INTEGER NOT NULL,
        PRIMARY KEY(user_id, time_step),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )",
    "CREATE TABLE IF NOT EXISTS session_records (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        session_key TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(user_id, session_key),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )",
    "CREATE TABLE IF NOT EXISTS audit_logs (
        action_type TEXT NOT NULL,
        actor_user_id TEXT,
        subject_user_id TEXT,
        ip_address TEXT,
        success INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        details_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS audit_rollups (
        action_type TEXT PRIMARY KEY,
        total_count INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
];

fn decode_user_row(row: &libsql::Row) -> Result<UserRecord> {
    let payload_json: String = row.get(3).context("failed to decode user payload json")?;
    let security =
        serde_json::from_str(&payload_json).context("failed to parse user payload json")?;
    let role_raw: String = row.get(2).context("failed to decode user role")?;

    Ok(UserRecord {
        id: row.get(0).context("failed to decode user id")?,
        username: row.get(1).context("failed to decode username")?,
        role: UserRole::parse(&role_raw)?,
        security,
        created_at_unix: row
            .get(4)
            .context("failed to decode user created timestamp")?,
        updated_at_unix: row
            .get(5)
            .context("failed to decode user updated timestamp")?,
    })
}

fn decode_auth_session_row(row: &libsql::Row) -> Result<AuthSessionRecord> {
    let idle_timeout_minutes = row
        .get::<Option<i64>>(8)
        .context("failed to decode auth session idle timeout")?
        .map(|value| u32::try_from(value).unwrap_or(u32::MAX));

    Ok(AuthSessionRecord {
        id: row.get(0).context("failed to decode auth session id")?,
        user_id: row
            .get(1)
            .context("failed to decode auth session user id")?,
        token_hash: row
            .get(2)
            .context("failed to decode auth session token hash")?,
        ip_address: row.get(3).context("failed to decode auth session ip")?,
        user_agent: row
            .get(4)
            .context("failed to decode auth session user agent")?,
        issued_at_unix: row
            .get(5)
            .context("failed to decode auth session issued at")?,
        expires_at_unix: row
            .get(6)
            .context("failed to decode auth session expires at")?,
        last_seen_at_unix: row
            .get(7)
            .context("failed to decode auth session last seen")?,
        idle_timeout_minutes,
        revoked_at_unix: row
            .get(9)
            .context("failed to decode auth session revoked at")?,
    })
}

fn decode_session_record_row(row: &libsql::Row) -> Result<SessionRecord> {
    Ok(SessionRecord {
        id: row.get(0).context("failed to decode session record id")?,
        user_id: row
            .get(1)
            .context("failed to decode session record user id")?,
        session_key: row
            .get(2)
            .context("failed to decode session record session key")?,
        storage_path: row
            .get(3)
            .context("failed to decode session record storage path")?,
        note: row.get(4).context("failed to decode session record note")?,
        created_at_unix: row
            .get(5)
            .context("failed to decode session record created at")?,
        updated_at_unix: row
            .get(6)
            .context("failed to decode session record updated at")?,
    })
}

fn now_unix() -> i64 {
    Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{PasswordVerification, hash_password, verify_password};

    #[tokio::test]
    async fn meta_store_round_trips_system_settings_and_users() {
        let store = MetaStore::open_memory()
            .await
            .expect("metadata store should open in memory");

        let mut settings = store
            .load_system_settings()
            .await
            .expect("default settings should load");
        settings.registration_policy = RegistrationPolicy::AdminSelectable;
        settings.public_registration_open = true;
        settings.argon_policy = settings.argon_policy.clone().raised(2, 96 * 1024, 4, 2);
        store
            .save_system_settings(&settings)
            .await
            .expect("settings should save");

        let loaded = store
            .load_system_settings()
            .await
            .expect("settings should reload");
        assert_eq!(loaded, settings);

        let mut admin = UserRecord::new("alice", UserRole::Admin);
        admin.security.password_hash = Some(
            hash_password("CorrectHorseBatteryStaple!1", &ArgonPolicy::minimum())
                .expect("password hashing should succeed"),
        );
        admin.security.password_argon_version = ArgonPolicy::minimum().version;
        admin.updated_at_unix = now_unix();
        store.save_user(&admin).await.expect("user should save");

        assert_eq!(
            store.count_users().await.expect("user count should load"),
            1
        );

        let loaded_admin = store
            .get_user_by_username("alice")
            .await
            .expect("user lookup should work")
            .expect("user should exist");
        let password_hash = loaded_admin
            .security
            .password_hash
            .clone()
            .expect("user password hash should exist");
        assert_eq!(
            verify_password(
                "CorrectHorseBatteryStaple!1",
                &password_hash,
                loaded_admin.security.password_argon_version,
                &loaded.argon_policy,
            )
            .expect("password verification should succeed"),
            PasswordVerification::ValidNeedsRehash
        );
    }

    #[tokio::test]
    async fn audit_retention_rolls_old_rows_into_rollups() {
        let store = MetaStore::open_memory()
            .await
            .expect("metadata store should open in memory");
        let mut settings = store
            .load_system_settings()
            .await
            .expect("settings should load");
        settings.audit_detail_limit = 2;
        store
            .save_system_settings(&settings)
            .await
            .expect("settings should save");

        for index in 0..4 {
            store
                .record_audit(&NewAuditEntry {
                    action_type: String::from("login_failed"),
                    actor_user_id: None,
                    subject_user_id: None,
                    ip_address: Some(format!("203.0.113.{index}")),
                    success: false,
                    details_json: format!(r#"{{"attempt":{index}}}"#),
                })
                .await
                .expect("audit entry should save");
        }

        let details = store
            .list_audit_logs()
            .await
            .expect("audit logs should load");
        let rollups = store
            .list_audit_rollups()
            .await
            .expect("audit rollups should load");

        assert_eq!(details.len(), 2);
        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].action_type, "login_failed");
        assert_eq!(rollups[0].total_count, 2);
    }
}
