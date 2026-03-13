// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use hanagram_web::account_reset::reset_user_account;
use hanagram_web::store::{MetaStore, NewAuditEntry, UserRole};
use serde_json::json;

const META_DB_FILE_NAME: &str = "app.db";

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let sessions_dir = std::env::var("SESSIONS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./sessions"));
    let meta_db_path = sessions_dir.join(".hanagram").join(META_DB_FILE_NAME);
    let users_dir = sessions_dir.join("users");

    ensure!(
        meta_db_path.exists(),
        "metadata database was not found at {}",
        meta_db_path.display()
    );

    let store = MetaStore::open(&meta_db_path).await.with_context(|| {
        format!(
            "failed opening metadata database {}",
            meta_db_path.display()
        )
    })?;
    let mut admins = store
        .list_users()
        .await?
        .into_iter()
        .filter(|user| user.role == UserRole::Admin)
        .collect::<Vec<_>>();

    ensure!(
        admins.len() == 1,
        "expected exactly one admin account, found {}",
        admins.len()
    );

    let mut admin = admins.remove(0);
    let username = admin.username.clone();
    let settings = store.load_system_settings().await?;
    let reset_result =
        reset_user_account(&store, &mut admin, &users_dir, &settings.argon_policy).await?;

    let _ = store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_cli_reset"),
            actor_user_id: None,
            subject_user_id: Some(admin.id.clone()),
            ip_address: None,
            success: true,
            details_json: json!({
                "username": username,
                "session_records_removed": reset_result.session_record_ids.len(),
                "auth_sessions_revoked": reset_result.auth_session_ids.len()
            })
            .to_string(),
        })
        .await;

    println!(
        "Admin account '{}' was reset.\nTemporary password: {}\nSign in with it, then change the password immediately.",
        admin.username, reset_result.temporary_password
    );

    Ok(())
}
