// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::collections::{HashSet, VecDeque};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use hanagram_web::security::{EncryptedBlob, decrypt_bytes, encrypt_bytes};

use crate::state::OtpMessage;

const CACHE_FILE_SUFFIX: &str = ".json.enc";
const CACHE_SCHEMA_VERSION: u32 = 1;
const MAX_CACHE_MESSAGES_PER_SESSION: usize = 32;
pub(crate) const MAX_HOT_MESSAGES_PER_SESSION: usize = 5;
const MAX_CACHE_BYTES_PER_SESSION: usize = 192 * 1024;
const MAX_CACHE_BYTES_TOTAL: u64 = 16 * 1024 * 1024;
const CACHE_ZSTD_LEVEL: i32 = 7;

#[derive(Clone)]
pub(crate) struct RuntimeCache {
    root_dir: PathBuf,
    io_guard: Arc<Mutex<()>>,
}

pub(crate) type RuntimeCacheHandle = Arc<RuntimeCache>;

#[derive(Debug, Default)]
pub(crate) struct RuntimeCacheGcReport {
    pub removed_files: usize,
    pub reclaimed_bytes: u64,
    pub retained_files: usize,
    pub retained_bytes: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct RuntimeCacheEntry {
    schema_version: u32,
    updated_at_unix: i64,
    recent_messages: Vec<CachedOtpMessage>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CachedOtpMessage {
    received_at_unix: i64,
    text: String,
    code: Option<String>,
}

#[derive(Clone, Debug)]
struct CacheFileRecord {
    path: PathBuf,
    session_id: String,
    size: u64,
    modified_at_unix: u64,
}

impl RuntimeCache {
    pub(crate) async fn open(root_dir: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&root_dir)
            .await
            .with_context(|| {
                format!("failed to create runtime cache dir {}", root_dir.display())
            })?;
        Ok(Self {
            root_dir,
            io_guard: Arc::new(Mutex::new(())),
        })
    }

    pub(crate) async fn load_hot_messages(
        &self,
        master_key: &[u8],
        session_id: &str,
    ) -> Result<VecDeque<OtpMessage>> {
        let _guard = self.io_guard.lock().await;
        let path = self.cache_path(session_id);
        let Some(entry) = self.read_entry(master_key, &path).await? else {
            return Ok(VecDeque::new());
        };

        Ok(entry
            .recent_messages
            .into_iter()
            .take(MAX_HOT_MESSAGES_PER_SESSION)
            .map(CachedOtpMessage::into_otp_message)
            .collect())
    }

    pub(crate) async fn append_message(
        &self,
        master_key: &[u8],
        session_id: &str,
        otp: &OtpMessage,
    ) -> Result<()> {
        let _guard = self.io_guard.lock().await;
        let path = self.cache_path(session_id);
        let mut entry = self
            .read_entry(master_key, &path)
            .await?
            .unwrap_or_else(RuntimeCacheEntry::default);
        let cached = CachedOtpMessage::from_otp_message(otp);

        if entry
            .recent_messages
            .first()
            .is_some_and(|message| message == &cached)
        {
            return Ok(());
        }

        entry.schema_version = CACHE_SCHEMA_VERSION;
        entry.updated_at_unix = Utc::now().timestamp();
        entry.recent_messages.insert(0, cached);
        Self::trim_entry_for_budget(master_key, &mut entry)?;
        self.write_entry(master_key, &path, &entry).await
    }

    pub(crate) async fn remove_session(&self, session_id: &str) -> Result<()> {
        let _guard = self.io_guard.lock().await;
        match tokio::fs::remove_file(self.cache_path(session_id)).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed removing runtime cache {}",
                    self.cache_path(session_id).display()
                )
            }),
        }
    }

    pub(crate) async fn perform_maintenance(
        &self,
        valid_session_ids: &HashSet<String>,
    ) -> Result<RuntimeCacheGcReport> {
        let _guard = self.io_guard.lock().await;
        tokio::fs::create_dir_all(&self.root_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create runtime cache dir {}",
                    self.root_dir.display()
                )
            })?;

        let mut report = RuntimeCacheGcReport::default();
        let mut records = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.root_dir)
            .await
            .with_context(|| format!("failed reading {}", self.root_dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = match entry.metadata().await {
                Ok(metadata) => metadata,
                Err(error) => {
                    tracing::warn!(
                        "failed reading runtime cache metadata {}: {}",
                        path.display(),
                        error
                    );
                    continue;
                }
            };
            if !metadata.is_file() {
                continue;
            }

            let Some(session_id) = session_id_from_cache_path(&path) else {
                report.reclaimed_bytes += metadata.len();
                report.removed_files += 1;
                let _ = tokio::fs::remove_file(&path).await;
                continue;
            };

            if !valid_session_ids.contains(&session_id) {
                report.reclaimed_bytes += metadata.len();
                report.removed_files += 1;
                let _ = tokio::fs::remove_file(&path).await;
                continue;
            }

            let modified_at_unix = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_secs())
                .unwrap_or_default();

            records.push(CacheFileRecord {
                path,
                session_id,
                size: metadata.len(),
                modified_at_unix,
            });
        }

        let mut total_bytes = records.iter().map(|record| record.size).sum::<u64>();
        if total_bytes > MAX_CACHE_BYTES_TOTAL {
            records.sort_by_key(|record| (record.modified_at_unix, record.session_id.clone()));
            for record in &records {
                if total_bytes <= MAX_CACHE_BYTES_TOTAL {
                    break;
                }

                total_bytes = total_bytes.saturating_sub(record.size);
                report.reclaimed_bytes += record.size;
                report.removed_files += 1;
                let _ = tokio::fs::remove_file(&record.path).await;
            }

            records.retain(|record| record.path.exists());
        }

        report.retained_files = records.len();
        report.retained_bytes = records.iter().map(|record| record.size).sum();
        Ok(report)
    }

    fn cache_path(&self, session_id: &str) -> PathBuf {
        self.root_dir
            .join(format!("{session_id}{CACHE_FILE_SUFFIX}"))
    }

    fn trim_entry_for_budget(master_key: &[u8], entry: &mut RuntimeCacheEntry) -> Result<()> {
        while entry.recent_messages.len() > MAX_CACHE_MESSAGES_PER_SESSION {
            entry.recent_messages.pop();
        }

        while !entry.recent_messages.is_empty()
            && Self::encoded_entry_len(master_key, entry)? > MAX_CACHE_BYTES_PER_SESSION
        {
            entry.recent_messages.pop();
        }

        Ok(())
    }

    fn encoded_entry_len(master_key: &[u8], entry: &RuntimeCacheEntry) -> Result<usize> {
        let packed = pack_runtime_cache_bytes(entry)?;
        let encrypted = encrypt_bytes(master_key, &packed)?;
        let encoded =
            serde_json::to_vec(&encrypted).context("failed to encode runtime cache blob")?;
        Ok(encoded.len())
    }

    async fn read_entry(
        &self,
        master_key: &[u8],
        path: &Path,
    ) -> Result<Option<RuntimeCacheEntry>> {
        let raw = match tokio::fs::read(path).await {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed reading runtime cache {}", path.display()));
            }
        };
        let payload: EncryptedBlob = serde_json::from_slice(&raw)
            .with_context(|| format!("failed decoding runtime cache blob {}", path.display()))?;
        let decrypted = decrypt_bytes(master_key, &payload)?;
        let entry = unpack_runtime_cache_bytes(decrypted.as_slice())
            .with_context(|| format!("failed parsing runtime cache {}", path.display()))?;
        if entry.schema_version != CACHE_SCHEMA_VERSION {
            return Ok(Some(RuntimeCacheEntry {
                schema_version: CACHE_SCHEMA_VERSION,
                ..entry
            }));
        }
        Ok(Some(entry))
    }

    async fn write_entry(
        &self,
        master_key: &[u8],
        path: &Path,
        entry: &RuntimeCacheEntry,
    ) -> Result<()> {
        let packed = pack_runtime_cache_bytes(entry)?;
        let encrypted = encrypt_bytes(master_key, &packed)?;
        let encoded =
            serde_json::to_vec(&encrypted).context("failed to encode runtime cache blob")?;
        tokio::fs::write(path, encoded)
            .await
            .with_context(|| format!("failed writing runtime cache {}", path.display()))
    }
}

impl CachedOtpMessage {
    fn from_otp_message(message: &OtpMessage) -> Self {
        Self {
            received_at_unix: message.received_at.timestamp(),
            text: message.text.clone(),
            code: message.code.clone(),
        }
    }

    fn into_otp_message(self) -> OtpMessage {
        OtpMessage {
            received_at: DateTime::from_timestamp(self.received_at_unix, 0)
                .unwrap_or_else(Utc::now),
            text: self.text,
            code: self.code,
        }
    }
}

impl PartialEq for CachedOtpMessage {
    fn eq(&self, other: &Self) -> bool {
        self.received_at_unix == other.received_at_unix
            && self.text == other.text
            && self.code == other.code
    }
}

fn session_id_from_cache_path(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_str()?;
    file_name
        .strip_suffix(CACHE_FILE_SUFFIX)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn pack_runtime_cache_bytes(entry: &RuntimeCacheEntry) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(entry).context("failed to encode runtime cache json")?;
    let compressed = zstd::stream::encode_all(Cursor::new(&json), CACHE_ZSTD_LEVEL)
        .context("failed compressing runtime cache json")?;
    if compressed.len() + 8 < json.len() {
        Ok(compressed)
    } else {
        Ok(json)
    }
}

fn unpack_runtime_cache_bytes(raw: &[u8]) -> Result<RuntimeCacheEntry> {
    if let Ok(entry) = serde_json::from_slice::<RuntimeCacheEntry>(raw) {
        return Ok(entry);
    }

    let decompressed = zstd::stream::decode_all(Cursor::new(raw))
        .context("failed decompressing runtime cache payload")?;
    serde_json::from_slice(&decompressed).context("failed decoding runtime cache json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_cache_dir() -> PathBuf {
        std::env::temp_dir().join(format!("hanagram-runtime-cache-{}", Uuid::new_v4()))
    }

    fn sample_message(text: &str, code: Option<&str>) -> OtpMessage {
        OtpMessage {
            received_at: Utc::now(),
            text: text.to_owned(),
            code: code.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn runtime_cache_round_trips_hot_messages() {
        let root_dir = test_cache_dir();
        let cache = RuntimeCache::open(root_dir.clone())
            .await
            .expect("runtime cache should open");
        let master_key = [17_u8; 32];

        cache
            .append_message(
                &master_key,
                "session-a",
                &sample_message("Code 12345", Some("12345")),
            )
            .await
            .expect("message should append");
        cache
            .append_message(
                &master_key,
                "session-a",
                &sample_message("Code 67890", Some("67890")),
            )
            .await
            .expect("message should append");

        let messages = cache
            .load_hot_messages(&master_key, "session-a")
            .await
            .expect("hot messages should load");

        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages.front().and_then(|message| message.code.as_deref()),
            Some("67890")
        );

        let _ = tokio::fs::remove_dir_all(root_dir).await;
    }

    #[tokio::test]
    async fn runtime_cache_maintenance_removes_orphans() {
        let root_dir = test_cache_dir();
        let cache = RuntimeCache::open(root_dir.clone())
            .await
            .expect("runtime cache should open");
        let master_key = [23_u8; 32];

        cache
            .append_message(
                &master_key,
                "keep",
                &sample_message("Code 12345", Some("12345")),
            )
            .await
            .expect("message should append");
        cache
            .append_message(
                &master_key,
                "drop",
                &sample_message("Code 67890", Some("67890")),
            )
            .await
            .expect("message should append");

        let valid = HashSet::from([String::from("keep")]);
        let report = cache
            .perform_maintenance(&valid)
            .await
            .expect("maintenance should succeed");

        assert_eq!(report.removed_files, 1);
        assert!(cache.cache_path("keep").exists());
        assert!(!cache.cache_path("drop").exists());

        let _ = tokio::fs::remove_dir_all(root_dir).await;
    }
}
