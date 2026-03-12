// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine;
use grammers_session::storages::SqliteSession;
use grammers_session::types::{
    ChannelState, DcOption, PeerId, PeerInfo, PeerKind, UpdateState, UpdatesState,
};
use grammers_session::{Session, SessionData};
use libsql::{Builder, OpenFlags};
use tracing::warn;

type SessionFuture<'a, T> = std::pin::Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;
const TELETHON_STRING_VERSION: char = '1';
const TELETHON_AUTH_KEY_LEN: usize = 256;
const TELETHON_IPV4_BYTES: usize = 4;
const TELETHON_IPV6_BYTES: usize = 16;

pub(crate) enum LoadedSession {
    Native(SqliteSession),
    Converted(TelethonMemorySession),
}

impl Session for LoadedSession {
    fn home_dc_id(&self) -> i32 {
        match self {
            Self::Native(session) => session.home_dc_id(),
            Self::Converted(session) => session.home_dc_id(),
        }
    }

    fn set_home_dc_id(&self, dc_id: i32) -> SessionFuture<'_, ()> {
        match self {
            Self::Native(session) => session.set_home_dc_id(dc_id),
            Self::Converted(session) => session.set_home_dc_id(dc_id),
        }
    }

    fn dc_option(&self, dc_id: i32) -> Option<DcOption> {
        match self {
            Self::Native(session) => session.dc_option(dc_id),
            Self::Converted(session) => session.dc_option(dc_id),
        }
    }

    fn set_dc_option(&self, dc_option: &DcOption) -> SessionFuture<'_, ()> {
        match self {
            Self::Native(session) => session.set_dc_option(dc_option),
            Self::Converted(session) => session.set_dc_option(dc_option),
        }
    }

    fn peer(&self, peer: PeerId) -> SessionFuture<'_, Option<PeerInfo>> {
        match self {
            Self::Native(session) => session.peer(peer),
            Self::Converted(session) => session.peer(peer),
        }
    }

    fn cache_peer(&self, peer: &PeerInfo) -> SessionFuture<'_, ()> {
        match self {
            Self::Native(session) => session.cache_peer(peer),
            Self::Converted(session) => session.cache_peer(peer),
        }
    }

    fn updates_state(&self) -> SessionFuture<'_, UpdatesState> {
        match self {
            Self::Native(session) => session.updates_state(),
            Self::Converted(session) => session.updates_state(),
        }
    }

    fn set_update_state(&self, update: UpdateState) -> SessionFuture<'_, ()> {
        match self {
            Self::Native(session) => session.set_update_state(update),
            Self::Converted(session) => session.set_update_state(update),
        }
    }
}

pub(crate) async fn load_session(path: &Path) -> Option<LoadedSession> {
    match probe_telethon_session(path).await {
        TelethonProbe::Record(record) => {
            build_converted_session(path, record).map(LoadedSession::Converted)
        }
        TelethonProbe::Empty => {
            warn!(
                "telethon session file {} does not contain any session rows; skipping",
                path.display()
            );
            None
        }
        TelethonProbe::Invalid => None,
        TelethonProbe::NotTelethon => match SqliteSession::open(path).await {
            Ok(session) => Some(LoadedSession::Native(session)),
            Err(error) => {
                warn!(
                    "failed to load {} as grammers sqlite session: {}",
                    path.display(),
                    error
                );
                None
            }
        },
    }
}

pub(crate) async fn save_telethon_string_session(path: &Path, session_string: &str) -> Result<()> {
    let record = parse_telethon_string_session(session_string)?;
    let session_data = build_telethon_session_data(path, record)
        .map_err(|error| anyhow!(error))
        .with_context(|| {
            format!(
                "failed to import telethon string session into {}",
                path.display()
            )
        })?;

    persist_session_data(path, &session_data).await
}

pub(crate) async fn persist_session_data(path: &Path, session_data: &SessionData) -> Result<()> {
    let session = SqliteSession::open(path)
        .await
        .with_context(|| format!("failed to open sqlite session {}", path.display()))?;
    session_data.import_to(&session).await;
    Ok(())
}

#[derive(Debug)]
struct TelethonSessionRecord {
    dc_id: i32,
    server_address: String,
    port: i32,
    auth_key: Vec<u8>,
}

enum TelethonProbe {
    Record(TelethonSessionRecord),
    Empty,
    Invalid,
    NotTelethon,
}

async fn probe_telethon_session(path: &Path) -> TelethonProbe {
    let database = match Builder::new_local(path)
        .flags(OpenFlags::SQLITE_OPEN_READ_ONLY)
        .build()
        .await
    {
        Ok(database) => database,
        Err(_) => return TelethonProbe::NotTelethon,
    };

    let connection = match database.connect() {
        Ok(connection) => connection,
        Err(_) => return TelethonProbe::NotTelethon,
    };

    let mut statement = match connection
        .prepare("SELECT dc_id, server_address, port, auth_key FROM sessions LIMIT 1")
        .await
    {
        Ok(statement) => statement,
        Err(error) if is_missing_table_error(&error) => return TelethonProbe::NotTelethon,
        Err(error) => {
            warn!(
                "failed to inspect {} for telethon session data: {}",
                path.display(),
                error
            );
            return TelethonProbe::Invalid;
        }
    };

    match statement.query_row(()).await {
        Ok(row) => match (row.get(0), row.get(1), row.get(2), row.get(3)) {
            (Ok(dc_id), Ok(server_address), Ok(port), Ok(auth_key)) => {
                TelethonProbe::Record(TelethonSessionRecord {
                    dc_id,
                    server_address,
                    port,
                    auth_key,
                })
            }
            (dc_id, server_address, port, auth_key) => {
                let error = dc_id
                    .err()
                    .or_else(|| server_address.err())
                    .or_else(|| port.err())
                    .or_else(|| auth_key.err())
                    .expect("row decoding should return at least one error");
                warn!(
                    "failed reading telethon session row from {}: {}",
                    path.display(),
                    error
                );
                TelethonProbe::Invalid
            }
        },
        Err(libsql::Error::QueryReturnedNoRows) => TelethonProbe::Empty,
        Err(error) => {
            warn!(
                "failed reading telethon session row from {}: {}",
                path.display(),
                error
            );
            TelethonProbe::Invalid
        }
    }
}

fn is_missing_table_error(error: &libsql::Error) -> bool {
    match error {
        libsql::Error::SqliteFailure(_, message) => message.contains("no such table"),
        _ => false,
    }
}

fn build_converted_session(
    path: &Path,
    record: TelethonSessionRecord,
) -> Option<TelethonMemorySession> {
    let data = match build_telethon_session_data(path, record) {
        Ok(data) => data,
        Err(error) => {
            warn!("{error}");
            return None;
        }
    };

    Some(TelethonMemorySession::from(data))
}

fn build_telethon_session_data(
    path: &Path,
    record: TelethonSessionRecord,
) -> std::result::Result<SessionData, String> {
    let port = match u16::try_from(record.port) {
        Ok(port) if port > 0 => port,
        Ok(_) | Err(_) => {
            return Err(format!(
                "invalid port {} in telethon session {}; skipping",
                record.port,
                path.display()
            ));
        }
    };

    let auth_key: [u8; TELETHON_AUTH_KEY_LEN] = match record.auth_key.try_into() {
        Ok(auth_key) => auth_key,
        Err(auth_key) => {
            return Err(format!(
                "unsupported auth_key length {} in telethon session {}; expected 256 bytes for current grammers-session",
                auth_key.len(),
                path.display()
            ));
        }
    };

    let mut data = SessionData::default();
    data.home_dc = record.dc_id;

    let existing = data.dc_options.remove(&record.dc_id);
    let had_existing = existing.is_some();
    let mut dc_option = match existing {
        Some(option) => option,
        None => default_dc_option(record.dc_id, port),
    };

    match parse_dc_addresses(&record.server_address, port) {
        Some((ipv4, ipv6)) => {
            dc_option.ipv4 = ipv4;
            dc_option.ipv6 = ipv6;
        }
        None if had_existing => {
            warn!(
                "could not parse server address '{}' in telethon session {}; using known default DC address",
                record.server_address,
                path.display()
            );
        }
        None => {
            return Err(format!(
                "could not parse server address '{}' in telethon session {}; skipping",
                record.server_address,
                path.display()
            ));
        }
    }

    dc_option.auth_key = Some(auth_key);
    data.dc_options.insert(record.dc_id, dc_option);

    Ok(data)
}

fn parse_telethon_string_session(session_string: &str) -> Result<TelethonSessionRecord> {
    let session_string = session_string.trim();
    ensure!(!session_string.is_empty(), "session string is empty");

    let mut chars = session_string.chars();
    let version = chars
        .next()
        .context("session string is missing a version prefix")?;
    ensure!(
        version == TELETHON_STRING_VERSION,
        "unsupported telethon string session version {}",
        version
    );

    let encoded = chars.as_str();
    let payload = decode_telethon_string_payload(encoded)?;
    let expected_ipv4_len = 1 + TELETHON_IPV4_BYTES + 2 + TELETHON_AUTH_KEY_LEN;
    let expected_ipv6_len = 1 + TELETHON_IPV6_BYTES + 2 + TELETHON_AUTH_KEY_LEN;
    let server_bytes_len = match payload.len() {
        len if len == expected_ipv4_len => TELETHON_IPV4_BYTES,
        len if len == expected_ipv6_len => TELETHON_IPV6_BYTES,
        len => {
            return Err(anyhow!(
                "unexpected telethon string session payload length {}; expected {} or {} bytes",
                len,
                expected_ipv4_len,
                expected_ipv6_len
            ));
        }
    };

    let dc_id = i32::from(payload[0]);
    let server_end = 1 + server_bytes_len;
    let port_end = server_end + 2;

    let server_address = if server_bytes_len == TELETHON_IPV4_BYTES {
        let bytes: [u8; TELETHON_IPV4_BYTES] = payload[1..server_end]
            .try_into()
            .map_err(|_| anyhow!("invalid IPv4 payload length in telethon string session"))?;
        Ipv4Addr::from(bytes).to_string()
    } else {
        let bytes: [u8; TELETHON_IPV6_BYTES] = payload[1..server_end]
            .try_into()
            .map_err(|_| anyhow!("invalid IPv6 payload length in telethon string session"))?;
        Ipv6Addr::from(bytes).to_string()
    };

    let port = u16::from_be_bytes(
        payload[server_end..port_end]
            .try_into()
            .map_err(|_| anyhow!("invalid port bytes in telethon string session"))?,
    );
    let auth_key = payload[port_end..].to_vec();
    ensure!(
        auth_key.iter().any(|byte| *byte != 0),
        "telethon string session does not contain an authorization key"
    );

    Ok(TelethonSessionRecord {
        dc_id,
        server_address,
        port: i32::from(port),
        auth_key,
    })
}

fn decode_telethon_string_payload(encoded: &str) -> Result<Vec<u8>> {
    let mut normalized = encoded.trim().to_owned();
    let missing_padding = normalized.len() % 4;
    if missing_padding != 0 {
        normalized.push_str(&"=".repeat(4 - missing_padding));
    }

    base64::engine::general_purpose::URL_SAFE
        .decode(normalized)
        .context("failed to decode telethon string session as urlsafe base64")
}

fn default_dc_option(dc_id: i32, port: u16) -> DcOption {
    DcOption {
        id: dc_id,
        ipv4: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
        ipv6: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0),
        auth_key: None,
    }
}

fn parse_dc_addresses(server_address: &str, port: u16) -> Option<(SocketAddrV4, SocketAddrV6)> {
    if let Ok(ipv4) = server_address.parse::<Ipv4Addr>() {
        return Some((
            SocketAddrV4::new(ipv4, port),
            SocketAddrV6::new(ipv4.to_ipv6_mapped(), port, 0, 0),
        ));
    }

    if let Ok(ipv6) = server_address.parse::<Ipv6Addr>() {
        let fallback_ipv4 = match ipv6.to_ipv4_mapped() {
            Some(mapped) => mapped,
            None => Ipv4Addr::UNSPECIFIED,
        };

        return Some((
            SocketAddrV4::new(fallback_ipv4, port),
            SocketAddrV6::new(ipv6, port, 0, 0),
        ));
    }

    None
}

pub(crate) struct TelethonMemorySession(Mutex<SessionData>);

impl From<SessionData> for TelethonMemorySession {
    fn from(session_data: SessionData) -> Self {
        Self(Mutex::new(session_data))
    }
}

impl TelethonMemorySession {
    fn lock_data(&self) -> MutexGuard<'_, SessionData> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Session for TelethonMemorySession {
    fn home_dc_id(&self) -> i32 {
        self.lock_data().home_dc
    }

    fn set_home_dc_id(&self, dc_id: i32) -> SessionFuture<'_, ()> {
        Box::pin(async move {
            self.lock_data().home_dc = dc_id;
        })
    }

    fn dc_option(&self, dc_id: i32) -> Option<DcOption> {
        self.lock_data().dc_options.get(&dc_id).cloned()
    }

    fn set_dc_option(&self, dc_option: &DcOption) -> SessionFuture<'_, ()> {
        let dc_option = dc_option.clone();

        Box::pin(async move {
            self.lock_data().dc_options.insert(dc_option.id, dc_option);
        })
    }

    fn peer(&self, peer: PeerId) -> SessionFuture<'_, Option<PeerInfo>> {
        Box::pin(async move {
            let data = self.lock_data();

            if peer.kind() == PeerKind::UserSelf {
                return data
                    .peer_infos
                    .values()
                    .find(|info| {
                        matches!(
                            info,
                            PeerInfo::User {
                                is_self: Some(true),
                                ..
                            }
                        )
                    })
                    .cloned();
            }

            data.peer_infos.get(&peer).cloned()
        })
    }

    fn cache_peer(&self, peer: &PeerInfo) -> SessionFuture<'_, ()> {
        let peer = peer.clone();

        Box::pin(async move {
            self.lock_data().peer_infos.insert(peer.id(), peer);
        })
    }

    fn updates_state(&self) -> SessionFuture<'_, UpdatesState> {
        Box::pin(async move { self.lock_data().updates_state.clone() })
    }

    fn set_update_state(&self, update: UpdateState) -> SessionFuture<'_, ()> {
        Box::pin(async move {
            let mut data = self.lock_data();

            match update {
                UpdateState::All(updates_state) => {
                    data.updates_state = updates_state;
                }
                UpdateState::Primary { pts, date, seq } => {
                    data.updates_state.pts = pts;
                    data.updates_state.date = date;
                    data.updates_state.seq = seq;
                }
                UpdateState::Secondary { qts } => {
                    data.updates_state.qts = qts;
                }
                UpdateState::Channel { id, pts } => {
                    data.updates_state
                        .channels
                        .retain(|channel| channel.id != id);
                    data.updates_state.channels.push(ChannelState { id, pts });
                }
            }
        })
    }
}
