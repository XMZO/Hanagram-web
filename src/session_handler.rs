// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use grammers_session::storages::SqliteSession;
use grammers_session::types::{
    ChannelState, DcOption, PeerId, PeerInfo, PeerKind, UpdateState, UpdatesState,
};
use grammers_session::{Session, SessionData};
use libsql::{Builder, OpenFlags};
use tracing::warn;

type SessionFuture<'a, T> = std::pin::Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;

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
    let port = match u16::try_from(record.port) {
        Ok(port) if port > 0 => port,
        Ok(_) | Err(_) => {
            warn!(
                "invalid port {} in telethon session {}; skipping",
                record.port,
                path.display()
            );
            return None;
        }
    };

    let auth_key: [u8; 256] = match record.auth_key.try_into() {
        Ok(auth_key) => auth_key,
        Err(auth_key) => {
            warn!(
                "unsupported auth_key length {} in telethon session {}; expected 256 bytes for current grammers-session",
                auth_key.len(),
                path.display()
            );
            return None;
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
            warn!(
                "could not parse server address '{}' in telethon session {}; skipping",
                record.server_address,
                path.display()
            );
            return None;
        }
    }

    dc_option.auth_key = Some(auth_key);
    data.dc_options.insert(record.dc_id, dc_option);

    Some(TelethonMemorySession::from(data))
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
