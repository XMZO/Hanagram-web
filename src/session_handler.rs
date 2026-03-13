// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use std::collections::HashMap;
use std::ffi::CStr;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use grammers_session::types::{
    ChannelKind, ChannelState, DcOption, PeerAuth, PeerId, PeerInfo, PeerKind, UpdateState,
    UpdatesState,
};
use grammers_session::{Session, SessionData};
use hanagram_web::security::{SensitiveBytes, into_sensitive_bytes};
use libsql_sys::ffi;
use libsql_sys::rusqlite::{self, Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tracing::warn;

type SessionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

const TELETHON_STRING_VERSION: char = '1';
const TELETHON_AUTH_KEY_LEN: usize = 256;
const TELETHON_IPV4_BYTES: usize = 4;
const TELETHON_IPV6_BYTES: usize = 16;
const GRAMMERS_SQLITE_VERSION: i64 = 1;
const PEER_SUBTYPE_USER_SELF: u8 = 1;
const PEER_SUBTYPE_USER_BOT: u8 = 2;
const PEER_SUBTYPE_USER_SELF_BOT: u8 = 3;
const PEER_SUBTYPE_MEGAGROUP: u8 = 4;
const PEER_SUBTYPE_BROADCAST: u8 = 8;
const PEER_SUBTYPE_GIGAGROUP: u8 = 12;
const SQLITE_MAIN_DB: &[u8] = b"main\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct PersistedSessionData {
    home_dc: i32,
    dc_options: HashMap<i32, DcOption>,
    peer_infos: HashMap<PeerId, PeerInfo>,
    updates_state: UpdatesState,
}

impl Default for PersistedSessionData {
    fn default() -> Self {
        SessionData::default().into()
    }
}

impl From<SessionData> for PersistedSessionData {
    fn from(data: SessionData) -> Self {
        Self {
            home_dc: data.home_dc,
            dc_options: data.dc_options,
            peer_infos: data.peer_infos,
            updates_state: data.updates_state,
        }
    }
}

impl From<PersistedSessionData> for SessionData {
    fn from(data: PersistedSessionData) -> Self {
        Self {
            home_dc: data.home_dc,
            dc_options: data.dc_options,
            peer_infos: data.peer_infos,
            updates_state: data.updates_state,
        }
    }
}

pub(crate) struct LoadedSession(Mutex<PersistedSessionData>);

pub(crate) struct SessionLoadResult {
    pub session: LoadedSession,
    pub needs_persist: bool,
}

impl Default for LoadedSession {
    fn default() -> Self {
        Self::from(SessionData::default())
    }
}

impl From<SessionData> for LoadedSession {
    fn from(session_data: SessionData) -> Self {
        Self(Mutex::new(session_data.into()))
    }
}

impl From<PersistedSessionData> for LoadedSession {
    fn from(session_data: PersistedSessionData) -> Self {
        Self(Mutex::new(session_data))
    }
}

impl LoadedSession {
    pub(crate) fn snapshot(&self) -> PersistedSessionData {
        self.lock_data().clone()
    }

    fn lock_data(&self) -> MutexGuard<'_, PersistedSessionData> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Session for LoadedSession {
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

pub(crate) fn load_session(raw: &[u8]) -> Result<SessionLoadResult> {
    if let Ok(snapshot) = serde_json::from_slice::<PersistedSessionData>(raw) {
        return Ok(SessionLoadResult {
            session: LoadedSession::from(snapshot),
            needs_persist: false,
        });
    }

    let session_data = load_sqlite_session_data(raw)?;
    Ok(SessionLoadResult {
        session: LoadedSession::from(session_data),
        needs_persist: true,
    })
}

pub(crate) fn serialize_session(session: &LoadedSession) -> Result<SensitiveBytes> {
    serde_json::to_vec(&session.snapshot())
        .map(into_sensitive_bytes)
        .context("failed to encode session snapshot")
}

pub(crate) fn load_telethon_string_session(session_string: &str) -> Result<LoadedSession> {
    let record = parse_telethon_string_session(session_string)?;
    let session_data = build_telethon_session_data("telethon string", record)
        .map_err(|error| anyhow!(error))
        .context("failed to import telethon string session")?;
    Ok(LoadedSession::from(session_data))
}

pub(crate) fn export_telethon_string_session(session: &LoadedSession) -> Result<String> {
    let record = build_export_record(&session.snapshot())?;
    encode_telethon_string_session(&record)
}

pub(crate) fn export_sqlite_session_bytes(session: &LoadedSession) -> Result<SensitiveBytes> {
    let snapshot = session.snapshot();
    let connection = Connection::open_in_memory().context("failed to open sqlite export buffer")?;
    initialize_grammers_schema(&connection)?;
    write_grammers_session_data(&connection, &snapshot)?;
    serialize_sqlite_bytes(&connection)
}

fn load_sqlite_session_data(raw: &[u8]) -> Result<SessionData> {
    let connection = open_sqlite_bytes(raw)?;
    match probe_telethon_session(&connection)? {
        TelethonProbe::Record(record) => {
            build_telethon_session_data("sqlite session", record).map_err(|error| anyhow!(error))
        }
        TelethonProbe::Empty => bail!("the sqlite session file does not contain any session rows"),
        TelethonProbe::Invalid => bail!("the sqlite session file could not be parsed"),
        TelethonProbe::NotTelethon => load_grammers_session_data(&connection),
    }
}

fn open_sqlite_bytes(raw: &[u8]) -> Result<Connection> {
    let connection =
        Connection::open_in_memory().context("failed to open in-memory sqlite buffer")?;
    let size = raw.len();
    let buffer = unsafe { ffi::sqlite3_malloc64(size as u64) as *mut u8 };
    ensure!(
        !buffer.is_null(),
        "failed allocating sqlite deserialize buffer"
    );

    unsafe {
        std::ptr::copy_nonoverlapping(raw.as_ptr(), buffer, size);
    }

    let rc = unsafe {
        ffi::sqlite3_deserialize(
            connection.handle(),
            SQLITE_MAIN_DB.as_ptr().cast(),
            buffer.cast(),
            size as i64,
            size as i64,
            (ffi::SQLITE_DESERIALIZE_FREEONCLOSE | ffi::SQLITE_DESERIALIZE_READONLY) as u32,
        )
    };
    if rc != ffi::SQLITE_OK {
        unsafe {
            ffi::sqlite3_free(buffer.cast());
        }
        bail!("{}", sqlite_error_message(&connection, rc));
    }
    Ok(connection)
}

fn serialize_sqlite_bytes(connection: &Connection) -> Result<SensitiveBytes> {
    let mut size: i64 = 0;
    let pointer = unsafe {
        ffi::sqlite3_serialize(
            connection.handle(),
            SQLITE_MAIN_DB.as_ptr().cast(),
            &mut size,
            0,
        )
    };
    ensure!(
        !pointer.is_null(),
        "{}",
        sqlite_error_message(connection, unsafe {
            ffi::sqlite3_errcode(connection.handle())
        })
    );

    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), size as usize).to_vec() };
    unsafe {
        ffi::sqlite3_free(pointer.cast());
    }
    Ok(into_sensitive_bytes(bytes))
}

fn sqlite_error_message(connection: &Connection, code: i32) -> String {
    let message = unsafe {
        CStr::from_ptr(ffi::sqlite3_errmsg(connection.handle()))
            .to_string_lossy()
            .into_owned()
    };
    format!("sqlite error {code}: {message}")
}

fn initialize_grammers_schema(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            "
            CREATE TABLE dc_home (
                dc_id INTEGER NOT NULL,
                PRIMARY KEY(dc_id)
            );
            CREATE TABLE dc_option (
                dc_id INTEGER NOT NULL,
                ipv4 TEXT NOT NULL,
                ipv6 TEXT NOT NULL,
                auth_key BLOB,
                PRIMARY KEY (dc_id)
            );
            CREATE TABLE peer_info (
                peer_id INTEGER NOT NULL,
                hash INTEGER,
                subtype INTEGER,
                PRIMARY KEY (peer_id)
            );
            CREATE TABLE update_state (
                pts INTEGER NOT NULL,
                qts INTEGER NOT NULL,
                date INTEGER NOT NULL,
                seq INTEGER NOT NULL
            );
            CREATE TABLE channel_state (
                peer_id INTEGER NOT NULL,
                pts INTEGER NOT NULL,
                PRIMARY KEY (peer_id)
            );
            ",
        )
        .context("failed to initialize sqlite session schema")?;
    connection
        .pragma_update(None, "user_version", GRAMMERS_SQLITE_VERSION)
        .context("failed to set sqlite session schema version")?;
    Ok(())
}

fn write_grammers_session_data(
    connection: &Connection,
    snapshot: &PersistedSessionData,
) -> Result<()> {
    let transaction = connection
        .unchecked_transaction()
        .context("failed to start sqlite session export transaction")?;

    transaction
        .execute("DELETE FROM dc_home", [])
        .context("failed clearing dc_home during export")?;
    transaction
        .execute("DELETE FROM dc_option", [])
        .context("failed clearing dc_option during export")?;
    transaction
        .execute("DELETE FROM peer_info", [])
        .context("failed clearing peer_info during export")?;
    transaction
        .execute("DELETE FROM update_state", [])
        .context("failed clearing update_state during export")?;
    transaction
        .execute("DELETE FROM channel_state", [])
        .context("failed clearing channel_state during export")?;

    transaction
        .execute(
            "INSERT INTO dc_home (dc_id) VALUES (?1)",
            params![snapshot.home_dc],
        )
        .context("failed writing dc_home during export")?;

    {
        let mut statement = transaction
            .prepare("INSERT INTO dc_option (dc_id, ipv4, ipv6, auth_key) VALUES (?1, ?2, ?3, ?4)")
            .context("failed preparing dc_option export statement")?;
        for option in snapshot.dc_options.values() {
            statement
                .execute(params![
                    option.id,
                    option.ipv4.to_string(),
                    option.ipv6.to_string(),
                    option.auth_key.map(|key| key.to_vec())
                ])
                .with_context(|| format!("failed writing dc option {}", option.id))?;
        }
    }

    {
        let mut statement = transaction
            .prepare("INSERT INTO peer_info (peer_id, hash, subtype) VALUES (?1, ?2, ?3)")
            .context("failed preparing peer_info export statement")?;
        for peer in snapshot.peer_infos.values() {
            statement
                .execute(params![
                    peer.id().bot_api_dialog_id(),
                    peer.auth().map(|auth| auth.hash()),
                    peer_subtype(peer).map(i64::from)
                ])
                .context("failed writing peer info during export")?;
        }
    }

    transaction
        .execute(
            "INSERT INTO update_state (pts, qts, date, seq) VALUES (?1, ?2, ?3, ?4)",
            params![
                snapshot.updates_state.pts,
                snapshot.updates_state.qts,
                snapshot.updates_state.date,
                snapshot.updates_state.seq
            ],
        )
        .context("failed writing update_state during export")?;

    {
        let mut statement = transaction
            .prepare("INSERT INTO channel_state (peer_id, pts) VALUES (?1, ?2)")
            .context("failed preparing channel_state export statement")?;
        for channel in &snapshot.updates_state.channels {
            statement
                .execute(params![channel.id, channel.pts])
                .context("failed writing channel_state during export")?;
        }
    }

    transaction
        .commit()
        .context("failed committing sqlite session export transaction")
}

fn load_grammers_session_data(connection: &Connection) -> Result<SessionData> {
    let home_dc = connection
        .query_row("SELECT dc_id FROM dc_home LIMIT 1", [], |row| row.get(0))
        .optional()
        .context("failed reading grammers home dc")?
        .unwrap_or_default();

    let mut dc_options = HashMap::new();
    {
        let mut statement = connection
            .prepare("SELECT dc_id, ipv4, ipv6, auth_key FROM dc_option")
            .context("failed preparing dc_option query")?;
        let rows = statement
            .query_map([], |row| {
                let auth_key = row.get::<_, Option<Vec<u8>>>(3)?.map(|value| {
                    value.try_into().map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Blob,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid auth key length",
                            )),
                        )
                    })
                });
                let auth_key = match auth_key {
                    Some(Ok(value)) => Some(value),
                    Some(Err(error)) => return Err(error),
                    None => None,
                };

                Ok(DcOption {
                    id: row.get(0)?,
                    ipv4: row
                        .get::<_, String>(1)?
                        .parse()
                        .map_err(to_sqlite_decode_error)?,
                    ipv6: row
                        .get::<_, String>(2)?
                        .parse()
                        .map_err(to_sqlite_decode_error)?,
                    auth_key,
                })
            })
            .context("failed reading dc_option rows")?;

        for row in rows {
            let option = row.context("failed decoding dc option row")?;
            dc_options.insert(option.id, option);
        }
    }

    let mut peer_infos = HashMap::new();
    {
        let mut statement = connection
            .prepare("SELECT peer_id, hash, subtype FROM peer_info")
            .context("failed preparing peer_info query")?;
        let rows = statement
            .query_map([], |row| {
                let dialog_id = row.get::<_, i64>(0)?;
                let hash = row.get::<_, Option<i64>>(1)?;
                let subtype = row.get::<_, Option<i64>>(2)?.map(|value| value as u8);
                let peer_id = peer_id_from_dialog_id(dialog_id).map_err(to_sqlite_decode_error)?;
                let peer_info =
                    peer_info_from_parts(peer_id, hash, subtype).map_err(to_sqlite_decode_error)?;
                Ok((peer_id, peer_info))
            })
            .context("failed reading peer_info rows")?;

        for row in rows {
            let (peer_id, peer_info) = row.context("failed decoding peer_info row")?;
            peer_infos.insert(peer_id, peer_info);
        }
    }

    let mut updates_state = connection
        .query_row(
            "SELECT pts, qts, date, seq FROM update_state LIMIT 1",
            [],
            |row| {
                Ok(UpdatesState {
                    pts: row.get(0)?,
                    qts: row.get(1)?,
                    date: row.get(2)?,
                    seq: row.get(3)?,
                    channels: Vec::new(),
                })
            },
        )
        .optional()
        .context("failed reading update_state row")?
        .unwrap_or_default();

    {
        let mut statement = connection
            .prepare("SELECT peer_id, pts FROM channel_state")
            .context("failed preparing channel_state query")?;
        let rows = statement
            .query_map([], |row| {
                Ok(ChannelState {
                    id: row.get(0)?,
                    pts: row.get(1)?,
                })
            })
            .context("failed reading channel_state rows")?;
        for row in rows {
            updates_state
                .channels
                .push(row.context("failed decoding channel_state row")?);
        }
    }

    Ok(SessionData {
        home_dc,
        dc_options,
        peer_infos,
        updates_state,
    })
}

fn to_sqlite_decode_error(error: impl Into<anyhow::Error>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.into().to_string(),
        )),
    )
}

fn peer_id_from_dialog_id(dialog_id: i64) -> Result<PeerId> {
    if (1..=0xffffffffff).contains(&dialog_id) {
        return Ok(PeerId::user(dialog_id));
    }
    if (-999999999999..=-1).contains(&dialog_id) {
        return Ok(PeerId::chat(-dialog_id));
    }
    if (-1997852516352..=-1000000000001).contains(&dialog_id)
        || (-4000000000000..=-2002147483649).contains(&dialog_id)
    {
        return Ok(PeerId::channel(-dialog_id - 1000000000000));
    }
    bail!("unsupported peer dialog id {dialog_id}")
}

fn peer_info_from_parts(
    peer_id: PeerId,
    hash: Option<i64>,
    subtype: Option<u8>,
) -> Result<PeerInfo> {
    Ok(match peer_id.kind() {
        PeerKind::User | PeerKind::UserSelf => PeerInfo::User {
            id: peer_id.bare_id(),
            auth: hash.map(PeerAuth::from_hash),
            bot: subtype.map(|value| value & PEER_SUBTYPE_USER_BOT != 0),
            is_self: subtype.map(|value| value & PEER_SUBTYPE_USER_SELF != 0),
        },
        PeerKind::Chat => PeerInfo::Chat {
            id: peer_id.bare_id(),
        },
        PeerKind::Channel => PeerInfo::Channel {
            id: peer_id.bare_id(),
            auth: hash.map(PeerAuth::from_hash),
            kind: subtype.and_then(channel_kind_from_subtype),
        },
    })
}

fn channel_kind_from_subtype(subtype: u8) -> Option<ChannelKind> {
    if (subtype & PEER_SUBTYPE_GIGAGROUP) == PEER_SUBTYPE_GIGAGROUP {
        Some(ChannelKind::Gigagroup)
    } else if subtype & PEER_SUBTYPE_BROADCAST != 0 {
        Some(ChannelKind::Broadcast)
    } else if subtype & PEER_SUBTYPE_MEGAGROUP != 0 {
        Some(ChannelKind::Megagroup)
    } else {
        None
    }
}

fn peer_subtype(peer: &PeerInfo) -> Option<u8> {
    match peer {
        PeerInfo::User { bot, is_self, .. } => {
            match (bot.unwrap_or_default(), is_self.unwrap_or_default()) {
                (true, true) => Some(PEER_SUBTYPE_USER_SELF_BOT),
                (true, false) => Some(PEER_SUBTYPE_USER_BOT),
                (false, true) => Some(PEER_SUBTYPE_USER_SELF),
                (false, false) => None,
            }
        }
        PeerInfo::Chat { .. } => None,
        PeerInfo::Channel { kind, .. } => kind.map(|kind| match kind {
            ChannelKind::Megagroup => PEER_SUBTYPE_MEGAGROUP,
            ChannelKind::Broadcast => PEER_SUBTYPE_BROADCAST,
            ChannelKind::Gigagroup => PEER_SUBTYPE_GIGAGROUP,
        }),
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

fn probe_telethon_session(connection: &Connection) -> Result<TelethonProbe> {
    let mut statement = match connection
        .prepare("SELECT dc_id, server_address, port, auth_key FROM sessions LIMIT 1")
    {
        Ok(statement) => statement,
        Err(error) if is_missing_table_error(&error) => return Ok(TelethonProbe::NotTelethon),
        Err(error) => {
            warn!(
                "failed to inspect sqlite bytes for telethon session data: {}",
                error
            );
            return Ok(TelethonProbe::Invalid);
        }
    };

    let result = statement
        .query_row([], |row| {
            Ok(TelethonSessionRecord {
                dc_id: row.get(0)?,
                server_address: row.get(1)?,
                port: row.get(2)?,
                auth_key: row.get(3)?,
            })
        })
        .optional();

    match result {
        Ok(Some(record)) => Ok(TelethonProbe::Record(record)),
        Ok(None) => Ok(TelethonProbe::Empty),
        Err(error) => {
            warn!(
                "failed reading telethon session row from sqlite bytes: {}",
                error
            );
            Ok(TelethonProbe::Invalid)
        }
    }
}

fn is_missing_table_error(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("no such table")
    )
}

fn build_telethon_session_data(
    source: &str,
    record: TelethonSessionRecord,
) -> std::result::Result<SessionData, String> {
    let port = match u16::try_from(record.port) {
        Ok(port) if port > 0 => port,
        Ok(_) | Err(_) => {
            return Err(format!(
                "invalid port {} in telethon session {}; skipping",
                record.port, source
            ));
        }
    };

    let auth_key: [u8; TELETHON_AUTH_KEY_LEN] = match record.auth_key.try_into() {
        Ok(auth_key) => auth_key,
        Err(auth_key) => {
            return Err(format!(
                "unsupported auth_key length {} in telethon session {}; expected 256 bytes",
                auth_key.len(),
                source
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
                record.server_address, source
            );
        }
        None => {
            return Err(format!(
                "could not parse server address '{}' in telethon session {}; skipping",
                record.server_address, source
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

fn build_export_record(snapshot: &PersistedSessionData) -> Result<TelethonSessionRecord> {
    let dc_id = snapshot.home_dc;
    let dc_option = snapshot
        .dc_options
        .get(&dc_id)
        .with_context(|| format!("the session does not contain datacenter option {dc_id}"))?;
    let auth_key = dc_option
        .auth_key
        .context("the session does not contain an authorization key")?;
    let (server_address, port) =
        choose_export_address(&dc_option.ipv4.to_string(), &dc_option.ipv6.to_string())?;

    Ok(TelethonSessionRecord {
        dc_id,
        server_address,
        port: i32::from(port),
        auth_key: auth_key.to_vec(),
    })
}

fn encode_telethon_string_session(record: &TelethonSessionRecord) -> Result<String> {
    let dc_id = u8::try_from(record.dc_id)
        .context("telethon string export only supports dc identifiers in the 1-255 range")?;
    let port = u16::try_from(record.port).context("session export contains an invalid port")?;
    ensure!(
        record.auth_key.len() == TELETHON_AUTH_KEY_LEN,
        "telethon string export requires a 256-byte authorization key"
    );

    let mut payload = Vec::with_capacity(1 + TELETHON_IPV6_BYTES + 2 + TELETHON_AUTH_KEY_LEN);
    payload.push(dc_id);

    if let Ok(ipv4) = record.server_address.parse::<Ipv4Addr>() {
        payload.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = record.server_address.parse::<Ipv6Addr>() {
        payload.extend_from_slice(&ipv6.octets());
    } else {
        return Err(anyhow!(
            "session export contains an unsupported server address '{}'",
            record.server_address
        ));
    }

    payload.extend_from_slice(&port.to_be_bytes());
    payload.extend_from_slice(&record.auth_key);

    Ok(format!(
        "{TELETHON_STRING_VERSION}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
    ))
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

fn choose_export_address(ipv4: &str, ipv6: &str) -> Result<(String, u16)> {
    if let Ok(socket) = ipv4.parse::<SocketAddrV4>() {
        if !socket.ip().is_unspecified() {
            return Ok((socket.ip().to_string(), socket.port()));
        }
    }

    if let Ok(socket) = ipv6.parse::<SocketAddrV6>() {
        if !socket.ip().is_unspecified() {
            return Ok((socket.ip().to_string(), socket.port()));
        }
    }

    Err(anyhow!(
        "the session does not contain an exportable datacenter address"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsql::Builder;

    fn sample_session() -> LoadedSession {
        let mut data = SessionData::default();
        data.home_dc = 2;
        data.peer_infos.insert(
            PeerId::user(12345),
            PeerInfo::User {
                id: 12345,
                auth: Some(PeerAuth::from_hash(67890)),
                bot: Some(false),
                is_self: Some(true),
            },
        );
        data.updates_state = UpdatesState {
            pts: 10,
            qts: 20,
            date: 30,
            seq: 40,
            channels: vec![ChannelState { id: 777, pts: 50 }],
        };
        LoadedSession::from(data)
    }

    fn ensure_libsql_initialized_for_tests() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build temporary runtime");
        runtime.block_on(async {
            let database = Builder::new_local(":memory:")
                .build()
                .await
                .expect("open libsql in-memory database");
            drop(database);
        });
    }

    #[test]
    fn snapshot_json_round_trips() {
        let session = sample_session();
        let encoded = serialize_session(&session).expect("encode session");
        let decoded = load_session(encoded.as_slice()).expect("decode session");
        assert!(!decoded.needs_persist);
        assert_eq!(decoded.session.snapshot(), session.snapshot());
    }

    #[test]
    fn sqlite_bytes_round_trip_without_disk() {
        ensure_libsql_initialized_for_tests();
        let session = sample_session();
        let sqlite_bytes = export_sqlite_session_bytes(&session).expect("export sqlite");
        let decoded = load_session(sqlite_bytes.as_slice()).expect("load sqlite bytes");
        assert!(decoded.needs_persist);
        assert_eq!(decoded.session.snapshot(), session.snapshot());
    }
}
