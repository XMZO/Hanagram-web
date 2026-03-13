// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::web::notifications;
use crate::web::runtime_cache::MAX_HOT_MESSAGES_PER_SESSION;
use crate::web::shared::*;

use super::storage::{hydrate_session_record, load_persisted_session, persist_loaded_session};

const WORKER_CHECKPOINT_SECONDS: u64 = 15 * 60;
const WORKER_RECYCLE_SECONDS: u64 = 3 * 60 * 60;
const WORKER_COMPACT_PEER_LIMIT: usize = 96;
const WORKER_COMPACT_CHANNEL_LIMIT: usize = 64;
const WORKER_RECYCLE_PEER_THRESHOLD: usize = 160;
const WORKER_RECYCLE_CHANNEL_THRESHOLD: usize = 128;

fn fallback_phone(session_file: &Path) -> String {
    match session_file.file_stem().and_then(|stem| stem.to_str()) {
        Some(stem) if !stem.is_empty() => stem.to_owned(),
        _ => String::from("unknown"),
    }
}

async fn initialize_session_entry(shared_state: &SharedState, record: &SessionRecord) {
    let mut state = shared_state.write().await;
    match state.entry(record.id.clone()) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            let session = entry.get_mut();
            session.user_id = record.user_id.clone();
            session.key = record.session_key.clone();
            session.note = record.note.clone();
            session.session_file = PathBuf::from(&record.storage_path);
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(SessionInfo {
                id: record.id.clone(),
                user_id: record.user_id.clone(),
                key: record.session_key.clone(),
                note: record.note.clone(),
                phone: fallback_phone(Path::new(&record.storage_path)),
                session_file: PathBuf::from(&record.storage_path),
                status: SessionStatus::Connecting,
                messages: VecDeque::new(),
            });
        }
    }
}

async fn set_session_status(shared_state: &SharedState, key: &str, status: SessionStatus) {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        info.status = status;
    }
}

async fn set_session_phone(shared_state: &SharedState, key: &str, phone: String) {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        info.phone = super::routes::format_phone_display(&phone);
    }
}

pub(crate) async fn set_session_note(shared_state: &SharedState, key: &str, note: String) {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        info.note = note;
    }
}

async fn push_otp_message(
    shared_state: &SharedState,
    key: &str,
    otp: OtpMessage,
) -> Option<SessionNotificationContext> {
    let mut state = shared_state.write().await;
    if let Some(info) = state.get_mut(key) {
        if info
            .messages
            .front()
            .is_some_and(|message| message.text == otp.text && message.code == otp.code)
        {
            return None;
        }

        info.messages.push_front(otp);
        info.messages.truncate(MAX_HOT_MESSAGES_PER_SESSION);
        return Some(info.notification_context());
    }

    None
}

async fn hydrate_cached_messages(
    shared_state: &SharedState,
    runtime_cache: &RuntimeCache,
    key: &str,
    master_key: &[u8],
) {
    match runtime_cache.load_hot_messages(master_key, key).await {
        Ok(messages) if !messages.is_empty() => {
            let mut state = shared_state.write().await;
            if let Some(info) = state.get_mut(key) {
                if info.messages.is_empty() {
                    info.messages = messages;
                }
            }
        }
        Ok(_) => {}
        Err(error) => {
            warn!("failed loading runtime cache for session {key}: {error:#}");
        }
    }
}

pub(crate) async fn register_session_record(app_state: &AppState, session_record: SessionRecord) {
    let mut runtime_record = session_record.clone();
    if let Err(error) = hydrate_session_record(app_state, &mut runtime_record).await {
        warn!(
            "failed hydrating session note for {}: {}",
            session_record.id, error
        );
        runtime_record.note.clear();
    }
    initialize_session_entry(&app_state.shared_state, &runtime_record).await;

    let existing_worker = app_state
        .session_workers
        .lock()
        .await
        .remove(&session_record.id);
    if let Some(existing_worker) = existing_worker {
        existing_worker.cancellation.cancel();
        let _ = existing_worker.task.await;
    }

    let worker_key = session_record.id.clone();
    let encrypted_session_file = PathBuf::from(&session_record.storage_path);
    let Some(master_key) = app_state
        .user_keys
        .read()
        .await
        .get(&session_record.user_id)
        .cloned()
    else {
        set_session_status(
            &app_state.shared_state,
            &worker_key,
            SessionStatus::Error(String::from(
                "Encrypted at rest. Sign in again to unlock this session.",
            )),
        )
        .await;
        return;
    };
    hydrate_cached_messages(
        &app_state.shared_state,
        app_state.runtime_cache.as_ref(),
        &worker_key,
        master_key.as_ref().as_slice(),
    )
    .await;
    let system_settings = app_state.system_settings.read().await.clone();
    let Some(telegram_api) = configured_telegram_api(&system_settings) else {
        set_session_status(
            &app_state.shared_state,
            &worker_key,
            SessionStatus::Error(String::from(
                "Telegram API credentials are not configured by the admin.",
            )),
        )
        .await;
        return;
    };
    let session =
        match load_persisted_session(master_key.as_ref().as_slice(), &encrypted_session_file).await
        {
            Ok(session) => Arc::new(session),
            Err(error) => {
                warn!(
                    "failed loading persisted session {}: {}",
                    encrypted_session_file.display(),
                    error
                );
                set_session_status(
                    &app_state.shared_state,
                    &worker_key,
                    SessionStatus::Error(String::from("failed to unlock encrypted session")),
                )
                .await;
                return;
            }
        };
    let worker_state = Arc::clone(&app_state.shared_state);
    let api_id = telegram_api
        .api_id
        .expect("configured telegram api id should exist");
    let meta_store = Arc::clone(&app_state.meta_store);
    let runtime_cache = Arc::clone(&app_state.runtime_cache);
    let http_client = app_state.http_client.clone();
    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();

    let task = tokio::spawn(async move {
        run_session_worker(
            worker_key,
            encrypted_session_file,
            session,
            worker_state,
            api_id,
            master_key,
            meta_store,
            runtime_cache,
            http_client,
            worker_cancellation,
        )
        .await;
    });

    app_state.session_workers.lock().await.insert(
        session_record.id,
        SessionWorkerHandle { cancellation, task },
    );
}

pub(crate) async fn unlock_user_sessions(app_state: &AppState, user_id: &str) {
    if let Ok(session_records) = app_state
        .meta_store
        .list_session_records_for_user(user_id)
        .await
    {
        for session_record in session_records {
            register_session_record(app_state, session_record).await;
        }
    }
}

pub(crate) async fn reload_all_session_workers(app_state: &AppState) {
    if let Ok(session_records) = app_state.meta_store.list_all_session_records().await {
        for session_record in session_records {
            register_session_record(app_state, session_record).await;
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum SessionFailureAction {
    Retryable(String),
    Terminal(String),
}

#[derive(Debug, Eq, PartialEq)]
enum SessionRunOutcome {
    Stopped,
    Recycle,
}

fn classify_session_failure(error: &anyhow::Error) -> SessionFailureAction {
    const SESSION_LOAD_FAILED: &str = "failed to load session";
    const SESSION_UNAUTHORIZED: &str = "session is no longer authorized";

    if error.to_string() == SESSION_LOAD_FAILED {
        return SessionFailureAction::Terminal(String::from(SESSION_LOAD_FAILED));
    }

    if error.to_string() == "session is not authorized" {
        return SessionFailureAction::Terminal(String::from(SESSION_UNAUTHORIZED));
    }

    for cause in error.chain() {
        if let Some(invocation_error) = cause.downcast_ref::<InvocationError>() {
            match invocation_error {
                InvocationError::Rpc(rpc_error) if rpc_error.code == 401 => {
                    return SessionFailureAction::Terminal(String::from(SESSION_UNAUTHORIZED));
                }
                InvocationError::Transport(transport_error)
                    if transport_error
                        .to_string()
                        .contains("bad status (negative length -404)") =>
                {
                    return SessionFailureAction::Terminal(String::from(SESSION_UNAUTHORIZED));
                }
                _ => {}
            }
        }
    }

    SessionFailureAction::Retryable(error.to_string())
}

async fn run_session_worker(
    key: String,
    encrypted_session_file: PathBuf,
    session: Arc<LoadedSession>,
    shared_state: SharedState,
    api_id: i32,
    master_key: SharedMasterKey,
    meta_store: MetaStoreHandle,
    runtime_cache: RuntimeCacheHandle,
    http_client: HttpClient,
    cancellation: CancellationToken,
) {
    let retry_delays = [5_u64, 10, 20, 40, 80];
    let mut attempt = 0_usize;

    loop {
        if cancellation.is_cancelled() {
            break;
        }

        set_session_status(&shared_state, &key, SessionStatus::Connecting).await;

        let result = run_session_once(
            &key,
            Arc::clone(&session),
            &shared_state,
            api_id,
            &meta_store,
            runtime_cache.as_ref(),
            master_key.as_ref().as_slice(),
            &http_client,
            &cancellation,
        )
        .await;

        if let Err(error) = persist_loaded_session(
            master_key.as_ref().as_slice(),
            &encrypted_session_file,
            session.as_ref(),
        )
        .await
        {
            warn!(
                "failed persisting encrypted session {}: {}",
                encrypted_session_file.display(),
                error
            );
        }

        match result {
            Ok(SessionRunOutcome::Stopped) => break,
            Ok(SessionRunOutcome::Recycle) => {
                attempt = 0;
                continue;
            }
            Err(error) => {
                warn!(
                    "session {} failed: {error:#}",
                    encrypted_session_file.display()
                );

                match classify_session_failure(&error) {
                    SessionFailureAction::Terminal(message) => {
                        set_session_status(&shared_state, &key, SessionStatus::Error(message))
                            .await;
                        break;
                    }
                    SessionFailureAction::Retryable(message) => {
                        set_session_status(&shared_state, &key, SessionStatus::Error(message))
                            .await;

                        if attempt >= retry_delays.len() {
                            break;
                        }

                        let delay = retry_delays[attempt];
                        attempt += 1;
                        tokio::select! {
                            _ = cancellation.cancelled() => break,
                            _ = sleep(Duration::from_secs(delay)) => {}
                        }
                    }
                }
            }
        }
    }

    if let Err(error) = persist_loaded_session(
        master_key.as_ref().as_slice(),
        &encrypted_session_file,
        session.as_ref(),
    )
    .await
    {
        warn!(
            "failed final session persistence {}: {}",
            encrypted_session_file.display(),
            error
        );
    }
}

async fn run_session_once(
    key: &str,
    session: Arc<LoadedSession>,
    shared_state: &SharedState,
    api_id: i32,
    meta_store: &MetaStoreHandle,
    runtime_cache: &RuntimeCache,
    master_key: &[u8],
    http_client: &HttpClient,
    cancellation: &CancellationToken,
) -> Result<SessionRunOutcome> {
    let SenderPool {
        runner,
        handle: pool_handle,
        updates,
    } = SenderPool::new(Arc::clone(&session), api_id);
    let client = Client::new(pool_handle.clone());
    let pool_task = tokio::spawn(runner.run());

    let result = tokio::select! {
        _ = cancellation.cancelled() => Ok(SessionRunOutcome::Stopped),
        result = async {
            if !client
                .is_authorized()
                .await
                .context("authorization check failed")?
            {
                anyhow::bail!("session is not authorized");
            }

            prime_session(&session, &client, key, shared_state).await;
            set_session_status(shared_state, key, SessionStatus::Connected).await;

            let code_regex = Regex::new(r"\b\d{5,6}\b").context("failed to compile OTP regex")?;
            let mut checkpoint = tokio::time::interval(Duration::from_secs(WORKER_CHECKPOINT_SECONDS));
            checkpoint.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            checkpoint.tick().await;
            let worker_started_at = std::time::Instant::now();
            let mut updates = client
                .stream_updates(
                    updates,
                    UpdatesConfiguration {
                        catch_up: true,
                        ..Default::default()
                    },
                )
                .await;

            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => return Ok(SessionRunOutcome::Stopped),
                    _ = checkpoint.tick() => {
                        if run_worker_maintenance(session.as_ref(), key, worker_started_at.elapsed()) {
                            return Ok(SessionRunOutcome::Recycle);
                        }
                    }
                    update = updates.next() => match update {
                        Ok(grammers_client::update::Update::NewMessage(message))
                            if message.sender_id() == Some(PeerId::user(777000)) =>
                        {
                            let text = message.text().to_string();
                            let code = code_regex
                                .find(&text)
                                .map(|matched| matched.as_str().to_string());
                            let otp = OtpMessage {
                                received_at: Utc::now(),
                                text,
                                code,
                            };
                            let session_context = push_otp_message(shared_state, key, otp.clone()).await;
                            if let Some(session_context) = session_context {
                                if let Err(error) = runtime_cache.append_message(master_key, key, &otp).await {
                                    warn!("failed appending runtime cache for session {key}: {error:#}");
                                }
                                notifications::maybe_dispatch_bot_notification(
                                    meta_store,
                                    http_client,
                                    &session_context,
                                    &otp,
                                )
                                .await;
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            updates.sync_update_state().await;
                            return Err(error).context("update loop failed");
                        }
                    }
                }
            }
        } => result,
    };

    let _ = pool_handle.quit();
    let _ = pool_task.await;
    result
}

fn run_worker_maintenance(session: &LoadedSession, key: &str, uptime: Duration) -> bool {
    let stats = session.runtime_stats();
    let prune =
        session.prune_runtime_state(WORKER_COMPACT_PEER_LIMIT, WORKER_COMPACT_CHANNEL_LIMIT);
    let should_recycle = uptime >= Duration::from_secs(WORKER_RECYCLE_SECONDS)
        || stats.peer_count >= WORKER_RECYCLE_PEER_THRESHOLD
        || stats.channel_count >= WORKER_RECYCLE_CHANNEL_THRESHOLD;

    if prune.before_peer_count != prune.after_peer_count
        || prune.before_channel_count != prune.after_channel_count
    {
        info!(
            "worker {key} compacted runtime state: peers {} -> {}, channels {} -> {}",
            prune.before_peer_count,
            prune.after_peer_count,
            prune.before_channel_count,
            prune.after_channel_count
        );
    }
    if should_recycle {
        info!(
            "worker {key} requested recycle after {:?} (peers={}, channels={})",
            uptime, stats.peer_count, stats.channel_count
        );
    }

    should_recycle
}

async fn prime_session(
    session: &LoadedSession,
    client: &Client,
    key: &str,
    shared_state: &SharedState,
) {
    match client.get_me().await {
        Ok(me) => {
            let auth = me.to_ref().await.map(|peer| peer.auth);
            let peer_info = PeerInfo::User {
                id: me.id().bare_id(),
                auth,
                bot: Some(me.is_bot()),
                is_self: Some(true),
            };
            session.cache_peer(&peer_info).await;

            if let Some(phone) = me.phone() {
                set_session_phone(shared_state, key, phone.to_owned()).await;
            }
        }
        Err(error) => {
            warn!("failed to fetch self user info for {}: {}", key, error);
        }
    }

    match client.invoke(&tl::functions::updates::GetState {}).await {
        Ok(tl::enums::updates::State::State(state)) => {
            session
                .set_update_state(UpdateState::All(UpdatesState {
                    pts: state.pts,
                    qts: state.qts,
                    date: state.date,
                    seq: state.seq,
                    channels: Vec::new(),
                }))
                .await;
        }
        Err(error) => {
            warn!("failed to prime update state for {}: {}", key, error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn classify_session_failure_stops_on_unauthorized_rpc() {
        let error = anyhow::Error::new(InvocationError::Rpc(grammers_client::sender::RpcError {
            code: 401,
            name: String::from("AUTH_KEY_UNREGISTERED"),
            value: None,
            caused_by: None,
        }))
        .context("update loop failed");

        assert_eq!(
            classify_session_failure(&error),
            SessionFailureAction::Terminal(String::from("session is no longer authorized"))
        );
    }

    #[test]
    fn classify_session_failure_stops_on_missing_session_file() {
        let error = anyhow::anyhow!("failed to load session");

        assert_eq!(
            classify_session_failure(&error),
            SessionFailureAction::Terminal(String::from("failed to load session"))
        );
    }

    #[test]
    fn classify_session_failure_retries_on_transient_io_error() {
        let error = anyhow::Error::new(InvocationError::Io(io::Error::other("temporary outage")))
            .context("update loop failed");

        assert_eq!(
            classify_session_failure(&error),
            SessionFailureAction::Retryable(String::from("update loop failed"))
        );
    }
}
