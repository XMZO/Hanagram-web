// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::web::shared::*;
use crate::web::{middleware, platforms::telegram as telegram_platform};

use super::runtime::set_session_note;
use super::storage::{
    ensure_user_sessions_dir, export_owned_session_file, finalize_pending_session,
    load_owned_session_record, load_persisted_session, persist_session_record,
    remove_file_if_exists, save_new_session_record, session_storage_path,
};

const PHONE_START_SUCCESS_COOLDOWN_SECONDS: u32 = 20;
const PHONE_START_FAILURE_COOLDOWN_SECONDS: u32 = 8;
const PHONE_VERIFY_FAILURE_COOLDOWN_SECONDS: u32 = 5;
const QR_START_COOLDOWN_SECONDS: u32 = 8;
const QR_POLL_COOLDOWN_SECONDS: u32 = QR_AUTO_REFRESH_SECONDS as u32;
const TELEGRAM_DEFAULT_RETRY_AFTER_SECONDS: u32 = 30;
const TELEGRAM_PHONE_FLOOD_RETRY_AFTER_SECONDS: u32 = 300;
const TELEGRAM_LOGIN_THROTTLE_PRUNE_THRESHOLD: usize = 512;

fn login_throttle_key(scope: &str, value: &str) -> String {
    format!("login-throttle:{scope}:{value}")
}

fn phone_start_throttle_key(user_id: &str, phone: &str) -> String {
    login_throttle_key("phone-start", &format!("{user_id}:{phone}"))
}

fn phone_code_throttle_key(flow_id: &str) -> String {
    login_throttle_key("phone-code", flow_id)
}

fn phone_password_throttle_key(flow_id: &str) -> String {
    login_throttle_key("phone-password", flow_id)
}

fn qr_start_throttle_key(user_id: &str) -> String {
    login_throttle_key("qr-start", user_id)
}

fn qr_poll_throttle_key(flow_id: &str) -> String {
    login_throttle_key("qr-poll", flow_id)
}

async fn remaining_login_throttle_seconds(app_state: &AppState, key: &str) -> Option<u32> {
    let now = Utc::now().timestamp();
    let mut throttles = app_state.session_login_throttle.lock().await;

    if throttles.len() > TELEGRAM_LOGIN_THROTTLE_PRUNE_THRESHOLD {
        throttles.retain(|_, not_before| *not_before > now);
    }

    match throttles.get(key).copied() {
        Some(not_before) if not_before > now => {
            let remaining = not_before.saturating_sub(now);
            Some(remaining.min(i64::from(u32::MAX)) as u32)
        }
        Some(_) => {
            throttles.remove(key);
            None
        }
        None => None,
    }
}

async fn set_login_throttle_seconds(app_state: &AppState, key: &str, wait_seconds: u32) {
    let now = Utc::now().timestamp();
    let mut throttles = app_state.session_login_throttle.lock().await;

    if throttles.len() > TELEGRAM_LOGIN_THROTTLE_PRUNE_THRESHOLD {
        throttles.retain(|_, not_before| *not_before > now);
    }

    throttles.insert(
        key.to_owned(),
        now.saturating_add(i64::from(wait_seconds.max(1))),
    );
}

fn format_retry_after_message(language: Language, template: &str, wait_seconds: u32) -> String {
    template.replace(
        "{duration}",
        &format_duration_for_display(language, i64::from(wait_seconds)),
    )
}

fn setup_retry_after_message(language: Language, wait_seconds: u32) -> String {
    format_retry_after_message(
        language,
        language.translations().setup_error_retry_after,
        wait_seconds,
    )
}

fn phone_retry_after_message(language: Language, wait_seconds: u32) -> String {
    format_retry_after_message(
        language,
        language.translations().phone_error_retry_after,
        wait_seconds,
    )
}

fn qr_retry_after_message(language: Language, wait_seconds: u32) -> String {
    format_retry_after_message(
        language,
        language.translations().qr_error_retry_after,
        wait_seconds,
    )
}

fn telegram_retry_after_seconds_for_rpc_error(
    rpc_error: &grammers_client::sender::RpcError,
) -> Option<u32> {
    let wait_like_error = rpc_error.code == 420
        || rpc_error.name.contains("FLOOD")
        || rpc_error.name.ends_with("_WAIT");
    if !wait_like_error {
        return None;
    }

    let fallback = match rpc_error.name.as_str() {
        "PHONE_NUMBER_FLOOD" => TELEGRAM_PHONE_FLOOD_RETRY_AFTER_SECONDS,
        "PHONE_CODE_FLOOD" | "PHONE_PASSWORD_FLOOD" => TELEGRAM_DEFAULT_RETRY_AFTER_SECONDS * 2,
        _ => TELEGRAM_DEFAULT_RETRY_AFTER_SECONDS,
    };

    Some(rpc_error.value.unwrap_or(fallback).saturating_add(2))
}

fn telegram_retry_after_seconds_for_invocation_error(error: &InvocationError) -> Option<u32> {
    match error {
        InvocationError::Rpc(rpc_error) => telegram_retry_after_seconds_for_rpc_error(rpc_error),
        _ => None,
    }
}

fn telegram_retry_after_seconds_for_anyhow(error: &anyhow::Error) -> Option<u32> {
    for cause in error.chain() {
        if let Some(invocation_error) = cause.downcast_ref::<InvocationError>() {
            if let Some(wait_seconds) =
                telegram_retry_after_seconds_for_invocation_error(invocation_error)
            {
                return Some(wait_seconds);
            }
        }
    }

    None
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(TELEGRAM_SETUP_PATH, get(session_setup_page_handler))
        .route(
            TELEGRAM_IMPORT_STRING_PATH,
            post(import_string_session_handler),
        )
        .route(
            TELEGRAM_IMPORT_UPLOAD_PATH,
            post(import_session_file_handler),
        )
        .route(
            "/platforms/telegram/{session_id}/note",
            post(update_session_note_handler),
        )
        .route(
            "/platforms/telegram/{session_id}/delete",
            post(delete_session_handler),
        )
        .route(
            "/platforms/telegram/{session_id}/rename",
            post(rename_session_handler),
        )
        .route(
            "/platforms/telegram/{session_id}/export/file",
            get(export_session_file_handler),
        )
        .route(
            "/platforms/telegram/{session_id}/export/string",
            get(export_string_session_handler),
        )
        .route(TELEGRAM_PHONE_LOGIN_PATH, post(start_phone_login_handler))
        .route(TELEGRAM_QR_LOGIN_PATH, post(start_qr_login_handler))
        .route(
            "/platforms/telegram/phone/{flow_id}",
            get(phone_flow_page_handler),
        )
        .route(
            "/platforms/telegram/phone/{flow_id}/code",
            post(verify_phone_code_handler),
        )
        .route(
            "/platforms/telegram/phone/{flow_id}/password",
            post(verify_phone_password_handler),
        )
        .route(
            "/platforms/telegram/phone/{flow_id}/cancel",
            post(cancel_phone_flow_handler),
        )
        .route(
            "/platforms/telegram/qr/{flow_id}",
            get(qr_flow_page_handler),
        )
        .route(
            "/platforms/telegram/qr/{flow_id}/cancel",
            post(cancel_qr_flow_handler),
        )
        .route("/sessions/new", get(session_setup_page_handler))
        .route(
            "/sessions/import/string",
            post(import_string_session_handler),
        )
        .route("/sessions/import/upload", post(import_session_file_handler))
        .route(
            "/sessions/{session_id}/note",
            post(update_session_note_handler),
        )
        .route(
            "/sessions/{session_id}/delete",
            post(delete_session_handler),
        )
        .route(
            "/sessions/{session_id}/rename",
            post(rename_session_handler),
        )
        .route(
            "/sessions/{session_id}/export/file",
            get(export_session_file_handler),
        )
        .route(
            "/sessions/{session_id}/export/string",
            get(export_string_session_handler),
        )
        .route("/sessions/login/phone", post(start_phone_login_handler))
        .route("/sessions/login/qr", post(start_qr_login_handler))
        .route("/sessions/phone/{flow_id}", get(phone_flow_page_handler))
        .route(
            "/sessions/phone/{flow_id}/code",
            post(verify_phone_code_handler),
        )
        .route(
            "/sessions/phone/{flow_id}/password",
            post(verify_phone_password_handler),
        )
        .route(
            "/sessions/phone/{flow_id}/cancel",
            post(cancel_phone_flow_handler),
        )
        .route("/sessions/qr/{flow_id}", get(qr_flow_page_handler))
        .route(
            "/sessions/qr/{flow_id}/cancel",
            post(cancel_qr_flow_handler),
        )
}

pub(crate) fn sanitize_phone_input(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|ch| ch.is_ascii_digit() || *ch == '+')
        .collect()
}

pub(crate) fn format_phone_display(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let candidate = if trimmed.starts_with('+') {
        trimmed.to_owned()
    } else if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        format!("+{trimmed}")
    } else {
        trimmed.to_owned()
    };

    match phonenumber::parse(None, &candidate) {
        Ok(phone) => phone
            .format()
            .mode(PhoneNumberMode::International)
            .to_string(),
        Err(_) => trimmed.split_whitespace().collect::<Vec<_>>().join(" "),
    }
}

fn sanitize_session_name(raw: &str) -> String {
    let mut cleaned = String::new();
    let mut pending_space = false;

    for ch in raw.trim().chars() {
        let mapped = match ch {
            '/' | '\\' | ':' | '"' | '<' | '>' | '|' | '?' | '*' => Some(' '),
            _ if ch.is_control() => None,
            _ if ch.is_whitespace() => Some(' '),
            _ => Some(ch),
        };

        match mapped {
            Some(' ') => {
                if !cleaned.is_empty() {
                    pending_space = true;
                }
            }
            Some(ch) => {
                if pending_space {
                    cleaned.push(' ');
                    pending_space = false;
                }
                cleaned.push(ch);
            }
            None => {}
        }
    }

    let cleaned = cleaned.trim().to_owned();
    if cleaned.is_empty() {
        format!("session-{}", Utc::now().timestamp())
    } else {
        cleaned
    }
}

async fn render_setup_page(
    app_state: &AppState,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, TELEGRAM_SETUP_PATH);

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("banner", &banner);
    context.insert("dashboard_href", &telegram_workspace_href(language));
    context.insert("telegram_import_string_action", TELEGRAM_IMPORT_STRING_PATH);
    context.insert("telegram_import_upload_action", TELEGRAM_IMPORT_UPLOAD_PATH);
    context.insert("telegram_phone_login_action", TELEGRAM_PHONE_LOGIN_PATH);
    context.insert("telegram_qr_login_action", TELEGRAM_QR_LOGIN_PATH);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "session_setup.html", &context)
}

fn phone_flow_href(flow_id: &str) -> String {
    format!("/platforms/telegram/phone/{flow_id}")
}

fn phone_flow_error_href(flow_id: &str, error: &str) -> String {
    format!("{}?error={error}", phone_flow_href(flow_id))
}

fn phone_flow_retry_after_href(flow_id: &str, wait_seconds: u32) -> String {
    format!(
        "{}?error=retry_after&wait_seconds={wait_seconds}",
        phone_flow_href(flow_id)
    )
}

fn phone_flow_cancel_href(flow_id: &str) -> String {
    format!("/platforms/telegram/phone/{flow_id}/cancel")
}

fn qr_flow_href(flow_id: &str) -> String {
    format!("/platforms/telegram/qr/{flow_id}")
}

fn qr_flow_error_href(flow_id: &str, error: &str) -> String {
    format!("{}?error={error}", qr_flow_href(flow_id))
}

fn qr_flow_retry_after_href(flow_id: &str, wait_seconds: u32) -> String {
    format!(
        "{}?error=retry_after&wait_seconds={wait_seconds}",
        qr_flow_href(flow_id)
    )
}

fn qr_flow_cancel_href(flow_id: &str) -> String {
    format!("/platforms/telegram/qr/{flow_id}/cancel")
}

fn build_phone_flow_view(flow_id: &str, flow: &PendingPhoneLogin) -> PhoneFlowView {
    let awaiting_password = matches!(flow.stage, PhoneLoginStage::AwaitingPassword { .. });
    let submit_action = if awaiting_password {
        format!("/platforms/telegram/phone/{flow_id}/password")
    } else {
        format!("/platforms/telegram/phone/{flow_id}/code")
    };
    let password_hint = match &flow.stage {
        PhoneLoginStage::AwaitingPassword { token } => token.hint().map(str::to_owned),
        PhoneLoginStage::AwaitingCode { .. } => None,
    };

    PhoneFlowView {
        session_name: flow.session_name.clone(),
        phone: flow.phone.clone(),
        awaiting_password,
        password_hint,
        submit_action,
        cancel_action: phone_flow_cancel_href(flow_id),
    }
}

async fn render_phone_flow_page(
    app_state: &AppState,
    language: Language,
    flow_id: &str,
    flow: &PendingPhoneLogin,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, &phone_flow_href(flow_id));
    let flow_view = build_phone_flow_view(flow_id, flow);

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("banner", &banner);
    context.insert("dashboard_href", &telegram_workspace_href(language));
    context.insert("setup_href", &telegram_setup_href(language));
    context.insert("flow", &flow_view);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "phone_login.html", &context)
}

async fn render_qr_flow_page(
    app_state: &AppState,
    language: Language,
    flow_id: &str,
    flow: &PendingQrLogin,
    pending: QrPendingState,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
    auto_refresh_seconds: u64,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, &qr_flow_href(flow_id));
    let flow_view = QrFlowView {
        session_name: flow.session_name.clone(),
        qr_link: pending.qr_link,
        qr_svg: pending.qr_svg,
        expires_at: pending.expires_at,
        cancel_action: qr_flow_cancel_href(flow_id),
    };

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("banner", &banner);
    context.insert("dashboard_href", &telegram_workspace_href(language));
    context.insert("setup_href", &telegram_setup_href(language));
    context.insert("flow", &flow_view);
    context.insert("auto_refresh_seconds", &auto_refresh_seconds);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "qr_login.html", &context)
}

async fn session_setup_page_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    match render_setup_page(&app_state, language, None, &headers).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn import_string_session_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<StringSessionForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.session_string.trim().is_empty() {
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_missing_string,
            &headers,
        )
        .await;
    }

    let session_id = Uuid::new_v4().to_string();
    let session_name = sanitize_session_name(&form.session_name);
    if let Err(error) = ensure_user_sessions_dir(&app_state.runtime, &authenticated.user.id).await {
        warn!("failed preparing user session dir: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_path_alloc,
            &headers,
        )
        .await;
    }
    match load_telethon_string_session(&form.session_string) {
        Ok(session) => {
            if let Err(error) = save_new_session_record(
                &app_state,
                &authenticated.user.id,
                &authenticated.auth_session.id,
                &session_id,
                &session_name,
                &session,
            )
            .await
            {
                warn!("failed saving imported string session record: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    translations.setup_error_path_alloc,
                    &headers,
                )
                .await;
            }
            Redirect::to(&telegram_workspace_href(language)).into_response()
        }
        Err(error) => {
            warn!("failed importing telethon string session: {}", error);
            render_setup_error_response(
                &app_state,
                language,
                translations.setup_error_invalid_string,
                &headers,
            )
            .await
        }
    }
}

async fn export_session_file_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<LangQuery>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    export_owned_session_file(&app_state, &authenticated, &session_id, language).await
}

async fn export_string_session_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<LangQuery>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for string export: {}", error);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiErrorResponse {
                        error: String::from(language.translations().export_string_error),
                    }),
                )
                    .into_response();
            }
        };

    let Some(session) = session else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                error: String::from(language.translations().dashboard_session_missing),
            }),
        )
            .into_response();
    };
    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::LOCKED,
            Json(ApiErrorResponse {
                error: String::from(language.translations().session_data_locked_message),
            }),
        )
            .into_response();
    };
    let session_file = PathBuf::from(&session.storage_path);
    let loaded_session =
        match load_persisted_session(master_key.as_ref().as_slice(), &session_file).await {
            Ok(session) => session,
            Err(error) => {
                warn!(
                    "failed decrypting session file {} for string export: {}",
                    session_file.display(),
                    error
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorResponse {
                        error: String::from(language.translations().export_string_error),
                    }),
                )
                    .into_response();
            }
        };
    let export_result = export_telethon_string_session(&loaded_session);

    match export_result {
        Ok(session_string) => Json(SessionStringExportResponse {
            session_key: session.session_key,
            session_string,
        })
        .into_response(),
        Err(error) => {
            warn!(
                "failed exporting telethon string session {}: {}",
                session_file.display(),
                error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    error: String::from(language.translations().export_string_error),
                }),
            )
                .into_response()
        }
    }
}

async fn import_session_file_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let mut language = detect_language(&headers, None);
    let mut session_name = String::new();
    let mut upload_name: Option<String> = None;
    let mut upload_bytes: Option<Vec<u8>> = None;

    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let field_name = field.name().unwrap_or_default().to_owned();

                match field_name.as_str() {
                    "lang" => {
                        if let Ok(raw) = field.text().await {
                            if let Some(parsed) = Language::parse(&raw) {
                                language = parsed;
                            }
                        }
                    }
                    "session_name" => {
                        session_name = field.text().await.unwrap_or_default();
                    }
                    "session_file" => {
                        upload_name = field.file_name().map(str::to_owned);
                        upload_bytes = match field.bytes().await {
                            Ok(bytes) => Some(bytes.to_vec()),
                            Err(error) => {
                                warn!("failed reading uploaded session file: {}", error);
                                return render_setup_error_response(
                                    &app_state,
                                    language,
                                    language.translations().setup_error_upload_read,
                                    &headers,
                                )
                                .await;
                            }
                        };
                    }
                    _ => {}
                }
            }
            Ok(None) => break,
            Err(error) => {
                warn!("failed reading multipart upload: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_upload_read,
                    &headers,
                )
                .await;
            }
        }
    }

    let file_bytes = match upload_bytes {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => {
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_missing_upload,
                &headers,
            )
            .await;
        }
    };

    let upload_stem = upload_name
        .as_deref()
        .and_then(|name| Path::new(name).file_stem().and_then(|stem| stem.to_str()))
        .unwrap_or("session");
    let session_name = sanitize_session_name(if session_name.trim().is_empty() {
        upload_stem
    } else {
        &session_name
    });
    if let Err(error) = ensure_user_sessions_dir(&app_state.runtime, &authenticated.user.id).await {
        warn!("failed preparing user session dir: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            language.translations().setup_error_path_alloc,
            &headers,
        )
        .await;
    }
    let session_id = Uuid::new_v4().to_string();
    match load_session(&file_bytes) {
        Ok(loaded_session) => {
            if let Err(error) = save_new_session_record(
                &app_state,
                &authenticated.user.id,
                &authenticated.auth_session.id,
                &session_id,
                &session_name,
                &loaded_session.session,
            )
            .await
            {
                warn!("failed saving uploaded session record: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_upload_write,
                    &headers,
                )
                .await;
            }
            Redirect::to(&telegram_workspace_href(language)).into_response()
        }
        Err(error) => {
            warn!("failed decoding uploaded session file: {}", error);
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_upload_write,
                &headers,
            )
            .await
        }
    }
}

async fn delete_session_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for deletion: {}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    let Some(session) = session else {
        return Redirect::to(&telegram_workspace_href(language)).into_response();
    };

    let worker = app_state.session_workers.lock().await.remove(&session.id);
    if let Some(worker) = worker {
        worker.cancellation.cancel();
        let _ = worker.task.await;
    }

    let session_file = PathBuf::from(&session.storage_path);
    if let Err(error) = remove_file_if_exists(&session_file).await {
        warn!(
            "failed deleting session file {}: {}",
            session_file.display(),
            error
        );
        return match telegram_platform::render_workspace_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language.translations().dashboard_delete_error,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    if let Err(error) = app_state
        .meta_store
        .delete_session_record(&session.id)
        .await
    {
        warn!("failed deleting session record {}: {}", session.id, error);
    }
    if let Err(error) = app_state.runtime_cache.remove_session(&session.id).await {
        warn!(
            "failed deleting runtime cache for session {}: {}",
            session.id, error
        );
    }

    app_state.shared_state.write().await.remove(&session.id);
    Redirect::to(&telegram_workspace_href(language)).into_response()
}

async fn rename_session_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<RenameSessionForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let new_name = form.session_name.trim();

    if new_name.is_empty() {
        return match telegram_platform::render_workspace_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.dashboard_rename_missing)),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let current_session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for rename: {}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    let Some(current_session) = current_session else {
        return match telegram_platform::render_workspace_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.dashboard_session_missing)),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::NOT_FOUND, html).into_response(),
            Err(status) => status.into_response(),
        };
    };
    let next_session_name = sanitize_session_name(new_name);

    if next_session_name == current_session.session_key {
        return Redirect::to(&telegram_workspace_href(language)).into_response();
    }

    let mut updated_session = current_session.clone();
    updated_session.session_key = next_session_name;
    updated_session.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = persist_session_record(&app_state, &updated_session).await {
        warn!("failed saving renamed session record: {}", error);
        return match telegram_platform::render_workspace_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(translations.dashboard_rename_error)),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    {
        let mut state = app_state.shared_state.write().await;
        if let Some(session) = state.get_mut(&session_id) {
            session.key = updated_session.session_key.clone();
            session.note = updated_session.note.clone();
        }
    }
    Redirect::to(&telegram_workspace_href(language)).into_response()
}

async fn update_session_note_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<SessionNoteForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let note = form.note.trim().chars().take(240).collect::<String>();
    let session =
        match load_owned_session_record(&app_state, &authenticated.user.id, &session_id).await {
            Ok(record) => record,
            Err(error) => {
                warn!("failed loading session record for note update: {}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    let Some(mut session) = session else {
        return Redirect::to(&telegram_workspace_href(language)).into_response();
    };
    session.note = note.clone();
    session.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = persist_session_record(&app_state, &session).await {
        warn!("failed saving session note: {}", error);
        return match telegram_platform::render_workspace_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(
                language.translations().session_note_update_failed_message,
            )),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    set_session_note(&app_state.shared_state, &session.id, note).await;
    Redirect::to(&telegram_workspace_href(language)).into_response()
}

async fn start_phone_login_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<StartPhoneLoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let phone = form.phone.trim();
    let login_phone = sanitize_phone_input(phone);

    if login_phone.is_empty() {
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_missing_phone,
            &headers,
        )
        .await;
    }

    let start_throttle_key = phone_start_throttle_key(&authenticated.user.id, &login_phone);
    if let Some(wait_seconds) =
        remaining_login_throttle_seconds(&app_state, &start_throttle_key).await
    {
        return render_setup_error_response(
            &app_state,
            language,
            &setup_retry_after_message(language, wait_seconds),
            &headers,
        )
        .await;
    }

    let flow_id = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string();
    let session_name = sanitize_session_name(&form.session_name);
    if let Err(error) = ensure_user_sessions_dir(&app_state.runtime, &authenticated.user.id).await {
        warn!("failed preparing user session dir: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_path_alloc,
            &headers,
        )
        .await;
    }
    let telegram_profile = configured_telegram_client_profile();
    let final_path = session_storage_path(&app_state.runtime, &authenticated.user.id, &session_id);
    let client_session = TelegramClientSession::open_empty(&telegram_profile);

    let result = client_session
        .client
        .request_login_code(&login_phone, &telegram_profile.api_hash)
        .await;
    let session_data = client_session.snapshot();
    client_session.shutdown().await;

    match result {
        Ok(token) => {
            set_login_throttle_seconds(
                &app_state,
                &start_throttle_key,
                PHONE_START_SUCCESS_COOLDOWN_SECONDS,
            )
            .await;
            let session_data = match session_data {
                Ok(data) => data,
                Err(error) => {
                    warn!("failed capturing phone login session snapshot: {}", error);
                    return render_setup_error_response(
                        &app_state,
                        language,
                        translations.setup_error_phone_unavailable,
                        &headers,
                    )
                    .await;
                }
            };
            let flow = PendingPhoneLogin {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                session_name,
                phone: format_phone_display(phone),
                session_id,
                final_path,
                session_data: share_sensitive_bytes(session_data),
                stage: PhoneLoginStage::AwaitingCode { token },
            };
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);

            Redirect::to(&phone_flow_href(&flow_id)).into_response()
        }
        Err(error) => {
            warn!("failed requesting login code: {}", error);
            if let Some(wait_seconds) = telegram_retry_after_seconds_for_invocation_error(&error) {
                set_login_throttle_seconds(&app_state, &start_throttle_key, wait_seconds).await;
                return render_setup_error_response(
                    &app_state,
                    language,
                    &setup_retry_after_message(language, wait_seconds),
                    &headers,
                )
                .await;
            }
            set_login_throttle_seconds(
                &app_state,
                &start_throttle_key,
                PHONE_START_FAILURE_COOLDOWN_SECONDS,
            )
            .await;
            render_setup_error_response(
                &app_state,
                language,
                translations.setup_error_phone_start,
                &headers,
            )
            .await
        }
    }
}

async fn start_qr_login_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<StartQrLoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();
    let start_throttle_key = qr_start_throttle_key(&authenticated.user.id);
    if let Some(wait_seconds) =
        remaining_login_throttle_seconds(&app_state, &start_throttle_key).await
    {
        return render_setup_error_response(
            &app_state,
            language,
            &setup_retry_after_message(language, wait_seconds),
            &headers,
        )
        .await;
    }

    let flow_id = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string();
    let session_name = sanitize_session_name(&form.session_name);
    if let Err(error) = ensure_user_sessions_dir(&app_state.runtime, &authenticated.user.id).await {
        warn!("failed preparing user session dir: {}", error);
        return render_setup_error_response(
            &app_state,
            language,
            translations.setup_error_path_alloc,
            &headers,
        )
        .await;
    }
    let final_path = session_storage_path(&app_state.runtime, &authenticated.user.id, &session_id);
    let session_data = match serialize_session(&LoadedSession::default()) {
        Ok(data) => data,
        Err(error) => {
            warn!(
                "failed creating initial qr login session snapshot: {}",
                error
            );
            return render_setup_error_response(
                &app_state,
                language,
                translations.setup_error_qr_unavailable,
                &headers,
            )
            .await;
        }
    };

    app_state.qr_flows.write().await.insert(
        flow_id.clone(),
        PendingQrLogin {
            user_id: authenticated.user.id.clone(),
            auth_session_id: authenticated.auth_session.id.clone(),
            session_name,
            session_id,
            final_path,
            session_data: share_sensitive_bytes(session_data),
            pending_state: None,
        },
    );
    set_login_throttle_seconds(&app_state, &start_throttle_key, QR_START_COOLDOWN_SECONDS).await;

    Redirect::to(&qr_flow_href(&flow_id)).into_response()
}

async fn phone_flow_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<FlowPageQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let flow_guard = app_state.phone_flows.read().await;
    let flow = match flow_guard.get(&flow_id) {
        Some(flow) if flow.user_id == authenticated.user.id => flow,
        Some(_) => {
            drop(flow_guard);
            return Redirect::to(&telegram_workspace_href(language)).into_response();
        }
        None => {
            drop(flow_guard);
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_phone_flow_missing,
                &headers,
            )
            .await;
        }
    };
    let banner = phone_flow_error_banner(language, query.error.as_deref(), query.wait_seconds);

    match render_phone_flow_page(&app_state, language, &flow_id, flow, banner, &headers).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn verify_phone_code_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<VerifyCodeForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let code = form.code.trim();

    if code.is_empty() {
        return Redirect::to(&phone_flow_error_href(&flow_id, "missing_code")).into_response();
    }

    let owner_matches = app_state
        .phone_flows
        .read()
        .await
        .get(&flow_id)
        .map(|flow| flow.user_id == authenticated.user.id)
        .unwrap_or(false);
    if !owner_matches {
        return Redirect::to(&telegram_workspace_href(language)).into_response();
    }

    let verify_throttle_key = phone_code_throttle_key(&flow_id);
    if let Some(wait_seconds) =
        remaining_login_throttle_seconds(&app_state, &verify_throttle_key).await
    {
        return Redirect::to(&phone_flow_retry_after_href(&flow_id, wait_seconds)).into_response();
    }

    let mut flows = app_state.phone_flows.write().await;
    let Some(mut flow) = flows.remove(&flow_id) else {
        drop(flows);
        return render_setup_error_response(
            &app_state,
            language,
            language.translations().setup_error_phone_flow_missing,
            &headers,
        )
        .await;
    };
    if flow.user_id != authenticated.user.id {
        drop(flows);
        return Redirect::to(&telegram_workspace_href(language)).into_response();
    }

    let token = match flow.stage {
        PhoneLoginStage::AwaitingCode { token } => token,
        PhoneLoginStage::AwaitingPassword { token } => {
            flow.stage = PhoneLoginStage::AwaitingPassword { token };
            flows.insert(flow_id.clone(), flow);
            drop(flows);
            return Redirect::to(&phone_flow_href(&flow_id)).into_response();
        }
    };
    drop(flows);

    let telegram_profile = configured_telegram_client_profile();
    let client_session = match TelegramClientSession::open_serialized(
        flow.session_data.as_ref().as_slice(),
        &telegram_profile,
    ) {
        Ok(client_session) => client_session,
        Err(error) => {
            warn!(
                "failed opening in-memory session for code verification: {}",
                error
            );
            app_state.phone_flows.write().await.insert(
                flow_id.clone(),
                PendingPhoneLogin {
                    stage: PhoneLoginStage::AwaitingCode { token },
                    ..flow
                },
            );
            return Redirect::to(&phone_flow_error_href(&flow_id, "code_failed")).into_response();
        }
    };

    let result = client_session.client.sign_in(&token, code).await;
    let session_data = client_session.snapshot();
    client_session.shutdown().await;
    let session_data = match session_data {
        Ok(data) => data,
        Err(error) => {
            warn!(
                "failed capturing phone code verification snapshot: {}",
                error
            );
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_finalize,
                &headers,
            )
            .await;
        }
    };

    match result {
        Ok(_) => {
            if let Err(error) = finalize_pending_session(
                &app_state,
                &flow.user_id,
                &flow.auth_session_id,
                &flow.session_id,
                &flow.session_name,
                &flow.final_path,
                session_data.as_slice(),
            )
            .await
            {
                warn!("failed finalizing phone login session: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_finalize,
                    &headers,
                )
                .await;
            }

            Redirect::to(&telegram_workspace_href(language)).into_response()
        }
        Err(SignInError::PasswordRequired(password_token)) => {
            flow.stage = PhoneLoginStage::AwaitingPassword {
                token: password_token,
            };
            flow.session_data = share_sensitive_bytes(session_data);
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&phone_flow_href(&flow_id)).into_response()
        }
        Err(SignInError::InvalidCode) => {
            set_login_throttle_seconds(
                &app_state,
                &verify_throttle_key,
                PHONE_VERIFY_FAILURE_COOLDOWN_SECONDS,
            )
            .await;
            flow.stage = PhoneLoginStage::AwaitingCode { token };
            flow.session_data = share_sensitive_bytes(session_data);
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&phone_flow_error_href(&flow_id, "invalid_code")).into_response()
        }
        Err(SignInError::SignUpRequired) => {
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_signup_required,
                &headers,
            )
            .await
        }
        Err(SignInError::Other(error)) => {
            warn!("failed finishing phone login: {}", error);
            if let Some(wait_seconds) = telegram_retry_after_seconds_for_invocation_error(&error) {
                set_login_throttle_seconds(&app_state, &verify_throttle_key, wait_seconds).await;
                flow.stage = PhoneLoginStage::AwaitingCode { token };
                flow.session_data = share_sensitive_bytes(session_data);
                app_state
                    .phone_flows
                    .write()
                    .await
                    .insert(flow_id.clone(), flow);
                return Redirect::to(&phone_flow_retry_after_href(&flow_id, wait_seconds))
                    .into_response();
            }
            set_login_throttle_seconds(
                &app_state,
                &verify_throttle_key,
                PHONE_VERIFY_FAILURE_COOLDOWN_SECONDS,
            )
            .await;
            flow.stage = PhoneLoginStage::AwaitingCode { token };
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&phone_flow_error_href(&flow_id, "code_failed")).into_response()
        }
        Err(SignInError::InvalidPassword(_)) => {
            Redirect::to(&phone_flow_error_href(&flow_id, "password_retry")).into_response()
        }
    }
}

async fn verify_phone_password_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<VerifyPasswordForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let password = form.password.trim();

    if password.is_empty() {
        return Redirect::to(&phone_flow_error_href(&flow_id, "missing_password")).into_response();
    }

    let owner_matches = app_state
        .phone_flows
        .read()
        .await
        .get(&flow_id)
        .map(|flow| flow.user_id == authenticated.user.id)
        .unwrap_or(false);
    if !owner_matches {
        return Redirect::to(&telegram_workspace_href(language)).into_response();
    }

    let verify_throttle_key = phone_password_throttle_key(&flow_id);
    if let Some(wait_seconds) =
        remaining_login_throttle_seconds(&app_state, &verify_throttle_key).await
    {
        return Redirect::to(&phone_flow_retry_after_href(&flow_id, wait_seconds)).into_response();
    }

    let mut flows = app_state.phone_flows.write().await;
    let Some(mut flow) = flows.remove(&flow_id) else {
        drop(flows);
        return render_setup_error_response(
            &app_state,
            language,
            language.translations().setup_error_phone_flow_missing,
            &headers,
        )
        .await;
    };
    if flow.user_id != authenticated.user.id {
        drop(flows);
        return Redirect::to(&telegram_workspace_href(language)).into_response();
    }

    let token = match flow.stage {
        PhoneLoginStage::AwaitingPassword { token } => token,
        PhoneLoginStage::AwaitingCode { token } => {
            flow.stage = PhoneLoginStage::AwaitingCode { token };
            flows.insert(flow_id.clone(), flow);
            drop(flows);
            return Redirect::to(&phone_flow_href(&flow_id)).into_response();
        }
    };
    drop(flows);

    let telegram_profile = configured_telegram_client_profile();
    let client_session = match TelegramClientSession::open_serialized(
        flow.session_data.as_ref().as_slice(),
        &telegram_profile,
    ) {
        Ok(client_session) => client_session,
        Err(error) => {
            warn!(
                "failed opening in-memory session for password verification: {}",
                error
            );
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_phone_password_reset,
                &headers,
            )
            .await;
        }
    };

    let result = client_session.client.check_password(token, password).await;
    let session_data = client_session.snapshot();
    client_session.shutdown().await;
    let session_data = match session_data {
        Ok(data) => data,
        Err(error) => {
            warn!(
                "failed capturing phone password verification snapshot: {}",
                error
            );
            return render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_phone_password_reset,
                &headers,
            )
            .await;
        }
    };

    match result {
        Ok(_) => {
            if let Err(error) = finalize_pending_session(
                &app_state,
                &flow.user_id,
                &flow.auth_session_id,
                &flow.session_id,
                &flow.session_name,
                &flow.final_path,
                session_data.as_slice(),
            )
            .await
            {
                warn!("failed finalizing password login session: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_finalize,
                    &headers,
                )
                .await;
            }

            Redirect::to(&telegram_workspace_href(language)).into_response()
        }
        Err(SignInError::InvalidPassword(password_token)) => {
            set_login_throttle_seconds(
                &app_state,
                &verify_throttle_key,
                PHONE_VERIFY_FAILURE_COOLDOWN_SECONDS,
            )
            .await;
            flow.stage = PhoneLoginStage::AwaitingPassword {
                token: password_token,
            };
            flow.session_data = share_sensitive_bytes(session_data);
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&phone_flow_error_href(&flow_id, "invalid_password")).into_response()
        }
        Err(SignInError::Other(error)) => {
            warn!("failed verifying 2fa password: {}", error);
            if let Some(wait_seconds) = telegram_retry_after_seconds_for_invocation_error(&error) {
                set_login_throttle_seconds(&app_state, &verify_throttle_key, wait_seconds).await;
                return render_setup_error_response(
                    &app_state,
                    language,
                    &setup_retry_after_message(language, wait_seconds),
                    &headers,
                )
                .await;
            }
            set_login_throttle_seconds(
                &app_state,
                &verify_throttle_key,
                PHONE_VERIFY_FAILURE_COOLDOWN_SECONDS,
            )
            .await;
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_phone_password_reset,
                &headers,
            )
            .await
        }
        Err(SignInError::PasswordRequired(password_token)) => {
            flow.stage = PhoneLoginStage::AwaitingPassword {
                token: password_token,
            };
            flow.session_data = share_sensitive_bytes(session_data);
            app_state
                .phone_flows
                .write()
                .await
                .insert(flow_id.clone(), flow);
            Redirect::to(&phone_flow_href(&flow_id)).into_response()
        }
        Err(SignInError::InvalidCode) => {
            Redirect::to(&phone_flow_error_href(&flow_id, "code_failed")).into_response()
        }
        Err(SignInError::SignUpRequired) => {
            render_setup_error_response(
                &app_state,
                language,
                language.translations().setup_error_signup_required,
                &headers,
            )
            .await
        }
    }
}

async fn cancel_phone_flow_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    let owner_matches = app_state
        .phone_flows
        .read()
        .await
        .get(&flow_id)
        .map(|flow| flow.user_id == authenticated.user.id)
        .unwrap_or(false);
    if owner_matches {
        let _ = app_state.phone_flows.write().await.remove(&flow_id);
    } else if app_state.phone_flows.read().await.contains_key(&flow_id) {
        return Redirect::to(&telegram_workspace_href(language)).into_response();
    }

    Redirect::to(&telegram_setup_href(language)).into_response()
}

async fn qr_flow_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<FlowPageQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let flow = {
        let flows = app_state.qr_flows.read().await;
        match flows.get(&flow_id) {
            Some(flow) if flow.user_id == authenticated.user.id => flow.clone(),
            Some(_) => {
                drop(flows);
                return Redirect::to(&telegram_workspace_href(language)).into_response();
            }
            None => {
                drop(flows);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_qr_flow_missing,
                    &headers,
                )
                .await;
            }
        }
    };

    let banner = qr_flow_error_banner(language, query.error.as_deref(), query.wait_seconds);
    let poll_throttle_key = qr_poll_throttle_key(&flow_id);
    if let Some(wait_seconds) =
        remaining_login_throttle_seconds(&app_state, &poll_throttle_key).await
    {
        if let Some(pending) = flow.pending_state.clone() {
            let banner = banner.or_else(|| {
                Some(PageBanner::error(qr_retry_after_message(
                    language,
                    wait_seconds,
                )))
            });
            return match render_qr_flow_page(
                &app_state,
                language,
                &flow_id,
                &flow,
                pending,
                banner,
                &headers,
                u64::from(wait_seconds).max(QR_AUTO_REFRESH_SECONDS),
            )
            .await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            };
        }

        return render_setup_error_response(
            &app_state,
            language,
            &setup_retry_after_message(language, wait_seconds),
            &headers,
        )
        .await;
    }

    let telegram_profile = configured_telegram_client_profile();
    match poll_qr_flow(&telegram_profile, &flow).await {
        Ok((QrStatus::Pending(pending), session_data)) => {
            set_login_throttle_seconds(&app_state, &poll_throttle_key, QR_POLL_COOLDOWN_SECONDS)
                .await;
            if let Some(active_flow) = app_state.qr_flows.write().await.get_mut(&flow_id) {
                active_flow.session_data = share_sensitive_bytes(session_data);
                active_flow.pending_state = Some(pending.clone());
            }
            match render_qr_flow_page(
                &app_state,
                language,
                &flow_id,
                &flow,
                pending,
                banner,
                &headers,
                QR_AUTO_REFRESH_SECONDS,
            )
            .await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            }
        }
        Ok((QrStatus::Authorized, session_data)) => {
            app_state.qr_flows.write().await.remove(&flow_id);

            if let Err(error) = finalize_pending_session(
                &app_state,
                &flow.user_id,
                &flow.auth_session_id,
                &flow.session_id,
                &flow.session_name,
                &flow.final_path,
                session_data.as_slice(),
            )
            .await
            {
                warn!("failed finalizing qr login session: {}", error);
                return render_setup_error_response(
                    &app_state,
                    language,
                    language.translations().setup_error_finalize,
                    &headers,
                )
                .await;
            }

            Redirect::to(&telegram_workspace_href(language)).into_response()
        }
        Err(error) => {
            warn!("failed polling qr login flow: {}", error);
            if let Some(wait_seconds) = telegram_retry_after_seconds_for_anyhow(&error) {
                set_login_throttle_seconds(&app_state, &poll_throttle_key, wait_seconds).await;
                if let Some(pending) = flow.pending_state.clone() {
                    return match render_qr_flow_page(
                        &app_state,
                        language,
                        &flow_id,
                        &flow,
                        pending,
                        Some(PageBanner::error(qr_retry_after_message(
                            language,
                            wait_seconds,
                        ))),
                        &headers,
                        u64::from(wait_seconds).max(QR_AUTO_REFRESH_SECONDS),
                    )
                    .await
                    {
                        Ok(html) => html.into_response(),
                        Err(status) => status.into_response(),
                    };
                }

                return Redirect::to(&qr_flow_retry_after_href(&flow_id, wait_seconds))
                    .into_response();
            }
            Redirect::to(&qr_flow_error_href(&flow_id, "qr_failed")).into_response()
        }
    }
}

async fn cancel_qr_flow_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(flow_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    let flow = app_state.qr_flows.read().await.get(&flow_id).cloned();
    if let Some(flow) = flow {
        if flow.user_id != authenticated.user.id {
            return Redirect::to(&telegram_workspace_href(language)).into_response();
        }
        app_state.qr_flows.write().await.remove(&flow_id);
    }

    Redirect::to(&telegram_setup_href(language)).into_response()
}

fn phone_flow_error_banner(
    language: Language,
    error: Option<&str>,
    wait_seconds: Option<u32>,
) -> Option<PageBanner> {
    let translations = language.translations();
    let message = match error {
        Some("missing_code") => Some(String::from(translations.phone_error_missing_code)),
        Some("invalid_code") => Some(String::from(translations.phone_error_invalid_code)),
        Some("code_failed") => Some(String::from(translations.phone_error_code_failed)),
        Some("missing_password") => Some(String::from(translations.phone_error_missing_password)),
        Some("invalid_password") => Some(String::from(translations.phone_error_invalid_password)),
        Some("password_retry") => Some(String::from(translations.phone_error_password_retry)),
        Some("retry_after") => wait_seconds.map(|wait| phone_retry_after_message(language, wait)),
        _ => None,
    }?;

    Some(PageBanner::error(message))
}

fn qr_flow_error_banner(
    language: Language,
    error: Option<&str>,
    wait_seconds: Option<u32>,
) -> Option<PageBanner> {
    let translations = language.translations();
    let message = match error {
        Some("qr_failed") => Some(String::from(translations.qr_error_failed)),
        Some("retry_after") => wait_seconds.map(|wait| qr_retry_after_message(language, wait)),
        _ => None,
    }?;

    Some(PageBanner::error(message))
}

async fn render_setup_error_response(
    app_state: &AppState,
    language: Language,
    message: &str,
    headers: &HeaderMap,
) -> Response {
    match render_setup_page(
        app_state,
        language,
        Some(PageBanner::error(message)),
        headers,
    )
    .await
    {
        Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
        Err(status) => status.into_response(),
    }
}

async fn poll_qr_flow(
    telegram_profile: &TelegramClientProfile,
    flow: &PendingQrLogin,
) -> Result<(QrStatus, SensitiveBytes)> {
    let client_session = TelegramClientSession::open_serialized(
        flow.session_data.as_ref().as_slice(),
        telegram_profile,
    )
    .context("failed to open qr login session")?;

    let export_result = client_session
        .client
        .invoke(&tl::functions::auth::ExportLoginToken {
            api_id: telegram_profile.api_id,
            api_hash: telegram_profile.api_hash.clone(),
            except_ids: Vec::new(),
        })
        .await;

    let status = match export_result {
        Ok(result) => resolve_qr_status(&client_session, result).await,
        Err(error) => Err(error).context("auth.exportLoginToken failed"),
    };

    let session_data = client_session.snapshot()?;
    client_session.shutdown().await;
    status.map(|status| (status, session_data))
}

async fn resolve_qr_status(
    client_session: &TelegramClientSession,
    mut result: tl::enums::auth::LoginToken,
) -> Result<QrStatus> {
    loop {
        match result {
            tl::enums::auth::LoginToken::Token(token) => {
                let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token.token);
                let qr_link = format!("tg://login?token={encoded}");
                let qr_svg = render_qr_svg(&qr_link)?;
                let expires_at = format_qr_expiry(token.expires);

                return Ok(QrStatus::Pending(QrPendingState {
                    qr_link,
                    qr_svg,
                    expires_at,
                }));
            }
            tl::enums::auth::LoginToken::Success(_) => return Ok(QrStatus::Authorized),
            tl::enums::auth::LoginToken::MigrateTo(migrate) => {
                let previous_dc = client_session.session.home_dc_id();
                client_session.session.set_home_dc_id(migrate.dc_id).await;
                let _ = client_session.pool_handle.disconnect_from_dc(previous_dc);
                result = client_session
                    .client
                    .invoke(&tl::functions::auth::ImportLoginToken {
                        token: migrate.token,
                    })
                    .await
                    .context("auth.importLoginToken failed after migration")?;
            }
        }
    }
}

fn format_qr_expiry(expires: i32) -> String {
    match DateTime::from_timestamp(i64::from(expires), 0) {
        Some(expires_at) => expires_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => String::from("-"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_session_name_falls_back_and_normalizes() {
        assert_eq!(sanitize_session_name("Hello   World"), "Hello World");
        assert_eq!(sanitize_session_name("中文 会话"), "中文 会话");
        assert_eq!(sanitize_session_name("中文/会话:*"), "中文 会话");
        assert_eq!(
            sanitize_session_name("Español العربية हिन्दी 🚀🎉"),
            "Español العربية हिन्दी 🚀🎉"
        );
        assert_eq!(sanitize_session_name("👨‍👩‍👧‍👦 family 会话"), "👨‍👩‍👧‍👦 family 会话");
        assert!(sanitize_session_name("  ").starts_with("session-"));
    }

    #[test]
    fn format_phone_display_formats_plain_digits() {
        let display = format_phone_display("13146288470");

        assert!(display.starts_with("+1 "));
        assert!(display.contains("314"));
    }

    #[test]
    fn telegram_retry_after_seconds_detects_flood_wait_values() {
        let error = InvocationError::Rpc(grammers_client::sender::RpcError {
            code: 420,
            name: String::from("FLOOD_WAIT"),
            value: Some(31),
            caused_by: None,
        });

        assert_eq!(
            telegram_retry_after_seconds_for_invocation_error(&error),
            Some(33)
        );
    }

    #[test]
    fn telegram_retry_after_seconds_uses_phone_flood_fallback() {
        let error = InvocationError::Rpc(grammers_client::sender::RpcError {
            code: 400,
            name: String::from("PHONE_NUMBER_FLOOD"),
            value: None,
            caused_by: None,
        });

        assert_eq!(
            telegram_retry_after_seconds_for_invocation_error(&error),
            Some(TELEGRAM_PHONE_FLOOD_RETRY_AFTER_SECONDS + 2)
        );
    }
}
