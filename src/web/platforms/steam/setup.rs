// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) async fn find_pending_setup_id_for_user(
    app_state: &AppState,
    user_id: &str,
) -> Option<String> {
    let setups = app_state.steam_setups.read().await;
    setups
        .iter()
        .find(|(_, pending)| pending.user_id == user_id)
        .map(|(id, _)| id.clone())
}

pub(super) async fn take_pending_setup_for_user(
    app_state: &AppState,
    user_id: &str,
) -> Option<(String, PendingSteamSetup)> {
    let setup_id = find_pending_setup_id_for_user(app_state, user_id).await?;
    let mut setups = app_state.steam_setups.write().await;
    let pending = setups.remove(&setup_id)?;
    Some((setup_id, pending))
}

pub(super) async fn store_pending_setup(
    app_state: &AppState,
    setup_id: String,
    pending: PendingSteamSetup,
) {
    app_state
        .steam_setups
        .write()
        .await
        .insert(setup_id, pending);
}

pub(super) async fn store_setup_login_code_prompt(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    setup_id: String,
    steam_username: String,
    login: steamguard::UserLogin<steamguard::transport::WebApiTransport>,
    transport: steamguard::transport::WebApiTransport,
    prompt: steam_platform::GuardLoginCodePrompt,
) -> Response {
    let code_kind = match prompt.kind {
        steam_platform::GuardLoginCodeKind::ExistingGuardCode => "device",
        steam_platform::GuardLoginCodeKind::EmailCode => "email",
    };
    let hint = prompt.hint.clone();
    store_pending_setup(
        app_state,
        setup_id.clone(),
        PendingSteamSetup {
            user_id: authenticated.user.id.clone(),
            auth_session_id: authenticated.auth_session.id.clone(),
            created_at: Utc::now().timestamp(),
            stage: SteamSetupStage::AwaitingLoginCode {
                login,
                transport,
                steam_username,
                prompt,
            },
        },
    )
    .await;

    Json(serde_json::json!({
        "ok": true,
        "step": "login_code",
        "setup_id": setup_id,
        "code_kind": code_kind,
        "hint": hint,
    }))
    .into_response()
}

pub(super) async fn store_setup_outcome(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    setup_id: String,
    steam_username: String,
    outcome: steam_platform::GuardEnrollmentResult,
) -> Response {
    match outcome {
        steam_platform::GuardEnrollmentResult::Provisioned {
            guard_data,
            steam_timestamp,
            masked_phone,
            verify_channel,
            registrar,
        } => {
            let pending = PendingSteamSetup {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                created_at: Utc::now().timestamp(),
                stage: SteamSetupStage::AwaitingVerification {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    masked_phone: masked_phone.clone(),
                    verify_channel: verify_channel.clone(),
                    steam_username,
                },
            };
            store_pending_setup(app_state, setup_id.clone(), pending).await;

            Json(serde_json::json!({
                "ok": true,
                "step": "confirm",
                "setup_id": setup_id,
                "masked_phone": masked_phone,
                "verify_channel": verify_channel
            }))
            .into_response()
        }
        steam_platform::GuardEnrollmentResult::EmailConfirmationRequired { registrar } => {
            let pending = PendingSteamSetup {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                created_at: Utc::now().timestamp(),
                stage: SteamSetupStage::AwaitingAccountEmailConfirmation {
                    registrar,
                    steam_username,
                },
            };
            store_pending_setup(app_state, setup_id.clone(), pending).await;

            Json(serde_json::json!({
                "ok": true,
                "step": "email",
                "setup_id": setup_id
            }))
            .into_response()
        }
        steam_platform::GuardEnrollmentResult::PhoneRequired { registrar } => {
            let pending = PendingSteamSetup {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                created_at: Utc::now().timestamp(),
                stage: SteamSetupStage::AwaitingPhoneNumber {
                    registrar,
                    steam_username,
                },
            };
            store_pending_setup(app_state, setup_id.clone(), pending).await;

            Json(serde_json::json!({
                "ok": true,
                "step": "phone_number",
                "setup_id": setup_id
            }))
            .into_response()
        }
        steam_platform::GuardEnrollmentResult::DeviceConflict { registrar } => {
            let pending = PendingSteamSetup {
                user_id: authenticated.user.id.clone(),
                auth_session_id: authenticated.auth_session.id.clone(),
                created_at: Utc::now().timestamp(),
                stage: SteamSetupStage::AwaitingMigrationCode {
                    registrar,
                    steam_username,
                },
            };
            store_pending_setup(app_state, setup_id.clone(), pending).await;

            Json(serde_json::json!({
                "ok": true,
                "step": "transfer",
                "setup_id": setup_id
            }))
            .into_response()
        }
    }
}

pub(super) async fn link_authenticator_for_account_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_account_missing_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    // Clear any previous setup for this user.
    {
        let mut setups = app_state.steam_setups.write().await;
        setups.retain(|_, pending| pending.user_id != authenticated.user.id);
    }

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::enroll_guard_for_managed_account(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
    )
    .await
    {
        Ok((steam_username, outcome)) => {
            let setup_id = Uuid::new_v4().to_string();
            store_setup_outcome(
                &app_state,
                &authenticated,
                setup_id,
                steam_username,
                outcome,
            )
            .await
        }
        Err(error) => {
            warn!(
                "failed linking authenticator for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_setup_link_failed_message)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Guard enrollment handlers (fresh login flow)
// ---------------------------------------------------------------------------

pub(super) async fn setup_begin_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupBeginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.steam_username.trim().is_empty() || form.steam_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_login_missing_username_message
            })),
        )
            .into_response();
    }

    let Some(_master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    // Clear any previous setup for this user.
    {
        let mut setups = app_state.steam_setups.write().await;
        setups.retain(|_, pending| pending.user_id != authenticated.user.id);
    }

    let username = form.steam_username.clone();
    let password = form.steam_password.clone();
    match steam_platform::enroll_new_guard(username, password).await {
        Ok(steam_platform::GuardEnrollmentStartResult::Ready {
            steam_username,
            outcome,
        }) => {
            let setup_id = Uuid::new_v4().to_string();
            store_setup_outcome(
                &app_state,
                &authenticated,
                setup_id,
                steam_username,
                outcome,
            )
            .await
        }
        Ok(steam_platform::GuardEnrollmentStartResult::LoginCodeRequired {
            steam_username,
            login,
            transport,
            prompt,
        }) => {
            let setup_id = Uuid::new_v4().to_string();
            store_setup_login_code_prompt(
                &app_state,
                &authenticated,
                setup_id,
                steam_username,
                login,
                transport,
                prompt,
            )
            .await
        }
        Err(error) => {
            warn!("Steam setup begin failed: {error}");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_setup_link_failed_message)
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn setup_login_code_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupLoginCodeForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_login_code_missing_message
            })),
        )
            .into_response();
    }

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingLoginCode {
            login,
            transport,
            steam_username,
            prompt,
        } => match steam_platform::continue_guard_enrollment_with_login_code(
            login, transport, prompt, form.code,
        )
        .await
        {
            Ok(steam_platform::GuardLoginCodeSubmitResult::Advanced(outcome)) => {
                store_setup_outcome(
                    &app_state,
                    &authenticated,
                    setup_id,
                    steam_username,
                    outcome,
                )
                .await
            }
            Ok(steam_platform::GuardLoginCodeSubmitResult::Retry {
                login,
                transport,
                prompt,
                error,
            }) => {
                warn!("Steam setup login-code verification failed: {error}");
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingLoginCode {
                            login,
                            transport,
                            steam_username,
                            prompt,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_login_code_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
            Err(error) => {
                warn!("Steam setup login-code task failed: {error}");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_login_code_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn setup_resume_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingAccountEmailConfirmation {
            registrar,
            steam_username,
        } => match steam_platform::resume_guard_enrollment(registrar).await {
            Ok(steam_platform::GuardEnrollmentResult::EmailConfirmationRequired { registrar }) => {
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingAccountEmailConfirmation {
                            registrar,
                            steam_username,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": translations.steam_setup_email_confirm_pending_message
                    })),
                )
                    .into_response()
            }
            Ok(outcome) => {
                store_setup_outcome(
                    &app_state,
                    &authenticated,
                    setup_id,
                    steam_username,
                    outcome,
                )
                .await
            }
            Err(error) => {
                warn!("Steam setup email resume failed: {error}");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_link_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        SteamSetupStage::AwaitingPhoneEmailConfirmation {
            registrar,
            steam_username,
            confirmation_email_address,
            phone_number_formatted,
        } => match steam_platform::continue_guard_phone_link(&registrar).await {
            Ok(steam_platform::GuardPhoneEmailContinuation::StillWaiting { seconds_to_wait }) => {
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneEmailConfirmation {
                            registrar,
                            steam_username,
                            confirmation_email_address,
                            phone_number_formatted,
                        },
                    },
                )
                .await;
                let mut message = translations
                    .steam_setup_phone_email_pending_message
                    .to_owned();
                if let Some(wait_seconds) = seconds_to_wait {
                    message.push_str(" (");
                    message.push_str(&format_duration_for_display(
                        language,
                        i64::from(wait_seconds),
                    ));
                    message.push(')');
                }
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": message
                    })),
                )
                    .into_response()
            }
            Ok(steam_platform::GuardPhoneEmailContinuation::SmsSent) => {
                store_pending_setup(
                    &app_state,
                    setup_id.clone(),
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneCode {
                            registrar,
                            steam_username,
                            phone_number_formatted: phone_number_formatted.clone(),
                        },
                    },
                )
                .await;
                Json(serde_json::json!({
                    "ok": true,
                    "step": "phone_code",
                    "setup_id": setup_id,
                    "phone_number": phone_number_formatted
                }))
                .into_response()
            }
            Err(error) => {
                warn!("Steam phone email resume failed: {error}");
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneEmailConfirmation {
                            registrar,
                            steam_username,
                            confirmation_email_address,
                            phone_number_formatted,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_phone_begin_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn setup_phone_begin_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupPhoneNumberForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.phone_number.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_phone_number_missing_message
            })),
        )
            .into_response();
    }

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingPhoneNumber {
            registrar,
            steam_username,
        } => match steam_platform::start_guard_phone_link(&registrar, form.phone_number).await {
            Ok(prompt) => {
                store_pending_setup(
                    &app_state,
                    setup_id.clone(),
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneEmailConfirmation {
                            registrar,
                            steam_username,
                            confirmation_email_address: prompt.confirmation_email_address.clone(),
                            phone_number_formatted: prompt.phone_number_formatted.clone(),
                        },
                    },
                )
                .await;
                Json(serde_json::json!({
                    "ok": true,
                    "step": "phone_email",
                    "setup_id": setup_id,
                    "phone_number": prompt.phone_number_formatted,
                    "confirmation_email": prompt.confirmation_email_address
                }))
                .into_response()
            }
            Err(error) => {
                warn!("Steam phone setup begin failed: {error}");
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneNumber {
                            registrar,
                            steam_username,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_phone_begin_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn setup_phone_verify_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupPhoneVerifyForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.verification_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_bad_sms_code_message
            })),
        )
            .into_response();
    }

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingPhoneCode {
            registrar,
            steam_username,
            phone_number_formatted,
        } => match steam_platform::verify_guard_phone_link(registrar, form.verification_code).await
        {
            Ok(steam_platform::GuardPhoneVerificationResult::Advanced(outcome)) => {
                store_setup_outcome(
                    &app_state,
                    &authenticated,
                    setup_id,
                    steam_username,
                    outcome,
                )
                .await
            }
            Ok(steam_platform::GuardPhoneVerificationResult::Retry { registrar, error }) => {
                warn!("Steam phone verification failed: {error}");
                store_pending_setup(
                    &app_state,
                    setup_id,
                    PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingPhoneCode {
                            registrar,
                            steam_username,
                            phone_number_formatted,
                        },
                    },
                )
                .await;
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_phone_code_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
            Err(error) => {
                warn!("Steam phone verification failed: {error}");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": steam_setup_failure_message(
                            language,
                            &error,
                            translations.steam_setup_phone_code_failed_message,
                        )
                    })),
                )
                    .into_response()
            }
        },
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn setup_finalize_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupFinalizeForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.confirm_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_missing_credentials_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingVerification {
            registrar,
            guard_data,
            steam_timestamp,
            steam_username,
            masked_phone,
            verify_channel,
            ..
        } => {
            let code = form.confirm_code.trim().to_owned();
            let username = steam_username.clone();

            let enrollment_result = tokio::task::spawn_blocking(move || {
                steam_platform::confirm_guard_enrollment(
                    registrar,
                    guard_data,
                    steam_timestamp,
                    code,
                )
            })
            .await;

            match enrollment_result {
                Ok(steam_platform::GuardFinalizeResult::Completed {
                    guard_data: enrolled_data,
                }) => {
                    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
                    match steam_platform::persist_enrolled_guard(
                        &steam_root,
                        master_key.as_ref().as_slice(),
                        &enrolled_data,
                        &username,
                    )
                    .await
                    {
                        Ok(saved) => {
                            let revocation_code = saved.revocation_code.clone().unwrap_or_default();
                            let account_id = saved.id.clone();

                            // Store completion state.
                            let complete = PendingSteamSetup {
                                user_id: authenticated.user.id.clone(),
                                auth_session_id: authenticated.auth_session.id.clone(),
                                created_at: Utc::now().timestamp(),
                                stage: SteamSetupStage::Complete,
                            };
                            app_state
                                .steam_setups
                                .write()
                                .await
                                .insert(setup_id, complete);

                            Json(serde_json::json!({
                                "ok": true,
                                "step": "complete",
                                "revocation_code": revocation_code,
                                "account_id": account_id
                            }))
                            .into_response()
                        }
                        Err(error) => {
                            warn!("Failed saving linked Steam account: {error}");
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({
                                    "ok": false,
                                    "message": translations.steam_setup_save_failed_message
                                })),
                            )
                                .into_response()
                        }
                    }
                }
                Ok(steam_platform::GuardFinalizeResult::Retry {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    error,
                }) => {
                    warn!("Steam setup finalize failed: {error}");
                    store_pending_setup(
                        &app_state,
                        setup_id,
                        PendingSteamSetup {
                            user_id: authenticated.user.id.clone(),
                            auth_session_id: authenticated.auth_session.id.clone(),
                            created_at: Utc::now().timestamp(),
                            stage: SteamSetupStage::AwaitingVerification {
                                registrar,
                                guard_data,
                                steam_timestamp,
                                masked_phone,
                                verify_channel,
                                steam_username,
                            },
                        },
                    )
                    .await;
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": steam_setup_failure_message(
                                language,
                                &error,
                                translations.steam_setup_finalize_failed_message,
                            )
                        })),
                    )
                        .into_response()
                }
                Err(join_error) => {
                    warn!("Steam setup finalize task panicked: {join_error}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": translations.steam_setup_finalize_failed_message
                        })),
                    )
                        .into_response()
                }
            }
        }
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn setup_transfer_start_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingMigrationCode {
            registrar,
            steam_username,
        } => {
            let username = steam_username.clone();

            let result = tokio::task::spawn_blocking(move || {
                steam_platform::initiate_guard_migration(registrar)
            })
            .await;

            match result {
                Ok(steam_platform::GuardMigrationStartResult::AwaitingSms {
                    registrar: registrar_back,
                }) => {
                    let ready = PendingSteamSetup {
                        user_id: authenticated.user.id.clone(),
                        auth_session_id: authenticated.auth_session.id.clone(),
                        created_at: Utc::now().timestamp(),
                        stage: SteamSetupStage::AwaitingMigrationCode {
                            registrar: registrar_back,
                            steam_username: username,
                        },
                    };
                    app_state.steam_setups.write().await.insert(setup_id, ready);

                    Json(serde_json::json!({
                        "ok": true,
                        "step": "transfer_sms"
                    }))
                    .into_response()
                }
                Ok(steam_platform::GuardMigrationStartResult::PhoneRequired {
                    registrar: registrar_back,
                }) => {
                    store_pending_setup(
                        &app_state,
                        setup_id,
                        PendingSteamSetup {
                            user_id: authenticated.user.id.clone(),
                            auth_session_id: authenticated.auth_session.id.clone(),
                            created_at: Utc::now().timestamp(),
                            stage: SteamSetupStage::AwaitingPhoneNumber {
                                registrar: registrar_back,
                                steam_username: username,
                            },
                        },
                    )
                    .await;

                    Json(serde_json::json!({
                        "ok": true,
                        "step": "phone_number"
                    }))
                    .into_response()
                }
                Ok(steam_platform::GuardMigrationStartResult::Retry {
                    registrar: registrar_back,
                    error,
                }) => {
                    warn!("Steam transfer start failed: {error}");
                    store_pending_setup(
                        &app_state,
                        setup_id,
                        PendingSteamSetup {
                            user_id: authenticated.user.id.clone(),
                            auth_session_id: authenticated.auth_session.id.clone(),
                            created_at: Utc::now().timestamp(),
                            stage: SteamSetupStage::AwaitingMigrationCode {
                                registrar: registrar_back,
                                steam_username: username,
                            },
                        },
                    )
                    .await;
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": steam_setup_failure_message(
                                language,
                                &error,
                                translations.steam_setup_transfer_failed_message,
                            )
                        })),
                    )
                        .into_response()
                }
                Err(join_error) => {
                    warn!("Steam transfer start panicked: {join_error}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": translations.steam_setup_transfer_failed_message
                        })),
                    )
                        .into_response()
                }
            }
        }
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn setup_transfer_finish_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<SteamSetupTransferFinishForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if form.sms_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_missing_credentials_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    let Some((setup_id, pending)) =
        take_pending_setup_for_user(&app_state, &authenticated.user.id).await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_setup_no_pending_message
            })),
        )
            .into_response();
    };

    match pending.stage {
        SteamSetupStage::AwaitingMigrationCode {
            registrar,
            steam_username,
        } => {
            let migration_code = form.sms_code.trim().to_owned();
            let username = steam_username.clone();

            let result = tokio::task::spawn_blocking(move || {
                steam_platform::complete_guard_migration(registrar, migration_code)
            })
            .await;

            match result {
                Ok(steam_platform::GuardMigrationFinishResult::Completed {
                    guard_data: migrated_guard,
                }) => {
                    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
                    match steam_platform::persist_enrolled_guard(
                        &steam_root,
                        master_key.as_ref().as_slice(),
                        &migrated_guard,
                        &username,
                    )
                    .await
                    {
                        Ok(saved) => {
                            let revocation_code = saved.revocation_code.clone().unwrap_or_default();
                            let account_id = saved.id.clone();

                            let complete = PendingSteamSetup {
                                user_id: authenticated.user.id.clone(),
                                auth_session_id: authenticated.auth_session.id.clone(),
                                created_at: Utc::now().timestamp(),
                                stage: SteamSetupStage::Complete,
                            };
                            app_state
                                .steam_setups
                                .write()
                                .await
                                .insert(setup_id, complete);

                            Json(serde_json::json!({
                                "ok": true,
                                "step": "complete",
                                "revocation_code": revocation_code,
                                "account_id": account_id
                            }))
                            .into_response()
                        }
                        Err(error) => {
                            warn!("Failed saving transferred Steam account: {error}");
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({
                                    "ok": false,
                                    "message": translations.steam_setup_save_failed_message
                                })),
                            )
                                .into_response()
                        }
                    }
                }
                Ok(steam_platform::GuardMigrationFinishResult::Retry { registrar, error }) => {
                    warn!("Steam transfer finish failed: {error}");
                    store_pending_setup(
                        &app_state,
                        setup_id,
                        PendingSteamSetup {
                            user_id: authenticated.user.id.clone(),
                            auth_session_id: authenticated.auth_session.id.clone(),
                            created_at: Utc::now().timestamp(),
                            stage: SteamSetupStage::AwaitingMigrationCode {
                                registrar,
                                steam_username,
                            },
                        },
                    )
                    .await;
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": steam_setup_failure_message(
                                language,
                                &error,
                                translations.steam_setup_transfer_failed_message,
                            )
                        })),
                    )
                        .into_response()
                }
                Err(join_error) => {
                    warn!("Steam transfer finish panicked: {join_error}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "message": translations.steam_setup_transfer_failed_message
                        })),
                    )
                        .into_response()
                }
            }
        }
        other_stage => {
            store_pending_setup(
                &app_state,
                setup_id,
                PendingSteamSetup {
                    user_id: pending.user_id,
                    auth_session_id: pending.auth_session_id,
                    created_at: pending.created_at,
                    stage: other_stage,
                },
            )
            .await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": translations.steam_setup_no_pending_message
                })),
            )
                .into_response()
        }
    }
}

pub(super) async fn setup_cancel_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Json(form): Json<LangQuery>,
) -> Response {
    let _language = detect_language(&headers, form.lang.as_deref());

    let mut setups = app_state.steam_setups.write().await;
    let before = setups.len();
    setups.retain(|_, pending| pending.user_id != authenticated.user.id);
    let removed = before - setups.len();

    Json(serde_json::json!({
        "ok": true,
        "removed": removed
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Guard revocation handler
// ---------------------------------------------------------------------------

pub(super) async fn remove_authenticator_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(account_id): AxumPath<String>,
    headers: HeaderMap,
    Json(form): Json<SteamRemoveAuthenticatorForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let translations = language.translations();

    if !steam_platform::is_valid_managed_account_id(&account_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_account_missing_message
            })),
        )
            .into_response();
    }

    if form.revocation_code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.steam_remove_missing_code_message
            })),
        )
            .into_response();
    }

    let Some(master_key) = middleware::resolved_user_master_key(&app_state, &authenticated).await
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "message": translations.session_data_locked_message
            })),
        )
            .into_response();
    };

    let steam_root = steam_accounts_dir(&app_state.runtime, &authenticated.user.id);
    match steam_platform::revoke_account_guard(
        &steam_root,
        master_key.as_ref().as_slice(),
        &account_id,
        form.revocation_code.trim().to_owned(),
    )
    .await
    {
        Ok(outcome) => {
            if outcome.revoked {
                Json(serde_json::json!({
                    "ok": true,
                    "message": translations.steam_remove_success_message
                }))
                .into_response()
            } else {
                let msg = if let Some(left) = outcome.tries_left {
                    format!(
                        "{} ({})",
                        translations.steam_remove_incorrect_code_message, left
                    )
                } else {
                    translations.steam_remove_incorrect_code_message.to_owned()
                };
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "message": msg,
                        "tries_left": outcome.tries_left
                    })),
                )
                    .into_response()
            }
        }
        Err(error) => {
            warn!(
                "guard revocation failed for account {}: {}",
                account_id, error
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "message": format!("{}: {error}", translations.steam_remove_failed_message)
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Logged-in device handlers
// ---------------------------------------------------------------------------
