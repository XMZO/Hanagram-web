// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

/// Resolve the enrollment attempt from an `AccountLinker` into a typed result.
pub(super) fn resolve_enrollment(
    mut registrar: AccountLinker<WebApiTransport>,
) -> Result<GuardEnrollmentResult> {
    match registrar.link() {
        Ok(provision) => {
            let verify_channel = match provision.confirm_type() {
                steamguard::accountlinker::AccountLinkConfirmType::SMS => "sms",
                steamguard::accountlinker::AccountLinkConfirmType::Email => "email",
                _ => "unknown",
            }
            .to_owned();
            let steam_timestamp = provision.server_time();
            let masked_phone = provision.phone_number_hint().to_owned();
            let guard_data = provision.into_account();
            Ok(GuardEnrollmentResult::Provisioned {
                guard_data,
                steam_timestamp,
                masked_phone,
                verify_channel,
                registrar,
            })
        }
        Err(AccountLinkError::MustConfirmEmail) => {
            Ok(GuardEnrollmentResult::EmailConfirmationRequired { registrar })
        }
        Err(AccountLinkError::MustProvidePhoneNumber) => {
            Ok(GuardEnrollmentResult::PhoneRequired { registrar })
        }
        Err(AccountLinkError::AuthenticatorPresent) => {
            Ok(GuardEnrollmentResult::DeviceConflict { registrar })
        }
        Err(e) => Err(e.into()),
    }
}

pub(crate) async fn resume_guard_enrollment(
    registrar: AccountLinker<WebApiTransport>,
) -> Result<GuardEnrollmentResult> {
    spawn_blocking(move || resolve_enrollment(registrar))
        .await
        .context("guard enrollment resume task panicked")?
}

pub(super) fn login_code_guard_type(kind: GuardLoginCodeKind) -> EAuthSessionGuardType {
    match kind {
        GuardLoginCodeKind::ExistingGuardCode => {
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
        }
        GuardLoginCodeKind::EmailCode => EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
    }
}

pub(crate) async fn continue_guard_enrollment_with_login_code(
    mut login: UserLogin<WebApiTransport>,
    transport: WebApiTransport,
    prompt: GuardLoginCodePrompt,
    code: String,
) -> Result<GuardLoginCodeSubmitResult> {
    spawn_blocking(move || {
        let trimmed = code.trim().to_owned();
        ensure!(!trimmed.is_empty(), "login_code_required");
        match login.submit_steam_guard_code(login_code_guard_type(prompt.kind), trimmed) {
            Ok(_) | Err(UpdateAuthSessionError::DuplicateRequest) => {}
            Err(error) => {
                return Ok::<GuardLoginCodeSubmitResult, anyhow::Error>(
                    GuardLoginCodeSubmitResult::Retry {
                        login,
                        transport,
                        prompt,
                        error: map_guard_submit_error(error),
                    },
                );
            }
        }

        let tokens = match login.poll_until_tokens() {
            Ok(tokens) => tokens,
            Err(error) => {
                return Ok::<GuardLoginCodeSubmitResult, anyhow::Error>(
                    GuardLoginCodeSubmitResult::Retry {
                        login,
                        transport,
                        prompt,
                        error: error
                            .context("could not obtain session tokens during guard enrollment"),
                    },
                );
            }
        };

        Ok::<GuardLoginCodeSubmitResult, anyhow::Error>(GuardLoginCodeSubmitResult::Advanced(
            resolve_enrollment(AccountLinker::new(transport, tokens))?,
        ))
    })
    .await
    .context("guard enrollment login-code task panicked")?
}

pub(super) fn build_phone_linker(tokens: SteamTokens) -> Result<PhoneLinker<WebApiTransport>> {
    let client = build_blocking_steam_client()?;
    let transport = WebApiTransport::new(client);
    Ok(PhoneLinker::new(PhoneClient::new(transport), tokens))
}

pub(super) fn map_phone_set_error(error: SetPhoneNumberError) -> anyhow::Error {
    match error {
        SetPhoneNumberError::UnknownEResult(EResult::RateLimitExceeded) => anyhow!("rate_limited"),
        SetPhoneNumberError::UnknownEResult(result) => {
            anyhow!("failed setting Steam phone number: {result:?}")
        }
        SetPhoneNumberError::TransportError(inner) => inner.into(),
    }
}

pub(super) fn map_phone_verify_error(error: VerifyPhoneError) -> anyhow::Error {
    match error {
        VerifyPhoneError::UnknownEResult(EResult::SMSCodeFailed) => anyhow!("bad_sms_code"),
        VerifyPhoneError::UnknownEResult(EResult::RateLimitExceeded) => anyhow!("rate_limited"),
        VerifyPhoneError::UnknownEResult(result) => {
            anyhow!("failed verifying Steam phone number: {result:?}")
        }
        VerifyPhoneError::TransportError(inner) => inner.into(),
    }
}

pub(crate) async fn start_guard_phone_link(
    registrar: &AccountLinker<WebApiTransport>,
    phone_number_raw: String,
) -> Result<GuardPhoneLinkPrompt> {
    let tokens = registrar.tokens().clone();
    spawn_blocking(move || {
        let trimmed = phone_number_raw.trim();
        ensure!(!trimmed.is_empty(), "phone_number_required");
        let parsed =
            phonenumber::parse(None, trimmed).map_err(|_| anyhow!("invalid_phone_number"))?;
        let linker = build_phone_linker(tokens)?;
        let response = linker
            .set_account_phone_number(parsed)
            .map_err(map_phone_set_error)?;
        Ok::<GuardPhoneLinkPrompt, anyhow::Error>(GuardPhoneLinkPrompt {
            confirmation_email_address: response.confirmation_email_address().to_owned(),
            phone_number_formatted: response.phone_number_formatted().to_owned(),
        })
    })
    .await
    .context("Steam phone setup task panicked")?
}

pub(crate) async fn continue_guard_phone_link(
    registrar: &AccountLinker<WebApiTransport>,
) -> Result<GuardPhoneEmailContinuation> {
    let tokens = registrar.tokens().clone();
    spawn_blocking(move || {
        let linker = build_phone_linker(tokens)?;
        let waiting = linker.is_account_waiting_for_email_confirmation()?;
        if waiting.is_some() {
            return Ok::<GuardPhoneEmailContinuation, anyhow::Error>(
                GuardPhoneEmailContinuation::StillWaiting {
                    seconds_to_wait: waiting,
                },
            );
        }
        linker.send_phone_verification_code(0).map_err(|error| {
            match error.downcast::<steamguard::transport::TransportError>() {
                Ok(transport_error) => anyhow!(transport_error.to_string()),
                Err(other) => {
                    let message = other.to_string();
                    if message.contains("RateLimitExceeded") {
                        anyhow!("rate_limited")
                    } else {
                        anyhow!("failed sending Steam phone verification code: {message}")
                    }
                }
            }
        })?;
        Ok::<GuardPhoneEmailContinuation, anyhow::Error>(GuardPhoneEmailContinuation::SmsSent)
    })
    .await
    .context("Steam phone email confirmation task panicked")?
}

pub(crate) async fn verify_guard_phone_link(
    registrar: AccountLinker<WebApiTransport>,
    verification_code: String,
) -> Result<GuardPhoneVerificationResult> {
    spawn_blocking(move || {
        let code = verification_code.trim().to_owned();
        ensure!(!code.is_empty(), "phone_verification_code_required");
        let linker = build_phone_linker(registrar.tokens().clone())?;
        if let Err(error) = linker
            .verify_account_phone_with_code(code)
            .map_err(map_phone_verify_error)
        {
            return Ok(GuardPhoneVerificationResult::Retry { registrar, error });
        }
        Ok(GuardPhoneVerificationResult::Advanced(resolve_enrollment(
            registrar,
        )?))
    })
    .await
    .context("Steam phone verification task panicked")?
}

/// Authenticate to Steam and request a new guard enrollment.
pub(crate) async fn enroll_new_guard(
    steam_username: String,
    steam_password: String,
) -> Result<GuardEnrollmentStartResult> {
    spawn_blocking(move || {
        let username = steam_username.trim().to_owned();
        ensure!(!username.is_empty(), "Steam username is required");
        ensure!(!steam_password.is_empty(), "Steam password is required");

        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);

        let mut login = UserLogin::new(transport.clone(), build_steam_mobile_device_details());
        let guard_methods = login
            .begin_auth_via_credentials(&username, &steam_password)
            .map_err(map_login_error)?;
        if let Some(prompt) = resolve_guard_setup_login_prompt(
            guard_methods
                .iter()
                .map(|method| (method.confirmation_type, method.associated_messsage.clone())),
        )? {
            return Ok::<GuardEnrollmentStartResult, anyhow::Error>(
                GuardEnrollmentStartResult::LoginCodeRequired {
                    steam_username: username,
                    login,
                    transport,
                    prompt,
                },
            );
        }

        let tokens = login
            .poll_until_tokens()
            .context("could not obtain session tokens during guard enrollment")?;

        let registrar = AccountLinker::new(transport, tokens);
        let outcome = resolve_enrollment(registrar)?;
        Ok(GuardEnrollmentStartResult::Ready {
            steam_username: username,
            outcome,
        })
    })
    .await
    .context("guard enrollment task panicked")?
}

/// Enroll a guard on an existing managed account using its stored session tokens.
pub(crate) async fn enroll_guard_for_managed_account(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<(String, GuardEnrollmentResult)> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let record = load_stored_account(master_key, &storage_path)
        .await?
        .context("account not found")?;

    let session = record.session.as_ref().context("no session on account")?;
    let access_jwt = session
        .access_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("no access token")?
        .to_owned();
    let refresh_jwt = session
        .refresh_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("no refresh token")?
        .to_owned();
    let display_name = record
        .steam_username
        .clone()
        .unwrap_or_else(|| record.account_name.clone());

    spawn_blocking(move || {
        let tokens = SteamTokens::new(SteamJwt::from(access_jwt), SteamJwt::from(refresh_jwt));
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let registrar = AccountLinker::new(transport, tokens);

        let outcome = resolve_enrollment(registrar)?;
        Ok((display_name, outcome))
    })
    .await
    .context("managed account guard enrollment task panicked")?
}

/// Submit the user-provided verification code to complete the guard enrollment.
pub(crate) fn confirm_guard_enrollment(
    mut registrar: AccountLinker<WebApiTransport>,
    mut guard_data: VendorSteamGuardAccount,
    mut steam_timestamp: u64,
    verification_code: String,
) -> GuardFinalizeResult {
    let mut remaining = GUARD_VERIFY_ATTEMPTS;
    loop {
        match registrar.finalize(steam_timestamp, &mut guard_data, verification_code.clone()) {
            Ok(()) => return GuardFinalizeResult::Completed { guard_data },
            Err(FinalizeLinkError::WantMore { server_time }) if remaining > 1 => {
                steam_timestamp = server_time;
                remaining -= 1;
            }
            Err(FinalizeLinkError::WantMore { .. }) => {
                return GuardFinalizeResult::Retry {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    error: anyhow!("guard enrollment verification exhausted"),
                };
            }
            Err(FinalizeLinkError::BadSmsCode) => {
                return GuardFinalizeResult::Retry {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    error: anyhow!("bad_sms_code"),
                };
            }
            Err(error) => {
                return GuardFinalizeResult::Retry {
                    registrar,
                    guard_data,
                    steam_timestamp,
                    error: error.into(),
                };
            }
        }
    }
}

/// Request Steam to start migrating an existing guard to this device.
pub(crate) fn initiate_guard_migration(
    mut registrar: AccountLinker<WebApiTransport>,
) -> GuardMigrationStartResult {
    match registrar.transfer_start() {
        Ok(()) => GuardMigrationStartResult::AwaitingSms { registrar },
        Err(TransferError::GenericFailure) => {
            GuardMigrationStartResult::PhoneRequired { registrar }
        }
        Err(error) => GuardMigrationStartResult::Retry {
            registrar,
            error: error.into(),
        },
    }
}

/// Finish the guard migration by providing the SMS verification code.
pub(crate) fn complete_guard_migration(
    mut registrar: AccountLinker<WebApiTransport>,
    code: String,
) -> GuardMigrationFinishResult {
    match registrar.transfer_finish(code) {
        Ok(guard_data) => GuardMigrationFinishResult::Completed { guard_data },
        Err(TransferError::BadSmsCode) => GuardMigrationFinishResult::Retry {
            registrar,
            error: anyhow!("bad_sms_code"),
        },
        Err(error) => GuardMigrationFinishResult::Retry {
            registrar,
            error: error.into(),
        },
    }
}

/// Persist a newly enrolled/migrated guard into our encrypted storage format.
pub(crate) async fn persist_enrolled_guard(
    root_dir: &Path,
    master_key: &[u8],
    guard_data: &VendorSteamGuardAccount,
    steam_username: &str,
) -> Result<SteamGuardAccount> {
    ensure_managed_accounts_dir(root_dir).await?;

    let secret_b64 =
        base64::engine::general_purpose::STANDARD.encode(guard_data.shared_secret.expose_secret());
    validate_shared_secret(&secret_b64)?;

    let tokens = guard_data
        .tokens
        .as_ref()
        .context("guard enrollment did not provide usable Steam session tokens")?;

    let now = Utc::now().timestamp();
    let record = StoredSteamAccount {
        schema_version: STEAM_MANAGED_SCHEMA_VERSION,
        id: Uuid::new_v4().to_string(),
        account_name: sanitize_account_name(&guard_data.account_name),
        steam_username: Some(steam_username.to_owned()),
        steam_id: Some(guard_data.steam_id),
        shared_secret: secret_b64,
        identity_secret: Some(guard_data.identity_secret.expose_secret().to_owned()),
        device_id: Some(guard_data.device_id.clone()),
        session: Some(StoredSteamWebSession {
            session_id: None,
            steam_login: None,
            steam_login_secure: None,
            web_cookie: None,
            oauth_token: None,
            access_token: Some(tokens.access_token().expose_secret().to_owned()),
            refresh_token: Some(tokens.refresh_token().expose_secret().to_owned()),
        }),
        imported_from: Some(String::from("guard-enrollment")),
        managed_origin: SteamManagedAccountOrigin::ManualEntry,
        created_at_unix: now,
        updated_at_unix: now,
        revocation_code: Some(guard_data.revocation_code.expose_secret().to_owned()),
        serial_number: Some(guard_data.serial_number.clone()),
        token_gid: Some(guard_data.token_gid.clone()),
        secret_1: Some(guard_data.secret_1.expose_secret().to_owned()),
        uri: Some(guard_data.uri.expose_secret().to_owned()),
        proxy_url: None,
    };
    let storage_path = managed_account_storage_path(root_dir, &record.id);
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(record.into_runtime(storage_path))
}

// ---------------------------------------------------------------------------
// Guard revocation
// ---------------------------------------------------------------------------

/// Revoke the guard on a managed account using the recovery code.
pub(crate) async fn revoke_account_guard(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    recovery_code: String,
) -> Result<GuardRevocationOutcome> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(record) = load_stored_account(master_key, &storage_path).await? else {
        bail!("account not found");
    };

    let session = record.session.as_ref().context("no session on account")?;
    let access_jwt = session
        .access_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("session lacks access token for guard revocation")?
        .to_owned();
    let refresh_jwt = session
        .refresh_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("session lacks refresh token for guard revocation")?
        .to_owned();

    let outcome = spawn_blocking(move || {
        let tokens = SteamTokens::new(SteamJwt::from(access_jwt), SteamJwt::from(refresh_jwt));
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let registrar = AccountLinker::new(transport, tokens);

        match registrar.remove_authenticator(Some(&recovery_code)) {
            Ok(()) => Ok(GuardRevocationOutcome {
                revoked: true,
                tries_left: None,
            }),
            Err(RemoveAuthenticatorError::IncorrectRevocationCode { attempts_remaining }) => {
                Ok(GuardRevocationOutcome {
                    revoked: false,
                    tries_left: Some(attempts_remaining),
                })
            }
            Err(RemoveAuthenticatorError::MissingRevocationCode) => {
                bail!("missing_revocation_code")
            }
            Err(e) => Err(e.into()),
        }
    })
    .await
    .context("guard revocation task panicked")??;

    if outcome.revoked {
        delete_managed_account(root_dir, account_id).await?;
    }

    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Account security profile
// ---------------------------------------------------------------------------

/// Fetch the current guard / 2FA security profile for a managed account.
pub(crate) async fn fetch_security_info(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<AccountSecurityInfo> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let record = load_stored_account(master_key, &storage_path)
        .await?
        .context("account not found")?;
    let session = record.session.as_ref().context("no session on account")?;
    let access_jwt = session
        .access_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("session lacks access token")?
        .to_owned();
    let refresh_jwt = session
        .refresh_token
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .context("session lacks refresh token")?
        .to_owned();
    let steam_id = record.steam_id.context("no steam_id on account")?;
    let shared_secret = record.shared_secret.clone();

    spawn_blocking(move || {
        let tokens = SteamTokens::new(SteamJwt::from(access_jwt), SteamJwt::from(refresh_jwt));
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);

        let mut stub = VendorSteamGuardAccount::new();
        stub.steam_id = steam_id;
        stub.shared_secret =
            TwoFactorSecret::parse_shared_secret(shared_secret).context("bad shared_secret")?;

        let registrar = AccountLinker::new(transport, tokens);
        let resp = registrar
            .query_status(&stub)
            .map_err(|e| anyhow!("security profile query failed: {e:?}"))?;

        Ok(AccountSecurityInfo {
            guard_state: resp.state(),
            protection_mode: resp.steamguard_scheme(),
            guard_type: resp.authenticator_type(),
            email_verified: resp.email_validated(),
            bound_device: resp.device_identifier().to_owned(),
            enrolled_at: resp.time_created(),
            remaining_revoke_tries: resp.revocation_attempts_remaining(),
            schema_ver: resp.version(),
        })
    })
    .await
    .context("security profile query task panicked")?
}

// ---------------------------------------------------------------------------
// Phone status check
// ---------------------------------------------------------------------------

/// Query whether the Steam account has a phone number linked.
pub(crate) async fn check_phone_status(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<bool> {
    refresh_confirmation_session_if_needed(root_dir, master_key, account_id, false).await?;

    let storage_path = managed_account_storage_path(root_dir, account_id);
    let record = load_stored_account(master_key, &storage_path)
        .await?
        .context("account not found")?;
    let account = record.into_runtime(storage_path);
    let vendor_tokens = build_vendor_tokens(&account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let phone_client = PhoneClient::new(transport);
        let request = CPhone_AccountPhoneStatus_Request::new();
        let response = phone_client
            .account_phone_status(request, vendor_tokens.access_token())
            .context("failed querying Steam phone status")?;
        let result = response.result();
        if result != EResult::OK {
            let error_detail = response
                .error_message()
                .cloned()
                .unwrap_or_else(|| format!("{result:?}"));
            bail!("Steam refused phone status query: {error_detail}");
        }
        Ok(response.into_response_data().has_phone())
    })
    .await
    .context("phone status query task panicked")?
}

// ---------------------------------------------------------------------------
// Emergency (recovery) codes
// ---------------------------------------------------------------------------

/// Generate a new set of emergency recovery codes for the Steam account.
pub(crate) async fn create_emergency_codes(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<Vec<String>> {
    refresh_confirmation_session_if_needed(root_dir, master_key, account_id, false).await?;

    let storage_path = managed_account_storage_path(root_dir, account_id);
    let record = load_stored_account(master_key, &storage_path)
        .await?
        .context("account not found")?;
    let account = record.into_runtime(storage_path);
    let vendor_tokens = build_vendor_tokens(&account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let twofactor_client = TwoFactorClient::new(transport);
        // Note: the `code` field on CreateEmergencyCodes is an SMS verification
        // code sent to the account's phone. We cannot generate it programmatically.
        // Steam may still accept the request without it for some accounts.
        let request = CTwoFactor_CreateEmergencyCodes_Request::new();
        let response = twofactor_client
            .create_emergency_codes(request, vendor_tokens.access_token())
            .context("failed creating Steam emergency codes")?;
        let result = response.result();
        if result != EResult::OK {
            let error_detail = response
                .error_message()
                .cloned()
                .unwrap_or_else(|| format!("{result:?}"));
            bail!("Steam refused emergency code creation: {error_detail}");
        }
        let data = response.into_response_data();
        let codes: Vec<String> = data.codes.to_vec();
        Ok(codes)
    })
    .await
    .context("emergency code creation task panicked")?
}

/// Destroy all existing emergency recovery codes for the Steam account.
pub(crate) async fn destroy_emergency_codes(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<()> {
    refresh_confirmation_session_if_needed(root_dir, master_key, account_id, false).await?;

    let storage_path = managed_account_storage_path(root_dir, account_id);
    let record = load_stored_account(master_key, &storage_path)
        .await?
        .context("account not found")?;
    let steam_id = record.steam_id.context("no steam_id on account")?;
    let account = record.into_runtime(storage_path);
    let vendor_tokens = build_vendor_tokens(&account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let twofactor_client = TwoFactorClient::new(transport);
        let mut request = CTwoFactor_DestroyEmergencyCodes_Request::new();
        request.set_steamid(steam_id);
        let response = twofactor_client
            .destroy_emergency_codes(request, vendor_tokens.access_token())
            .context("failed destroying Steam emergency codes")?;
        let result = response.result();
        if result != EResult::OK {
            let error_detail = response
                .error_message()
                .cloned()
                .unwrap_or_else(|| format!("{result:?}"));
            bail!("Steam refused emergency code destruction: {error_detail}");
        }
        Ok(())
    })
    .await
    .context("emergency code destruction task panicked")?
}

// ---------------------------------------------------------------------------
// Validate authenticator token
// ---------------------------------------------------------------------------

/// Ask Steam whether a given TOTP code is currently valid for the account.
pub(crate) async fn validate_authenticator_token(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    code: String,
) -> Result<bool> {
    refresh_confirmation_session_if_needed(root_dir, master_key, account_id, false).await?;

    let storage_path = managed_account_storage_path(root_dir, account_id);
    let record = load_stored_account(master_key, &storage_path)
        .await?
        .context("account not found")?;
    let account = record.into_runtime(storage_path);
    let vendor_tokens = build_vendor_tokens(&account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let twofactor_client = TwoFactorClient::new(transport);
        let mut request = CTwoFactor_ValidateToken_Request::new();
        request.set_code(code);
        let response = twofactor_client
            .validate_token(request, vendor_tokens.access_token())
            .context("failed validating Steam authenticator token")?;
        let result = response.result();
        if result != EResult::OK {
            let error_detail = response
                .error_message()
                .cloned()
                .unwrap_or_else(|| format!("{result:?}"));
            bail!("Steam refused token validation: {error_detail}");
        }
        Ok(response.into_response_data().valid())
    })
    .await
    .context("token validation task panicked")?
}

// ---------------------------------------------------------------------------
// TOTP export URI
// ---------------------------------------------------------------------------

/// Rotate emergency codes: destroy existing → create new → destroy the new ones.
/// The TOTP code is auto-generated from the account's shared_secret.
pub(super) async fn rotate_emergency_codes(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
) -> Result<()> {
    destroy_emergency_codes(root_dir, master_key, account_id).await?;
    create_emergency_codes(root_dir, master_key, account_id).await?;
    destroy_emergency_codes(root_dir, master_key, account_id).await?;
    Ok(())
}
