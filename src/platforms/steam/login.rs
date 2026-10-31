// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) fn build_blocking_steam_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(STEAM_CONFIRMATION_USER_AGENT)
        .build()
        .context("failed building blocking Steam client")
}

pub(super) fn build_steam_mobile_device_details() -> DeviceDetails {
    DeviceDetails {
        friendly_name: String::from("Hanagram Web"),
        platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
        os_type: -500,
        gaming_device_type: 528,
    }
}

pub(super) fn map_login_error(error: LoginError) -> anyhow::Error {
    match error {
        LoginError::BadCredentials => anyhow!("Steam username or password is incorrect"),
        LoginError::TooManyAttempts => anyhow!("Steam is rate limiting login attempts"),
        LoginError::SessionExpired => anyhow!("Steam login session expired before completion"),
        other => anyhow!("Steam credential login failed: {other}"),
    }
}

pub(super) fn map_guard_submit_error(error: UpdateAuthSessionError) -> anyhow::Error {
    match error {
        UpdateAuthSessionError::IncorrectSteamGuardCode => {
            anyhow!("the generated Steam Guard code was rejected")
        }
        UpdateAuthSessionError::TooManyAttempts => {
            anyhow!("Steam rate limited Steam Guard submissions")
        }
        UpdateAuthSessionError::SessionExpired => anyhow!("Steam login session expired"),
        UpdateAuthSessionError::DuplicateRequest => {
            anyhow!("Steam login request was already approved elsewhere")
        }
        other => anyhow!("failed submitting Steam Guard code: {other}"),
    }
}

pub(super) fn classify_guard_setup_login_gate<I>(confirmation_types: I) -> GuardSetupLoginGate
where
    I: IntoIterator<Item = EAuthSessionGuardType>,
{
    let mut has_guardless_flow = false;
    let mut has_device_code = false;
    let mut requires_device_confirmation = false;
    let mut requires_email_code = false;
    let mut requires_email_confirmation = false;
    let mut saw_any = false;

    for confirmation_type in confirmation_types {
        saw_any = true;
        match confirmation_type {
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => {
                has_guardless_flow = true;
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                has_device_code = true;
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                requires_device_confirmation = true;
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => {
                requires_email_code = true;
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
                requires_email_confirmation = true;
            }
            _ => {}
        }
    }

    if has_guardless_flow || !saw_any {
        return GuardSetupLoginGate::CanContinue;
    }
    if has_device_code {
        return GuardSetupLoginGate::RequiresExistingGuardCode;
    }
    if requires_device_confirmation {
        return GuardSetupLoginGate::RequiresTrustedDeviceConfirmation;
    }
    if requires_email_code {
        return GuardSetupLoginGate::RequiresEmailCode;
    }
    if requires_email_confirmation {
        return GuardSetupLoginGate::RequiresEmailConfirmation;
    }
    GuardSetupLoginGate::Unsupported
}

pub(super) fn resolve_guard_setup_login_prompt<I>(
    confirmation_methods: I,
) -> Result<Option<GuardLoginCodePrompt>>
where
    I: IntoIterator<Item = (EAuthSessionGuardType, String)>,
{
    let mut gate_inputs = Vec::new();
    let mut email_hint = None;

    for (confirmation_type, associated_message) in confirmation_methods {
        if confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
            && email_hint.is_none()
        {
            email_hint = normalize_optional_string(Some(associated_message));
        }
        gate_inputs.push(confirmation_type);
    }

    match classify_guard_setup_login_gate(gate_inputs) {
        GuardSetupLoginGate::CanContinue => Ok(None),
        GuardSetupLoginGate::RequiresTrustedDeviceConfirmation => {
            bail!("requires_trusted_device_confirmation")
        }
        GuardSetupLoginGate::RequiresEmailConfirmation => {
            bail!("requires_email_login_confirmation")
        }
        GuardSetupLoginGate::RequiresEmailCode => Ok(Some(GuardLoginCodePrompt {
            kind: GuardLoginCodeKind::EmailCode,
            hint: email_hint,
        })),
        GuardSetupLoginGate::RequiresExistingGuardCode => Ok(Some(GuardLoginCodePrompt {
            kind: GuardLoginCodeKind::ExistingGuardCode,
            hint: None,
        })),
        GuardSetupLoginGate::Unsupported => bail!("unsupported_login_confirmation_method"),
    }
}

pub(super) async fn perform_credential_login(
    shared_secret: String,
    steam_username: String,
    steam_password: String,
) -> Result<SteamCredentialLoginResult> {
    spawn_blocking(move || {
        let username = steam_username.trim().to_owned();
        ensure!(!username.is_empty(), "Steam username is required");
        ensure!(
            !steam_password.is_empty(),
            "Steam password is required for credential login"
        );

        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let shared_secret = TwoFactorSecret::parse_shared_secret(shared_secret.trim().to_owned())
            .context("failed parsing Steam shared_secret")?;

        let mut vendor_account = VendorSteamGuardAccount::new();
        vendor_account.account_name = username.clone();
        vendor_account.shared_secret = shared_secret;

        let mut login = UserLogin::new(transport.clone(), build_steam_mobile_device_details());
        let confirmation_methods = login
            .begin_auth_via_credentials(&username, &steam_password)
            .map_err(map_login_error)?;

        let has_guardless_flow = confirmation_methods.iter().any(|method| {
            method.confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_None
        });
        let has_device_code = confirmation_methods.iter().any(|method| {
            method.confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
        });
        let requires_device_confirmation = confirmation_methods.iter().any(|method| {
            method.confirmation_type
                == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation
        });
        let requires_email_code = confirmation_methods.iter().any(|method| {
            method.confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
        });
        let requires_email_confirmation = confirmation_methods.iter().any(|method| {
            method.confirmation_type
                == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation
        });

        if !has_guardless_flow {
            if has_device_code {
                let server_time = steamguard::steamapi::get_server_time(transport.clone())
                    .context("failed querying Steam server time for credential login")?
                    .server_time();
                let guard_code = vendor_account.generate_code(server_time);
                match login.submit_steam_guard_code(
                    EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
                    guard_code,
                ) {
                    Ok(_) | Err(UpdateAuthSessionError::DuplicateRequest) => {}
                    Err(error) => return Err(map_guard_submit_error(error)),
                }
            } else if requires_device_confirmation {
                bail!("Steam requested mobile confirmation on another device for this login");
            } else if requires_email_code {
                bail!("Steam requested an email code for this login");
            } else if requires_email_confirmation {
                bail!("Steam requested email confirmation for this login");
            } else if !confirmation_methods.is_empty() {
                bail!("Steam requested an unsupported login confirmation method");
            }
        }

        let tokens = login
            .poll_until_tokens()
            .context("failed polling Steam for credential login tokens")?;
        let steam_id = tokens
            .access_token()
            .decode()
            .context("failed decoding Steam access token")?
            .steam_id();

        Ok::<SteamCredentialLoginResult, anyhow::Error>(SteamCredentialLoginResult {
            steam_username: username,
            steam_id,
            access_token: tokens.access_token().expose_secret().to_owned(),
            refresh_token: tokens.refresh_token().expose_secret().to_owned(),
        })
    })
    .await
    .context("Steam credential login task failed")?
}

pub(super) fn apply_credential_login_result(
    record: &mut StoredSteamAccount,
    login_result: &SteamCredentialLoginResult,
) {
    record.steam_username = Some(login_result.steam_username.clone());
    record.steam_id = Some(login_result.steam_id);
    if record.device_id.is_none() && record.identity_secret.is_some() {
        record.device_id = Some(generate_device_id_for_steam_id(login_result.steam_id));
    }

    let session = stored_web_session_mut(record);
    session.access_token = Some(login_result.access_token.clone());
    session.refresh_token = Some(login_result.refresh_token.clone());
}

pub(crate) async fn create_logged_in_account(
    root_dir: &Path,
    master_key: &[u8],
    input: CredentialSteamAccountInput,
) -> Result<SteamGuardAccount> {
    ensure_managed_accounts_dir(root_dir).await?;
    validate_shared_secret(&input.shared_secret)?;

    let identity_secret = normalize_optional_string(input.identity_secret);
    if let Some(secret) = identity_secret.as_deref() {
        validate_identity_secret(secret)?;
    }

    let login_result = perform_credential_login(
        input.shared_secret.trim().to_owned(),
        input.steam_username,
        input.steam_password,
    )
    .await?;

    let display_name = if input.account_name.trim().is_empty() {
        login_result.steam_username.as_str()
    } else {
        input.account_name.as_str()
    };
    let now = Utc::now().timestamp();
    let mut record = StoredSteamAccount {
        schema_version: STEAM_MANAGED_SCHEMA_VERSION,
        id: Uuid::new_v4().to_string(),
        account_name: sanitize_account_name(display_name),
        steam_username: Some(login_result.steam_username.clone()),
        steam_id: Some(login_result.steam_id),
        shared_secret: input.shared_secret.trim().to_owned(),
        identity_secret,
        device_id: normalize_optional_string(input.device_id),
        session: None,
        imported_from: Some(String::from("credential-login")),
        managed_origin: SteamManagedAccountOrigin::ManualEntry,
        created_at_unix: now,
        updated_at_unix: now,
        revocation_code: None,
        serial_number: None,
        token_gid: None,
        secret_1: None,
        uri: None,
        proxy_url: None,
    };
    apply_credential_login_result(&mut record, &login_result);

    let storage_path = managed_account_storage_path(root_dir, &record.id);
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(record.into_runtime(storage_path))
}

pub(crate) async fn login_managed_account_with_credentials(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    input: SteamCredentialLoginInput,
) -> Result<Option<SteamGuardAccount>> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(mut record) = load_stored_account(master_key, &storage_path).await? else {
        return Ok(None);
    };

    let steam_username = normalize_optional_string(Some(input.steam_username))
        .or_else(|| record.steam_username.clone())
        .context("Steam username is required")?;
    let login_result = perform_credential_login(
        record.shared_secret.clone(),
        steam_username,
        input.steam_password,
    )
    .await?;

    apply_credential_login_result(&mut record, &login_result);
    record.updated_at_unix = Utc::now().timestamp();
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(Some(record.into_runtime(storage_path)))
}

pub(super) fn build_vendor_account(account: &SteamGuardAccount) -> Result<VendorSteamGuardAccount> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID for login approvals")?;
    let shared_secret =
        TwoFactorSecret::parse_shared_secret(account.shared_secret.trim().to_owned())
            .context("failed parsing Steam shared_secret for login approvals")?;

    let mut vendor_account = VendorSteamGuardAccount::new();
    vendor_account.account_name = account
        .steam_username
        .clone()
        .unwrap_or_else(|| account.account_name.clone());
    vendor_account.steam_id = steam_id;
    vendor_account.shared_secret = shared_secret;
    Ok(vendor_account)
}

pub(super) fn build_vendor_tokens(account: &SteamGuardAccount) -> Result<SteamTokens> {
    let session = account
        .session
        .as_ref()
        .context("Steam account is missing session material")?;
    let access_token = session
        .access_token()
        .context("Steam account is missing an access token")?
        .to_owned();
    let refresh_token = session.refresh_token().unwrap_or_default().to_owned();
    Ok(SteamTokens::new(
        SteamJwt::from(access_token),
        SteamJwt::from(refresh_token),
    ))
}

pub(crate) fn confirmation_session_can_refresh(account: &SteamGuardAccount) -> bool {
    account.has_refreshable_session()
}

pub(crate) fn confirmation_session_should_refresh(account: &SteamGuardAccount) -> bool {
    let Some(session) = account.session.as_ref() else {
        return false;
    };
    if session.refresh_token().is_none() {
        return false;
    }

    match session.access_token() {
        Some(access_token) => access_token_expires_soon(access_token, Utc::now().timestamp()),
        None => true,
    }
}

pub(crate) async fn refresh_confirmation_session_if_needed(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    force_refresh: bool,
) -> Result<Option<SteamGuardAccount>> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(mut record) = load_stored_account(master_key, &storage_path).await? else {
        return Ok(None);
    };

    let Some(session) = record.session.as_mut() else {
        return Ok(Some(record.into_runtime(storage_path)));
    };

    let Some(refresh_token) = session
        .refresh_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
    else {
        return Ok(Some(record.into_runtime(storage_path)));
    };

    let needs_refresh = match session
        .access_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(access_token) => access_token_expires_soon(access_token, Utc::now().timestamp()),
        None => true,
    };
    if !force_refresh && !needs_refresh {
        return Ok(Some(record.into_runtime(storage_path)));
    }

    let steam_id = record
        .steam_id
        .or_else(|| derive_stored_session_steam_id(session))
        .context(
            "Steam account is missing SteamID and could not derive one from stored session tokens",
        )?;
    let current_access_token = session
        .access_token
        .as_deref()
        .unwrap_or_default()
        .to_owned();
    let refreshed_access_token =
        refresh_access_token_from_refresh_token(steam_id, current_access_token, refresh_token)
            .await?;

    session.access_token = Some(refreshed_access_token);
    record.steam_id = Some(steam_id);
    record.updated_at_unix = Utc::now().timestamp();
    persist_stored_account(master_key, &storage_path, &record).await?;
    Ok(Some(record.into_runtime(storage_path)))
}

pub(super) fn derive_session_steam_id(session: &RawSteamSession) -> Option<u64> {
    session
        .steam_id
        .or_else(|| {
            session
                .access_token
                .as_deref()
                .and_then(steam_id_from_jwt_unverified)
        })
        .or_else(|| {
            session
                .refresh_token
                .as_deref()
                .and_then(steam_id_from_jwt_unverified)
        })
}

pub(super) fn steam_id_from_jwt_unverified(token: &str) -> Option<u64> {
    steam_jwt_claims_unverified(token).map(|claims| claims.sub)
}

pub(super) fn derive_stored_session_steam_id(session: &StoredSteamWebSession) -> Option<u64> {
    session
        .access_token
        .as_deref()
        .and_then(steam_id_from_jwt_unverified)
        .or_else(|| {
            session
                .refresh_token
                .as_deref()
                .and_then(steam_id_from_jwt_unverified)
        })
}

pub(super) fn access_token_expires_soon(token: &str, now_unix: i64) -> bool {
    steam_jwt_claims_unverified(token)
        .and_then(|claims| claims.exp)
        .map(|exp| exp as i64 <= now_unix + STEAM_ACCESS_TOKEN_REFRESH_SKEW_SECONDS)
        .unwrap_or(false)
}

pub(super) fn steam_jwt_claims_unverified(token: &str) -> Option<SteamJwtClaims> {
    let mut parts = token.trim().split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    serde_json::from_slice::<SteamJwtClaims>(&decoded).ok()
}

pub(super) async fn refresh_access_token_from_refresh_token(
    steam_id: u64,
    current_access_token: String,
    refresh_token: String,
) -> Result<String> {
    spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .user_agent(STEAM_CONFIRMATION_USER_AGENT)
            .build()
            .context("failed building blocking Steam auth client")?;
        let transport = WebApiTransport::new(client);
        let auth_client = AuthenticationClient::new(transport);
        let mut refresher = TokenRefresher::new(auth_client);
        let tokens = SteamTokens::new(
            SteamJwt::from(current_access_token),
            SteamJwt::from(refresh_token),
        );
        let refreshed = refresher
            .refresh(steam_id, &tokens)
            .context("failed refreshing Steam access token from refresh token")?;
        Ok::<String, anyhow::Error>(refreshed.expose_secret().to_owned())
    })
    .await
    .context("Steam access token refresh task failed")?
}
