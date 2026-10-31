// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) fn build_refresh_token_revoke_signature(
    shared_secret_bytes: &[u8; 20],
    token_id: u64,
) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret_bytes)
        .context("failed to initialize HMAC for Steam device revoke signature")?;
    let token_id_message = token_id.to_string();
    mac.update(token_id_message.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) fn revoke_verification_accepts_session_loss(result: EResult) -> bool {
    matches!(
        result,
        EResult::AccessDenied
            | EResult::InvalidPassword
            | EResult::LoggedInElsewhere
            | EResult::NotLoggedOn
            | EResult::Revoked
            | EResult::Expired
            | EResult::LogonSessionReplaced
            | EResult::AlreadyLoggedInElsewhere
    )
}

pub(super) fn verify_revoked_login_device_token<T>(
    auth_client: &AuthenticationClient<T>,
    access_token: &SteamJwt,
    token_id: u64,
    allow_session_loss: bool,
) -> Result<()>
where
    T: Transport,
{
    for attempt in 1..=STEAM_DEVICE_REVOKE_VERIFICATION_ATTEMPTS {
        let request = CAuthentication_RefreshToken_Enumerate_Request::new();
        let response = auth_client
            .enumerate_tokens(request, access_token)
            .with_context(|| {
                format!("failed verifying Steam login device token {token_id} after revoke")
            })?;
        let result = response.result();

        if result == EResult::OK {
            let payload = response.into_response_data();
            let still_logged_in = payload
                .refresh_tokens
                .iter()
                .any(|device| device.logged_in() && device.token_id() == token_id);
            if !still_logged_in {
                return Ok(());
            }

            if attempt < STEAM_DEVICE_REVOKE_VERIFICATION_ATTEMPTS {
                info!(
                    "Steam login device token {} still appears online after revoke verification attempt {}; retrying",
                    token_id, attempt
                );
                thread::sleep(STEAM_DEVICE_REVOKE_VERIFICATION_DELAY);
                continue;
            }

            bail!(
                "Steam reported token {token_id} revoked, but it still appears in the login device list"
            );
        }

        if allow_session_loss && revoke_verification_accepts_session_loss(result) {
            info!(
                "Steam login device token {} revoked and verification lost the current session with result {:?}; treating as success",
                token_id, result
            );
            return Ok(());
        }

        let error_detail = response
            .error_message()
            .cloned()
            .unwrap_or_else(|| format!("{result:?}"));
        bail!("Steam revoke verification failed for token {token_id}: {error_detail}");
    }

    unreachable!("verification attempts must either return success or error")
}

pub(super) fn login_approval_platform_label(platform_type: EAuthTokenPlatformType) -> &'static str {
    match platform_type {
        EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient => "Steam Client",
        EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser => "Web Browser",
        EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp => "Mobile App",
        _ => "Unknown",
    }
}

pub(super) fn build_login_approval(
    client_id: u64,
    session: &CAuthentication_GetAuthSessionInfo_Response,
) -> SteamLoginApproval {
    SteamLoginApproval {
        client_id: client_id.to_string(),
        ip: normalize_optional_string(Some(session.ip().to_owned())),
        geolocation: normalize_optional_string(Some(session.geoloc().to_owned())),
        city: normalize_optional_string(Some(session.city().to_owned())),
        state: normalize_optional_string(Some(session.state().to_owned())),
        country: normalize_optional_string(Some(session.country().to_owned())),
        platform_label: login_approval_platform_label(session.platform_type()).to_owned(),
        device_label: normalize_optional_string(Some(session.device_friendly_name().to_owned())),
    }
}

pub(crate) async fn list_login_approvals(
    account: &SteamGuardAccount,
) -> Result<Vec<SteamLoginApproval>> {
    let vendor_account = build_vendor_account(account)?;
    let vendor_tokens = build_vendor_tokens(account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let approver = LoginApprover::new(transport, &vendor_tokens);
        let client_ids = approver
            .list_auth_sessions()
            .context("failed listing Steam login approvals")?;

        let mut approvals = Vec::with_capacity(client_ids.len());
        for client_id in client_ids {
            let session = approver
                .get_auth_session_info(client_id)
                .with_context(|| format!("failed loading Steam approval session {client_id}"))?;
            approvals.push(build_login_approval(client_id, &session));
        }

        let _ = vendor_account;
        Ok::<Vec<SteamLoginApproval>, anyhow::Error>(approvals)
    })
    .await
    .context("Steam login approval listing task failed")?
}

pub(crate) async fn respond_to_login_approval(
    account: &SteamGuardAccount,
    client_id: u64,
    approve: bool,
) -> Result<()> {
    let vendor_account = build_vendor_account(account)?;
    let vendor_tokens = build_vendor_tokens(account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let mut approver = LoginApprover::new(transport, &vendor_tokens);
        let challenge = Challenge::new(1, client_id);
        if approve {
            approver
                .approve(
                    &vendor_account,
                    challenge,
                    ESessionPersistence::k_ESessionPersistence_Persistent,
                )
                .context("failed approving Steam login session")?;
        } else {
            approver
                .deny(&vendor_account, challenge)
                .context("failed denying Steam login session")?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Steam login approval action task failed")?
}

pub(super) fn ordered_selected_session_tokens(
    inventory: &SteamSessionDeviceInventory,
    selection: SteamSessionDeviceSelection,
) -> Result<Vec<u64>> {
    let mut token_ids = match selection {
        SteamSessionDeviceSelection::Token(token_id) => {
            ensure!(
                inventory
                    .devices
                    .iter()
                    .any(|device| device.token_id == token_id),
                "requested Steam login device was not found"
            );
            vec![token_id]
        }
        SteamSessionDeviceSelection::Others => {
            let current_token_id = inventory
                .current_token_id
                .context("current Steam login device is unknown")?;
            inventory
                .devices
                .iter()
                .filter(|device| device.token_id != current_token_id)
                .map(|device| device.token_id)
                .collect::<Vec<_>>()
        }
        SteamSessionDeviceSelection::All => inventory
            .devices
            .iter()
            .map(|device| device.token_id)
            .collect::<Vec<_>>(),
    };

    if let Some(current_token_id) = inventory.current_token_id {
        if let Some(index) = token_ids
            .iter()
            .position(|token_id| *token_id == current_token_id)
        {
            let current = token_ids.remove(index);
            token_ids.push(current);
        }
    }

    Ok(token_ids)
}

pub(crate) async fn list_logged_in_devices(
    account: &SteamGuardAccount,
) -> Result<SteamSessionDeviceInventory> {
    let vendor_tokens = build_vendor_tokens(account)?;

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let auth_client = AuthenticationClient::new(transport);
        let request = CAuthentication_RefreshToken_Enumerate_Request::new();
        let response = auth_client
            .enumerate_tokens(request, vendor_tokens.access_token())
            .context("failed listing Steam login devices")?;
        let result = response.result();
        if result != EResult::OK {
            let error_detail = response
                .error_message()
                .cloned()
                .unwrap_or_else(|| format!("{result:?}"));
            bail!("Steam refused to enumerate login devices: {error_detail}");
        }
        let payload = response.into_response_data();
        let current_token_id = match payload.requesting_token() {
            0 => None,
            token_id => Some(token_id),
        };

        let mut devices = payload
            .refresh_tokens
            .iter()
            .filter(|device| device.logged_in())
            .map(|device| {
                let platform_label =
                    login_approval_platform_label(device.platform_type()).to_owned();
                let device_label =
                    normalize_optional_string(Some(device.token_description().to_owned()))
                        .unwrap_or_else(|| platform_label.clone());

                let last_seen = device.last_seen.as_ref();
                let first_seen = device.first_seen.as_ref();
                let location_source = last_seen.or(first_seen);
                let location_label = location_source.and_then(|event| {
                    let mut parts = Vec::new();
                    if let Some(city) = normalize_optional_string(Some(event.city().to_owned())) {
                        parts.push(city);
                    }
                    if let Some(state) = normalize_optional_string(Some(event.state().to_owned())) {
                        parts.push(state);
                    }
                    if let Some(country) =
                        normalize_optional_string(Some(event.country().to_owned()))
                    {
                        parts.push(country);
                    }
                    if parts.is_empty() {
                        None
                    } else {
                        Some(parts.join(", "))
                    }
                });

                SteamSessionDevice {
                    token_id: device.token_id(),
                    device_label,
                    platform_label,
                    location_label,
                    first_seen_at_unix: first_seen
                        .map(|event| event.time() as i64)
                        .filter(|time| *time > 0),
                    last_seen_at_unix: last_seen
                        .map(|event| event.time() as i64)
                        .filter(|time| *time > 0),
                    is_current: current_token_id == Some(device.token_id()),
                }
            })
            .collect::<Vec<_>>();

        devices.sort_by(|left, right| {
            right
                .is_current
                .cmp(&left.is_current)
                .then_with(|| {
                    right
                        .last_seen_at_unix
                        .unwrap_or(0)
                        .cmp(&left.last_seen_at_unix.unwrap_or(0))
                })
                .then_with(|| left.device_label.cmp(&right.device_label))
                .then_with(|| left.token_id.cmp(&right.token_id))
        });

        Ok::<SteamSessionDeviceInventory, anyhow::Error>(SteamSessionDeviceInventory {
            current_token_id,
            devices,
        })
    })
    .await
    .context("Steam login device listing task failed")?
}

pub(crate) async fn revoke_logged_in_devices(
    root_dir: &Path,
    master_key: &[u8],
    account_id: &str,
    selection: SteamSessionDeviceSelection,
) -> Result<SteamSessionRevokeOutcome> {
    let storage_path = managed_account_storage_path(root_dir, account_id);
    let Some(mut record) = load_stored_account(master_key, &storage_path).await? else {
        bail!("account not found");
    };

    let mut account =
        refresh_confirmation_session_if_needed(root_dir, master_key, account_id, false)
            .await?
            .context("account not found")?;
    let inventory = match list_logged_in_devices(&account).await {
        Ok(inventory) => inventory,
        Err(error) if account.has_refreshable_session() => {
            warn!(
                "Steam login device listing failed for account {}; retrying after refresh: {}",
                account_id, error
            );
            account =
                refresh_confirmation_session_if_needed(root_dir, master_key, account_id, true)
                    .await?
                    .context("account not found")?;
            list_logged_in_devices(&account)
                .await
                .context("failed listing Steam login devices after refreshing the session")?
        }
        Err(error) => return Err(error),
    };

    let token_ids = ordered_selected_session_tokens(&inventory, selection)?;
    if token_ids.is_empty() {
        return Ok(SteamSessionRevokeOutcome {
            revoked_count: 0,
            current_device_revoked: false,
        });
    }

    let vendor_tokens = build_vendor_tokens(&account)?;
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID for device revocation")?;
    let shared_secret_bytes: [u8; 20] = base64::engine::general_purpose::STANDARD
        .decode(account.shared_secret.trim())
        .context("failed to decode shared_secret as base64 for device revoke signature")?
        .try_into()
        .map_err(|_| anyhow!("shared_secret must decode to exactly 20 bytes"))?;
    let current_device_revoked = inventory
        .current_token_id
        .is_some_and(|token_id| token_ids.contains(&token_id));
    let revoked_count = token_ids.len();

    info!(
        "Revoking {} Steam login device(s) for account {}: token_ids={:?}, current_token={:?}, current_will_be_revoked={}",
        revoked_count, account_id, token_ids, inventory.current_token_id, current_device_revoked
    );

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let mut auth_client = AuthenticationClient::new(transport);
        let current_token_id = inventory.current_token_id;

        for token_id in token_ids {
            let signature = build_refresh_token_revoke_signature(&shared_secret_bytes, token_id)?;

            let mut attempts = Vec::new();

            let mut signed_request = CAuthentication_RefreshToken_Revoke_Request::new();
            signed_request.set_token_id(token_id);
            signed_request.set_revoke_action(EAuthTokenRevokeAction::k_EAuthTokenRevokePermanent);
            signed_request.set_signature(signature.clone());
            let signed_response = auth_client
                .revoke_refresh_token(signed_request, vendor_tokens.access_token())
                .with_context(|| format!("failed revoking Steam login device token {token_id}"))?;
            let signed_result = signed_response.result();
            attempts.push(format!(
                "signature_only={signed_result:?}:{:?}",
                signed_response.error_message()
            ));
            info!(
                "Steam RevokeRefreshToken for token {} (signature only): result={:?}, error_message={:?}",
                token_id,
                signed_result,
                signed_response.error_message()
            );
            if signed_result == EResult::OK {
                verify_revoked_login_device_token(
                    &auth_client,
                    vendor_tokens.access_token(),
                    token_id,
                    current_token_id == Some(token_id),
                )?;
                continue;
            }

            let mut signed_steamid_request = CAuthentication_RefreshToken_Revoke_Request::new();
            signed_steamid_request.set_token_id(token_id);
            signed_steamid_request.set_steamid(steam_id);
            signed_steamid_request
                .set_revoke_action(EAuthTokenRevokeAction::k_EAuthTokenRevokePermanent);
            signed_steamid_request.set_signature(signature);
            let signed_steamid_response = auth_client
                .revoke_refresh_token(signed_steamid_request, vendor_tokens.access_token())
                .with_context(|| {
                    format!(
                        "failed revoking Steam login device token {token_id} (signature + steamid)"
                    )
                })?;
            let signed_steamid_result = signed_steamid_response.result();
            attempts.push(format!(
                "signature_steamid={signed_steamid_result:?}:{:?}",
                signed_steamid_response.error_message()
            ));
            info!(
                "Steam RevokeRefreshToken for token {} (signature+steamid): result={:?}, error_message={:?}",
                token_id,
                signed_steamid_result,
                signed_steamid_response.error_message()
            );
            if signed_steamid_result == EResult::OK {
                verify_revoked_login_device_token(
                    &auth_client,
                    vendor_tokens.access_token(),
                    token_id,
                    current_token_id == Some(token_id),
                )?;
                continue;
            }

            let mut bare_request = CAuthentication_RefreshToken_Revoke_Request::new();
            bare_request.set_token_id(token_id);
            bare_request.set_revoke_action(EAuthTokenRevokeAction::k_EAuthTokenRevokePermanent);
            let bare_response = auth_client
                .revoke_refresh_token(bare_request, vendor_tokens.access_token())
                .with_context(|| {
                    format!("failed revoking Steam login device token {token_id} (bare request)")
                })?;
            let bare_result = bare_response.result();
            attempts.push(format!(
                "bare={bare_result:?}:{:?}",
                bare_response.error_message()
            ));
            info!(
                "Steam RevokeRefreshToken for token {} (bare request): result={:?}, error_message={:?}",
                token_id,
                bare_result,
                bare_response.error_message()
            );
            if bare_result == EResult::OK {
                verify_revoked_login_device_token(
                    &auth_client,
                    vendor_tokens.access_token(),
                    token_id,
                    current_token_id == Some(token_id),
                )?;
                continue;
            }

            let mut support_request = CAuthenticationSupport_RevokeToken_Request::new();
            support_request.set_token_id(token_id);
            support_request.set_steamid(steam_id);
            let support_response = auth_client
                .revoke_access_token(support_request, vendor_tokens.access_token())
                .with_context(|| {
                    format!(
                        "failed revoking Steam login device token {token_id} via AuthenticationSupport"
                    )
                })?;
            let support_result = support_response.result();
            attempts.push(format!(
                "support={support_result:?}:{:?}",
                support_response.error_message()
            ));
            info!(
                "Steam AuthenticationSupport.RevokeToken for token {}: result={:?}, error_message={:?}",
                token_id,
                support_result,
                support_response.error_message()
            );
            if support_result == EResult::OK {
                verify_revoked_login_device_token(
                    &auth_client,
                    vendor_tokens.access_token(),
                    token_id,
                    current_token_id == Some(token_id),
                )?;
                continue;
            }

            bail!(
                "Steam refused to revoke login device token {token_id}: {}",
                attempts.join(" | ")
            );
        }

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Steam login device revoke task failed")??;

    if current_device_revoked {
        clear_stored_session_material(&mut record);
        record.updated_at_unix = Utc::now().timestamp();
        persist_stored_account(master_key, &storage_path, &record).await?;
    }

    Ok(SteamSessionRevokeOutcome {
        revoked_count,
        current_device_revoked,
    })
}

pub(crate) async fn approve_login_challenge(
    account: &SteamGuardAccount,
    challenge_url: &str,
) -> Result<()> {
    let vendor_account = build_vendor_account(account)?;
    let vendor_tokens = build_vendor_tokens(account)?;
    let challenge_url = challenge_url.trim().to_owned();
    ensure!(!challenge_url.is_empty(), "Steam challenge URL is required");

    spawn_blocking(move || {
        let client = build_blocking_steam_client()?;
        let transport = WebApiTransport::new(client);
        let mut approver = LoginApprover::new(transport, &vendor_tokens);
        approver
            .approve_from_challenge_url(
                &vendor_account,
                challenge_url,
                ESessionPersistence::k_ESessionPersistence_Persistent,
            )
            .context("failed approving Steam QR login challenge")?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Steam QR approval task failed")?
}

pub(crate) fn extract_login_challenge_url_from_qr_image(raw_bytes: &[u8]) -> Result<String> {
    let image = ImageReader::new(Cursor::new(raw_bytes))
        .with_guessed_format()
        .context("failed reading Steam QR image format")?
        .decode()
        .context("failed decoding Steam QR image")?
        .to_luma8();
    let mut prepared = PreparedImage::prepare(image);
    for grid in prepared.detect_grids() {
        let (_, text) = grid.decode().context("failed decoding Steam QR image")?;
        if text.contains("s.team") {
            return Ok(text);
        }
    }
    bail!("no Steam login challenge URL was found in the QR image")
}
