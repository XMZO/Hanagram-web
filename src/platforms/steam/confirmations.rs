// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(crate) async fn fetch_confirmations(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
) -> Result<Vec<SteamConfirmation>> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let time = query_steam_server_time(http_client).await?;
    let query = build_confirmation_query(account, "conf", time)?;
    let cookie_header = build_confirmation_cookie_header(account, steam_id)?;
    let response = http_client
        .get("https://steamcommunity.com/mobileconf/getlist")
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .header(reqwest::header::COOKIE, cookie_header)
        .query(&query)
        .send()
        .await
        .context("failed fetching Steam confirmations")?;
    let response = response
        .error_for_status()
        .context("Steam confirmation list endpoint returned an error")?;
    let payload: SteamConfirmationListResponse = response
        .json()
        .await
        .context("failed decoding Steam confirmation list")?;
    if payload.needauth.unwrap_or(false) {
        bail!("Steam confirmation session is no longer authorized");
    }
    if !payload.success {
        bail!(
            "{}",
            payload
                .message
                .unwrap_or_else(|| String::from("Steam confirmation list request failed"))
        );
    }

    Ok(payload
        .conf
        .into_iter()
        .map(|confirmation| SteamConfirmation {
            id: confirmation.id,
            nonce: confirmation.nonce,
            creator_id: confirmation.creator_id,
            confirmation_type: confirmation.confirmation_type,
            type_name: confirmation.type_name,
            headline: confirmation.headline,
            summary: confirmation.summary,
            icon: normalize_optional_string(confirmation.icon),
            created_at_unix: confirmation.creation_time,
        })
        .collect())
}

pub(crate) async fn respond_to_confirmation(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
    confirmation_id: &str,
    nonce: &str,
    accept: bool,
) -> Result<()> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let time = query_steam_server_time(http_client).await?;
    let mut query = build_confirmation_query(account, "conf", time)?;
    query.push((
        String::from("op"),
        String::from(if accept { "allow" } else { "cancel" }),
    ));
    query.push((String::from("cid"), confirmation_id.trim().to_owned()));
    query.push((String::from("ck"), nonce.trim().to_owned()));

    let cookie_header = build_confirmation_cookie_header(account, steam_id)?;
    let response = http_client
        .get("https://steamcommunity.com/mobileconf/ajaxop")
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .header(reqwest::header::COOKIE, cookie_header)
        .header(reqwest::header::ORIGIN, "https://steamcommunity.com")
        .query(&query)
        .send()
        .await
        .context("failed sending Steam confirmation action")?;
    let response = response
        .error_for_status()
        .context("Steam confirmation action endpoint returned an error")?;
    let payload: SteamConfirmationActionResponse = response
        .json()
        .await
        .context("failed decoding Steam confirmation action response")?;
    payload.into_result()
}

pub(super) fn build_confirmation_query(
    account: &SteamGuardAccount,
    tag: &str,
    unix_time: i64,
) -> Result<Vec<(String, String)>> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let identity_secret = account
        .identity_secret
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .context("Steam account is missing identity_secret")?;
    let device_id = account
        .device_id
        .as_deref()
        .map(str::to_owned)
        .or_else(|| Some(generate_device_id_for_steam_id(steam_id)))
        .context("Steam account is missing device_id")?;
    Ok(vec![
        (String::from("p"), device_id),
        (String::from("a"), steam_id.to_string()),
        (
            String::from("k"),
            generate_confirmation_key(identity_secret, unix_time, tag)?,
        ),
        (String::from("t"), unix_time.to_string()),
        (String::from("m"), String::from("react")),
        (String::from("tag"), tag.to_owned()),
    ])
}

pub(super) fn build_confirmation_cookie_header(
    account: &SteamGuardAccount,
    steam_id: u64,
) -> Result<String> {
    let steam_login_secure = account
        .session
        .as_ref()
        .and_then(|session| session.effective_confirmation_cookie(Some(steam_id)))
        .context("Steam account is missing a usable confirmation session")?;
    Ok(format!(
        "dob=; steamid={steam_id}; steamLoginSecure={steam_login_secure}"
    ))
}

/// Approve all pending confirmations in one request. Returns the count on success.
pub(crate) async fn batch_approve_trades(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
) -> Result<usize> {
    batch_respond_to_confirmations(http_client, account, true).await
}

/// Reject all pending confirmations in one request. Returns the count on success.
pub(crate) async fn batch_reject_trades(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
) -> Result<usize> {
    batch_respond_to_confirmations(http_client, account, false).await
}

pub(super) fn build_bulk_confirmation_request(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
    pending: &[SteamConfirmation],
    accept: bool,
    unix_time: i64,
) -> Result<reqwest::Request> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let mut params = build_confirmation_query(account, "conf", unix_time)?;
    params.push((
        String::from("op"),
        String::from(if accept { "allow" } else { "cancel" }),
    ));
    for item in pending {
        params.push((String::from("cid[]"), item.id.trim().to_owned()));
        params.push((String::from("ck[]"), item.nonce.trim().to_owned()));
    }

    http_client
        .post("https://steamcommunity.com/mobileconf/multiajaxop")
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .header(
            reqwest::header::COOKIE,
            build_confirmation_cookie_header(account, steam_id)?,
        )
        .header(reqwest::header::ORIGIN, "https://steamcommunity.com")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        .form(&params)
        .build()
        .context("failed building Steam bulk confirmation request")
}

pub(super) async fn batch_respond_to_confirmations(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
    accept: bool,
) -> Result<usize> {
    let pending = fetch_confirmations(http_client, account).await?;
    if pending.is_empty() {
        return Ok(0);
    }
    let time = query_steam_server_time(http_client).await?;
    let request = build_bulk_confirmation_request(http_client, account, &pending, accept, time)?;
    let response = http_client
        .execute(request)
        .await
        .context("failed sending Steam bulk confirmation action")?
        .error_for_status()
        .context("Steam bulk confirmation endpoint returned an error")?;
    let payload: SteamConfirmationActionResponse = response
        .json()
        .await
        .context("failed decoding Steam bulk confirmation response")?;
    payload.into_result()?;
    Ok(pending.len())
}

// ---------------------------------------------------------------------------
// Proxied HTTP client helper
// ---------------------------------------------------------------------------
