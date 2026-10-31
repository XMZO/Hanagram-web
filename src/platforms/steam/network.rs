// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(crate) async fn query_steam_server_time(http_client: &reqwest::Client) -> Result<i64> {
    match query_steam_server_time_via_client(http_client).await {
        Ok(server_time) => Ok(server_time),
        Err(primary_error) => {
            warn!(
                error = %primary_error,
                "Steam server time query failed on shared client; retrying with a dedicated client"
            );

            let dedicated_client = reqwest::Client::builder()
                .user_agent(STEAM_CONFIRMATION_USER_AGENT)
                .build()
                .context("failed building dedicated Steam server time client")?;
            match query_steam_server_time_via_client(&dedicated_client).await {
                Ok(server_time) => Ok(server_time),
                Err(secondary_error) => {
                    let fallback_time = Utc::now().timestamp().max(0);
                    warn!(
                        error = %secondary_error,
                        fallback_time,
                        "Steam server time query failed again; falling back to local unix time"
                    );
                    Ok(fallback_time)
                }
            }
        }
    }
}

pub(super) async fn query_steam_server_time_via_client(
    http_client: &reqwest::Client,
) -> Result<i64> {
    let response = http_client
        .post("https://api.steampowered.com/ITwoFactorService/QueryTime/v0001/?format=json")
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .send()
        .await
        .context("failed querying Steam server time")?;
    let response = response
        .error_for_status()
        .context("Steam server time endpoint returned an error")?;
    let payload: SteamQueryTimeEnvelope = response
        .json()
        .await
        .context("failed decoding Steam server time response")?;
    Ok(payload.response.server_time as i64)
}

#[allow(dead_code)]
pub(crate) fn create_proxied_http_client(
    proxy_url: Option<&str>,
) -> Result<reqwest::blocking::Client> {
    let mut builder =
        reqwest::blocking::Client::builder().user_agent(STEAM_CONFIRMATION_USER_AGENT);
    if let Some(url) = proxy_url.filter(|v| !v.trim().is_empty()) {
        builder = builder.proxy(
            reqwest::Proxy::all(url.trim())
                .with_context(|| format!("malformed proxy address: {url}"))?,
        );
    }
    builder.build().context("could not construct HTTP client")
}

// ---------------------------------------------------------------------------
// Clock drift measurement
// ---------------------------------------------------------------------------

/// Query the Steam server clock and compare with local time. Returns `(remote, local, drift)`.
pub(crate) async fn measure_clock_drift(http_client: &reqwest::Client) -> Result<(i64, i64, i64)> {
    let local = Utc::now().timestamp();
    let remote = query_steam_server_time(http_client).await?;
    Ok((remote, local, remote - local))
}

// ---------------------------------------------------------------------------
// Zero Trust sweep
// ---------------------------------------------------------------------------
