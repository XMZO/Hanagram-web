// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

pub(super) fn steam_help_language_path(language_code: &str) -> &'static str {
    match language_code {
        "zh-CN" | "zh-cn" | "zh_CN" | "schinese" => "zh-cn",
        _ => "en",
    }
}

pub(super) fn steam_help_trade_restore_url(language_code: &str) -> String {
    format!(
        "{}/{}/wizard/HelpTradeRestore",
        STEAM_HELP_BASE_URL,
        steam_help_language_path(language_code)
    )
}

pub(super) fn steam_help_revert_eligible_trades_url(language_code: &str) -> String {
    format!(
        "{}/{}/wizard/AjaxRevertEligibleTrades/",
        STEAM_HELP_BASE_URL,
        steam_help_language_path(language_code)
    )
}

pub(super) fn build_help_cookie_header(
    account: &SteamGuardAccount,
    steam_id: u64,
    session_id: Option<&str>,
) -> Result<String> {
    let steam_login_secure = account
        .session
        .as_ref()
        .and_then(|session| session.effective_confirmation_cookie(Some(steam_id)))
        .context("Steam account is missing a usable Steam web session")?;
    let steam_login_secure = steam_login_secure.trim().replace('|', "%7C");

    let mut cookies = Vec::new();
    if let Some(session_id) = session_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            account
                .session
                .as_ref()
                .and_then(|session| session.session_id.as_deref())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
    {
        cookies.push(format!("sessionid={session_id}"));
    }
    cookies.push(format!("steamid={steam_id}"));
    cookies.push(format!("steamLoginSecure={steam_login_secure}"));
    Ok(cookies.join("; "))
}

pub(super) fn extract_js_string_assignment(source: &str, name: &str) -> Option<String> {
    let index = source.find(name)?;
    let after_name = &source[index + name.len()..];
    let equals = after_name.find('=')?;
    let after_equals = after_name[equals + 1..].trim_start();
    let quote = after_equals.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let after_quote = &after_equals[quote.len_utf8()..];
    let end = after_quote.find(quote)?;
    let value = after_quote[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

pub(super) fn extract_session_id_from_set_cookie(
    headers: &reqwest::header::HeaderMap,
) -> Option<String> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            if name.trim() == "sessionid" {
                let value = value.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                }
            } else {
                None
            }
        })
}

pub(super) fn steam_help_page_requires_login(final_url: &str, body: &str) -> bool {
    final_url.contains("/login")
        || body.contains("data-featuretarget=\"login\"")
        || body.contains("data-featuretarget='login'")
}

pub(super) async fn fetch_trade_restore_page(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
    language_code: &str,
) -> Result<(String, String)> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let url = steam_help_trade_restore_url(language_code);
    let cookie_header = build_help_cookie_header(account, steam_id, None)?;
    let response = http_client
        .get(&url)
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .header(reqwest::header::ACCEPT, "text/html,*/*;q=0.8")
        .header(reqwest::header::COOKIE, cookie_header)
        .send()
        .await
        .context("failed loading Steam Help trade restore page")?;
    let final_url = response.url().to_string();
    let set_cookie_session_id = extract_session_id_from_set_cookie(response.headers());
    let response = response
        .error_for_status()
        .context("Steam Help trade restore page returned an error")?;
    let body = response
        .text()
        .await
        .context("failed reading Steam Help trade restore page")?;

    if steam_help_page_requires_login(&final_url, &body) {
        bail!("Steam Help login session is not authorized");
    }

    let session_id = extract_js_string_assignment(&body, "g_sessionID")
        .or(set_cookie_session_id)
        .or_else(|| {
            account
                .session
                .as_ref()
                .and_then(|session| session.session_id.clone())
        })
        .context("Steam Help page did not expose a session id")?;

    Ok((session_id, body))
}

pub(crate) async fn check_trade_restore_status(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
    language_code: &str,
) -> Result<SteamTradeRestoreStatus> {
    let (_session_id, body) = fetch_trade_restore_page(http_client, account, language_code).await?;
    Ok(SteamTradeRestoreStatus {
        can_revert: body.contains("AjaxRevertEligibleTrades"),
        session_ready: true,
    })
}

pub(crate) async fn revert_eligible_trades(
    http_client: &reqwest::Client,
    account: &SteamGuardAccount,
    language_code: &str,
) -> Result<SteamTradeRestoreOutcome> {
    let steam_id = account
        .steam_id
        .context("Steam account is missing SteamID")?;
    let (session_id, body) = fetch_trade_restore_page(http_client, account, language_code).await?;
    ensure!(
        body.contains("AjaxRevertEligibleTrades"),
        "Steam Help reports no eligible protected trades to revert"
    );

    let revert_url = steam_help_revert_eligible_trades_url(language_code);
    let referer = steam_help_trade_restore_url(language_code);
    let cookie_header = build_help_cookie_header(account, steam_id, Some(&session_id))?;
    let response = http_client
        .post(&revert_url)
        .header(reqwest::header::USER_AGENT, STEAM_CONFIRMATION_USER_AGENT)
        .header(reqwest::header::ACCEPT, "*/*")
        .header(reqwest::header::COOKIE, cookie_header)
        .header(reqwest::header::ORIGIN, STEAM_HELP_BASE_URL)
        .header(reqwest::header::REFERER, referer)
        .header("X-Requested-With", "XMLHttpRequest")
        .form(&[("sessionid", session_id.as_str())])
        .send()
        .await
        .context("failed submitting Steam protected trade revert request")?;
    let response = response
        .error_for_status()
        .context("Steam protected trade revert endpoint returned an error")?;
    let payload: SteamHelpRevertResponse = response
        .json()
        .await
        .context("failed decoding Steam protected trade revert response")?;
    if !payload.success {
        bail!(
            "{}",
            payload
                .message
                .unwrap_or_else(|| String::from("Steam protected trade revert request failed"))
        );
    }

    Ok(SteamTradeRestoreOutcome {
        redir: payload.redir,
    })
}
