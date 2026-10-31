// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::*;

/// Execute a full zero-trust protective sweep for a single managed Steam account.
///
/// The sweep proceeds through seven stages in order, with the API-dependent steps
/// executed first (before the session is destroyed).  Each step is individually
/// guarded with a timeout so that one failure or hang does not abort or block
/// the remaining steps.
pub(crate) async fn execute_zero_trust_sweep(
    root_dir: &Path,
    master_key: &[u8],
    http_client: &reqwest::Client,
    account_id: &str,
    initial_guard_state: Option<u32>,
    initial_device_id: Option<&str>,
    skip_emergency_codes: bool,
) -> Result<ZeroTrustSweepResult> {
    use tokio::time::timeout;

    let mut errors: Vec<String> = Vec::new();
    let mut confirmations_rejected: usize = 0;
    let mut approvals_denied: usize = 0;
    let mut devices_revoked: usize = 0;
    let mut current_device_revoked = false;
    let mut guard_state_changed = false;
    let mut device_id_changed = false;

    // Step 1: Refresh session (15s timeout)
    let account = match timeout(
        Duration::from_secs(15),
        refresh_confirmation_session_if_needed(root_dir, master_key, account_id, true),
    )
    .await
    {
        Ok(Ok(Some(account))) => Some(account),
        Ok(Ok(None)) => {
            errors.push(String::from("account not found during session refresh"));
            None
        }
        Ok(Err(e)) => {
            errors.push(format!("session refresh failed: {e}"));
            None
        }
        Err(_) => {
            errors.push(String::from("session refresh timed out (15s)"));
            None
        }
    };

    // Step 2: Fetch security info and compare with initial state (15s timeout)
    match timeout(
        Duration::from_secs(15),
        fetch_security_info(root_dir, master_key, account_id),
    )
    .await
    {
        Ok(Ok(info)) => {
            if let Some(initial) = initial_guard_state {
                if info.guard_state != initial {
                    guard_state_changed = true;
                }
            }
            if let Some(initial_dev) = initial_device_id {
                if info.bound_device != initial_dev {
                    device_id_changed = true;
                }
            }
        }
        Ok(Err(e)) => {
            errors.push(format!("security info check failed: {e}"));
        }
        Err(_) => {
            errors.push(String::from("security info check timed out (15s)"));
        }
    }

    // Step 3: Reject all confirmations (30s timeout)
    if let Some(ref account) = account {
        match timeout(
            Duration::from_secs(30),
            batch_reject_trades(http_client, account),
        )
        .await
        {
            Ok(Ok(count)) => confirmations_rejected = count,
            Ok(Err(e)) => errors.push(format!("confirmation rejection failed: {e}")),
            Err(_) => errors.push(String::from("confirmation rejection timed out (30s)")),
        }
    }

    // Step 4: Deny all login approvals (30s timeout for the entire group)
    if let Some(ref account) = account {
        match timeout(Duration::from_secs(30), async {
            let mut denied = 0usize;
            let mut step_errors = Vec::new();
            match list_login_approvals(account).await {
                Ok(approvals) => {
                    for approval in &approvals {
                        let client_id = approval.client_id.parse::<u64>().unwrap_or(0);
                        if client_id == 0 {
                            step_errors.push(format!(
                                "invalid approval client_id: {}",
                                approval.client_id
                            ));
                            continue;
                        }
                        match respond_to_login_approval(account, client_id, false).await {
                            Ok(()) => denied += 1,
                            Err(e) => step_errors.push(format!(
                                "failed denying login approval {}: {e}",
                                approval.client_id
                            )),
                        }
                    }
                }
                Err(e) => step_errors.push(format!("failed listing login approvals: {e}")),
            }
            (denied, step_errors)
        })
        .await
        {
            Ok((denied, step_errors)) => {
                approvals_denied = denied;
                errors.extend(step_errors);
            }
            Err(_) => errors.push(String::from("login approval denial timed out (30s)")),
        }
    }

    // Step 5: Rotate emergency codes (optional, 20s timeout)
    let emergency_codes_rotated = if skip_emergency_codes {
        false
    } else {
        match timeout(Duration::from_secs(20), async {
            rotate_emergency_codes(root_dir, master_key, account_id).await
        })
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                errors.push(format!("emergency code rotation failed: {e}"));
                false
            }
            Err(_) => {
                errors.push(String::from("emergency code rotation timed out (20s)"));
                false
            }
        }
    };

    // Step 6: Revoke other logged-in devices (30s timeout) while preserving the
    // current managed control session whenever Steam can identify it.
    match timeout(
        Duration::from_secs(30),
        revoke_logged_in_devices(
            root_dir,
            master_key,
            account_id,
            SteamSessionDeviceSelection::Others,
        ),
    )
    .await
    {
        Ok(Ok(outcome)) => {
            devices_revoked = outcome.revoked_count;
            current_device_revoked = outcome.current_device_revoked;
        }
        Ok(Err(e)) => errors.push(format!("device revocation failed: {e}")),
        Err(_) => errors.push(String::from("device revocation timed out (30s)")),
    }

    // Step 7: Clear local session material only when the current managed
    // session itself was revoked.
    if current_device_revoked {
        match timeout(Duration::from_secs(5), async {
            let storage_path = managed_account_storage_path(root_dir, account_id);
            match load_stored_account(master_key, &storage_path).await {
                Ok(Some(mut record)) => {
                    clear_stored_session_material(&mut record);
                    persist_stored_account(master_key, &storage_path, &record)
                        .await
                        .map_err(|e| anyhow::anyhow!("failed persisting cleared session: {e}"))
                }
                Ok(None) => Err(anyhow::anyhow!("account not found for session clearing")),
                Err(e) => Err(anyhow::anyhow!(
                    "failed loading account for session clearing: {e}"
                )),
            }
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => errors.push(e.to_string()),
            Err(_) => errors.push(String::from("session clearing timed out (5s)")),
        }
    }

    Ok(ZeroTrustSweepResult {
        confirmations_rejected,
        approvals_denied,
        devices_revoked,
        emergency_codes_rotated,
        guard_state_changed,
        device_id_changed,
        errors,
    })
}
