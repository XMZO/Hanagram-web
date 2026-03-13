// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::shared::*;

const MAINTENANCE_INTERVAL_SECONDS: u64 = 15 * 60;

pub(crate) async fn run_startup_maintenance(app_state: &AppState) -> Result<()> {
    perform_runtime_maintenance(app_state).await
}

pub(crate) fn spawn_background_maintenance(app_state: AppState) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(MAINTENANCE_INTERVAL_SECONDS)).await;
            if let Err(error) = perform_runtime_maintenance(&app_state).await {
                warn!("runtime maintenance failed: {error:#}");
            }
        }
    });
}

async fn perform_runtime_maintenance(app_state: &AppState) -> Result<()> {
    let valid_session_ids = app_state
        .meta_store
        .list_all_session_records()
        .await?
        .into_iter()
        .map(|record| record.id)
        .collect::<HashSet<_>>();

    let report = app_state
        .runtime_cache
        .perform_maintenance(&valid_session_ids)
        .await?;
    if report.removed_files > 0 {
        info!(
            "runtime cache GC removed {} files and reclaimed {} bytes",
            report.removed_files, report.reclaimed_bytes
        );
    }

    trim_process_allocator();
    Ok(())
}

fn trim_process_allocator() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::malloc_trim(0);
    }
}
