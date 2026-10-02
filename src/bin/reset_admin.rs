// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hanagram_web::admin_reset_cli::run().await
}
