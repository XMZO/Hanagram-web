// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

mod i18n;
mod platforms;
mod state;
mod web;
mod web_auth;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    web::run().await
}
