// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

pub(crate) mod admin;
pub(crate) mod auth;
pub(crate) mod bootstrap;
pub(crate) mod dashboard;
pub(crate) mod maintenance;
pub(crate) mod middleware;
pub(crate) mod notifications;
pub(crate) mod platform_key;
pub(crate) mod platforms;
pub(crate) mod runtime_cache;
pub(crate) mod shared;
pub(crate) mod telegram_workspace;

pub(crate) use bootstrap::run;
