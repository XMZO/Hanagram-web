// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::TranslationSet;

pub const TRANSLATIONS: TranslationSet = TranslationSet {
    code: "en",
    html_lang: "en",
    page_title: "Hanagram Web",
    hero_eyebrow: "Telegram OTP Monitor",
    hero_title: "Hanagram Web",
    hero_description_prefix: "Mounted sessions stream messages from Telegram account",
    hero_description_suffix: ". The dashboard refreshes every 30 seconds.",
    stat_accounts: "Accounts",
    stat_connected: "Connected",
    stat_updated: "Updated",
    language_switch: "Language",
    empty_state_title: "No Sessions",
    empty_state_description_prefix: "Place one or more",
    empty_state_description_suffix: "files into the mounted sessions directory.",
    latest_otp: "Latest OTP",
    otp_placeholder: "------",
    copy: "Copy",
    copied: "Copied",
    copy_fallback: "Copy OTP",
    recent_messages: "Recent Messages",
    newest_first: "Newest first",
    no_messages: "No OTP messages received yet.",
    status_connecting: "Connecting",
    status_connected: "Connected",
    status_error: "Error",
};
