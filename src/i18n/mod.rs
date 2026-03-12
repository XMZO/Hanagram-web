// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

mod en;
mod zh_cn;

use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Language {
    En,
    ZhCn,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct TranslationSet {
    pub code: &'static str,
    pub html_lang: &'static str,
    pub page_title: &'static str,
    pub login_page_title: &'static str,
    pub setup_page_title: &'static str,
    pub phone_page_title: &'static str,
    pub qr_page_title: &'static str,
    pub hero_eyebrow: &'static str,
    pub hero_title: &'static str,
    pub hero_description_prefix: &'static str,
    pub hero_description_suffix: &'static str,
    pub stat_accounts: &'static str,
    pub stat_connected: &'static str,
    pub stat_updated: &'static str,
    pub language_switch: &'static str,
    pub login_title: &'static str,
    pub login_description: &'static str,
    pub login_username: &'static str,
    pub login_password: &'static str,
    pub login_submit: &'static str,
    pub login_error_invalid: &'static str,
    pub logout: &'static str,
    pub dashboard_add_session: &'static str,
    pub dashboard_delete_error: &'static str,
    pub bot_settings_title: &'static str,
    pub bot_settings_description: &'static str,
    pub bot_enabled_label: &'static str,
    pub bot_enabled_hint: &'static str,
    pub bot_token_label: &'static str,
    pub bot_chat_id_label: &'static str,
    pub bot_template_label: &'static str,
    pub bot_template_hint: &'static str,
    pub bot_placeholders_title: &'static str,
    pub bot_placeholder_code: &'static str,
    pub bot_placeholder_phone: &'static str,
    pub bot_placeholder_session_key: &'static str,
    pub bot_placeholder_session_file: &'static str,
    pub bot_placeholder_received_at: &'static str,
    pub bot_placeholder_status: &'static str,
    pub bot_placeholder_message: &'static str,
    pub bot_save: &'static str,
    pub bot_saved: &'static str,
    pub bot_error_missing_token: &'static str,
    pub bot_error_missing_chat_id: &'static str,
    pub bot_error_save: &'static str,
    pub bot_status_enabled: &'static str,
    pub bot_status_disabled: &'static str,
    pub back_to_dashboard: &'static str,
    pub back_to_setup: &'static str,
    pub cancel: &'static str,
    pub close: &'static str,
    pub open_details: &'static str,
    pub session_details: &'static str,
    pub session_file_label: &'static str,
    pub latest_update_label: &'static str,
    pub new_code_badge: &'static str,
    pub delete_session: &'static str,
    pub delete_confirm: &'static str,
    pub rename_session: &'static str,
    pub rename_submit: &'static str,
    pub dashboard_rename_missing: &'static str,
    pub dashboard_rename_error: &'static str,
    pub dashboard_session_missing: &'static str,
    pub empty_state_title: &'static str,
    pub empty_state_description_prefix: &'static str,
    pub empty_state_description_suffix: &'static str,
    pub latest_otp: &'static str,
    pub otp_placeholder: &'static str,
    pub copy: &'static str,
    pub copied: &'static str,
    pub copy_fallback: &'static str,
    pub export_session_title: &'static str,
    pub export_file: &'static str,
    pub export_string: &'static str,
    pub export_string_loading: &'static str,
    pub export_string_copy: &'static str,
    pub export_string_ready: &'static str,
    pub export_string_error: &'static str,
    pub recent_messages: &'static str,
    pub newest_first: &'static str,
    pub no_messages: &'static str,
    pub status_connecting: &'static str,
    pub status_connected: &'static str,
    pub status_error: &'static str,
    pub setup_title: &'static str,
    pub setup_description: &'static str,
    pub setup_string_title: &'static str,
    pub setup_string_description: &'static str,
    pub setup_string_label: &'static str,
    pub setup_string_placeholder: &'static str,
    pub setup_file_title: &'static str,
    pub setup_file_description: &'static str,
    pub setup_file_label: &'static str,
    pub setup_file_button: &'static str,
    pub setup_phone_title: &'static str,
    pub setup_phone_description: &'static str,
    pub setup_phone_label: &'static str,
    pub setup_phone_placeholder: &'static str,
    pub setup_phone_button: &'static str,
    pub setup_qr_title: &'static str,
    pub setup_qr_description: &'static str,
    pub setup_qr_button: &'static str,
    pub setup_session_name: &'static str,
    pub setup_session_name_hint: &'static str,
    pub setup_error_missing_string: &'static str,
    pub setup_error_invalid_string: &'static str,
    pub setup_error_missing_upload: &'static str,
    pub setup_error_upload_read: &'static str,
    pub setup_error_upload_write: &'static str,
    pub setup_error_missing_phone: &'static str,
    pub setup_error_path_alloc: &'static str,
    pub setup_error_phone_unavailable: &'static str,
    pub setup_error_phone_start: &'static str,
    pub setup_error_phone_flow_missing: &'static str,
    pub setup_error_phone_password_reset: &'static str,
    pub setup_error_qr_unavailable: &'static str,
    pub setup_error_qr_flow_missing: &'static str,
    pub setup_error_finalize: &'static str,
    pub setup_error_signup_required: &'static str,
    pub phone_title: &'static str,
    pub phone_description: &'static str,
    pub phone_code_label: &'static str,
    pub phone_code_placeholder: &'static str,
    pub phone_password_label: &'static str,
    pub phone_password_placeholder: &'static str,
    pub phone_password_hint_label: &'static str,
    pub phone_meta_session: &'static str,
    pub phone_meta_phone: &'static str,
    pub phone_submit_code: &'static str,
    pub phone_submit_password: &'static str,
    pub phone_error_missing_code: &'static str,
    pub phone_error_invalid_code: &'static str,
    pub phone_error_code_failed: &'static str,
    pub phone_error_missing_password: &'static str,
    pub phone_error_invalid_password: &'static str,
    pub phone_error_password_retry: &'static str,
    pub qr_title: &'static str,
    pub qr_description: &'static str,
    pub qr_steps: &'static str,
    pub qr_link_label: &'static str,
    pub qr_expires_label: &'static str,
    pub qr_refresh_note: &'static str,
    pub qr_open_link: &'static str,
    pub qr_error_failed: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct LanguageOption {
    pub code: &'static str,
    pub label: &'static str,
    pub href: String,
    pub active: bool,
}

impl Language {
    pub fn detect(query_lang: Option<&str>, accept_language: Option<&str>) -> Self {
        query_lang
            .and_then(Self::parse)
            .or_else(|| accept_language.and_then(parse_accept_language))
            .unwrap_or(Self::ZhCn)
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase();

        if normalized.starts_with("zh") || normalized == "cn" {
            Some(Self::ZhCn)
        } else if normalized.starts_with("en") {
            Some(Self::En)
        } else {
            None
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhCn => "zh-CN",
        }
    }

    pub fn translations(self) -> &'static TranslationSet {
        match self {
            Self::En => &en::TRANSLATIONS,
            Self::ZhCn => &zh_cn::TRANSLATIONS,
        }
    }
}

pub fn language_options(current: Language, path: &str) -> [LanguageOption; 2] {
    [
        LanguageOption {
            code: Language::ZhCn.code(),
            label: "中文",
            href: format!("{path}?lang=zh-CN"),
            active: current == Language::ZhCn,
        },
        LanguageOption {
            code: Language::En.code(),
            label: "English",
            href: format!("{path}?lang=en"),
            active: current == Language::En,
        },
    ]
}

fn parse_accept_language(header: &str) -> Option<Language> {
    header.split(',').find_map(|entry| {
        let language = entry.split(';').next().map(str::trim)?;
        Language::parse(language)
    })
}
