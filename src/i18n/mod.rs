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
    pub empty_state_title: &'static str,
    pub empty_state_description_prefix: &'static str,
    pub empty_state_description_suffix: &'static str,
    pub latest_otp: &'static str,
    pub otp_placeholder: &'static str,
    pub copy: &'static str,
    pub copied: &'static str,
    pub copy_fallback: &'static str,
    pub recent_messages: &'static str,
    pub newest_first: &'static str,
    pub no_messages: &'static str,
    pub status_connecting: &'static str,
    pub status_connected: &'static str,
    pub status_error: &'static str,
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
