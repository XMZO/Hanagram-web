// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::TranslationSet;

pub const TRANSLATIONS: TranslationSet = TranslationSet {
    code: "zh-CN",
    html_lang: "zh-CN",
    page_title: "Hanagram Web",
    hero_eyebrow: "Telegram 验证码监控",
    hero_title: "Hanagram Web",
    hero_description_prefix: "已挂载的会话会实时接收来自 Telegram 官方账号",
    hero_description_suffix: "，面板每 30 秒自动刷新一次。",
    stat_accounts: "账号数",
    stat_connected: "已连接",
    stat_updated: "更新时间",
    language_switch: "语言",
    empty_state_title: "暂无会话",
    empty_state_description_prefix: "将一个或多个",
    empty_state_description_suffix: "文件放入挂载的 sessions 目录。",
    latest_otp: "最新验证码",
    otp_placeholder: "------",
    copy: "复制",
    copied: "已复制",
    copy_fallback: "复制验证码",
    recent_messages: "最近消息",
    newest_first: "最新在前",
    no_messages: "尚未收到验证码消息。",
    status_connecting: "连接中",
    status_connected: "已连接",
    status_error: "错误",
};
