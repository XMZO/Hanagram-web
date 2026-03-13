// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::shared::*;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/dashboard/snapshot", get(dashboard_snapshot_handler))
}

async fn build_dashboard_snapshot(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
) -> DashboardSnapshot {
    let sessions = {
        let state = app_state.shared_state.read().await;
        let mut sessions: Vec<SessionInfo> = state
            .values()
            .filter(|session| session.user_id == authenticated.user.id)
            .cloned()
            .collect();
        sessions.sort_by(|left, right| {
            right
                .latest_code_message()
                .map(|message| message.received_at)
                .cmp(
                    &left
                        .latest_code_message()
                        .map(|message| message.received_at),
                )
                .then_with(|| left.phone.cmp(&right.phone))
        });
        sessions
    };

    let connected_count = sessions
        .iter()
        .filter(|session| matches!(session.status, SessionStatus::Connected))
        .count();

    DashboardSnapshot {
        connected_count,
        generated_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        sessions,
    }
}

pub(crate) async fn render_dashboard_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/");
    let snapshot = build_dashboard_snapshot(app_state, authenticated).await;
    let settings_page_href = settings_href(language);

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("current_username", &authenticated.user.username);
    context.insert("show_admin", &(authenticated.user.role == UserRole::Admin));
    context.insert(
        "logout_action",
        &format!("/logout?lang={}", language.code()),
    );
    context.insert("setup_href", &setup_href(language));
    context.insert("settings_href", &settings_page_href);
    context.insert("admin_href", &admin_href(language));
    context.insert(
        "settings_label",
        &match language {
            Language::En => "Settings",
            Language::ZhCn => "设置",
        },
    );
    context.insert(
        "admin_label",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理后台",
        },
    );
    context.insert(
        "settings_security_href",
        &format!("{settings_page_href}#security"),
    );
    context.insert(
        "settings_notifications_href",
        &format!("{settings_page_href}#notifications"),
    );
    context.insert(
        "settings_access_href",
        &format!("{settings_page_href}#access"),
    );
    context.insert(
        "admin_overview_href",
        &format!("{}#overview", admin_href(language)),
    );
    context.insert(
        "dashboard_workspace_eyebrow",
        &match language {
            Language::En => "Workspace Map",
            Language::ZhCn => "工作区地图",
        },
    );
    context.insert(
        "dashboard_workspace_title",
        &match language {
            Language::En => "Session-first dashboard",
            Language::ZhCn => "会话优先主面板",
        },
    );
    context.insert(
        "dashboard_workspace_description",
        &match language {
            Language::En => "This screen is reserved for Telegram sessions and OTP flow. Security, reminder delivery, and browser access management are routed into Settings, while user policy and audit stay in Admin.",
            Language::ZhCn => "这个页面只保留给 Telegram 会话和验证码流。安全设置、提醒投递、网页登录管理统一收进设置页，用户策略和审计则集中在后台。",
        },
    );
    context.insert(
        "dashboard_lane_sessions_title",
        &match language {
            Language::En => "Dashboard",
            Language::ZhCn => "主面板",
        },
    );
    context.insert(
        "dashboard_lane_sessions_body",
        &match language {
            Language::En => "Watch live OTP state, open details, copy codes, rename sessions, and export access data.",
            Language::ZhCn => "查看实时验证码状态、打开详情、复制验证码、重命名会话和导出访问数据。",
        },
    );
    context.insert(
        "dashboard_lane_settings_title",
        &match language {
            Language::En => "Settings",
            Language::ZhCn => "设置",
        },
    );
    context.insert(
        "dashboard_lane_settings_body",
        &match language {
            Language::En => "Password changes, TOTP, recovery codes, reminder delivery, idle timeout, and active web sessions.",
            Language::ZhCn => "密码修改、TOTP、恢复码、提醒投递、空闲登出和网页登录会话都在这里。",
        },
    );
    context.insert(
        "dashboard_lane_admin_title",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理后台",
        },
    );
    context.insert(
        "dashboard_lane_admin_body",
        &match language {
            Language::En => "Create users, unlock accounts, tune policies, and review audit history without crowding the session view.",
            Language::ZhCn => "创建用户、解锁账号、调整策略和查看审计历史，避免挤占会话视图。",
        },
    );
    context.insert(
        "dashboard_shortcuts_title",
        &match language {
            Language::En => "Jump Directly",
            Language::ZhCn => "快速直达",
        },
    );
    context.insert(
        "dashboard_shortcuts_description",
        &match language {
            Language::En => "Secondary capabilities stay one click away and land on the exact section that owns them.",
            Language::ZhCn => "所有次级能力都保持一跳直达，并且直接落到对应的设置区块。",
        },
    );
    context.insert(
        "dashboard_security_card_title",
        &match language {
            Language::En => "Security Hub",
            Language::ZhCn => "安全中心",
        },
    );
    context.insert(
        "dashboard_security_card_body",
        &match language {
            Language::En => "Password, TOTP, recovery codes, and security posture.",
            Language::ZhCn => "密码、TOTP、恢复码和整体安全状态。",
        },
    );
    context.insert(
        "dashboard_notifications_card_title",
        &match language {
            Language::En => "Reminder Center",
            Language::ZhCn => "提醒中心",
        },
    );
    context.insert(
        "dashboard_notifications_card_body",
        &match language {
            Language::En => "Compact bot reminder controls without leaving the session workflow.",
            Language::ZhCn => "不离开会话工作流即可管理紧凑型 Bot 提醒设置。",
        },
    );
    context.insert(
        "dashboard_access_card_title",
        &match language {
            Language::En => "Web Access",
            Language::ZhCn => "网页登录",
        },
    );
    context.insert(
        "dashboard_access_card_body",
        &match language {
            Language::En => "Review active browser sessions and tune idle auto logout.",
            Language::ZhCn => "查看活跃浏览器会话并调整空闲自动登出策略。",
        },
    );
    context.insert(
        "dashboard_admin_card_title",
        &match language {
            Language::En => "Control Center",
            Language::ZhCn => "后台控制",
        },
    );
    context.insert(
        "dashboard_admin_card_body",
        &match language {
            Language::En => "User operations, policy tuning, lockouts, and audit visibility.",
            Language::ZhCn => "用户操作、策略调优、锁定状态和审计可见性。",
        },
    );
    context.insert(
        "session_note_placeholder",
        &match language {
            Language::En => "No note",
            Language::ZhCn => "暂无备注",
        },
    );
    context.insert(
        "session_note_label",
        &match language {
            Language::En => "Note",
            Language::ZhCn => "备注",
        },
    );
    context.insert(
        "save_note_label",
        &match language {
            Language::En => "Save Note",
            Language::ZhCn => "保存备注",
        },
    );
    context.insert("banner", &banner);
    context.insert("sessions", &snapshot.sessions);
    context.insert("connected_count", &snapshot.connected_count);
    context.insert("now", &snapshot.generated_at);
    context.insert(
        "snapshot_api",
        &format!("/api/dashboard/snapshot?lang={}", language.code()),
    );
    context.insert(
        "dashboard_incremental_refresh_seconds",
        &DASHBOARD_INCREMENTAL_SYNC_SECONDS,
    );
    context.insert(
        "dashboard_full_refresh_seconds",
        &DASHBOARD_FULL_SYNC_SECONDS,
    );

    render_template(&app_state.tera, "index.html", &context)
}

async fn index_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let language = detect_language(&headers, query.lang.as_deref());
    render_dashboard_page(&app_state, &authenticated, language, None).await
}

async fn dashboard_snapshot_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
) -> Json<DashboardSnapshot> {
    Json(build_dashboard_snapshot(&app_state, &authenticated).await)
}
