// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use super::auth;
use super::middleware::{
    auth_session_is_active, clear_auth_session_sensitive_state, clear_pending_flows_for_user,
    drop_user_master_key_if_no_active_sessions, sync_active_session_idle_timeouts,
};
use super::sessions;
use super::shared::*;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(admin_page_handler))
        .route("/admin/users/create", post(admin_create_user_handler))
        .route(
            "/admin/users/{user_id}/unlock",
            post(admin_unlock_user_handler),
        )
        .route(
            "/admin/users/{user_id}/reset",
            post(admin_reset_user_handler),
        )
        .route(
            "/admin/users/{user_id}/sessions/revoke",
            post(admin_revoke_user_sessions_handler),
        )
        .route("/admin/settings", post(admin_save_system_settings_handler))
}

pub(crate) async fn render_admin_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let system_settings = app_state.system_settings.read().await.clone();
    let raw_users = app_state.meta_store.list_users().await.map_err(|error| {
        warn!("failed loading users for admin page: {}", error);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let audit_logs = app_state
        .meta_store
        .list_audit_logs()
        .await
        .map_err(|error| {
            warn!("failed loading audit logs: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let audit_rollups = app_state
        .meta_store
        .list_audit_rollups()
        .await
        .map_err(|error| {
            warn!("failed loading audit rollups: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let now = Utc::now().timestamp();
    let registration_options = registration_policy_options(language);
    let totp_policy_options = enforcement_mode_options(language);
    let password_policy_options = enforcement_mode_options(language);
    let current_registration_label = selected_option_label(
        &registration_options,
        registration_policy_value(system_settings.registration_policy),
    );
    let current_totp_policy_label = selected_option_label(
        &totp_policy_options,
        enforcement_mode_value(system_settings.totp_policy),
    );
    let current_password_policy_label = selected_option_label(
        &password_policy_options,
        enforcement_mode_value(system_settings.password_strength_rules.mode),
    );
    let bot_settings = normalized_bot_settings(
        authenticated
            .user
            .security
            .bot_notification_settings
            .clone(),
    );
    let telegram_api_status = telegram_api_status_summary(&system_settings, language);

    let mut locked_users_count = 0_usize;
    let mut total_active_auth_sessions = 0_usize;
    let mut mfa_enabled_users = 0_usize;
    let mut users = Vec::new();
    for user in raw_users {
        let locked = user.security.locked_until_unix.unwrap_or_default() > now;
        let auth_sessions = app_state
            .meta_store
            .list_auth_sessions_for_user(&user.id)
            .await
            .map_err(|error| {
                warn!(
                    "failed loading auth sessions for admin user card: {}",
                    error
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        let active_sessions = auth_sessions
            .iter()
            .filter(|session| auth_session_is_active(session, now))
            .count();
        let recovery_codes_remaining = app_state
            .meta_store
            .count_active_recovery_codes(&user.id)
            .await
            .map_err(|error| {
                warn!(
                    "failed counting recovery codes for admin user card: {}",
                    error
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        if locked {
            locked_users_count += 1;
        }
        if user.security.totp_enabled {
            mfa_enabled_users += 1;
        }
        total_active_auth_sessions += active_sessions;
        users.push(AdminUserView {
            id: user.id,
            username: user.username,
            role: match user.role {
                UserRole::Admin => String::from("admin"),
                UserRole::User => String::from("user"),
            },
            locked,
            totp_enabled: user.security.totp_enabled,
            password_ready: user.security.password_hash.is_some(),
            active_sessions,
            recovery_codes_remaining,
            last_login_ip: user.security.last_login_ip,
        });
    }
    let total_users = users.len();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert(
        "title",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理后台",
        },
    );
    context.insert("description", &match language {
        Language::En => "Manage users, registration strategy, session lifetime, and audit visibility from one place.",
        Language::ZhCn => "在这里统一管理用户、注册策略、登录会话时长和审计可见性。",
    });
    context.insert(
        "admin_sections_title",
        &match language {
            Language::En => "Control Center",
            Language::ZhCn => "控制中心",
        },
    );
    context.insert(
        "admin_nav_overview",
        &match language {
            Language::En => "Overview",
            Language::ZhCn => "总览",
        },
    );
    context.insert(
        "admin_nav_users",
        &match language {
            Language::En => "Users",
            Language::ZhCn => "用户",
        },
    );
    context.insert(
        "admin_nav_policy",
        &match language {
            Language::En => "Policy",
            Language::ZhCn => "策略",
        },
    );
    context.insert(
        "admin_nav_audit",
        &match language {
            Language::En => "Audit",
            Language::ZhCn => "审计",
        },
    );
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("settings_href", &settings_href(language));
    context.insert(
        "dashboard_label",
        &match language {
            Language::En => "Dashboard",
            Language::ZhCn => "主面板",
        },
    );
    context.insert(
        "settings_label",
        &match language {
            Language::En => "Settings",
            Language::ZhCn => "设置",
        },
    );
    context.insert(
        "api_title",
        &match language {
            Language::En => "Telegram API",
            Language::ZhCn => "Telegram API",
        },
    );
    context.insert(
        "api_description",
        &match language {
            Language::En => "This is the shared Telegram application credential used for phone login, QR login, and live session connectivity across the workspace.",
            Language::ZhCn => "这是整个工作区共用的 Telegram 应用凭据，用于手机号登录、扫码登录和实时会话连接。",
        },
    );
    context.insert(
        "api_status_label",
        &match language {
            Language::En => "API Status",
            Language::ZhCn => "API 状态",
        },
    );
    context.insert("api_status_value", &telegram_api_status);
    context.insert(
        "api_id_label",
        &match language {
            Language::En => "API ID",
            Language::ZhCn => "API ID",
        },
    );
    context.insert(
        "api_hash_label",
        &match language {
            Language::En => "API Hash",
            Language::ZhCn => "API Hash",
        },
    );
    context.insert(
        "api_hint",
        &match language {
            Language::En => "Leave both fields blank only if you intentionally want Telegram session connectivity disabled until they are configured.",
            Language::ZhCn => "只有在你明确想让 Telegram 会话连接暂时停用时，才把这两个字段一起留空。",
        },
    );
    context.insert(
        "telegram_api_id",
        &system_settings
            .telegram_api
            .api_id
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    context.insert("telegram_api_hash", &system_settings.telegram_api.api_hash);
    context.insert(
        "create_user_title",
        &match language {
            Language::En => "Create User",
            Language::ZhCn => "创建用户",
        },
    );
    context.insert(
        "username_label",
        &match language {
            Language::En => "Username",
            Language::ZhCn => "用户名",
        },
    );
    context.insert(
        "password_label",
        &match language {
            Language::En => "Password",
            Language::ZhCn => "密码",
        },
    );
    context.insert(
        "create_user_label",
        &match language {
            Language::En => "Create User",
            Language::ZhCn => "创建用户",
        },
    );
    context.insert(
        "policy_title",
        &match language {
            Language::En => "System Policy",
            Language::ZhCn => "系统策略",
        },
    );
    context.insert(
        "personal_bot_title",
        &match language {
            Language::En => "My Bot Alerts",
            Language::ZhCn => "我的 Bot 提醒",
        },
    );
    context.insert(
        "personal_bot_description",
        &match language {
            Language::En => "Bot delivery is personal now. Each user configures their own bot target and template, including the admin account.",
            Language::ZhCn => "现在 Bot 提醒是按用户独立配置的。每个人都要设置自己的 Bot 目标和模板，管理员账号也不例外。",
        },
    );
    context.insert("bot_settings", &build_bot_settings_view(&bot_settings));
    context.insert(
        "bot_settings_action",
        &format!("/settings/bot?lang={}", language.code()),
    );
    context.insert(
        "registration_label",
        &match language {
            Language::En => "Registration Mode",
            Language::ZhCn => "注册模式",
        },
    );
    context.insert("registration_options", &registration_options);
    context.insert(
        "current_registration_policy",
        &registration_policy_value(system_settings.registration_policy),
    );
    context.insert("totp_policy_options", &totp_policy_options);
    context.insert(
        "current_totp_policy",
        &enforcement_mode_value(system_settings.totp_policy),
    );
    context.insert("password_policy_options", &password_policy_options);
    context.insert(
        "current_password_policy",
        &enforcement_mode_value(system_settings.password_strength_rules.mode),
    );
    context.insert("current_registration_label", &current_registration_label);
    context.insert("current_totp_policy_label", &current_totp_policy_label);
    context.insert(
        "current_password_policy_label",
        &current_password_policy_label,
    );
    context.insert(
        "public_registration_open",
        &system_settings.public_registration_open,
    );
    context.insert(
        "public_registration_label",
        &match language {
            Language::En => "Open registration when using admin toggle mode",
            Language::ZhCn => "当模式为管理员可开关时，当前允许公开注册",
        },
    );
    context.insert(
        "session_ttl_label",
        &match language {
            Language::En => "Session TTL (hours)",
            Language::ZhCn => "登录会话有效期（小时）",
        },
    );
    context.insert(
        "audit_limit_label",
        &match language {
            Language::En => "Detailed Audit Rows",
            Language::ZhCn => "审计详细记录保留条数",
        },
    );
    context.insert(
        "totp_policy_label",
        &match language {
            Language::En => "TOTP Requirement",
            Language::ZhCn => "TOTP 强制策略",
        },
    );
    context.insert(
        "password_policy_label",
        &match language {
            Language::En => "Password Strength Rule",
            Language::ZhCn => "密码强度策略",
        },
    );
    context.insert(
        "password_min_length_label",
        &match language {
            Language::En => "Password Minimum Length",
            Language::ZhCn => "密码最小长度",
        },
    );
    context.insert(
        "password_require_uppercase_label",
        &match language {
            Language::En => "Require uppercase letters",
            Language::ZhCn => "必须包含大写字母",
        },
    );
    context.insert(
        "password_require_lowercase_label",
        &match language {
            Language::En => "Require lowercase letters",
            Language::ZhCn => "必须包含小写字母",
        },
    );
    context.insert(
        "password_require_number_label",
        &match language {
            Language::En => "Require numbers",
            Language::ZhCn => "必须包含数字",
        },
    );
    context.insert(
        "password_require_symbol_label",
        &match language {
            Language::En => "Require symbols",
            Language::ZhCn => "必须包含符号",
        },
    );
    context.insert(
        "lockout_threshold_label",
        &match language {
            Language::En => "Lock After Failures",
            Language::ZhCn => "连续失败多少次后开始锁定",
        },
    );
    context.insert(
        "lockout_base_label",
        &match language {
            Language::En => "Initial Delay (seconds)",
            Language::ZhCn => "初始延迟（秒）",
        },
    );
    context.insert(
        "lockout_max_label",
        &match language {
            Language::En => "Maximum Delay (seconds)",
            Language::ZhCn => "最大延迟（秒）",
        },
    );
    context.insert(
        "system_idle_limit_label",
        &match language {
            Language::En => "System Idle Timeout Cap (minutes)",
            Language::ZhCn => "系统空闲登出上限（分钟）",
        },
    );
    context.insert(
        "system_idle_limit_hint",
        &match language {
            Language::En => "Leave blank to allow permanent sessions.",
            Language::ZhCn => "留空表示允许永久不登出。",
        },
    );
    context.insert(
        "argon_memory_label",
        &match language {
            Language::En => "Argon2 Memory (MiB)",
            Language::ZhCn => "Argon2 内存（MiB）",
        },
    );
    context.insert(
        "argon_iterations_label",
        &match language {
            Language::En => "Argon2 Iterations",
            Language::ZhCn => "Argon2 迭代次数",
        },
    );
    context.insert(
        "argon_lanes_label",
        &match language {
            Language::En => "Argon2 Lanes",
            Language::ZhCn => "Argon2 并行线程数",
        },
    );
    context.insert("argon_raise_only_hint", &match language {
        Language::En => "These minimums can only move upward. Existing users are rehashed after their next successful login.",
        Language::ZhCn => "这些下限只能调高不能调低。现有用户在下次成功登录后会自动重新派生。",
    });
    context.insert(
        "save_policy_label",
        &match language {
            Language::En => "Save Policy",
            Language::ZhCn => "保存策略",
        },
    );
    context.insert(
        "users_title",
        &match language {
            Language::En => "Users",
            Language::ZhCn => "用户列表",
        },
    );
    context.insert(
        "users_description",
        &match language {
            Language::En => "Create regular users, unlock them, revoke their web sessions, or fully reset their encrypted account state.",
            Language::ZhCn => "在这里创建普通用户、解锁账号、踢下线，或彻底重置其加密账户状态。",
        },
    );
    context.insert(
        "unlock_label",
        &match language {
            Language::En => "Unlock",
            Language::ZhCn => "解锁",
        },
    );
    context.insert(
        "revoke_sessions_label",
        &match language {
            Language::En => "Force Logout",
            Language::ZhCn => "强制下线",
        },
    );
    context.insert(
        "reset_label",
        &match language {
            Language::En => "Reset",
            Language::ZhCn => "重置",
        },
    );
    context.insert(
        "role_admin_label",
        &match language {
            Language::En => "Admin",
            Language::ZhCn => "管理员",
        },
    );
    context.insert(
        "role_user_label",
        &match language {
            Language::En => "User",
            Language::ZhCn => "普通用户",
        },
    );
    context.insert(
        "locked_badge_label",
        &match language {
            Language::En => "Locked",
            Language::ZhCn => "已锁定",
        },
    );
    context.insert(
        "totp_enabled_badge_label",
        &match language {
            Language::En => "TOTP On",
            Language::ZhCn => "TOTP 已开",
        },
    );
    context.insert(
        "totp_missing_badge_label",
        &match language {
            Language::En => "TOTP Off",
            Language::ZhCn => "TOTP 未开",
        },
    );
    context.insert(
        "password_ready_badge_label",
        &match language {
            Language::En => "Password Ready",
            Language::ZhCn => "密码已配置",
        },
    );
    context.insert(
        "password_reset_badge_label",
        &match language {
            Language::En => "Reset Pending",
            Language::ZhCn => "等待重新设置",
        },
    );
    context.insert(
        "user_active_sessions_label",
        &match language {
            Language::En => "Active Web Sessions",
            Language::ZhCn => "活跃网页登录会话",
        },
    );
    context.insert(
        "user_recovery_codes_label",
        &match language {
            Language::En => "Recovery Codes",
            Language::ZhCn => "恢复码剩余",
        },
    );
    context.insert(
        "user_last_ip_label",
        &match language {
            Language::En => "Last Login IP",
            Language::ZhCn => "最近登录 IP",
        },
    );
    context.insert(
        "audit_title",
        &match language {
            Language::En => "Audit Log",
            Language::ZhCn => "审计日志",
        },
    );
    context.insert(
        "audit_description",
        &match language {
            Language::En => "Detailed rows stay visible until the configured cap, then older detail collapses into rollups.",
            Language::ZhCn => "详细审计保留到配置上限，超出后旧数据会折叠成汇总统计。",
        },
    );
    context.insert(
        "rollup_title",
        &match language {
            Language::En => "Audit Rollups",
            Language::ZhCn => "审计汇总",
        },
    );
    context.insert(
        "audit_success_label",
        &match language {
            Language::En => "OK",
            Language::ZhCn => "成功",
        },
    );
    context.insert(
        "audit_failure_label",
        &match language {
            Language::En => "FAIL",
            Language::ZhCn => "失败",
        },
    );
    context.insert(
        "audit_empty_label",
        &match language {
            Language::En => "No detailed audit rows have been recorded yet.",
            Language::ZhCn => "当前还没有详细审计记录。",
        },
    );
    context.insert(
        "rollup_empty_label",
        &match language {
            Language::En => "No audit rollups have been generated yet.",
            Language::ZhCn => "当前还没有生成审计汇总。",
        },
    );
    context.insert(
        "overview_title",
        &match language {
            Language::En => "System Snapshot",
            Language::ZhCn => "系统快照",
        },
    );
    context.insert(
        "overview_users_label",
        &match language {
            Language::En => "Users",
            Language::ZhCn => "用户数",
        },
    );
    context.insert(
        "overview_locked_label",
        &match language {
            Language::En => "Locked Users",
            Language::ZhCn => "锁定用户",
        },
    );
    context.insert(
        "overview_web_sessions_label",
        &match language {
            Language::En => "Active Web Sessions",
            Language::ZhCn => "活跃网页登录会话",
        },
    );
    context.insert(
        "overview_mfa_label",
        &match language {
            Language::En => "Users With TOTP",
            Language::ZhCn => "已启用 TOTP 的用户",
        },
    );
    context.insert(
        "overview_audit_rows_label",
        &match language {
            Language::En => "Detailed Audit Rows",
            Language::ZhCn => "详细审计记录",
        },
    );
    context.insert(
        "policy_stack_title",
        &match language {
            Language::En => "Policy Stack",
            Language::ZhCn => "策略栈",
        },
    );
    context.insert(
        "policy_description",
        &match language {
            Language::En => "Each control is grouped by outcome: who can enter, how strong credentials must be, how long sessions stay alive, and how expensive key derivation should become.",
            Language::ZhCn => "所有策略按结果分组：谁能进入、凭据强度、会话存活时长，以及密钥派生成本。",
        },
    );
    context.insert("total_users", &total_users);
    context.insert("locked_users_count", &locked_users_count);
    context.insert("total_active_auth_sessions", &total_active_auth_sessions);
    context.insert("mfa_enabled_users", &mfa_enabled_users);
    context.insert("audit_log_count", &audit_logs.len());
    context.insert("users", &users);
    context.insert("audit_logs", &audit_logs);
    context.insert("audit_rollups", &audit_rollups);
    context.insert("system_settings", &system_settings);
    context.insert(
        "system_max_idle_timeout_minutes",
        &system_settings
            .max_idle_timeout_minutes
            .map(|minutes| minutes.to_string())
            .unwrap_or_default(),
    );
    context.insert(
        "argon_memory_mib",
        &(system_settings.argon_policy.memory_kib / 1024),
    );
    context.insert("argon_iterations", &system_settings.argon_policy.iterations);
    context.insert("argon_lanes", &system_settings.argon_policy.lanes);
    context.insert(
        "bot_placeholders",
        &build_bot_placeholder_hints(language).to_vec(),
    );
    context.insert("banner", &banner);
    context.insert("current_admin_username", &authenticated.user.username);

    render_template(&app_state.tera, "admin.html", &context)
}

async fn admin_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }
    match render_admin_page(&app_state, &authenticated, language, None).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_create_user_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<AdminCreateUserForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }

    let settings = app_state.system_settings.read().await.clone();
    let username = match normalize_username(&form.username) {
        Ok(value) => value,
        Err(error) => {
            return match render_admin_page(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(error.to_string())),
            )
            .await
            {
                Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                Err(status) => status.into_response(),
            };
        }
    };
    let strength =
        evaluate_password_strength(&form.password, &settings.password_strength_rules, false);
    if !strength.valid {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(strength.reasons.join("; "))),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    if app_state
        .meta_store
        .get_user_by_username(&username)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "That username already exists.",
                Language::ZhCn => "这个用户名已经存在。",
            })),
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let mut user = hanagram_web::store::UserRecord::new(username.clone(), UserRole::User);
    if let Err(error) =
        initialize_user_credentials(&mut user, &form.password, &settings.argon_policy)
    {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let save_result = app_state.meta_store.save_user(&user).await;
    if let Err(error) = save_result {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_user_created"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({ "username": username }).to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "User created.",
            Language::ZhCn => "用户已创建。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_unlock_user_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(user_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&user_id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&admin_href(language)).into_response();
    };
    if user.role == UserRole::Admin {
        return Redirect::to(&admin_href(language)).into_response();
    }

    user.security.login_failures = 0;
    user.security.lockout_level = 0;
    user.security.locked_until_unix = None;
    user.updated_at_unix = Utc::now().timestamp();
    if let Err(error) = app_state.meta_store.save_user(&user).await {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_user_unlocked"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({ "username": user.username }).to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "User unlocked.",
            Language::ZhCn => "用户已解锁。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_reset_user_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(user_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&user_id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&admin_href(language)).into_response();
    };
    if user.role == UserRole::Admin {
        return Redirect::to(&admin_href(language)).into_response();
    }

    if let Ok(session_records) = app_state
        .meta_store
        .list_session_records_for_user(&user.id)
        .await
    {
        for record in session_records {
            if let Some(worker) = app_state.session_workers.lock().await.remove(&record.id) {
                worker.cancellation.cancel();
                let _ = worker.task.await;
            }
        }
    }
    let reset_result = match reset_user_account(
        &app_state.meta_store,
        &mut user,
        &app_state.runtime.users_dir,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            return match render_admin_page(
                &app_state,
                &authenticated,
                language,
                Some(PageBanner::error(error.to_string())),
            )
            .await
            {
                Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
                Err(status) => status.into_response(),
            };
        }
    };

    for auth_session_id in &reset_result.auth_session_ids {
        clear_auth_session_sensitive_state(&app_state, auth_session_id).await;
    }
    app_state.user_keys.write().await.remove(&user.id);
    clear_pending_flows_for_user(&app_state, &user.id).await;
    {
        let mut shared_state = app_state.shared_state.write().await;
        for session_record_id in &reset_result.session_record_ids {
            shared_state.remove(session_record_id);
        }
    }
    for session_record_id in &reset_result.session_record_ids {
        if let Err(error) = app_state
            .runtime_cache
            .remove_session(session_record_id)
            .await
        {
            warn!(
                "failed deleting runtime cache for reset session {}: {}",
                session_record_id, error
            );
        }
    }
    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("admin_user_reset"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "username": user.username,
                "credentials_cleared": true,
                "session_records_removed": reset_result.session_record_ids.len(),
                "auth_sessions_revoked": reset_result.auth_session_ids.len()
            })
            .to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "User credentials and encrypted data were cleared. They must register again with the same username.",
            Language::ZhCn => "该用户的凭据和加密数据已清空。对方需要使用相同用户名重新注册。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_revoke_user_sessions_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    AxumPath(user_id): AxumPath<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
    Form(form): Form<RevokeSessionsForm>,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let allow_self = authenticated.user.id == user_id;
    if authenticated.user.role != UserRole::Admin && !allow_self {
        return Redirect::to(&dashboard_href(language)).into_response();
    }

    if let Some(session_id) = form.session_id.as_deref() {
        if let Ok(Some(session)) = app_state
            .meta_store
            .get_auth_session_by_id(session_id)
            .await
        {
            if session.user_id == user_id {
                let _ = app_state.meta_store.revoke_auth_session(session_id).await;
                clear_auth_session_sensitive_state(&app_state, session_id).await;
                drop_user_master_key_if_no_active_sessions(&app_state, &user_id).await;
            }
        }
    } else {
        if let Ok(sessions) = app_state
            .meta_store
            .list_auth_sessions_for_user(&user_id)
            .await
        {
            for session in sessions {
                clear_auth_session_sensitive_state(&app_state, &session.id).await;
            }
        }
        let _ = app_state
            .meta_store
            .revoke_all_auth_sessions_for_user(&user_id)
            .await;
        app_state.user_keys.write().await.remove(&user_id);
        clear_pending_flows_for_user(&app_state, &user_id).await;
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("auth_sessions_revoked"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(user_id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({ "single_session": form.session_id.is_some() })
                .to_string(),
        })
        .await;

    if authenticated.user.role == UserRole::Admin && authenticated.user.id != user_id {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::success(match language {
                Language::En => "User sessions revoked.",
                Language::ZhCn => "该用户的登录会话已强制下线。",
            })),
        )
        .await
        {
            Ok(html) => html.into_response(),
            Err(status) => status.into_response(),
        };
    }

    match auth::render_settings_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "Selected sessions were revoked.",
            Language::ZhCn => "选中的登录会话已被强制下线。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn admin_save_system_settings_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<AdminSaveSettingsForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    if authenticated.user.role != UserRole::Admin {
        return Redirect::to(&dashboard_href(language)).into_response();
    }

    let mut settings = app_state.system_settings.read().await.clone();
    let previous_telegram_api = settings.telegram_api.clone();
    settings.telegram_api =
        match parse_telegram_api_settings(&form.telegram_api_id, &form.telegram_api_hash) {
            Ok(value) => value,
            Err(error) => {
                return match render_admin_page(
                    &app_state,
                    &authenticated,
                    language,
                    Some(PageBanner::error(error.to_string())),
                )
                .await
                {
                    Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                    Err(status) => status.into_response(),
                };
            }
        };
    settings.registration_policy = parse_registration_policy(&form.registration_policy);
    settings.public_registration_open = form.public_registration_open.is_some();
    settings.session_absolute_ttl_hours = form.session_absolute_ttl_hours.max(1);
    settings.audit_detail_limit = form.audit_detail_limit.max(1);
    settings.totp_policy = parse_enforcement_mode(&form.totp_policy);
    settings.password_strength_policy = parse_enforcement_mode(&form.password_strength_policy);
    settings.password_strength_rules.mode = settings.password_strength_policy;
    settings.password_strength_rules.min_length = form.password_min_length.max(1);
    settings.password_strength_rules.require_uppercase = form.password_require_uppercase.is_some();
    settings.password_strength_rules.require_lowercase = form.password_require_lowercase.is_some();
    settings.password_strength_rules.require_number = form.password_require_number.is_some();
    settings.password_strength_rules.require_symbol = form.password_require_symbol.is_some();
    settings.lockout_policy.threshold = form.lockout_threshold.max(1);
    settings.lockout_policy.base_delay_seconds = form.lockout_base_delay_seconds.max(1);
    settings.lockout_policy.max_delay_seconds = form
        .lockout_max_delay_seconds
        .max(settings.lockout_policy.base_delay_seconds);
    settings.max_idle_timeout_minutes =
        match parse_admin_idle_timeout_cap(&form.max_idle_timeout_minutes) {
            Ok(value) => value,
            Err(error) => {
                return match render_admin_page(
                    &app_state,
                    &authenticated,
                    language,
                    Some(PageBanner::error(error.to_string())),
                )
                .await
                {
                    Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                    Err(status) => status.into_response(),
                };
            }
        };

    let requested_memory_kib = form.argon_memory_mib.max(64).saturating_mul(1024);
    let requested_iterations = form.argon_iterations.max(3);
    let requested_lanes = form.argon_lanes.max(2);
    let current_argon_policy = settings.argon_policy.clone();
    let next_argon_version = current_argon_policy.version + 1;
    let argon_policy_changed = requested_memory_kib > current_argon_policy.memory_kib
        || requested_iterations > current_argon_policy.iterations
        || requested_lanes > current_argon_policy.lanes;
    if argon_policy_changed {
        settings.argon_policy = current_argon_policy.raised(
            next_argon_version,
            requested_memory_kib,
            requested_iterations,
            requested_lanes,
        );
    }
    let telegram_api_changed = previous_telegram_api != settings.telegram_api;
    let telegram_api_configured = configured_telegram_api(&settings).is_some();

    if let Err(error) = app_state.meta_store.save_system_settings(&settings).await {
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    if let Err(error) = sync_active_session_idle_timeouts(&app_state, &settings).await {
        *app_state.system_settings.write().await = settings.clone();
        return match render_admin_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(format!(
                "{}{}",
                match language {
                    Language::En =>
                        "Settings were saved, but refreshing active session timeouts failed: ",
                    Language::ZhCn => "系统设置已保存，但刷新活跃登录会话超时失败：",
                },
                error
            ))),
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }
    *app_state.system_settings.write().await = settings;
    if telegram_api_changed {
        sessions::reload_all_session_workers(&app_state).await;
    }

    let _ = app_state
        .meta_store
        .record_audit(&NewAuditEntry {
            action_type: String::from("system_settings_updated"),
            actor_user_id: Some(authenticated.user.id.clone()),
            subject_user_id: Some(authenticated.user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "telegram_api_configured": telegram_api_configured,
                "registration_policy": form.registration_policy,
                "totp_policy": form.totp_policy,
                "password_strength_policy": form.password_strength_policy,
                "argon_policy_changed": argon_policy_changed,
                "telegram_api_changed": telegram_api_changed
            })
            .to_string(),
        })
        .await;

    match render_admin_page(
        &app_state,
        &authenticated,
        language,
        Some(PageBanner::success(match language {
            Language::En => "System settings saved.",
            Language::ZhCn => "系统设置已保存。",
        })),
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}
