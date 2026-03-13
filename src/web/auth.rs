// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

use crate::web_auth;

use super::middleware::{
    cache_user_master_key, clear_auth_session_sensitive_state, clear_invalid_cookie_state,
    drop_user_master_key_if_no_active_sessions,
};
use super::shared::*;

pub(crate) fn public_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/register",
            get(register_page_handler).post(register_submit_handler),
        )
        .route("/login", get(login_page_handler).post(login_submit_handler))
        .route("/logout", post(logout_handler))
}

pub(crate) fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/settings", get(settings_page_handler))
        .route("/settings/security/password", post(change_password_handler))
        .route(
            "/settings/security/idle-timeout",
            post(update_idle_timeout_handler),
        )
        .route(
            "/settings/security/totp/setup",
            get(totp_setup_page_handler).post(confirm_totp_setup_handler),
        )
}

async fn render_login_page(
    app_state: &AppState,
    language: Language,
    error_message: Option<&str>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let languages = language_options(language, "/login");
    let settings = app_state.system_settings.read().await.clone();
    let show_register = registration_page_allowed(&app_state.meta_store, &settings).await;
    let register_label = match language {
        Language::En => "Create Account",
        Language::ZhCn => "创建账号",
    };
    let mfa_label = match language {
        Language::En => "TOTP Code",
        Language::ZhCn => "TOTP 动态码",
    };
    let recovery_label = match language {
        Language::En => "Recovery Code",
        Language::ZhCn => "恢复码",
    };
    let mfa_hint = match language {
        Language::En => {
            "If the account already enabled MFA, enter either a TOTP code or one recovery code."
        }
        Language::ZhCn => "如果账号已经启用二次验证，请填写 TOTP 动态码或一条恢复码。",
    };

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert("languages", &languages);
    context.insert("error_message", &error_message);
    context.insert("show_register", &show_register);
    context.insert(
        "register_href",
        &format!("/register?lang={}", language.code()),
    );
    context.insert("register_label", &register_label);
    context.insert("mfa_label", &mfa_label);
    context.insert("recovery_label", &recovery_label);
    context.insert("mfa_hint", &mfa_hint);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "login.html", &context)
}

async fn render_register_page(
    app_state: &AppState,
    language: Language,
    error_message: Option<&str>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let languages = language_options(language, "/register");
    let mut context = Context::new();
    let title = match language {
        Language::En => "Create Account",
        Language::ZhCn => "创建账号",
    };
    let description = match language {
        Language::En => {
            "The first account becomes the only admin. New accounts must finish TOTP setup before entering the dashboard. If an administrator reset your account, reclaim it by registering again with the same username."
        }
        Language::ZhCn => {
            "第一个注册的账号会成为唯一管理员。新账号进入面板前必须先完成 TOTP 设置。如果管理员清空了你的账号凭据，请使用相同用户名重新注册以接管原账号。"
        }
    };
    let username_label = match language {
        Language::En => "Username",
        Language::ZhCn => "用户名",
    };
    let password_label = match language {
        Language::En => "Password",
        Language::ZhCn => "密码",
    };
    let confirm_label = match language {
        Language::En => "Confirm Password",
        Language::ZhCn => "确认密码",
    };
    let submit_label = match language {
        Language::En => "Create Account",
        Language::ZhCn => "创建账号",
    };
    let back_label = match language {
        Language::En => "Back to Login",
        Language::ZhCn => "返回登录",
    };

    context.insert("lang", &language.code());
    context.insert("languages", &languages);
    context.insert("title", &title);
    context.insert("description", &description);
    context.insert("username_label", &username_label);
    context.insert("password_label", &password_label);
    context.insert("confirm_label", &confirm_label);
    context.insert("submit_label", &submit_label);
    context.insert("back_label", &back_label);
    context.insert("back_href", &format!("/login?lang={}", language.code()));
    context.insert("error_message", &error_message);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "register.html", &context)
}

pub(crate) async fn render_settings_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let translations = language.translations();
    let active_sessions = app_state
        .meta_store
        .list_auth_sessions_for_user(&authenticated.user.id)
        .await
        .map_err(|error| {
            warn!(
                "failed loading auth sessions for {}: {}",
                authenticated.user.username, error
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let active_sessions: Vec<ActiveSessionView> = active_sessions
        .into_iter()
        .filter(|session| session.revoked_at_unix.is_none())
        .map(|session| ActiveSessionView {
            is_current: session.id == authenticated.auth_session.id,
            id: session.id,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            issued_at: format_unix_timestamp(session.issued_at_unix),
            expires_at: format_unix_timestamp(session.expires_at_unix),
        })
        .collect();

    let totp_status = match language {
        Language::En if authenticated.user.security.totp_enabled => "Enabled",
        Language::En => "Not enabled",
        Language::ZhCn if authenticated.user.security.totp_enabled => "已启用",
        Language::ZhCn => "未启用",
    };
    let idle_timeout = format_idle_timeout_label(
        authenticated.user.security.preferred_idle_timeout_minutes,
        language,
    );
    let effective_idle_timeout =
        format_idle_timeout_label(authenticated.auth_session.idle_timeout_minutes, language);
    let idle_timeout_field_value = authenticated
        .user
        .security
        .preferred_idle_timeout_minutes
        .map(|minutes| minutes.to_string())
        .unwrap_or_default();
    let system_settings = app_state.system_settings.read().await.clone();
    let idle_timeout_hint = match system_settings.max_idle_timeout_minutes {
        Some(maximum) => match language {
            Language::En => {
                format!("Leave blank to use the system default. Maximum: {maximum} minutes.")
            }
            Language::ZhCn => format!("留空表示使用系统默认值。当前上限：{maximum} 分钟。"),
        },
        None => match language {
            Language::En => String::from(
                "Leave blank to use the system default. Enter 0 for a permanent session.",
            ),
            Language::ZhCn => String::from("留空表示使用系统默认值。输入 0 表示永久不自动登出。"),
        },
    };
    let bot_settings = normalized_bot_settings(
        authenticated
            .user
            .security
            .bot_notification_settings
            .clone(),
    );
    let bot_status = bot_status_summary(&bot_settings, language);
    let bot_destination = bot_destination_summary(&bot_settings, language);
    let bot_template_preview = template_preview(&bot_settings.template, 68);
    let bot_placeholders = build_bot_placeholder_hints(language).to_vec();

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert("i18n", translations);
    context.insert(
        "title",
        &match language {
            Language::En => "Settings",
            Language::ZhCn => "设置",
        },
    );
    context.insert("description", &match language {
        Language::En => "Security, active sessions, and notification preferences live here so the main dashboard stays focused on Telegram sessions.",
        Language::ZhCn => "安全、活跃会话和提醒设置都放在这里，让主面板专注于 Telegram 会话本身。",
    });
    context.insert("current_username", &authenticated.user.username);
    context.insert("show_admin", &(authenticated.user.role == UserRole::Admin));
    context.insert("admin_href", &admin_href(language));
    context.insert("dashboard_href", &dashboard_href(language));
    context.insert("notifications_href", &notifications_href(language));
    context.insert(
        "settings_sections_title",
        &match language {
            Language::En => "Workspace",
            Language::ZhCn => "工作区",
        },
    );
    context.insert(
        "settings_overview_title",
        &match language {
            Language::En => "Overview",
            Language::ZhCn => "概览",
        },
    );
    context.insert(
        "settings_nav_security",
        &match language {
            Language::En => "Security",
            Language::ZhCn => "安全",
        },
    );
    context.insert(
        "settings_nav_notifications",
        &match language {
            Language::En => "Reminders",
            Language::ZhCn => "提醒",
        },
    );
    context.insert(
        "settings_nav_access",
        &match language {
            Language::En => "Access",
            Language::ZhCn => "访问控制",
        },
    );
    context.insert(
        "dashboard_label",
        &match language {
            Language::En => "Dashboard",
            Language::ZhCn => "主面板",
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
        "notifications_label",
        &match language {
            Language::En => "Notifications",
            Language::ZhCn => "提醒设置",
        },
    );
    context.insert(
        "admin_access_description",
        &match language {
            Language::En => "User resets, policy tuning, and audit logs live in the admin console.",
            Language::ZhCn => "用户重置、策略调优和审计日志都在管理后台。",
        },
    );
    context.insert(
        "security_title",
        &match language {
            Language::En => "Security",
            Language::ZhCn => "安全",
        },
    );
    context.insert(
        "security_description",
        &match language {
            Language::En => "Password, TOTP, recovery coverage, and your personal sign-in policy are grouped here.",
            Language::ZhCn => "密码、TOTP、恢复码覆盖情况和你的个人登录策略统一放在这里。",
        },
    );
    context.insert(
        "totp_label",
        &match language {
            Language::En => "TOTP",
            Language::ZhCn => "TOTP",
        },
    );
    context.insert("totp_status", &totp_status);
    context.insert(
        "totp_hint",
        &match language {
            Language::En => "If TOTP is required and not configured, this page is the only path back into the dashboard.",
            Language::ZhCn => "如果系统要求 TOTP 但还没启用，这里就是重新进入主面板前必须完成的步骤。",
        },
    );
    context.insert(
        "recovery_label",
        &match language {
            Language::En => "Recovery Codes",
            Language::ZhCn => "恢复码",
        },
    );
    context.insert(
        "recovery_remaining",
        &authenticated.recovery_codes_remaining.to_string(),
    );
    context.insert(
        "recovery_hint",
        &match language {
            Language::En => "Each recovery code works once. Once all 5 are consumed, you must generate a new set.",
            Language::ZhCn => "每个恢复码只能用一次。5 个都用完后，必须重新生成一组新的恢复码。",
        },
    );
    context.insert(
        "idle_label",
        &match language {
            Language::En => "Idle Timeout Preference",
            Language::ZhCn => "空闲登出偏好",
        },
    );
    context.insert("idle_timeout", &idle_timeout);
    context.insert(
        "idle_effective_label",
        &match language {
            Language::En => "Current Session Timeout",
            Language::ZhCn => "当前登录会话超时",
        },
    );
    context.insert("idle_effective_timeout", &effective_idle_timeout);
    context.insert(
        "idle_summary_label",
        &match language {
            Language::En => "Current Auto Logout",
            Language::ZhCn => "当前自动登出规则",
        },
    );
    context.insert(
        "idle_form_title",
        &match language {
            Language::En => "Auto Logout",
            Language::ZhCn => "自动登出设置",
        },
    );
    context.insert(
        "idle_form_action",
        &format!("/settings/security/idle-timeout?lang={}", language.code()),
    );
    context.insert(
        "idle_input_label",
        &match language {
            Language::En => "Minutes",
            Language::ZhCn => "分钟数",
        },
    );
    context.insert("idle_timeout_field_value", &idle_timeout_field_value);
    context.insert("idle_timeout_hint", &idle_timeout_hint);
    context.insert(
        "idle_submit_label",
        &match language {
            Language::En => "Save Idle Timeout",
            Language::ZhCn => "保存空闲登出设置",
        },
    );
    context.insert(
        "totp_setup_href",
        &format!("/settings/security/totp/setup?lang={}", language.code()),
    );
    context.insert(
        "totp_setup_label",
        &match language {
            Language::En => "Manage TOTP",
            Language::ZhCn => "管理 TOTP",
        },
    );
    context.insert(
        "password_title",
        &match language {
            Language::En => "Change Password",
            Language::ZhCn => "修改密码",
        },
    );
    context.insert(
        "password_action",
        &format!("/settings/security/password?lang={}", language.code()),
    );
    context.insert(
        "current_password_label",
        &match language {
            Language::En => "Current Password",
            Language::ZhCn => "当前密码",
        },
    );
    context.insert(
        "new_password_label",
        &match language {
            Language::En => "New Password",
            Language::ZhCn => "新密码",
        },
    );
    context.insert(
        "confirm_password_label",
        &match language {
            Language::En => "Confirm New Password",
            Language::ZhCn => "确认新密码",
        },
    );
    context.insert(
        "change_password_label",
        &match language {
            Language::En => "Update Password",
            Language::ZhCn => "更新密码",
        },
    );
    context.insert(
        "password_description",
        &match language {
            Language::En => "Changing the password re-wraps your user master key and immediately refreshes this sign-in session.",
            Language::ZhCn => "修改密码会重新包裹你的用户主密钥，并立即刷新当前登录会话的解锁状态。",
        },
    );
    context.insert(
        "notifications_section_title",
        &match language {
            Language::En => "Reminder Center",
            Language::ZhCn => "提醒中心",
        },
    );
    context.insert(
        "notifications_section_description",
        &match language {
            Language::En => "These are your personal reminder settings. Each user keeps their own bot destination and template without sharing a global bot profile.",
            Language::ZhCn => "这里是你自己的提醒配置。每个用户都单独维护自己的 Bot 目标和模板，不再共享全局 Bot 配置。",
        },
    );
    context.insert(
        "notifications_expand_label",
        &match language {
            Language::En => "Expand Reminder Settings",
            Language::ZhCn => "展开提醒设置",
        },
    );
    context.insert(
        "notifications_manage_fullpage_label",
        &match language {
            Language::En => "Open Full Page",
            Language::ZhCn => "打开独立页面",
        },
    );
    context.insert(
        "notification_status_label",
        &match language {
            Language::En => "Status",
            Language::ZhCn => "状态",
        },
    );
    context.insert("notification_status_value", &bot_status);
    context.insert(
        "notification_destination_label",
        &match language {
            Language::En => "Target Chat",
            Language::ZhCn => "目标聊天",
        },
    );
    context.insert("notification_destination_value", &bot_destination);
    context.insert(
        "notification_template_preview_label",
        &match language {
            Language::En => "Template Preview",
            Language::ZhCn => "模板预览",
        },
    );
    context.insert("notification_template_preview", &bot_template_preview);
    context.insert("bot_settings", &build_bot_settings_view(&bot_settings));
    context.insert("bot_placeholders", &bot_placeholders);
    context.insert(
        "bot_settings_action",
        &format!("/settings/bot?lang={}", language.code()),
    );
    context.insert(
        "sessions_title",
        &match language {
            Language::En => "Active Sessions",
            Language::ZhCn => "活跃登录会话",
        },
    );
    context.insert(
        "sessions_description",
        &match language {
            Language::En => "You can review every live browser session here and cut off stale devices without leaving the settings page.",
            Language::ZhCn => "你可以在这里查看所有仍然在线的浏览器会话，并直接清理不再需要的设备登录。",
        },
    );
    context.insert("sessions", &active_sessions);
    context.insert("active_session_count", &active_sessions.len());
    context.insert("current_session_id", &authenticated.auth_session.id);
    context.insert("current_user_id", &authenticated.user.id);
    context.insert(
        "revoke_label",
        &match language {
            Language::En => "Force Logout",
            Language::ZhCn => "强制下线",
        },
    );
    context.insert(
        "revoke_all_action",
        &format!(
            "/admin/users/{}/sessions/revoke?lang={}",
            authenticated.user.id,
            language.code()
        ),
    );
    context.insert(
        "revoke_all_label",
        &match language {
            Language::En => "Force Logout Other Sessions",
            Language::ZhCn => "强制下线其他会话",
        },
    );
    context.insert(
        "session_device_label",
        &match language {
            Language::En => "Device",
            Language::ZhCn => "设备",
        },
    );
    context.insert(
        "unknown_user_agent_label",
        &match language {
            Language::En => "Unknown User Agent",
            Language::ZhCn => "未知设备",
        },
    );
    context.insert(
        "session_ip_label",
        &match language {
            Language::En => "IP",
            Language::ZhCn => "IP",
        },
    );
    context.insert(
        "session_issued_label",
        &match language {
            Language::En => "Issued",
            Language::ZhCn => "签发时间",
        },
    );
    context.insert(
        "session_expires_label",
        &match language {
            Language::En => "Expires",
            Language::ZhCn => "到期时间",
        },
    );
    context.insert(
        "session_empty_label",
        &match language {
            Language::En => "No active browser sessions are currently recorded.",
            Language::ZhCn => "当前没有记录到活跃的浏览器登录会话。",
        },
    );
    context.insert(
        "current_session_label",
        &match language {
            Language::En => "Current Session",
            Language::ZhCn => "当前会话",
        },
    );
    context.insert("banner", &banner);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "settings.html", &context)
}

async fn render_totp_setup_page(
    app_state: &AppState,
    authenticated: &AuthenticatedSession,
    language: Language,
    banner: Option<PageBanner>,
    headers: &HeaderMap,
) -> std::result::Result<Html<String>, StatusCode> {
    let pending = {
        let mut setups = app_state.totp_setups.write().await;
        setups
            .entry(authenticated.auth_session.id.clone())
            .or_insert_with(|| {
                let material = build_totp_setup_material(&authenticated.user.username);
                PendingTotpSetup {
                    secret: material.secret,
                    recovery_codes: material.recovery_codes,
                    otp_auth_uri: material.otp_auth_uri,
                }
            })
            .clone()
    };
    let qr_svg = render_qr_svg(pending.otp_auth_uri.as_ref().as_str()).map_err(|error| {
        warn!(
            "failed rendering totp qr for {}: {}",
            authenticated.user.username, error
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut context = Context::new();
    context.insert("lang", &language.code());
    context.insert(
        "title",
        &match language {
            Language::En => "TOTP Setup",
            Language::ZhCn => "TOTP 设置",
        },
    );
    context.insert("description", &match language {
        Language::En => "Scan the QR code, store the recovery codes, then confirm with one TOTP code before entering the dashboard.",
        Language::ZhCn => "先扫码、保存恢复码，再输入一次 TOTP 动态码完成确认，然后才能进入主面板。",
    });
    context.insert("settings_href", &settings_href(language));
    context.insert(
        "back_label",
        &match language {
            Language::En => "Back to Settings",
            Language::ZhCn => "返回设置",
        },
    );
    context.insert(
        "qr_title",
        &match language {
            Language::En => "Authenticator QR",
            Language::ZhCn => "认证器二维码",
        },
    );
    context.insert("qr_svg", &qr_svg);
    context.insert(
        "secret_label",
        &match language {
            Language::En => "Manual Secret",
            Language::ZhCn => "手动输入密钥",
        },
    );
    context.insert("secret", pending.secret.as_ref().as_str());
    context.insert(
        "recovery_title",
        &match language {
            Language::En => "Recovery Codes",
            Language::ZhCn => "恢复码",
        },
    );
    context.insert(
        "recovery_description",
        &match language {
            Language::En => {
                "Each code works once. After all 5 are used, you must generate a new set."
            }
            Language::ZhCn => "每个恢复码只能使用一次。5 个都用完后，必须重新生成一组。",
        },
    );
    let recovery_codes = pending
        .recovery_codes
        .iter()
        .map(|code| code.as_ref().as_str().to_owned())
        .collect::<Vec<_>>();
    context.insert("recovery_codes", &recovery_codes);
    context.insert(
        "confirm_action",
        &format!("/settings/security/totp/setup?lang={}", language.code()),
    );
    context.insert(
        "confirm_label",
        &match language {
            Language::En => "Enter One TOTP Code",
            Language::ZhCn => "输入一个 TOTP 动态码",
        },
    );
    context.insert(
        "confirm_submit",
        &match language {
            Language::En => "Enable TOTP",
            Language::ZhCn => "启用 TOTP",
        },
    );
    context.insert("banner", &banner);
    insert_transport_security_warning(&mut context, language, headers);

    render_template(&app_state.tera, "totp_setup.html", &context)
}

async fn login_page_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());

    let settings = app_state.system_settings.read().await.clone();
    if let Ok(Some(authenticated)) =
        resolve_authenticated_session(&app_state.meta_store, &settings, &headers).await
    {
        let target =
            if authenticated.requires_totp_setup || authenticated.recovery_codes_remaining == 0 {
                format!("/settings/security/totp/setup?lang={}", language.code())
            } else {
                login_redirect_target(language)
            };
        return Redirect::to(&target).into_response();
    }
    clear_invalid_cookie_state(&app_state, &headers).await;

    match render_login_page(&app_state, language, None, &headers).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn register_page_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let settings = app_state.system_settings.read().await.clone();
    let allowed = registration_page_allowed(&app_state.meta_store, &settings).await;

    if !allowed {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    }

    match render_register_page(&app_state, language, None, &headers).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn login_submit_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let settings = app_state.system_settings.read().await.clone();
    let ip_address = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    match web_auth::authenticate_user(
        &app_state.meta_store,
        &settings,
        &form.username,
        &form.password,
        form.mfa_code.as_deref(),
        form.recovery_code.as_deref(),
        ip_address.as_deref(),
        user_agent.as_deref(),
    )
    .await
    {
        Ok(login_result) => {
            cache_user_master_key(
                &app_state,
                &login_result.auth_session.user_id,
                &login_result.auth_session.id,
                login_result.master_key,
            )
            .await;

            let max_age = i64::from(settings.session_absolute_ttl_hours) * 3600;
            let redirect_target = if login_result.requires_totp_setup {
                format!("/settings/security/totp/setup?lang={}", language.code())
            } else {
                login_redirect_target(language)
            };
            let mut response = Redirect::to(&redirect_target).into_response();
            let cookie_secure = effective_auth_cookie_secure(&settings, &headers);

            match set_cookie_header(&build_auth_cookie(
                &login_result.session_token,
                max_age,
                cookie_secure,
            )) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                    response
                }
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::LockedUntil(locked_until)) => {
            let message = match language {
                Language::En => format!("This account is locked until {locked_until}."),
                Language::ZhCn => format!("这个账号已被锁定，解锁时间戳：{locked_until}。"),
            };
            match render_login_page(&app_state, language, Some(&message), &headers).await {
                Ok(html) => (StatusCode::TOO_MANY_REQUESTS, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::MissingSecondFactor) => {
            let message = match language {
                Language::En => "Enter a TOTP code or recovery code to finish signing in.",
                Language::ZhCn => "请输入 TOTP 动态码或恢复码以完成登录。",
            };
            match render_login_page(&app_state, language, Some(message), &headers).await {
                Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::InvalidSecondFactor) => {
            let message = match language {
                Language::En => "The TOTP code or recovery code was invalid.",
                Language::ZhCn => "TOTP 动态码或恢复码不正确。",
            };
            match render_login_page(&app_state, language, Some(message), &headers).await {
                Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(LoginError::InvalidCredentials) => {
            match render_login_page(
                &app_state,
                language,
                Some(language.translations().login_error_invalid),
                &headers,
            )
            .await
            {
                Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
    }
}

async fn register_submit_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let settings = app_state.system_settings.read().await.clone();
    let allowed =
        registration_submit_allowed(&app_state.meta_store, &settings, &form.username).await;

    if !allowed {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    }
    if form.password != form.confirm_password {
        let message = match language {
            Language::En => "The two password fields must match.",
            Language::ZhCn => "两次输入的密码必须一致。",
        };
        return match render_register_page(&app_state, language, Some(message), &headers).await {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    match web_auth::register_user(
        &app_state.meta_store,
        &settings,
        &form.username,
        &form.password,
        extract_client_ip(&headers).as_deref(),
        extract_user_agent(&headers).as_deref(),
    )
    .await
    {
        Ok(RegistrationResult {
            user,
            auth_session,
            session_token,
            master_key,
        }) => {
            cache_user_master_key(&app_state, &user.id, &auth_session.id, master_key).await;

            let max_age = i64::from(settings.session_absolute_ttl_hours) * 3600;
            let mut response = Redirect::to(&format!(
                "/settings/security/totp/setup?lang={}",
                language.code()
            ))
            .into_response();
            let cookie_secure = effective_auth_cookie_secure(&settings, &headers);
            match set_cookie_header(&build_auth_cookie(
                &session_token,
                max_age,
                cookie_secure,
            )) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                    response
                }
                Err(status) => status.into_response(),
            }
        }
        Err(error) => {
            match render_register_page(&app_state, language, Some(&error.to_string()), &headers)
                .await
            {
                Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                Err(status) => status.into_response(),
            }
        }
    }
}

async fn settings_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    match render_settings_page(&app_state, &authenticated, language, None, &headers).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn change_password_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    if form.new_password != form.confirm_password {
        let message = match language {
            Language::En => "The new password fields must match.",
            Language::ZhCn => "两次输入的新密码必须一致。",
        };
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(message)),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let settings = app_state.system_settings.read().await.clone();
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    };

    match web_auth::change_password(
        &app_state.meta_store,
        &settings,
        &mut user,
        &form.current_password,
        &form.new_password,
    )
    .await
    {
        Ok(master_key) => {
            cache_user_master_key(
                &app_state,
                &user.id,
                &authenticated.auth_session.id,
                master_key,
            )
            .await;
            let mut refreshed = authenticated.clone();
            refreshed.user = user;
            match render_settings_page(
                &app_state,
                &refreshed,
                language,
                Some(PageBanner::success(match language {
                    Language::En => "Password updated.",
                    Language::ZhCn => "密码已更新。",
                })),
                &headers,
            )
            .await
            {
                Ok(html) => html.into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(error) => match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        },
    }
}

async fn update_idle_timeout_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<IdleTimeoutForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let settings = app_state.system_settings.read().await.clone();
    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    };

    let preferred_idle_timeout_minutes =
        match parse_user_idle_timeout_preference(&form.idle_timeout_minutes, &settings) {
            Ok(value) => value,
            Err(error) => {
                return match render_settings_page(
                    &app_state,
                    &authenticated,
                    language,
                    Some(PageBanner::error(error.to_string())),
                    &headers,
                )
                .await
                {
                    Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
                    Err(status) => status.into_response(),
                };
            }
        };

    user.security.preferred_idle_timeout_minutes = preferred_idle_timeout_minutes;
    user.updated_at_unix = Utc::now().timestamp();

    if let Err(error) = app_state.meta_store.save_user(&user).await {
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let effective_idle_timeout = effective_idle_timeout_minutes(&user, &settings);
    if let Err(error) = app_state
        .meta_store
        .set_idle_timeout_for_user_sessions(&user.id, effective_idle_timeout)
        .await
    {
        return match render_settings_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
            &headers,
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
            action_type: String::from("user_idle_timeout_updated"),
            actor_user_id: Some(user.id.clone()),
            subject_user_id: Some(user.id.clone()),
            ip_address: extract_client_ip(&headers),
            success: true,
            details_json: serde_json::json!({
                "preferred_idle_timeout_minutes": preferred_idle_timeout_minutes,
                "effective_idle_timeout_minutes": effective_idle_timeout
            })
            .to_string(),
        })
        .await;

    let mut refreshed = authenticated.clone();
    refreshed.user = user;
    refreshed.auth_session.idle_timeout_minutes = effective_idle_timeout;

    match render_settings_page(
        &app_state,
        &refreshed,
        language,
        Some(PageBanner::success(match language {
            Language::En => "Idle timeout updated.",
            Language::ZhCn => "空闲登出设置已更新。",
        })),
        &headers,
    )
    .await
    {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn totp_setup_page_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    match render_totp_setup_page(&app_state, &authenticated, language, None, &headers).await {
        Ok(html) => html.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn confirm_totp_setup_handler(
    State(app_state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedSession>,
    headers: HeaderMap,
    Form(form): Form<TotpConfirmForm>,
) -> Response {
    let language = detect_language(&headers, form.lang.as_deref());
    let code = form.code.trim();
    if code.is_empty() {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "Enter a TOTP code to confirm setup.",
                Language::ZhCn => "请输入一个 TOTP 动态码完成确认。",
            })),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let pending = {
        let mut setups = app_state.totp_setups.write().await;
        setups
            .entry(authenticated.auth_session.id.clone())
            .or_insert_with(|| {
                let material = build_totp_setup_material(&authenticated.user.username);
                PendingTotpSetup {
                    secret: material.secret,
                    recovery_codes: material.recovery_codes,
                    otp_auth_uri: material.otp_auth_uri,
                }
            })
            .clone()
    };
    let verification = verify_totp(
        pending.secret.as_ref().as_str(),
        code,
        Utc::now().timestamp(),
        1,
        &HashSet::new(),
    );
    let valid = matches!(verification, Ok(TotpVerification::Valid { .. }));
    if !valid {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "That TOTP code did not match the new secret.",
                Language::ZhCn => "这个 TOTP 动态码与新的密钥不匹配。",
            })),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::BAD_REQUEST, html).into_response(),
            Err(status) => status.into_response(),
        };
    }

    let Some(master_key) = app_state
        .unlock_cache
        .read()
        .await
        .get(&authenticated.auth_session.id)
        .cloned()
    else {
        return match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(match language {
                Language::En => "Your unlock state expired. Sign in again and retry TOTP setup.",
                Language::ZhCn => "当前解锁状态已失效，请重新登录后再完成 TOTP 设置。",
            })),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::UNAUTHORIZED, html).into_response(),
            Err(status) => status.into_response(),
        };
    };

    let Some(mut user) = app_state
        .meta_store
        .get_user_by_id(&authenticated.user.id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    };

    match web_auth::save_totp_setup(
        &app_state.meta_store,
        &mut user,
        master_key.as_ref().as_slice(),
        pending.secret.as_ref().as_str(),
        &pending.recovery_codes,
    )
    .await
    {
        Ok(()) => {
            app_state
                .totp_setups
                .write()
                .await
                .remove(&authenticated.auth_session.id);
            Redirect::to(&settings_href(language)).into_response()
        }
        Err(error) => match render_totp_setup_page(
            &app_state,
            &authenticated,
            language,
            Some(PageBanner::error(error.to_string())),
            &headers,
        )
        .await
        {
            Ok(html) => (StatusCode::INTERNAL_SERVER_ERROR, html).into_response(),
            Err(status) => status.into_response(),
        },
    }
}

async fn logout_handler(
    State(app_state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let language = detect_language(&headers, query.lang.as_deref());
    let mut response = Redirect::to(&format!("/login?lang={}", language.code())).into_response();
    let settings = app_state.system_settings.read().await.clone();
    let cookie_secure = effective_auth_cookie_secure(&settings, &headers);
    if let Some(token) = find_cookie(&headers, AUTH_COOKIE_NAME) {
        let token_hash = hash_session_token(token);
        if let Ok(Some(session)) = app_state
            .meta_store
            .get_auth_session_by_token_hash(&token_hash)
            .await
        {
            clear_auth_session_sensitive_state(&app_state, &session.id).await;
            let _ = app_state.meta_store.revoke_auth_session(&session.id).await;
            drop_user_master_key_if_no_active_sessions(&app_state, &session.user_id).await;
        } else {
            clear_invalid_cookie_state(&app_state, &headers).await;
        }
    }

    match set_cookie_header(&clear_auth_cookie(cookie_secure)) {
        Ok(cookie) => {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
            response
        }
        Err(status) => status.into_response(),
    }
}
