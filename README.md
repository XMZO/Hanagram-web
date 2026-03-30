<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Hanagram-web contributors -->
# Hanagram-web

Language: [中文](#zh) | [English](#en)

---

<a id="zh"></a>
## 简体中文

[跳到 English](#en)

Hanagram-web 是一个基于 Rust + Axum + Tera 构建的多用户安全工作台。它把 **Telegram OTP 会话管理** 和 **Steam Guard 工具箱** 整合到同一个服务端渲染的 Web 应用中，支持多用户隔离、加密存储和双语界面。

### 目录

1. [核心模型](#zh-core-model)
2. [功能总览](#zh-features)
3. [页面结构](#zh-ui)
4. [安全模型](#zh-security)
5. [持久化目录](#zh-data)
6. [配置方式](#zh-config)
7. [快速开始](#zh-quickstart)
8. [首次部署流程](#zh-first-run)
9. [Telegram 会话](#zh-telegram)
10. [Steam 工具箱](#zh-steam)
11. [管理员功能](#zh-admin)
12. [密码与账号恢复](#zh-recovery)
13. [升级说明](#zh-upgrade)
14. [运维](#zh-ops)
15. [构建说明](#zh-build)
16. [常见问题](#zh-faq)

---

<a id="zh-core-model"></a>
### 1. 核心模型

- 第一个注册的账号自动成为唯一管理员。
- Telegram API ID / API Hash 由管理员在 Web 后台配置，不再写入 `.env`。
- Bot 提醒按用户独立配置，互不影响。
- Telegram 会话和 Steam 账号数据按用户加密存储，互相隔离。
- 服务重启后，用户需要重新登录 Web 才能解锁其加密数据。

<a id="zh-features"></a>
### 2. 功能总览

#### Telegram

- 多用户 Web 登录、注册、退出、活跃会话管理
- 会话导入：Telethon string session / `.session` 文件上传 / 手机号验证码 / QR 扫码
- OTP 监控与复制
- 会话备注、重命名、删除、导出
- 用户级 Bot 提醒模板
- 审计日志

#### Steam Guard 工具箱

- 动态码生成（自动刷新、一键复制）
- 账号导入：maFile 拖拽上传 / 手动录入 / 凭据登录 / WinAuth URI 粘贴导入
- Guard 绑定向导（全新绑定或从其他设备迁移）
- Guard 解绑（通过撤销码移除认证器）
- 交易确认管理（逐条或批量确认/拒绝）
- 登录审批（QR 登录请求的批准/拒绝）
- 2FA 安全状态查询
- QR 码导出（SVG 渲染）
- 每账号独立代理配置
- Steam 时间偏差检测
- 中英双语

#### 安全

- Argon2id 密码存储
- TOTP + 恢复码
- 登录失败递增锁定
- 空闲自动登出（用户偏好 + 管理员上限）
- 活跃会话可查看并强制下线

<a id="zh-ui"></a>
### 3. 页面结构

| 路径 | 功能 |
|------|------|
| `/` | Telegram 主面板：会话状态、OTP、备注、导出 |
| `/platforms/steam` | Steam 工具箱：动态码、管理、绑定、确认、审批、关于 |
| `/settings` | 用户安全设置：密码、TOTP、恢复码、Bot 提醒、空闲登出 |
| `/admin` | 管理员控制台：API 配置、用户管理、策略、审计日志 |

<a id="zh-security"></a>
### 4. 安全模型

- 密码通过 Argon2id 派生存储。
- 每个用户拥有独立加密主密钥，Telegram 会话和 Steam 账号文件以 **zstd + AES-GCM** 加密后落盘。
- Web 登录支持 TOTP 和恢复码。
- 审计日志记录重要操作，旧日志按保留策略折叠为汇总。

> 服务重启后不会自动恢复会话监控。用户需要重新登录 Web 才能解锁其加密数据。

<a id="zh-data"></a>
### 5. 持久化目录

```
sessions/
├── .hanagram/
│   └── app.db              # 元数据数据库
└── users/
    └── <user-id>/
        ├── *.session        # 加密的 Telegram 会话
        └── steam/
            └── managed/     # 加密的 Steam 账号
```

<a id="zh-config"></a>
### 6. 配置方式

| 项目 | 配置者 | 位置 |
|------|--------|------|
| Telegram API (ID / Hash) | 管理员 | `/admin` |
| Bot 提醒 | 各用户 | `/settings` |
| 注册模式 / 密码策略 / TOTP 策略 | 管理员 | `/admin` |
| 用户密码 / TOTP / 恢复码 | 各用户 | `/settings` |

#### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SESSIONS_DIR` | `./sessions` | 加密数据根目录 |
| `BIND_ADDR` | `0.0.0.0:8080` | 监听地址 |
| `RUST_LOG` | `info` | 日志级别 |
| `HANAGRAM_IMAGE` | `ghcr.io/xmzo/hanagram-web:latest` | Docker Compose 镜像标签 |

旧的 `API_ID`、`API_HASH`、`BOT_NOTIFY_*`、`ADMIN_USERNAME`、`ADMIN_PASSWORD` 已废弃，可以删除。

<a id="zh-quickstart"></a>
### 7. 快速开始

#### Docker Compose

```bash
cp .env.example .env
# 按需编辑 .env
mkdir -p sessions
docker compose pull && docker compose up -d
```

浏览器打开 `http://<host>:8080/`

#### 源码运行

```bash
cp .env.example .env
mkdir -p sessions
cargo run --release
```

#### 本地构建镜像

```bash
docker compose -f docker-compose.build.yml build
docker compose -f docker-compose.build.yml up -d
```

<a id="zh-first-run"></a>
### 8. 首次部署流程

1. 注册第一个账号（自动成为管理员）
2. 登录后在 `/admin` 保存 Telegram API ID / Hash
3. 根据需要调整注册模式、TOTP 策略、密码策略
4. 配置个人 Bot 提醒
5. 创建普通用户或开放自助注册
6. 开始导入 Telegram 会话 / 添加 Steam 账号

<a id="zh-telegram"></a>
### 9. Telegram 会话

**导入方式：** Telethon string session / `.session` 文件上传 / 手机号验证码登录 / QR 扫码登录

**日常操作：** 查看连接状态 · 查看并复制 OTP · 编辑备注 · 重命名 · 删除 · 导出 `.session` / string session

> 管理员未配置 Telegram API 时，手机号登录、QR 登录和实时会话监控不可用。

<a id="zh-steam"></a>
### 10. Steam 工具箱

Steam 工具箱位于 `/platforms/steam`，提供完整的 Steam Guard 二步验证管理能力。

| 功能 | 说明 |
|------|------|
| 动态码 | 自动生成并刷新 Steam Guard 验证码，一键复制 |
| 账号导入 | maFile 拖拽上传、手动录入、Steam 凭据登录、WinAuth URI 粘贴 |
| Guard 绑定 | 4 步向导：全新绑定或从其他设备迁移现有认证器 |
| Guard 解绑 | 通过撤销码移除认证器，显示剩余尝试次数 |
| 交易确认 | 查看待确认交易，逐条或批量确认/拒绝 |
| 登录审批 | 审批或拒绝 Steam QR 登录请求 |
| 安全状态 | 查询账号 2FA 状态（Guard 类型、保护模式、设备 ID 等） |
| QR 导出 | 服务端 SVG 渲染 + URI 复制，60 秒后自动隐藏 |
| 代理配置 | 每个账号可独立设置 HTTP/SOCKS5 代理 |
| 时间检查 | 对比本机与 Steam 服务器时钟偏差 |

所有 Steam 账号数据以 zstd + AES-GCM 加密存储，与 Telegram 会话采用相同的安全等级。

<a id="zh-admin"></a>
### 11. 管理员功能

- 配置 Telegram API ID / Hash
- 创建 / 解锁 / 重置普通用户
- 强制下线用户会话
- 调整注册模式、TOTP 策略、密码强度、Argon2 参数、空闲登出上限
- 查看审计日志与汇总
- 配置管理员自己的 Bot 提醒

<a id="zh-recovery"></a>
### 12. 密码与账号恢复

**普通用户：** 没有自助找回。管理员在 `/admin` 执行重置，生成临时密码，用户登录后必须立即改密。重置会清空该用户的 TOTP、恢复码、会话数据和 Bot 设置。

**管理员：** 使用内置 `reset_admin` 工具。

```bash
# Docker Compose
docker compose exec hanagram-web /app/reset_admin

# 源码
cargo run --release --bin reset_admin
```

管理员重置后：系统级 Telegram API 配置和其他用户不受影响。

> `reset_admin` 必须指向与主服务相同的 `SESSIONS_DIR`。

<a id="zh-upgrade"></a>
### 13. 升级说明

旧版元数据库不兼容时，删除 `sessions/.hanagram/app.db` 后重启服务，重新导入所需会话。

<a id="zh-ops"></a>
### 14. 运维

```
GET /health → {"status":"ok","sessions":3}
```

Docker 镜像内置健康检查命令。

<a id="zh-build"></a>
### 15. 构建说明

- Docker 镜像包含 `/app/hanagram-web` 和 `/app/reset_admin` 两个二进制
- 运行时镜像基于 `scratch`
- 模板在编译时嵌入二进制，无需单独拷贝 `templates/`

<a id="zh-faq"></a>
### 16. 常见问题

**为什么重启后会话没有立刻恢复？**
会话按用户加密存储，重启后需要用户重新登录 Web 解锁。

**为什么手机号/QR 登录不可用？**
管理员尚未在 `/admin` 配置 Telegram API。

**Bot 是全局共享的吗？**
不是，每个用户独立配置。

**管理员重置后 Telegram API 还在吗？**
还在。重置只影响管理员账号本身的凭据和数据。

**Steam 账号数据安全吗？**
与 Telegram 会话相同的加密方案（zstd + AES-GCM），按用户隔离。

---

<a id="en"></a>
## English

[Jump to 中文](#zh)

Hanagram-web is a multi-user security workbench built with Rust, Axum, and Tera. It combines **Telegram OTP session management** and a **Steam Guard toolbox** in a single server-rendered web application with per-user isolation, encrypted storage, and bilingual UI.

### Table of Contents

1. [Core Model](#en-core-model)
2. [Feature Overview](#en-features)
3. [UI Map](#en-ui)
4. [Security Model](#en-security)
5. [Persistent Data Layout](#en-data)
6. [Configuration](#en-config)
7. [Quick Start](#en-quickstart)
8. [First-Time Setup](#en-first-run)
9. [Telegram Sessions](#en-telegram)
10. [Steam Toolbox](#en-steam)
11. [Admin Features](#en-admin)
12. [Password and Account Recovery](#en-recovery)
13. [Upgrade Notes](#en-upgrade)
14. [Operations](#en-ops)
15. [Build Notes](#en-build)
16. [FAQ](#en-faq)

---

<a id="en-core-model"></a>
### 1. Core Model

- The first registered account automatically becomes the sole admin.
- Telegram API ID / API Hash are configured by the admin in the web console, not in `.env`.
- Bot alerts are configured individually per user.
- Telegram sessions and Steam account data are encrypted per user, fully isolated.
- After a service restart, users must sign in again to unlock their encrypted data.

<a id="en-features"></a>
### 2. Feature Overview

#### Telegram

- Multi-user web sign-in, registration, logout, active session management
- Session onboarding: Telethon string session / `.session` upload / phone code / QR login
- OTP monitoring and copy
- Session notes, rename, delete, export
- Per-user bot alert templates
- Audit logs

#### Steam Guard Toolbox

- 2FA code generation (auto-refresh, one-click copy)
- Account import: maFile drag-and-drop / manual entry / credential login / WinAuth URI paste
- Guard enrollment wizard (fresh enrollment or migrate from another device)
- Guard revocation (remove authenticator via recovery code)
- Trade confirmation management (individual or batch accept/deny)
- Login approval (approve/deny QR login requests)
- 2FA security profile query
- QR code export (server-side SVG rendering)
- Per-account proxy configuration
- Steam clock drift detection
- Bilingual (Chinese / English)

#### Security

- Argon2id password storage
- TOTP + recovery codes
- Progressive login lockout
- Idle auto-logout (user preference + admin cap)
- Active sessions can be viewed and force-revoked

<a id="en-ui"></a>
### 3. UI Map

| Path | Purpose |
|------|---------|
| `/` | Telegram dashboard: session status, OTPs, notes, export |
| `/platforms/steam` | Steam toolbox: codes, manage, enrollment, confirmations, approvals, about |
| `/settings` | User security: password, TOTP, recovery codes, bot alerts, idle logout |
| `/admin` | Admin console: API config, user management, policies, audit logs |

<a id="en-security"></a>
### 4. Security Model

- Passwords are derived and stored with Argon2id.
- Each user has an independent encryption master key. Telegram sessions and Steam accounts are encrypted with **zstd + AES-GCM** before writing to disk.
- Web sign-in supports TOTP and recovery codes.
- Audit logs record important operations; older entries are folded into rollups.

> After a restart, session monitoring does not resume automatically. Users must sign in again to unlock their encrypted data.

<a id="en-data"></a>
### 5. Persistent Data Layout

```
sessions/
├── .hanagram/
│   └── app.db              # Metadata database
└── users/
    └── <user-id>/
        ├── *.session        # Encrypted Telegram sessions
        └── steam/
            └── managed/     # Encrypted Steam accounts
```

<a id="en-config"></a>
### 6. Configuration

| Item | Who | Where |
|------|-----|-------|
| Telegram API (ID / Hash) | Admin | `/admin` |
| Bot alerts | Each user | `/settings` |
| Registration / password / TOTP policy | Admin | `/admin` |
| User password / TOTP / recovery | Each user | `/settings` |

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSIONS_DIR` | `./sessions` | Root directory for encrypted data |
| `BIND_ADDR` | `0.0.0.0:8080` | HTTP bind address |
| `RUST_LOG` | `info` | Log filter |
| `HANAGRAM_IMAGE` | `ghcr.io/xmzo/hanagram-web:latest` | Docker Compose image tag |

Legacy `API_ID`, `API_HASH`, `BOT_NOTIFY_*`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` variables are obsolete and can be removed.

<a id="en-quickstart"></a>
### 7. Quick Start

#### Docker Compose

```bash
cp .env.example .env
# Edit .env as needed
mkdir -p sessions
docker compose pull && docker compose up -d
```

Open `http://<host>:8080/`

#### From Source

```bash
cp .env.example .env
mkdir -p sessions
cargo run --release
```

#### Build Docker Image Locally

```bash
docker compose -f docker-compose.build.yml build
docker compose -f docker-compose.build.yml up -d
```

<a id="en-first-run"></a>
### 8. First-Time Setup

1. Register the first account (becomes admin automatically)
2. Sign in and save Telegram API ID / Hash in `/admin`
3. Adjust registration mode, TOTP policy, password policy as needed
4. Configure personal bot alerts
5. Create regular users or enable self-registration
6. Begin importing Telegram sessions / adding Steam accounts

<a id="en-telegram"></a>
### 9. Telegram Sessions

**Onboarding:** Telethon string session / `.session` file upload / phone code login / QR login

**Daily operations:** View connection status · View and copy OTPs · Edit notes · Rename · Delete · Export `.session` / string session

> Phone login, QR login, and live session workers are unavailable until the admin saves the Telegram API credentials.

<a id="en-steam"></a>
### 10. Steam Toolbox

The Steam toolbox is available at `/platforms/steam` and provides comprehensive Steam Guard 2FA management.

| Feature | Description |
|---------|-------------|
| 2FA Codes | Auto-generated and auto-refreshed Steam Guard codes, one-click copy |
| Account Import | maFile drag-and-drop, manual entry, Steam credential login, WinAuth URI paste |
| Guard Enrollment | 4-step wizard: fresh enrollment or migrate an existing authenticator |
| Guard Revocation | Remove authenticator via recovery code, shows remaining attempts |
| Trade Confirmations | View pending trades, accept/deny individually or in batch |
| Login Approvals | Approve or deny Steam QR login requests |
| Security Profile | Query 2FA status (guard type, protection mode, device ID, etc.) |
| QR Export | Server-side SVG rendering + URI copy, auto-hides after 60 seconds |
| Proxy Config | Per-account HTTP/SOCKS5 proxy settings |
| Clock Check | Compare local time with Steam server clock |

All Steam account data is encrypted at rest with zstd + AES-GCM, same security level as Telegram sessions.

<a id="en-admin"></a>
### 11. Admin Features

- Configure Telegram API ID / Hash
- Create / unlock / reset regular users
- Force-revoke user sessions
- Adjust registration mode, TOTP policy, password strength, Argon2 settings, idle timeout cap
- Review audit logs and rollups
- Configure admin's own bot alerts

<a id="en-recovery"></a>
### 12. Password and Account Recovery

**Regular users:** No self-service reset. The admin resets the user from `/admin`, generating a temporary password. The user must change it immediately after signing in. The reset clears the user's TOTP, recovery codes, session data, and bot settings.

**Admin:** Use the built-in `reset_admin` tool.

```bash
# Docker Compose
docker compose exec hanagram-web /app/reset_admin

# From source
cargo run --release --bin reset_admin
```

Admin reset preserves the system-level Telegram API config and does not affect other users.

> `reset_admin` must point to the same `SESSIONS_DIR` as the main service.

<a id="en-upgrade"></a>
### 13. Upgrade Notes

If the system reports an incompatible metadata database after upgrading, delete `sessions/.hanagram/app.db`, restart, and re-import sessions.

<a id="en-ops"></a>
### 14. Operations

```
GET /health → {"status":"ok","sessions":3}
```

The Docker image ships with a built-in healthcheck command.

<a id="en-build"></a>
### 15. Build Notes

- Docker image contains `/app/hanagram-web` and `/app/reset_admin`
- Runtime image is based on `scratch`
- Templates are embedded into the binary at build time

<a id="en-faq"></a>
### 16. FAQ

**Why don't sessions resume immediately after a restart?**
Sessions are encrypted per user. After a restart, the user must sign in again to unlock them.

**Why are phone login or QR login unavailable?**
The admin has not yet saved the Telegram API credentials in `/admin`.

**Are bot settings global?**
No. Each user configures their own bot alerts independently.

**Does the Telegram API survive an admin reset?**
Yes. The reset only clears the admin account's own credentials and data.

**Is Steam account data secure?**
Same encryption scheme as Telegram sessions (zstd + AES-GCM), isolated per user.
