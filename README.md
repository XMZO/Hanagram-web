<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Hanagram-web contributors -->
# Hanagram-web

Language: [中文](#zh) | [English](#en)

Contents: [中文目录](#zh-toc) | [English TOC](#en-toc)

<a id="zh"></a>
## 简体中文

[跳到 English](#en)

`Hanagram-web` 是一个基于 Rust、Axum、Tera 和 grammers 构建的多用户 Telegram OTP 管理面板。它把 Telegram 会话接入、验证码可视化、网页登录安全、管理员策略控制和用户级 Bot 提醒整合到同一套系统里。

<a id="zh-toc"></a>
### 中文目录

- [跳到 English](#en)
1. [项目概览](#zh-overview)
2. [核心模型](#zh-core-model)
3. [功能清单](#zh-feature-summary)
4. [页面结构](#zh-ui-map)
5. [安全与数据模型](#zh-security-and-data-model)
6. [持久化目录](#zh-persistent-data-layout)
7. [配置方式](#zh-configuration-model)
8. [快速开始](#zh-quick-start)
9. [首次部署后的推荐流程](#zh-recommended-first-time-workflow)
10. [会话接入与日常使用](#zh-session-onboarding-and-daily-use)
11. [管理员功能](#zh-admin-features)
12. [密码找回与账号恢复](#zh-password-recovery-and-account-recovery)
13. [兼容性与升级说明](#zh-compatibility-and-upgrade-notes)
14. [健康检查与运行维护](#zh-healthcheck-and-operations)
15. [构建与镜像说明](#zh-build-and-image-notes)
16. [常见问题](#zh-faq)
17. [仓库说明](#zh-repository-notes)

<a id="zh-overview"></a>
### 1. 项目概览

这个项目适合需要统一管理多个 Telegram 登录会话、查看 OTP 消息、控制 Web 登录安全策略，并支持多用户隔离使用的场景。它不是前后端分离 SPA，而是一个服务器渲染的 Web 应用。

<a id="zh-core-model"></a>
### 2. 核心模型

- 第一个注册的账号会成为唯一管理员。
- 系统严格限制只能存在一个管理员账号。
- Telegram `API ID` 和 `API Hash` 不再通过 `.env` 提供，而是由管理员在 Web 后台配置。
- Bot 提醒不是全局共享配置，而是每个用户在自己的设置页中单独配置。
- Telegram 会话数据按用户加密保存，用户之间互相隔离。
- 服务重启后，某个用户的 Telegram 会话需要该用户重新登录一次，系统才能重新解锁并恢复该用户的会话监控。

<a id="zh-feature-summary"></a>
### 3. 功能清单

- 多用户 Web 登录、注册、退出与活跃网页登录会话管理
- 首个账号自动成为管理员
- 管理员创建普通用户、解锁账号、重置用户、踢下线、修改系统策略
- 用户密码使用 Argon2id 存储
- TOTP、恢复码、登录失败锁定、空闲自动登出
- Telegram 会话导入方式：
  - Telethon string session
  - `.session` 文件上传
  - 手机号验证码登录
  - QR 扫码登录
- OTP 监控与展示
- 会话备注、重命名、删除、导出 `.session`、导出字符串会话
- 用户级 Bot 提醒模板与占位符
- 审计日志与审计汇总
- `/health` 健康检查

<a id="zh-ui-map"></a>
### 4. 页面结构

- `/`
  - 主面板
  - 查看 Telegram 会话状态、OTP、备注、导出、删除、重命名
- `/settings`
  - 当前用户的安全设置
  - 修改密码、TOTP、恢复码、空闲登出、活跃网页登录会话、个人 Bot 提醒
- `/admin`
  - 管理员控制台
  - Telegram API 配置、注册策略、密码策略、Argon2 参数、用户管理、审计日志

<a id="zh-security-and-data-model"></a>
### 5. 安全与数据模型

- 密码使用 Argon2id 派生与存储。
- 每个用户拥有独立的加密主密钥，Telegram 会话文件会用该主密钥加密后再落盘。
- Web 登录支持 TOTP 和恢复码。
- 支持登录失败次数递增锁定策略。
- 支持用户个人空闲登出偏好，也支持管理员设置系统级上限。
- 活跃网页登录会话可查看并可强制下线。
- 审计日志记录重要操作，旧详细日志会根据保留策略折叠成汇总。

#### 重要提醒

Telegram 会话是加密落盘的，因此服务重启后并不会自动恢复所有用户的会话监控。对应用户需要重新登录一次 Web，系统才能再次解锁其 Telegram 会话。

<a id="zh-persistent-data-layout"></a>
### 6. 持久化目录

所有持久化数据都存放在 `SESSIONS_DIR` 下面：

```text
sessions/
├── .hanagram/
│   └── app.db
└── users/
    └── <user-id>/
        └── *.session
```

- `sessions/.hanagram/app.db`
  - 元数据数据库
  - 包含用户、系统设置、网页登录会话、恢复码、审计日志等
- `sessions/users/<user-id>/`
  - 用户自己的 Telegram 会话文件
  - 文件内容是加密后的数据，不是明文 Telegram 会话

<a id="zh-configuration-model"></a>
### 7. 配置方式

#### 配置归属

| Item | Who Configures It | Where |
| --- | --- | --- |
| Telegram API (`API ID` / `API Hash`) | Admin | `/admin` |
| Bot alerts | Each user individually | `/settings` or the admin's own bot section in `/admin` |
| Registration mode | Admin | `/admin` |
| Password policy | Admin | `/admin` |
| TOTP requirement policy | Admin | `/admin` |
| User password, TOTP, recovery usage | Each user | `/settings` |

#### 环境变量

应用本身现在只需要少量运行环境变量，Telegram API 和 Bot 不再来自 `.env`。

| Variable | Default | Scope | Description |
| --- | --- | --- | --- |
| `SESSIONS_DIR` | `./sessions` | App | Root directory for encrypted user data and metadata |
| `BIND_ADDR` | `0.0.0.0:8080` | App | HTTP bind address |
| `RUST_LOG` | `info` | App | Rust log filter |
| `HANAGRAM_IMAGE` | `ghcr.io/xmzo/hanagram-web:latest` | Docker Compose only | Image tag used by `docker compose` |

- 旧的 `API_ID`、`API_HASH`、`BOT_NOTIFY_*`、`ADMIN_USERNAME`、`ADMIN_PASSWORD` 都已经废弃。
- 如果你的旧 `.env` 还保留这些变量，可以直接删除。
- 如果你在 Docker Compose 中把容器内的 `SESSIONS_DIR` 改成别的路径，记得同步修改 volume 挂载目标，否则数据不会持久化到你预期的位置。

<a id="zh-quick-start"></a>
### 8. 快速开始

#### Docker Compose

1. 复制环境文件：

```bash
cp .env.example .env
```

2. 编辑 `.env`：

```dotenv
SESSIONS_DIR=./sessions
BIND_ADDR=0.0.0.0:8080
RUST_LOG=info
HANAGRAM_IMAGE=ghcr.io/<your-user-or-org>/<your-repo>:latest
```

3. 创建持久化目录：

```bash
mkdir -p sessions
```

4. 启动服务：

```bash
docker compose pull
docker compose up -d
```

5. 浏览器打开：

```text
http://<your-host>:8080/
```

#### PowerShell 等价命令

```powershell
Copy-Item .env.example .env
New-Item -ItemType Directory -Force -Path sessions | Out-Null
docker compose pull
docker compose up -d
```

#### 本地源码运行

```bash
cp .env.example .env
mkdir -p sessions
cargo run --release
```

打开地址：

```text
http://127.0.0.1:8080/
```

PowerShell / Windows:

```powershell
Copy-Item .env.example .env
New-Item -ItemType Directory -Force -Path sessions | Out-Null
cargo run --release
```

#### 直接运行已构建二进制

如果你已经有编译好的 `hanagram-web` 可执行文件，可以直接运行它。确保 `SESSIONS_DIR` 指向你想持久化数据的位置。

```bash
mkdir -p sessions
./hanagram-web
```

PowerShell / Windows:

```powershell
New-Item -ItemType Directory -Force -Path sessions | Out-Null
.\hanagram-web.exe
```

#### 本地构建镜像

```bash
docker compose -f docker-compose.build.yml build
docker compose -f docker-compose.build.yml up -d
```

<a id="zh-recommended-first-time-workflow"></a>
### 9. 首次部署后的推荐流程

推荐首次部署后按这个顺序操作：

1. 注册第一个账号，这个账号会自动成为唯一管理员。
2. 登录管理员账号。
3. 如果系统策略要求 TOTP，先完成 TOTP 设置并妥善保存恢复码。
4. 打开 `/admin`，保存 Telegram `API ID` 和 `API Hash`。
5. 根据需要调整注册模式、TOTP 策略、密码策略和空闲登出上限。
6. 管理员为自己配置个人 Bot 提醒。
7. 创建普通用户，或者打开自助注册。
8. 每个用户登录后在自己的 `/settings` 中配置自己的 Bot；如果策略要求，也要完成自己的 TOTP 设置。
9. 再开始导入 Telegram 会话。

<a id="zh-session-onboarding-and-daily-use"></a>
### 10. 会话接入与日常使用

#### 支持的会话接入方式

- Telethon string session 导入
- 上传 `.session` 文件
- 手机号验证码登录
- QR 扫码登录

#### 会话日常操作

- 查看连接状态
- 查看最近 OTP / 最近消息
- 复制 OTP
- 编辑备注
- 重命名会话
- 删除会话
- 导出 `.session`
- 导出字符串会话

#### Telegram API 配置缺失时的行为

系统可以在未配置 Telegram API 的情况下启动，但下面这些功能在管理员保存 API 之前不可用：

- 手机号登录
- QR 登录
- 需要 Telegram API 连通性的实时会话工作器

<a id="zh-admin-features"></a>
### 11. 管理员功能

管理员可以在 `/admin` 执行这些操作：

- 配置 Telegram `API ID` / `API Hash`
- 创建普通用户
- 解锁因登录失败而被锁定的用户
- 重置普通用户账号
- 强制下线某个用户的网页登录会话
- 调整注册策略：
  - 仅管理员创建
  - 管理员可切换是否开放注册
  - 始终开放注册
- 调整 TOTP 强制策略
- 调整密码强度规则
- 调整 Argon2 参数下限
- 调整空闲登出系统上限
- 查看审计日志与汇总
- 配置管理员自己的个人 Bot 提醒

<a id="zh-password-recovery-and-account-recovery"></a>
### 12. 密码找回与账号恢复

#### 普通用户忘记密码

普通用户没有自助“忘记密码”入口。管理员需要在 `/admin` 中对该用户执行重置。重置后：

- 系统会为该用户生成一个新的临时随机密码
- 该用户的 TOTP、恢复码会被清空
- 该用户当前所有网页登录会话会被强制失效
- 该用户的加密 Telegram 会话数据会被删除
- 该用户的个人 Bot 设置会被清空
- 管理员需要把临时密码发给该用户
- 该用户必须使用临时密码登录，并在进入其他工作区功能前立刻修改密码

#### 管理员忘记密码

管理员也没有邮件找回、环境变量后门或网页上的第二恢复通道。正确做法是使用内置的 `reset_admin` 工具。

重置管理员后：

- 管理员账号本身仍然保留
- 系统会为管理员生成一个新的临时随机密码
- 管理员的 TOTP、恢复码会被清空
- 管理员当前所有网页登录会话会被强制失效
- 管理员自己的加密 Telegram 会话数据会被删除
- 管理员自己的个人 Bot 设置会被清空
- 系统级 Telegram API 设置会保留
- 其他普通用户不受影响
- 需要使用临时密码重新登录，并立即修改为自己的正式密码

#### 管理员恢复命令

执行后，命令会直接输出新的临时密码。

Docker Compose 容器内执行：

```bash
docker compose exec hanagram-web /app/reset_admin
```

直接运行二进制：

```bash
./reset_admin
```

源码方式运行：

```bash
cargo run --release --bin reset_admin
```

#### 关于 `SESSIONS_DIR` 的注意事项

无论你用哪种方式运行 `reset_admin`，都必须让它指向和主服务相同的 `SESSIONS_DIR`，否则会找不到正确的数据库和用户目录。

对 Docker Compose 部署，最稳妥的方式是在现有容器里直接执行 `reset_admin`，这样会天然复用相同的挂载目录和环境变量。

Bash / POSIX Shell:

```bash
export SESSIONS_DIR=/path/to/sessions
./reset_admin
```

PowerShell / Windows:

```powershell
$env:SESSIONS_DIR="E:\path\to\sessions"
.\reset_admin.exe
```

<a id="zh-compatibility-and-upgrade-notes"></a>
### 13. 兼容性与升级说明

旧版重构之前的元数据数据库布局故意不兼容。如果升级后系统提示元数据数据库不兼容，请删除：

```text
sessions/.hanagram/app.db
```

然后重新启动服务，并重新导入你仍然需要的 Telegram 会话。

<a id="zh-healthcheck-and-operations"></a>
### 14. 健康检查与运行维护

服务暴露以下接口：

```text
GET /health
```

示例响应：

```json
{"status":"ok","sessions":3}
```

Docker 镜像内置了健康检查命令，不依赖 shell 脚本探针。

<a id="zh-build-and-image-notes"></a>
### 15. 构建与镜像说明

- Docker 镜像最终包含两个二进制：
  - `/app/hanagram-web`
  - `/app/reset_admin`
- 运行时镜像基于 `scratch`
- 模板在编译时嵌入二进制，运行时不需要再单独拷贝 `templates/`

<a id="zh-faq"></a>
### 16. 常见问题

#### 为什么服务重启后，会话没有立刻恢复监控？

因为 Telegram 会话是按用户加密保存的。服务重启后，系统不知道每个用户的解锁主密钥，必须等该用户重新登录一次 Web，才能重新解锁并恢复监控。

#### 为什么手机号登录或扫码登录不可用？

通常是管理员还没有在 `/admin` 中保存 Telegram `API ID` 和 `API Hash`。

#### Bot 是不是全局共享的？

不是。Bot 提醒现在是每个用户自己单独配置、自己单独使用。

#### 管理员重置后，Telegram API 还在吗？

会保留。管理员重置的是管理员账号本身的安全凭据和管理员名下的数据，不会清掉系统级 Telegram API 配置。

<a id="zh-repository-notes"></a>
### 17. 仓库说明

- `templates/` 在构建时嵌入程序
- `sessions/` 和 `.env` 不应该提交到仓库
- `reset_admin` 是正式恢复工具，不是仅供开发环境使用的脚本

<a id="en"></a>
## English

[Jump to 中文](#zh)

`Hanagram-web` is a multi-user Telegram OTP dashboard built with Rust, Axum, Tera, and grammers. It combines Telegram session onboarding, OTP visibility, web sign-in security, admin policy controls, and per-user bot alerts into one system.

<a id="en-toc"></a>
### English TOC

- [Jump to 中文](#zh)
1. [Overview](#en-overview)
2. [Core Model](#en-core-model)
3. [Feature Summary](#en-feature-summary)
4. [UI Map](#en-ui-map)
5. [Security and Data Model](#en-security-and-data-model)
6. [Persistent Data Layout](#en-persistent-data-layout)
7. [Configuration Model](#en-configuration-model)
8. [Quick Start](#en-quick-start)
9. [Recommended First-Time Workflow](#en-recommended-first-time-workflow)
10. [Session Onboarding and Daily Use](#en-session-onboarding-and-daily-use)
11. [Admin Features](#en-admin-features)
12. [Password Recovery and Account Recovery](#en-password-recovery-and-account-recovery)
13. [Compatibility and Upgrade Notes](#en-compatibility-and-upgrade-notes)
14. [Healthcheck and Operations](#en-healthcheck-and-operations)
15. [Build and Image Notes](#en-build-and-image-notes)
16. [FAQ](#en-faq)
17. [Repository Notes](#en-repository-notes)

<a id="en-overview"></a>
### 1. Overview

This project is designed for teams or operators who need to manage multiple Telegram login sessions, inspect OTP messages, enforce web sign-in security policies, and keep users isolated from one another. It is not a frontend SPA; it is a server-rendered web application.

<a id="en-core-model"></a>
### 2. Core Model

- The first registered account becomes the only admin.
- The system strictly enforces a single-admin model.
- Telegram `API ID` and `API Hash` are no longer provided through `.env`; they are configured by the admin in the web console.
- Bot alerts are not global. Each user configures their own bot settings in their own settings page.
- Telegram session data is stored per user and encrypted at rest.
- After the service restarts, a user's Telegram sessions remain locked until that user signs in once again to unlock and resume monitoring.

<a id="en-feature-summary"></a>
### 3. Feature Summary

- Multi-user web sign-in, registration, logout, and active browser session management
- Automatic elevation of the first account to admin
- Admin capabilities for user creation, unlock, reset, forced logout, and policy management
- Argon2id password storage
- TOTP, recovery codes, login lockout, and idle auto-logout
- Telegram session onboarding through:
  - Telethon string session import
  - `.session` file upload
  - phone login with Telegram verification code
  - QR login
- OTP monitoring and display
- Session notes, rename, delete, `.session` export, and string session export
- Per-user bot alert templates and placeholders
- Audit logs and audit rollups
- `/health` endpoint for health checks

<a id="en-ui-map"></a>
### 4. UI Map

- `/`
  - Main dashboard
  - View Telegram session status, OTPs, notes, exports, deletion, and renaming
- `/settings`
  - Current user's security center
  - Change password, manage TOTP and recovery codes, idle logout, active browser sessions, and personal bot alerts
- `/admin`
  - Admin console
  - Configure Telegram API, registration policy, password policy, Argon2 settings, user management, and audit logs

<a id="en-security-and-data-model"></a>
### 5. Security and Data Model

- Passwords are derived and stored with Argon2id.
- Each user has an independent encryption master key, and Telegram session files are encrypted with that key before being written to disk.
- Web sign-in supports TOTP and recovery codes.
- Incremental lockout policies are supported for repeated login failures.
- Users can set personal idle logout preferences, while admins can enforce system-wide upper bounds.
- Active browser sessions can be reviewed and revoked.
- Audit logs record important operations, and older detailed logs can be folded into summarized rollups.

#### Important Note

Telegram sessions are encrypted at rest, so a service restart does not automatically resume monitoring for every user. The corresponding user must sign in to the web UI once so the system can unlock that user's Telegram sessions again.

<a id="en-persistent-data-layout"></a>
### 6. Persistent Data Layout

All persistent data lives under `SESSIONS_DIR`:

```text
sessions/
├── .hanagram/
│   └── app.db
└── users/
    └── <user-id>/
        └── *.session
```

- `sessions/.hanagram/app.db`
  - Metadata database
  - Stores users, system settings, browser sessions, recovery codes, audit logs, and more
- `sessions/users/<user-id>/`
  - The user's Telegram session files
  - The file contents are encrypted, not plaintext Telegram sessions

<a id="en-configuration-model"></a>
### 7. Configuration Model

#### Configuration Ownership

| Item | Who Configures It | Where |
| --- | --- | --- |
| Telegram API (`API ID` / `API Hash`) | Admin | `/admin` |
| Bot alerts | Each user individually | `/settings` or the admin's own bot section in `/admin` |
| Registration mode | Admin | `/admin` |
| Password policy | Admin | `/admin` |
| TOTP requirement policy | Admin | `/admin` |
| User password, TOTP, recovery usage | Each user | `/settings` |

#### Environment Variables

The application itself now needs only a small set of runtime environment variables. Telegram API and bot configuration no longer come from `.env`.

| Variable | Default | Scope | Description |
| --- | --- | --- | --- |
| `SESSIONS_DIR` | `./sessions` | App | Root directory for encrypted user data and metadata |
| `BIND_ADDR` | `0.0.0.0:8080` | App | HTTP bind address |
| `RUST_LOG` | `info` | App | Rust log filter |
| `HANAGRAM_IMAGE` | `ghcr.io/xmzo/hanagram-web:latest` | Docker Compose only | Image tag used by `docker compose` |

- Legacy `API_ID`, `API_HASH`, `BOT_NOTIFY_*`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD` variables are obsolete.
- If they still exist in an old `.env`, you can remove them safely.
- If you change the in-container `SESSIONS_DIR` in Docker Compose, update the mounted volume target as well, or persistence will not match the configured path.

<a id="en-quick-start"></a>
### 8. Quick Start

#### Docker Compose

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Edit `.env`:

```dotenv
SESSIONS_DIR=./sessions
BIND_ADDR=0.0.0.0:8080
RUST_LOG=info
HANAGRAM_IMAGE=ghcr.io/<your-user-or-org>/<your-repo>:latest
```

3. Create the persistence directory:

```bash
mkdir -p sessions
```

4. Start the service:

```bash
docker compose pull
docker compose up -d
```

5. Open in your browser:

```text
http://<your-host>:8080/
```

#### PowerShell Equivalents

```powershell
Copy-Item .env.example .env
New-Item -ItemType Directory -Force -Path sessions | Out-Null
docker compose pull
docker compose up -d
```

#### Local Source Run

```bash
cp .env.example .env
mkdir -p sessions
cargo run --release
```

Open:

```text
http://127.0.0.1:8080/
```

PowerShell / Windows:

```powershell
Copy-Item .env.example .env
New-Item -ItemType Directory -Force -Path sessions | Out-Null
cargo run --release
```

#### Run a Built Binary Directly

If you already have a compiled `hanagram-web` binary, you can run it directly. Make sure `SESSIONS_DIR` points at the data directory you want to persist.

```bash
mkdir -p sessions
./hanagram-web
```

PowerShell / Windows:

```powershell
New-Item -ItemType Directory -Force -Path sessions | Out-Null
.\hanagram-web.exe
```

#### Build the Docker Image Locally

```bash
docker compose -f docker-compose.build.yml build
docker compose -f docker-compose.build.yml up -d
```

<a id="en-recommended-first-time-workflow"></a>
### 9. Recommended First-Time Workflow

For a clean first-time setup, use this order:

1. Register the first account. It becomes the only admin automatically.
2. Sign in as that admin.
3. If policy requires TOTP, finish TOTP enrollment first and store the recovery codes safely.
4. Open `/admin` and save the Telegram `API ID` and `API Hash`.
5. Adjust registration mode, TOTP policy, password policy, and idle timeout caps as needed.
6. Configure the admin account's own personal bot alerts.
7. Create regular users, or allow self-registration.
8. Let each user configure their own bot alerts in `/settings`; if policy requires it, they should also finish their own TOTP setup.
9. Only then begin importing Telegram sessions.

<a id="en-session-onboarding-and-daily-use"></a>
### 10. Session Onboarding and Daily Use

#### Supported Session Onboarding Methods

- Telethon string session import
- `.session` file upload
- Phone login with Telegram verification code
- QR login

#### Daily Session Operations

- View connection status
- View recent OTPs and recent messages
- Copy OTPs
- Edit notes
- Rename sessions
- Delete sessions
- Export `.session`
- Export string session

#### Behavior When Telegram API Is Missing

The system can start even if Telegram API settings are missing, but the following remain unavailable until the admin saves the API credentials:

- Phone login
- QR login
- Live session workers that require Telegram API connectivity

<a id="en-admin-features"></a>
### 11. Admin Features

From `/admin`, the admin can:

- Configure Telegram `API ID` / `API Hash`
- Create regular users
- Unlock users who were locked by repeated login failures
- Reset regular user accounts
- Force-log out a user's browser sessions
- Change registration mode:
  - admin only
  - admin toggle
  - always public
- Adjust TOTP enforcement policy
- Adjust password strength rules
- Raise Argon2 minimum settings
- Set system idle timeout caps
- Review audit logs and rollups
- Configure the admin account's own personal bot alerts

<a id="en-password-recovery-and-account-recovery"></a>
### 12. Password Recovery and Account Recovery

#### Regular User Forgot Password

There is no self-service password reset flow for regular users. The admin must reset that user from `/admin`. After the reset:

- a new temporary random password is generated for that user
- the user's TOTP and recovery codes are cleared
- all of the user's active browser sessions are revoked
- the user's encrypted Telegram session data is removed
- the user's personal bot settings are cleared
- the admin must deliver the temporary password to the user
- the user must sign in with that temporary password and change it before using the rest of the workspace

#### Admin Forgot Password

The admin also has no email recovery, no env-based backdoor, and no second recovery flow in the UI. The correct recovery method is the built-in `reset_admin` tool.

After the admin reset:

- the admin account itself still exists
- a new temporary random password is generated for the admin
- the admin TOTP and recovery codes are cleared
- all of the admin's active browser sessions are revoked
- the admin's own encrypted Telegram session data is removed
- the admin's personal bot settings are cleared
- the system-level Telegram API settings remain intact
- other regular users are not affected
- sign in again with the temporary password and immediately change it to a permanent one

#### Admin Recovery Commands

After running it, the command prints the new temporary password directly.

Run inside Docker Compose:

```bash
docker compose exec hanagram-web /app/reset_admin
```

Direct binary deployment:

```bash
./reset_admin
```

Running from source:

```bash
cargo run --release --bin reset_admin
```

#### `SESSIONS_DIR` Reminder

No matter how you invoke `reset_admin`, it must point to the same `SESSIONS_DIR` as the main service, or it will not find the correct database and user directories.

For Docker Compose deployments, the safest option is to run `reset_admin` inside the existing container so it automatically reuses the same bind mount and environment.

Bash / POSIX Shell:

```bash
export SESSIONS_DIR=/path/to/sessions
./reset_admin
```

PowerShell / Windows:

```powershell
$env:SESSIONS_DIR="E:\path\to\sessions"
.\reset_admin.exe
```

<a id="en-compatibility-and-upgrade-notes"></a>
### 13. Compatibility and Upgrade Notes

The metadata database layout from the pre-redesign versions is intentionally unsupported. If the upgraded system reports an incompatible metadata database, delete:

```text
sessions/.hanagram/app.db
```

Then restart the service and re-import the Telegram sessions you still need.

<a id="en-healthcheck-and-operations"></a>
### 14. Healthcheck and Operations

The service exposes:

```text
GET /health
```

Example response:

```json
{"status":"ok","sessions":3}
```

The Docker image ships with a built-in healthcheck command rather than relying on a shell probe.

<a id="en-build-and-image-notes"></a>
### 15. Build and Image Notes

- The Docker image contains two binaries:
  - `/app/hanagram-web`
  - `/app/reset_admin`
- The runtime image is based on `scratch`
- Templates are embedded into the binary at build time, so the runtime image does not need a separate `templates/` directory

<a id="en-faq"></a>
### 16. FAQ

#### Why don't sessions resume immediately after a restart?

Because Telegram sessions are stored encrypted per user. After a restart, the system does not have each user's unlock key in memory, so the user must sign in once again before monitoring can resume for that user's sessions.

#### Why are phone login or QR login unavailable?

Most commonly, the admin has not yet saved the Telegram `API ID` and `API Hash` in `/admin`.

#### Are bot settings global?

No. Bot alerts are now configured and used individually by each user.

#### Does the Telegram API configuration survive admin reset?

Yes. The admin reset clears the admin account's own credentials and admin-owned data, but it does not remove the system-level Telegram API configuration.

<a id="en-repository-notes"></a>
### 17. Repository Notes

- `templates/` are embedded into the executable at build time
- `sessions/` and `.env` should not be committed
- `reset_admin` is a real recovery tool, not just a development-only helper
