<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Hanagram-web contributors -->
# Hanagram-web

轻量级 Telegram 会话验证码面板。挂载已有的 Telegram `.session` 文件后，服务会监听来自 `777000` 的消息，提取 5/6 位验证码，并通过一个带站内登录页的 Web 面板展示。

Lightweight Telegram session OTP dashboard. Mount existing Telegram `.session` files, listen for messages from `777000`, extract 5/6-digit login codes, and display them in a web panel protected by an in-app login page.

## 中文

### 项目概览

Hanagram-web 是一个基于 Rust、Tokio、Axum、Tera 和 grammers 的多会话面板。

它的目标很单一：

- 扫描 `SESSIONS_DIR` 下的 `.session` 文件
- 尝试加载 Telethon 或 grammers 格式的会话
- 为每个会话启动独立后台任务
- 持续监听 Telegram 官方账号 `777000` 的新消息
- 使用正则 `\b\d{5,6}\b` 提取验证码
- 在网页中展示每个账号的连接状态、最新验证码和最近消息

当前界面支持中文和英文两种语言。

### 主要特性

- 多账号并行监听，每个 `.session` 文件对应一个后台任务
- Web 面板首页受站内登录保护
- `/health` 健康检查接口不受鉴权保护，适合 Docker/反向代理探活
- 自动提取 5 位或 6 位 Telegram 验证码
- 每个账号最多保留 20 条消息，页面展示最近 5 条
- 页面每 30 秒自动刷新
- 支持一键复制最新验证码，浏览器不支持剪贴板时会退回到 `prompt`
- 支持中英双语
- 支持 Docker 多阶段构建
- session 转换失败只记录警告并跳过，不会因为单个坏文件导致服务整体崩掉

### 支持的 session 格式

当前实现支持两类 `.session`：

1. Telethon SQLite session
2. grammers 原生 SQLite session

加载逻辑如下：

1. 先把文件按 Telethon SQLite session 探测
2. 如果能读到 `sessions` 表中的 `dc_id / server_address / port / auth_key`，则转换成内存 session
3. 如果不是 Telethon 格式，则回退为 grammers 原生 SQLite session 加载
4. 任意阶段报错，只会 `warn` 并跳过该文件

### Telethon 转换限制

Telethon session 转换依赖当前 `grammers-session` 的内部数据结构。当前实现要求读取到的 `auth_key` 长度能够转换成当前 grammers 需要的固定长度数组。

这意味着：

- 某些旧的或特殊生成方式的 Telethon session 可能无法转换
- 遇到不兼容的文件时，服务会记录 warning，然后跳过该 session
- 如果你需要最稳定的行为，优先建议使用 grammers 原生 session

### 页面行为

首页会显示：

- 账号总数
- 已连接账号数
- 最近刷新时间
- 每个账号的手机号
- 每个账号的连接状态
- 每个账号当前最新验证码
- 最近 5 条验证码相关消息

状态分为：

- `Connecting`
- `Connected`
- `Error`

验证码来源固定为 Telegram 官方账号 `777000`。

### 语言切换规则

语言选择顺序如下：

1. 查询参数 `?lang=zh-CN` 或 `?lang=en`
2. 请求头 `Accept-Language`
3. 默认回退为中文

示例：

```text
http://127.0.0.1:8080/?lang=zh-CN
http://127.0.0.1:8080/?lang=en
```

### 路由

- `GET /`
  - 主页面
  - 需要先登录
- `GET /health`
  - 返回 `{"status":"ok","sessions":N}`
  - 不需要认证

### 环境变量

| 变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `AUTH_USER` | 是 | 无 | Web 面板登录用户名 |
| `AUTH_PASS` | 是 | 无 | Web 面板登录密码 |
| `API_ID` | 是 | 无 | Telegram API ID |
| `API_HASH` | 是 | 无 | Telegram API HASH |
| `HANAGRAM_IMAGE` | 否 | `hanagram-web:latest` | Docker Compose 使用的镜像标签 |
| `SESSIONS_DIR` | 否 | `./sessions` | 会话文件目录，启动时会扫描其中的 `*.session` |
| `BIND_ADDR` | 否 | `0.0.0.0:8080` | Web 服务监听地址 |
| `RUST_LOG` | 否 | `info` | Rust 日志级别 |

`.env.example` 已提供基础模板。

### 快速开始

#### 方式一：Docker Compose

这是最推荐的部署方式，尤其是 Linux `x86_64/amd64` 服务器。

默认的 `docker-compose.yml` 不会在服务器上编译镜像，只会启动一个已经存在的镜像。这样可以避免服务器为了构建 Rust 项目而下载大量构建依赖并占用额外磁盘空间。

仓库已经包含 GitHub Actions 工作流 `.github/workflows/docker-image.yml`。只要你把仓库推到 GitHub 默认分支，工作流就可以自动构建并发布镜像到 GHCR。

1. 复制环境变量模板：

```bash
cp .env.example .env
```

2. 编辑 `.env`，至少填好：

```dotenv
AUTH_USER=admin
AUTH_PASS=change-me
API_ID=123456
API_HASH=0123456789abcdef0123456789abcdef
HANAGRAM_IMAGE=ghcr.io/<your-user-or-org>/<your-repo>:latest
SESSIONS_DIR=./sessions
BIND_ADDR=0.0.0.0:8080
RUST_LOG=info
```

3. 创建 session 目录并放入 `.session` 文件：

```bash
mkdir -p sessions
```

4. 把仓库推到 GitHub 默认分支，等待镜像自动发布到 GHCR

5. 在服务器拉取并启动：

```bash
docker compose pull
docker compose up -d
```

6. 打开：

```text
http://<your-host>:8080/
```

如果你暂时不想接 GitHub Actions，仍然可以走手工构建路径：

```bash
docker compose -f docker-compose.build.yml build
```

然后你可以：

1. 在本机构建后直接运行
2. 用 `docker save` 导出镜像，再到服务器 `docker load`

#### 方式二：本地直接运行

需要本机安装 Rust 工具链。

1. 准备环境变量：

```bash
cp .env.example .env
mkdir -p sessions
```

2. 放入 `.session` 文件

3. 运行：

```bash
cargo run --release
```

4. 浏览器访问：

```text
http://127.0.0.1:8080/
```

### Docker 说明

当前 Dockerfile 采用多阶段构建：

- 构建阶段：`ghcr.io/rust-cross/rust-musl-cross:x86_64-musl`
- 运行阶段：`alpine:3.21`

配套文件用途：

- `docker-compose.yml`
  - 运行时 compose
  - 默认只使用已经存在的镜像
  - 适合服务器部署
- `docker-compose.build.yml`
  - 本地打包 compose
  - 会执行镜像构建
  - 适合开发机或 CI 生成镜像
- `.github/workflows/docker-image.yml`
  - GitHub Actions 自动构建并推送镜像到 GHCR
  - 适合日常发布
- `.dockerignore`
  - 避免把 `.git`、`target/`、`sessions/`、`.env` 等无关内容打进构建上下文

容器内默认环境：

- `BIND_ADDR=0.0.0.0:8080`
- `SESSIONS_DIR=./sessions`
- `RUST_LOG=info`

健康检查命令：

```bash
wget -qO- http://localhost:8080/health
```

### Linux 兼容性

当前 Docker 方案默认面向：

- Linux
- `x86_64 / amd64`

如果你运行在 ARM 平台，例如：

- 部分 ARM 云服务器
- Apple Silicon 的原生 Linux 容器场景
- 树莓派

则需要额外处理平台兼容，当前仓库没有内置多架构镜像配置。

### 目录结构

```text
hanagram-web/
├── .dockerignore
├── .github/
│   └── workflows/
│       └── docker-image.yml
├── .env.example
├── .gitignore
├── Cargo.toml
├── Dockerfile
├── docker-compose.build.yml
├── docker-compose.yml
├── README.md
├── src/
│   ├── i18n/
│   │   ├── en.rs
│   │   ├── mod.rs
│   │   └── zh_cn.rs
│   ├── main.rs
│   ├── session_handler.rs
│   └── state.rs
├── templates/
│   └── index.html
└── sessions/
```

### 工作流程

服务启动后大致会做以下事情：

1. 读取 `.env`
2. 初始化日志
3. 初始化共享状态
4. 扫描 `SESSIONS_DIR/*.session`
5. 为每个 session 启动一个 Tokio 任务
6. 启动 Axum Web 服务
7. 每个任务连接 Telegram 并监听更新
8. 捕获来自 `777000` 的消息
9. 提取验证码并写入共享状态
10. 页面定时刷新展示最新结果

### 重连策略

每个 session worker 在连接失败时会进行指数退避重试，最多 5 次：

- 5 秒
- 10 秒
- 20 秒
- 40 秒
- 80 秒

### 安全建议

- `.session` 文件本质上是 Telegram 登录凭据，必须当作敏感数据管理
- 不要把 `sessions/` 和 `.env` 提交到 Git
- 当前界面鉴权是站内登录页加 cookie，会话仍然建议放在 HTTPS 或反向代理后面使用
- `/health` 是公开接口，请不要在其中暴露敏感信息

### 已验证内容

当前仓库代码已经完成过以下验证：

```bash
cargo build --release
cargo test --release
```

### 常见问题

#### 1. 页面打开后没有任何账号

检查：

- `SESSIONS_DIR` 是否正确
- 目录下是否真的有 `*.session`
- 容器挂载是否生效

#### 2. 账号显示 Error

常见原因：

- session 本身未授权
- Telethon session 格式不兼容
- 文件损坏
- 网络无法连接 Telegram

#### 3. 能打开页面，但一直没有验证码

检查：

- 该账号是否真的会收到 `777000` 消息
- session 是否仍然有效
- 是否有日志里的连接错误或 update 错误

#### 4. Docker 在 Linux 能跑，别的平台不行

当前镜像构建目标是 `x86_64-musl`。ARM 机器需要自行扩展多架构构建方案。

### 许可证

本项目采用 AGPL-3.0-or-later。详情见仓库中的 `LICENSE` 文件。

---

## English

### Overview

Hanagram-web is a Rust-based Telegram OTP dashboard built with Tokio, Axum, Tera, and grammers.

Its purpose is straightforward:

- scan `.session` files under `SESSIONS_DIR`
- load Telethon or grammers session files
- spawn one background task per session
- listen for incoming messages from Telegram official account `777000`
- extract login codes with regex `\b\d{5,6}\b`
- render connection status, latest OTP, and recent messages in a web panel

The UI currently supports both Simplified Chinese and English.

### Features

- Multi-account monitoring with one worker per `.session`
- Dashboard protected by an in-app login page
- Public `/health` endpoint for container or proxy health checks
- Automatic extraction of 5-digit and 6-digit Telegram login codes
- Up to 20 stored messages per account, with the newest 5 shown in the UI
- Auto-refresh every 30 seconds
- One-click copy for the latest OTP, with prompt fallback if clipboard access fails
- Built-in bilingual UI
- Multi-stage Docker build
- Bad or incompatible session files are skipped with warnings instead of crashing the whole service

### Supported session formats

The current implementation supports two `.session` families:

1. Telethon SQLite sessions
2. grammers native SQLite sessions

Loading flow:

1. Probe the file as a Telethon SQLite session first
2. If the `sessions` table can be read, convert it into an in-memory grammers-compatible session
3. If it is not a Telethon session, fall back to grammers native SQLite loading
4. Any failure only produces a warning and the file is skipped

### Telethon conversion limitations

Telethon conversion depends on the current internal expectations of `grammers-session`. The implementation currently expects an `auth_key` length compatible with the current grammers session representation.

This means:

- some older or custom Telethon session files may fail to convert
- incompatible files are skipped with warnings
- if you want the most predictable behavior, grammers native sessions are preferred

### Dashboard behavior

The dashboard shows:

- total account count
- connected account count
- last refresh time
- phone number per account
- connection status per account
- latest OTP per account
- recent 5 relevant messages

States:

- `Connecting`
- `Connected`
- `Error`

OTP messages are only taken from Telegram official account `777000`.

### Language selection

Language selection order:

1. query parameter `?lang=zh-CN` or `?lang=en`
2. `Accept-Language` request header
3. fallback to Chinese

Examples:

```text
http://127.0.0.1:8080/?lang=zh-CN
http://127.0.0.1:8080/?lang=en
```

### Routes

- `GET /`
  - main dashboard
  - requires login first
- `GET /health`
  - returns `{"status":"ok","sessions":N}`
  - intentionally public

### Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `AUTH_USER` | Yes | none | Dashboard login username |
| `AUTH_PASS` | Yes | none | Dashboard login password |
| `API_ID` | Yes | none | Telegram API ID |
| `API_HASH` | Yes | none | Telegram API hash |
| `HANAGRAM_IMAGE` | No | `hanagram-web:latest` | Image tag used by Docker Compose |
| `SESSIONS_DIR` | No | `./sessions` | Directory scanned for `*.session` files |
| `BIND_ADDR` | No | `0.0.0.0:8080` | Bind address for the web server |
| `RUST_LOG` | No | `info` | Rust logging level |

Use `.env.example` as the starting point.

### Quick start

#### Option 1: Docker Compose

This is the recommended deployment method, especially on Linux `x86_64/amd64`.

The default `docker-compose.yml` does not build on the server. It only starts an already available image, which avoids downloading large Rust build dependencies and wasting extra disk space on the deployment host.

The repository already includes the GitHub Actions workflow `.github/workflows/docker-image.yml`. Once you push to the default branch on GitHub, the workflow can automatically build and publish an image to GHCR.

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Edit `.env` and fill in at least:

```dotenv
AUTH_USER=admin
AUTH_PASS=change-me
API_ID=123456
API_HASH=0123456789abcdef0123456789abcdef
HANAGRAM_IMAGE=ghcr.io/<your-user-or-org>/<your-repo>:latest
SESSIONS_DIR=./sessions
BIND_ADDR=0.0.0.0:8080
RUST_LOG=info
```

3. Create the session directory and place your `.session` files inside:

```bash
mkdir -p sessions
```

4. Push the repository to the default branch on GitHub and wait for the image to be published to GHCR

5. Pull and start on the server:

```bash
docker compose pull
docker compose up -d
```

6. Open:

```text
http://<your-host>:8080/
```

If you do not want to use GitHub Actions yet, you can still use the manual build path:

```bash
docker compose -f docker-compose.build.yml build
```

Then you can either:

1. run it locally
2. export it with `docker save` and import it on the server with `docker load`

#### Option 2: Run locally

You need a working Rust toolchain on the host.

1. Prepare runtime files:

```bash
cp .env.example .env
mkdir -p sessions
```

2. Put your `.session` files into the directory

3. Run:

```bash
cargo run --release
```

4. Visit:

```text
http://127.0.0.1:8080/
```

### Docker notes

The Dockerfile uses a multi-stage build:

- build stage: `ghcr.io/rust-cross/rust-musl-cross:x86_64-musl`
- runtime stage: `alpine:3.21`

File roles:

- `docker-compose.yml`
  - runtime compose
  - uses an existing image by default
  - intended for servers
- `docker-compose.build.yml`
  - build compose
  - performs the actual image build
  - intended for developer machines or CI
- `.github/workflows/docker-image.yml`
  - GitHub Actions workflow that builds and publishes the image to GHCR
  - intended for routine releases
- `.dockerignore`
  - keeps `.git`, `target/`, `sessions/`, `.env`, and other local files out of the Docker build context

Default container environment:

- `BIND_ADDR=0.0.0.0:8080`
- `SESSIONS_DIR=./sessions`
- `RUST_LOG=info`

Health check:

```bash
wget -qO- http://localhost:8080/health
```

### Linux compatibility

The bundled container setup is aimed at:

- Linux
- `x86_64 / amd64`

If you are deploying on ARM, such as:

- ARM cloud servers
- native ARM Linux container environments
- Raspberry Pi

you will need to adapt the build for multi-arch support. That is not built into the repository yet.

### Project structure

```text
hanagram-web/
├── .dockerignore
├── .github/
│   └── workflows/
│       └── docker-image.yml
├── .env.example
├── .gitignore
├── Cargo.toml
├── Dockerfile
├── docker-compose.build.yml
├── docker-compose.yml
├── README.md
├── src/
│   ├── i18n/
│   │   ├── en.rs
│   │   ├── mod.rs
│   │   └── zh_cn.rs
│   ├── main.rs
│   ├── session_handler.rs
│   └── state.rs
├── templates/
│   └── index.html
└── sessions/
```

### Runtime flow

At startup the service roughly does the following:

1. load `.env`
2. initialize logging
3. initialize shared state
4. scan `SESSIONS_DIR/*.session`
5. spawn one Tokio task per session
6. start the Axum web server
7. connect each session worker to Telegram
8. watch updates from `777000`
9. extract OTP codes and update shared state
10. render the latest state in the UI

### Retry strategy

Each session worker uses exponential backoff on failure, up to 5 retries:

- 5 seconds
- 10 seconds
- 20 seconds
- 40 seconds
- 80 seconds

### Security notes

- `.session` files are effectively Telegram login credentials and should be treated as secrets
- do not commit `sessions/` or `.env`
- the UI uses an in-app login page with cookies, so HTTPS or a reverse proxy is still strongly recommended
- `/health` is public by design and should not expose sensitive data

### Verified commands

The current repository has already been verified with:

```bash
cargo build --release
cargo test --release
```

### Troubleshooting

#### 1. The dashboard shows no accounts

Check:

- `SESSIONS_DIR` is correct
- the directory actually contains `*.session`
- your container volume mount is working

#### 2. An account shows Error

Common causes:

- the session is no longer authorized
- the Telethon session format is incompatible
- the file is corrupted
- the host cannot reach Telegram

#### 3. The page loads but no OTP ever appears

Check:

- the account really receives messages from `777000`
- the session is still valid
- logs for connection or update errors

#### 4. Docker works on Linux but not on another platform

The current image target is `x86_64-musl`. ARM hosts require additional multi-arch build work.

### License

This project is licensed under AGPL-3.0-or-later. See `LICENSE` for details.
