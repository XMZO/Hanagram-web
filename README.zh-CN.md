<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Hanagram-web contributors -->
# Hanagram-web

**自托管的多用户 Web 工作台，统一管理 Telegram 登录验证码与 Steam 令牌。**

让 Telegram 会话保持在线以接收 OTP 验证码，同时在一个浏览器标签页里管理 Steam Guard（动态码、交易确认、登录审批）。每个用户的数据都用自己的密钥加密落盘。Rust（Axum + Tera）编写，单二进制部署，界面中英双语。

[English](README.md) | 简体中文

## 功能

**Telegram**
- 通过 Telethon string session、`.session` 文件、手机号验证码或扫码登录导入会话
- 实时查看收到的登录验证码，一键复制
- 备注、重命名、删除，导出为 `.session` 或 string session
- 每个用户独立的 Bot 提醒

**Steam Guard**
- 自动刷新的二步验证码
- 从 maFile、手动录入、Steam 账号登录或 WinAuth URI 导入；导出为 maFile 或二维码
- 绑定新令牌或从其他设备迁移；用撤销码解绑
- 逐条或一键全部确认 / 拒绝交易
- 审批或拒绝扫码登录请求；查看并下线已登录设备
- 恢复码、手机绑定状态、交易撤回、时钟偏差检测、每账号独立 HTTP/SOCKS5 代理
- **Zero Trust 模式**：自动拒绝所有确认、登录请求和新设备

**账号与安全**
- 按用户加密（zstd + AES-GCM）；密码使用 Argon2id 哈希
- Passkey、TOTP 和恢复码；登录失败递增锁定；空闲自动登出
- 管理员后台：用户管理（创建、封禁、解锁、重置、强制下线）、注册与密码策略、审计日志

## 快速开始

```bash
cp .env.example .env
mkdir -p sessions
docker compose pull && docker compose up -d
```

打开 `http://<host>:8080/`，然后：

1. 注册账号。第一个注册的账号自动成为管理员。
2. 在 **管理后台**填写 Telegram API ID / Hash（在 [my.telegram.org](https://my.telegram.org) 申请）。
3. 添加 Telegram 会话或 Steam 账号。

未配置 Telegram API 时，手机号 / 扫码登录和实时验证码监听不可用；Steam 功能不需要它。

从源码运行：`cargo run --release`（需要 Rust 1.85+）。

## 配置

除下列环境变量外，其余设置都在网页里完成。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SESSIONS_DIR` | `./sessions` | 数据目录（请放在持久化卷上） |
| `BIND_ADDR` | `0.0.0.0:8080` | 监听地址 |
| `RUST_LOG` | `info` | 日志级别 |
| `HANAGRAM_IMAGE` | `ghcr.io/xmzo/hanagram-web:latest` | Compose 使用的镜像，可固定版本如 `:0.2.3` |

Passkey 只能在 HTTPS（或 `localhost`）下使用，建议在前面加一层 TLS 反向代理。

## 须知

- **服务重启后，每个用户需要重新登录**，其会话才会重新上线。用户的加密密钥只有登录后才会解锁。
- **忘记密码：** 普通用户没有自助找回，由管理员重置，重置会清空该用户的数据。重置管理员请运行 `docker compose exec hanagram-web /app/reset_admin`（源码运行用 `cargo run --release --bin reset_admin`），需指向同一个 `SESSIONS_DIR`。其他用户和 Telegram API 配置不受影响。
- **升级：** 如果提示数据库不兼容，删除 `sessions/.hanagram/app.db` 后重启。
- **健康检查：** `GET /health`，Docker 镜像已内置 healthcheck。

<details>
<summary>数据目录</summary>

```
sessions/
├── .hanagram/app.db          # 元数据
└── users/<user-id>/
    ├── *.session             # 加密的 Telegram 会话
    └── steam/managed/        # 加密的 Steam 账号
```
</details>

<details>
<summary>构建与发布</summary>

- 本地构建镜像：`docker compose -f docker-compose.build.yml up -d --build`
- 镜像基于 `scratch`，只含一个静态二进制；`/app/reset_admin` 是指向它的符号链接。模板在编译时嵌入。
- 只有推送版本标签时才构建镜像。修改 `Cargo.toml` 的 `version` 并提交，然后 `git tag vX.Y.Z && git push origin vX.Y.Z`，会发布 `X.Y.Z`、`X.Y` 和 `latest`。预发布标签不会覆盖 `latest`。
</details>

## 许可证

[AGPL-3.0-or-later](LICENSE)
