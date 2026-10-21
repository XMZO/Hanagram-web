<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Hanagram-web contributors -->
# Hanagram-web

**A self-hosted, multi-user web workbench for Telegram login codes and Steam Guard.**

Keep Telegram sessions online to catch OTP codes, and manage Steam Guard authenticators (codes, trade confirmations, login approvals) from one browser tab. Each user's data is encrypted at rest with their own key. Built in Rust (Axum + Tera), ships as a single binary, UI in English and Chinese.

English | [简体中文](README.zh-CN.md)

## Features

**Telegram**
- Import sessions from a Telethon string, a `.session` file, a phone code login, or a QR login
- Watch incoming login codes live and copy them in one click
- Notes, rename, delete, export as `.session` or string session
- Per-user bot reminders

**Steam Guard**
- Auto-refreshing 2FA codes
- Import from maFile, manual entry, Steam login, or WinAuth URI; export as maFile or QR
- Link a new authenticator or move an existing one; remove it with the revocation code
- Accept or deny trade confirmations, one by one or all at once
- Approve or deny QR sign-in requests; review and sign out devices
- Recovery codes, phone status, trade restore, clock-drift check, per-account HTTP/SOCKS5 proxy
- **Zero Trust mode**: automatically rejects every confirmation, sign-in request and new device

**Accounts & security**
- Per-user encryption (zstd + AES-GCM); passwords hashed with Argon2id
- Passkeys, TOTP and recovery codes; progressive lockout; idle auto-logout
- Admin console: users (create, ban, unlock, reset, revoke sessions), sign-up and password policy, audit log

## Quick start

```bash
cp .env.example .env
mkdir -p sessions
docker compose pull && docker compose up -d
```

Open `http://<host>:8080/`, then:

1. Register. The first account becomes the admin.
2. In **Admin**, save your Telegram API ID / Hash (from [my.telegram.org](https://my.telegram.org)).
3. Add Telegram sessions or Steam accounts.

Without the Telegram API credentials, phone/QR login and live code watching are off. Steam does not need them.

To run from source instead: `cargo run --release` (Rust 1.85+).

## Configuration

Everything except the following is set in the web UI.

| Variable | Default | Purpose |
|---|---|---|
| `SESSIONS_DIR` | `./sessions` | Data directory (keep it on a persistent volume) |
| `BIND_ADDR` | `0.0.0.0:8080` | Listen address |
| `RUST_LOG` | `info` | Log level |
| `HANAGRAM_IMAGE` | `ghcr.io/xmzo/hanagram-web:latest` | Image used by Compose; pin a version such as `:0.2.3` |

Passkeys only work over HTTPS (or on `localhost`), so put the app behind a TLS reverse proxy.

## Good to know

- **After a restart, each user must sign in again** before their sessions come back online. Each user's encryption key is only unlocked by signing in.
- **Forgot password:** users have no self-service reset; the admin resets them, which also wipes that user's data. To reset the admin, run `docker compose exec hanagram-web /app/reset_admin` (or `cargo run --release --bin reset_admin`) against the same `SESSIONS_DIR`. Other users and the Telegram API settings stay as they are.
- **Upgrading:** if the app reports an incompatible database, delete `sessions/.hanagram/app.db` and restart.
- **Health check:** `GET /health`. The Docker image has a healthcheck built in.

<details>
<summary>Data layout</summary>

```
sessions/
├── .hanagram/app.db          # metadata
└── users/<user-id>/
    ├── *.session             # encrypted Telegram sessions
    └── steam/managed/        # encrypted Steam accounts
```
</details>

<details>
<summary>Building & releasing</summary>

- Local image: `docker compose -f docker-compose.build.yml up -d --build`
- The image is `scratch` plus one static binary; `/app/reset_admin` is a symlink to it. Templates are compiled in.
- Images are only built for version tags. Bump `version` in `Cargo.toml`, commit, then `git tag vX.Y.Z && git push origin vX.Y.Z`. This publishes `X.Y.Z`, `X.Y` and `latest`. Pre-release tags never move `latest`.
</details>

## License

[AGPL-3.0-or-later](LICENSE)

