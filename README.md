<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Hanagram-web contributors -->
# Hanagram-web

**A self-hosted, multi-user account security workspace for anyone who manages Telegram sessions and Steam Guard authenticators.**

Keep Telegram sessions online to catch login codes, and manage Steam Guard authenticators (codes, trade confirmations, login approvals) from one browser tab. Each user's data is encrypted at rest with their own key. Built in Rust (Axum + Tera), ships as a single binary in a Docker image, UI in English and Chinese.

English | [简体中文](README.zh-CN.md)

## Who is it for

Two-factor codes and signed-in sessions tend to end up scattered across phones, desktop apps and exported files. Hanagram-web puts them in one encrypted place that you host yourself. It is built for:

- **Self-hosters** who want their 2FA secrets and sessions on hardware they control.
- **People and community admins with several Telegram accounts** who need every login code in one place.
- **Steam players and traders** who want Guard codes and trade confirmations in a browser, not tied to a single phone.
- **Admins of a family, club or small team** who run one instance and give everyone a separate, isolated account.

## Why Hanagram-web

Compared with keeping an authenticator on one phone, or handing your secrets to a hosted service:

- **Self-hosted**: secrets stay on your own server. Losing a phone doesn't lock you out.
- **Encrypted at rest**: every user's sessions and authenticators are encrypted with a key of their own.
- **Multi-user with isolation**: one instance serves many people. Users cannot see each other's data.
- **Strong sign-in**: passkeys (WebAuthn), TOTP and recovery codes.
- **Easy to run**: one Docker container with no external database. Everything lives in a single data directory.

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
- **Zero Trust mode**: immediately rejects pending confirmations and sign-in requests and signs out other devices, then keeps rejecting new ones every few seconds while the Steam page stays open in a browser

**Accounts & security**
- Per-user encryption (zstd + AES-256-GCM); passwords hashed with Argon2id
- Passkeys, TOTP and recovery codes; progressive lockout; idle auto-logout
- Admin console: users (create, ban, unlock, reset, revoke sessions), sign-up and password policy, audit log

## Quick start

One command with Docker:

```bash
docker run -d --name hanagram-web -p 8080:8080 -v hanagram-data:/app/sessions ghcr.io/xmzo/hanagram-web:latest
```

Or with Docker Compose:

```bash
git clone https://github.com/XMZO/Hanagram-web.git && cd Hanagram-web
cp .env.example .env
docker compose up -d
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

## Security model

- Every user gets a random 256-bit master key. Their Telegram sessions and Steam accounts are compressed with zstd and encrypted with AES-256-GCM under that key before they touch the disk.
- The master key is stored only in wrapped form, under a key derived from the user's password with Argon2id. A signed-in browser session keeps its own copy, wrapped by the session token; the server stores only a hash of that token.
- Passkey sign-in unlocks the master key with a server key in `.hanagram/passkey-login-key.json`. Treat the whole `SESSIONS_DIR` as sensitive and back it up as a unit.
- Users are isolated by separate keys and directories. Sign-ins and important actions go to an audit log.

## Good to know

- **After a restart**, a user's sessions come back online the next time they open the app. If their browser session has expired, they sign in again first.
- **Forgot password:** users have no self-service reset; the admin resets them, which also wipes that user's data. To reset the admin, run `docker compose exec hanagram-web /app/reset_admin` (or `cargo run --release --bin reset_admin`) against the same `SESSIONS_DIR`. Other users and the Telegram API settings stay as they are.
- **Upgrading:** if the app reports an incompatible database, delete `sessions/.hanagram/app.db` and restart.
- **Health check:** `GET /health`. The Docker image has a healthcheck built in.

<details>
<summary>Data layout</summary>

```
sessions/
├── .hanagram/
│   ├── app.db                    # metadata
│   └── passkey-login-key.json    # server key for passkey sign-in
└── users/<user-id>/
    ├── *.session                 # encrypted Telegram sessions
    └── steam/managed/            # encrypted Steam accounts
```
</details>

<details>
<summary>Building & releasing</summary>

- Local image: `docker compose -f docker-compose.build.yml up -d --build`
- The image is `scratch` plus one static binary; `/app/reset_admin` is a symlink to it. Templates are compiled in.
- Published images cover `linux/amd64` and `linux/arm64`. CI builds each one natively on a GitHub runner of that architecture.
- Images are only built for version tags. Bump `version` in `Cargo.toml`, commit, then `git tag vX.Y.Z && git push origin vX.Y.Z`. This publishes `X.Y.Z`, `X.Y` and `latest`. Pre-release tags never move `latest`.
</details>

## Contributing

Bug reports, ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and guidelines.

## License

Hanagram-web is free software under the [GNU AGPL v3.0 or later](LICENSE). You may use, modify and self-host it. If you offer a modified version to others over a network, you must also make its source available to them.

Hanagram-web is an independent project and is not affiliated with Telegram or Valve.
