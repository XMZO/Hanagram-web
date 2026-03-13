<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Hanagram-web contributors -->
# Hanagram-web

Multi-user Telegram OTP dashboard built with Rust, Axum, Tera, and grammers.

`Hanagram-web` keeps the main page focused on Telegram sessions and OTP visibility. Account security, reminder delivery, active browser sessions, and admin policy controls live behind dedicated settings pages.

## Current Model

- The first registered account becomes the only admin.
- Additional users can be created by the admin, or self-register if the configured registration mode allows it.
- Passwords are stored with Argon2id.
- TOTP, recovery codes, lockout, active session management, and audit logs are built in.
- User-owned Telegram session data is encrypted at rest.
- Persistent metadata lives in `SESSIONS_DIR/.hanagram/app.db`.
- User session storage lives under `SESSIONS_DIR/users/`.

## Persistent Data Layout

Everything persistent is stored under `SESSIONS_DIR`:

```text
sessions/
├── .hanagram/
│   ├── app.db
│   └── .hanagram-bot.json
└── users/
    └── <user-id-or-username-managed-layout>/
```

This is why Docker Compose still mounts the entire `./sessions` directory into `/app/sessions`.

## Important Compatibility Note

Old metadata databases from the pre-redesign layout are intentionally unsupported.

If you are upgrading from an old build and the app reports an incompatible metadata database, delete:

```text
sessions/.hanagram/app.db
```

Then start again and re-import the Telegram sessions you still need.

## Environment Variables

Required:

| Variable | Description |
| --- | --- |
| `API_ID` | Telegram API ID |
| `API_HASH` | Telegram API hash |

Optional:

| Variable | Default | Description |
| --- | --- | --- |
| `SESSIONS_DIR` | `./sessions` | Root directory for encrypted user data and metadata |
| `BIND_ADDR` | `0.0.0.0:8080` | HTTP bind address |
| `RUST_LOG` | `info` | Rust log filter |
| `BOT_NOTIFY_ENABLED` | `0` | Enable Telegram bot reminders from env defaults |
| `BOT_NOTIFY_TOKEN` | empty | Telegram bot token |
| `BOT_NOTIFY_CHAT_ID` | empty | Telegram destination chat ID |
| `BOT_NOTIFY_TEMPLATE` | empty | Reminder message template |
| `HANAGRAM_IMAGE` | `ghcr.io/xmzo/hanagram-web:latest` | Image tag used by Compose |

`BOT_NOTIFY_*` values are only bootstrap defaults. Runtime edits are persisted to `SESSIONS_DIR/.hanagram/.hanagram-bot.json`.

## Quick Start

### Docker Compose

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Edit `.env` and set at least:

```dotenv
API_ID=123456
API_HASH=0123456789abcdef0123456789abcdef
SESSIONS_DIR=./sessions
BIND_ADDR=0.0.0.0:8080
RUST_LOG=info
HANAGRAM_IMAGE=ghcr.io/<your-user-or-org>/<your-repo>:latest
```

3. Create the persistent data directory:

```bash
mkdir -p sessions
```

4. Start the service:

```bash
docker compose pull
docker compose up -d
```

5. Open:

```text
http://<your-host>:8080/
```

6. On a fresh install, register the first account. That account becomes the only admin.

Build locally instead of pulling a prebuilt image:

```bash
docker compose -f docker-compose.build.yml build
docker compose -f docker-compose.build.yml up -d
```

### Local Run

```bash
cp .env.example .env
mkdir -p sessions
cargo run --release
```

Then open:

```text
http://127.0.0.1:8080/
```

## Admin Reset

The image contains `/app/reset_admin`.

With Docker Compose:

```bash
docker compose exec hanagram-web ./reset_admin
```

Direct binary deployment:

```bash
./reset_admin
```

This clears only the admin account credentials and encrypted admin-owned data. Other users remain untouched. The next registration using the same admin username reclaims the admin account.

## What the UI Is Organized Around

- `/`
  - Telegram sessions, OTP visibility, copy/export, rename, note editing
- `/settings`
  - password, TOTP, recovery codes, reminder center, idle timeout, active browser sessions
- `/admin`
  - user lifecycle, lockouts, registration mode, TOTP/password policy, Argon2 floor, audit logs

## Telegram Session Sources

Users can add Telegram sessions through:

- Telethon string session import
- `.session` file upload/import
- phone login
- QR login

## Healthcheck

The container exposes:

```text
GET /health
```

It returns:

```json
{"status":"ok","sessions":N}
```

The Docker image uses the built-in healthcheck command instead of a shell probe.

## Repository Notes

- `docs/redesign-plan.md` was removed because it had become an outdated scratchpad rather than maintained product documentation.
- `templates/` are embedded into the binary at build time, so the runtime image does not need template files copied into it.
- Do not commit `sessions/` or `.env`.
