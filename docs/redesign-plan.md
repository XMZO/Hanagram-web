# Hanagram Web Security Redesign Plan

This document captures the target architecture for the multi-user security redesign.

## Goals

- Keep the dashboard focused on Telegram sessions and OTP visibility.
- Move security, reminder, and administration features behind dedicated settings views.
- Replace the current single-user environment-variable login model with a persistent multi-user auth system.
- Encrypt user-owned data at rest and make password resets destructive for encrypted data.
- Keep the deployment lightweight enough for small Docker hosts.

## UI Information Architecture

### Dashboard

- `/`
- Primary content: session cards, session status, latest OTP, latest messages, session note.
- Secondary content: `Settings` button, `Add Session` button, language switch, logout.
- No bot reminder form on the dashboard.

### Settings

- `/settings`
- Compact cards linking to:
  - Security: password, TOTP, recovery codes, active sessions, auto logout.
  - Reminders: Telegram bot reminder settings.
  - Preferences: idle timeout, language, session lifetime hints.

### Admin

- `/admin`
- Users: list, unlock, force logout, destructive reset.
- Policies: registration mode, TOTP enforcement, password strength enforcement, Argon2 floor, audit retention.
- Audit: detailed recent events plus rollup counters.

### Enrollment and Login

- `/register`
- `/login`
- `/login/mfa`
- `/settings/security/totp/setup`

## Registration Modes

- `always_public`: anyone can self-register.
- `admin_only`: only the admin can create users.
- `admin_selectable`: admin can open or close public registration without changing the global mode.

## Data Layout

### Metadata database

- `SESSIONS_DIR/.hanagram/app.db`
- Stores users, auth sessions, recovery codes, used TOTP windows, audit logs, policy metadata, and Telegram session metadata.

### User-owned session files

- `SESSIONS_DIR/users/<username>/...`
- Long-term target: encrypted blobs at rest.
- Runtime target: decrypted temporary copies under `SESSIONS_DIR/.hanagram/runtime/`.

## Security Model

### Passwords

- Argon2id with versioned policy metadata.
- Minimum policy floor starts at 64 MiB memory, 3 iterations, 2 lanes.
- When the floor increases, users are rehashed after the next successful password login.

### TOTP

- Enforced by policy mode.
- Fresh registrations must complete TOTP before reaching the dashboard.
- If a policy requires TOTP and the user does not have it yet, successful password login leads into forced TOTP setup instead of the dashboard.
- Used TOTP windows are tracked server-side to prevent replay within the 30-second step.

### Recovery Codes

- Five codes issued at a time.
- Only hashes are stored.
- Each code is single-use and marked consumed immediately.
- When the set is exhausted, the user must generate a new set.

### Data Encryption

- Each user gets a random master key.
- User private data is encrypted with AES-256-GCM using that master key.
- The master key is wrapped by a KEK derived from the user password via Argon2id.
- Admin reset destroys password material, TOTP material, recovery codes, and encrypted user data.

### Session Tokens

- Random opaque session token stored in a `HttpOnly + Secure + SameSite=Strict` cookie.
- Server stores only the token hash, along with issue time, expiry time, last-seen time, IP, and user agent.
- Users can view and revoke their active sessions.
- Admin can revoke any user session.

## Audit Retention

- Keep the latest `N` detailed events.
- Older events are rolled into per-action counters.
- Always log at least:
  - login success
  - login failure
  - TOTP enrollment or rotation
  - password change
  - user unlock
  - destructive reset
  - new IP login

## Migration Strategy

- There is no existing business database to preserve yet.
- Existing `.session` files need ownership assignment.
- Safe default migration rule: assign current root-level sessions to the admin account until they are re-imported or explicitly moved.

## Runtime Optimization Targets

- Add release profile tuning: LTO, strip, panic abort, fewer codegen units.
- Move template loading toward compile-time embedding where practical.
- Replace shell-based container healthchecks with an app-native healthcheck command.
- Revisit dependency features after the auth rewrite lands.
