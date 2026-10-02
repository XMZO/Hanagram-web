// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

let steamPanels = null;
let steamClockOffset = 0;
let steamCodePeriod = 30;
let steamSnapshotInFlight = false;
let steamSnapshotLastAt = 0;
let steamApprovalsInFlight = false;
let steamApprovalsLoadedAt = 0;
let steamConfirmationsInFlight = false;
let steamConfirmationsLoadedAt = 0;
let hoveredSteamApprovalDropzone = null;
let focusedSteamApprovalDropzone = null;

const esc = (value) => UI.escapeHtml(value);
const serverNow = () => Date.now() / 1000 + steamClockOffset;
const initialOf = (name) => (Array.from(String(name || "?").trim())[0] || "?").toUpperCase();

async function readJsonResponse(resp, fallbackMessage) {
    const contentType = resp.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
        throw new Error(`${fallbackMessage || "Server returned non-JSON response"} (HTTP ${resp.status || 0})`);
    }
    return resp.json();
}

async function maybeReadJsonResponse(resp, fallbackMessage) {
    try { return await readJsonResponse(resp, fallbackMessage); } catch (_) { return null; }
}

async function jsonPost(url, body) {
    const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify(body)
    });
    return readJsonResponse(resp, "Server returned non-JSON response");
}

function showStatus(element, message, tone) {
    const kind = typeof tone === "string" ? tone : (tone ? "error" : "success");
    UI.status(element, kind, message);
}

function setRoleText(role, value) {
    document.querySelectorAll(`[data-role='${role}']`).forEach((element) => {
        element.textContent = value;
        if (element.hasAttribute("data-hide-zero")) { element.hidden = !Number(value); }
    });
}

function emptyBlock(iconName, message, tone) {
    return `<div class="empty empty--compact${tone === "success" ? " empty--success" : ""}"><span class="empty__icon">${UI.icon(iconName)}</span><p class="empty__desc">${esc(message)}</p></div>`;
}

/* ---------------- Codes ---------------- */
function sourceLabel(account) {
    if (account.is_manual_entry) { return I18N.sourceManual; }
    if (account.is_uploaded_mafile) { return I18N.sourceUpload; }
    return I18N.sourceLegacy;
}

function renderSteamCodeCard(account) {
    const sub = account.steam_username ? esc(account.steam_username) : `<span class="mono">${esc(account.steam_id || "-")}</span>`;
    return `<article class="code-tile" data-steam-account data-account-id="${esc(account.id)}" data-code-expires-at="${esc(account.code_expires_at_unix || 0)}" data-filter-text="${esc(`${account.account_name} ${account.steam_username || ""} ${account.steam_id || ""}`)}">
        <div class="code-tile__head">
            <span class="avatar avatar--steam">${esc(initialOf(account.account_name))}</span>
            <div class="code-tile__who"><p class="code-tile__name">${esc(account.account_name)}</p><p class="code-tile__sub">${sub}</p></div>
            <div class="code-tile__badges">
                ${account.zero_trust_active ? `<span class="badge badge--solid-danger">${esc(I18N.ztAccountBadge)}</span>` : ""}
                <span class="badge badge--steam">${esc(sourceLabel(account))}</span>
            </div>
        </div>
        <button type="button" class="otp otp--steam" data-code="${esc(account.current_code || "")}" onclick="copySteamCode(this)" aria-label="${esc(I18N.copy)} ${esc(account.account_name)}">
            <span class="otp__top"><span class="otp__label" data-role="steam-code-label">${esc(I18N.currentCodeLabel)}</span><span class="otp__hint">${UI.icon("copy")}${esc(I18N.copy)}</span></span>
            <span class="otp__row"><span class="otp__code" data-role="steam-code-value">${esc(account.current_code || "")}</span><span class="otp__time" data-role="steam-refresh-label"></span></span>
            <span class="otp__bar"><i></i></span>
        </button>
    </article>`;
}

function renderEmptySteamCodes() {
    return `<div class="empty span-all">
        <span class="empty__icon">${UI.icon("key")}</span>
        <p class="empty__title">${esc(I18N.emptyTitle)}</p>
        <p class="empty__desc">${esc(I18N.emptyDescription)}</p>
        <div class="empty__actions"><a class="btn btn--primary" href="#import" data-panel-link="import">${UI.icon("download")}${esc(I18N.importLabel)}</a></div>
    </div>`;
}

function syncCodeBar(card) {
    const bar = card.querySelector(".otp__bar > i");
    const expiresAt = Number(card.dataset.codeExpiresAt || 0);
    if (!bar || !expiresAt) { return; }
    const remaining = Math.max(0, Math.min(steamCodePeriod, expiresAt - serverNow()));
    bar.style.setProperty("--period", String(steamCodePeriod));
    bar.style.setProperty("--elapsed", (steamCodePeriod - remaining).toFixed(2));
    bar.style.setProperty("--ratio", (remaining / steamCodePeriod).toFixed(3));
    bar.style.animation = "none";
    void bar.offsetWidth;
    bar.style.animation = "";
}

function updateSteamCodeCard(card, account) {
    const button = card.querySelector(".otp");
    const value = card.querySelector("[data-role='steam-code-value']");
    const nextCode = account.current_code || "";
    const changed = button && button.dataset.code !== nextCode;
    const previousExpiry = Number(card.dataset.codeExpiresAt || 0);
    card.dataset.codeExpiresAt = account.code_expires_at_unix || 0;
    if (button) { button.dataset.code = nextCode; }
    if (value) { value.textContent = nextCode; }
    if (changed && button) {
        button.classList.remove("is-fresh", "is-low");
        void button.offsetWidth;
        button.classList.add("is-fresh");
    }
    if (changed || previousExpiry !== Number(card.dataset.codeExpiresAt)) { syncCodeBar(card); }
}

async function copySteamCode(button) {
    if (!button || button.disabled) { return; }
    const code = button.dataset.code || "";
    if (!code) { return; }
    const copied = await UI.copy(code);
    const label = button.querySelector("[data-role='steam-code-label']");
    button.classList.toggle("is-copied", copied);
    if (label) { label.textContent = copied ? I18N.copied : I18N.copyFallback; }
    UI.toast(copied ? `${I18N.copied} · ${code}` : I18N.copyFallback, copied ? "success" : "error");
    window.clearTimeout(button.__copyTimer);
    button.__copyTimer = window.setTimeout(() => {
        button.classList.remove("is-copied");
        if (label) { label.textContent = I18N.currentCodeLabel; }
    }, 1200);
}

function refreshSteamCountdowns() {
    const now = serverNow();
    let shouldSync = false;
    document.querySelectorAll("[data-steam-account]").forEach((card) => {
        const expiresAt = Number(card.dataset.codeExpiresAt || 0);
        const label = card.querySelector("[data-role='steam-refresh-label']");
        const button = card.querySelector(".otp");
        if (!label) { return; }
        if (!Number.isFinite(expiresAt) || expiresAt <= 0) {
            label.textContent = "";
            return;
        }
        const remaining = expiresAt - now;
        const bar = card.querySelector(".otp__bar > i");
        if (bar) { bar.style.setProperty("--ratio", Math.max(0, Math.min(1, remaining / steamCodePeriod)).toFixed(3)); }
        if (remaining <= 0) {
            label.textContent = I18N.refreshIn.replace("{countdown}", "00:00");
            if (button) { button.classList.add("is-low"); }
            shouldSync = true;
            return;
        }
        label.textContent = I18N.refreshIn.replace("{countdown}", UI.formatCountdown(remaining));
        if (button) { button.classList.toggle("is-low", remaining <= 5); }
    });
    if (shouldSync) { syncSteamSnapshot(); }
}

function applySteamSnapshot(snapshot) {
    steamCodePeriod = Number(snapshot.code_period_seconds) || 30;
    if (snapshot.generated_at_unix) { steamClockOffset = Number(snapshot.generated_at_unix) - Date.now() / 1000; }
    setRoleText("steam-total-count", snapshot.total_count);
    setRoleText("steam-ready-count", snapshot.ready_count);
    setRoleText("steam-managed-count", snapshot.managed_count);
    setRoleText("steam-encrypted-count", snapshot.encrypted_count);
    setRoleText("steam-confirmation-count", snapshot.confirmation_ready_count);
    setRoleText("steam-issue-count", snapshot.issue_count);
    setRoleText("steam-updated-at", snapshot.generated_at);

    const codesRoot = document.querySelector("[data-role='steam-codes-list']");
    if (codesRoot) {
        const ready = snapshot.accounts.filter((account) => account.current_code);
        const existing = new Map(Array.from(codesRoot.querySelectorAll("[data-steam-account]")).map((card) => [card.dataset.accountId, card]));
        const sameSet = ready.length === existing.size && ready.every((account) => existing.has(account.id));
        if (sameSet && ready.length > 0) {
            ready.forEach((account) => updateSteamCodeCard(existing.get(account.id), account));
        } else {
            codesRoot.innerHTML = ready.length > 0 ? ready.map(renderSteamCodeCard).join("") : renderEmptySteamCodes();
            codesRoot.querySelectorAll("[data-steam-account]").forEach(syncCodeBar);
        }
        UI.refilter(codesRoot.closest("[data-filter-scope]"));
    }

    const issuesRoot = document.querySelector("[data-role='steam-issues-list']");
    if (issuesRoot) {
        issuesRoot.innerHTML = snapshot.issues.length > 0
            ? snapshot.issues.map((issue) => `<div class="tile" style="border-color:var(--danger-border);background:var(--danger-soft)">
                <p class="tile__label">${esc(I18N.fileLabel)}</p>
                <p class="tile__value mono text-sm">${esc(issue.storage_file)}</p>
                <p class="tile__hint text-danger">${esc(issue.error)}</p>
            </div>`).join("")
            : `<div class="span-all">${emptyBlock("check-circle", I18N.issueEmpty, "success")}</div>`;
    }
    refreshSteamCountdowns();
}

async function syncSteamSnapshot() {
    if (steamSnapshotInFlight || Date.now() - steamSnapshotLastAt < 1500) { return; }
    steamSnapshotInFlight = true;
    steamSnapshotLastAt = Date.now();
    try {
        const response = await fetch(SNAPSHOT_API, { headers: { "Accept": "application/json" }, cache: "no-store" });
        if (!response.ok) { return; }
        applySteamSnapshot(await readJsonResponse(response));
    } catch (_) {
        // transient
    } finally {
        steamSnapshotInFlight = false;
    }
}

/* ---------------- Confirmations ---------------- */
function setConfirmationStatus(kind, message) {
    const root = document.querySelector("[data-role='steam-confirmations-status']");
    UI.status(root, kind || "loading", message);
    window.clearTimeout(setConfirmationStatus.timer);
    if (kind === "success") {
        setConfirmationStatus.timer = window.setTimeout(() => UI.status(root, null, ""), 4500);
    }
}

function idleSummary(accounts, message) {
    const names = accounts.map((account) => account.account_name).join("、");
    return `<div class="callout cluster cluster--nowrap" style="align-items:flex-start">${UI.icon("check-circle", "text-success")}<span class="clamp-2"><strong>${esc(names)}</strong> · ${esc(message)}</span></div>`;
}

function accountHead(account, count, extra) {
    return `<header class="card__head">
        <div class="card__heading">
            <span class="avatar avatar--steam avatar--sm">${esc(initialOf(account.account_name))}</span>
            <div class="grow"><p class="card__title truncate">${esc(account.account_name)}</p><p class="card__desc mono">${account.steam_username ? `${esc(account.steam_username)} · ` : ""}${esc(account.steam_id || "-")}</p></div>
            <span class="count ${account.error ? "count--danger" : "count--accent"}">${esc(String(count || 0))}</span>
        </div>
        ${extra || ""}
    </header>`;
}

function renderConfirmationEntry(confirmation) {
    const headline = confirmation.headline || confirmation.type_name || I18N.confirmationType;
    const visual = confirmation.icon
        ? `<img src="${esc(confirmation.icon)}" alt="" loading="lazy" class="avatar" style="object-fit:cover;padding:0">`
        : `<span class="avatar avatar--steam">${esc((confirmation.type_name || "?").slice(0, 2))}</span>`;
    const summary = Array.isArray(confirmation.summary) && confirmation.summary.length > 0
        ? `<div class="stack stack--xs mt-1">${confirmation.summary.map((line) => `<p class="text-sm" style="color:var(--text-2)">${esc(line)}</p>`).join("")}</div>`
        : "";
    return `<article class="row row--top row--stack-sm" data-confirmation>
        ${visual}
        <div class="row__main">
            <p class="row__title"><span>${esc(headline)}</span><span class="badge">${esc(confirmation.type_name || I18N.confirmationType)}</span></p>
            ${summary}
            <p class="row__meta"><span>${esc(I18N.confirmationCreatedAt)} · <span class="mono">${esc(confirmation.created_at || "-")}</span></span><span>${esc(I18N.confirmationCreatorId)} · <span class="mono">${esc(confirmation.creator_id || "-")}</span></span></p>
        </div>
        <div class="row__aside">
            <button type="button" class="btn btn--success-soft btn--sm" data-action="${esc(confirmation.accept_action)}" data-nonce="${esc(confirmation.nonce)}" data-confirmation-action-kind="accept" onclick="submitConfirmationAction(this)">${UI.icon("check")}${esc(I18N.confirmationAccept)}</button>
            <button type="button" class="btn btn--danger-soft btn--sm" data-action="${esc(confirmation.deny_action)}" data-nonce="${esc(confirmation.nonce)}" data-confirmation-action-kind="deny" onclick="submitConfirmationAction(this)">${UI.icon("x")}${esc(I18N.confirmationDeny)}</button>
        </div>
    </article>`;
}

function renderConfirmationAccount(account) {
    const count = account.confirmation_count || (account.confirmations || []).length;
    const bulk = !account.error && count > 0
        ? `<div class="btn-row">
            <button type="button" class="btn btn--success-soft btn--xs" data-bulk-accept="${esc(account.account_id)}">${UI.icon("check")}${esc(I18N.bulkAcceptBtn)}</button>
            <button type="button" class="btn btn--danger-soft btn--xs" data-bulk-deny="${esc(account.account_id)}">${UI.icon("x")}${esc(I18N.bulkDenyBtn)}</button>
        </div>`
        : "";
    const body = account.error
        ? `<div class="card__body"><div class="inline-status inline-status--error">${UI.icon("alert")}<span><strong>${esc(I18N.confirmationsAccountError)}</strong> · ${esc(account.error)}</span></div></div>`
        : `<div class="list">${(account.confirmations || []).map(renderConfirmationEntry).join("")}</div>`;
    return `<section class="card" data-confirmation-account>${accountHead(account, count, bulk)}${body}</section>`;
}

function applyConfirmationSnapshot(snapshot) {
    setRoleText("steam-confirmations-ready-accounts", snapshot.ready_account_count ?? 0);
    setRoleText("steam-confirmations-total", snapshot.confirmation_count ?? 0);
    setRoleText("steam-confirmations-updated-at", snapshot.generated_at || "-");
    const root = document.querySelector("[data-role='steam-confirmations-list']");
    if (!root) { return; }
    if (!Array.isArray(snapshot.accounts) || snapshot.accounts.length === 0) {
        root.innerHTML = emptyBlock("swap", I18N.confirmationsUnavailable);
        return;
    }
    const active = snapshot.accounts.filter((account) => account.error || (account.confirmations || []).length > 0);
    const idle = snapshot.accounts.filter((account) => !account.error && (account.confirmations || []).length === 0);
    let html = active.length === 0 ? emptyBlock("check-circle", I18N.confirmationsEmpty, "success") : "";
    html += active.map(renderConfirmationAccount).join("");
    if (idle.length > 0 && active.length > 0) { html += idleSummary(idle, I18N.confirmationsNoneForAccount); }
    root.innerHTML = html;
}

async function syncSteamConfirmations(force, announceLoading) {
    const announce = announceLoading !== false;
    const stale = Date.now() - steamConfirmationsLoadedAt > STEAM_CONFIRMATIONS_REFRESH_INTERVAL_MS;
    if (steamConfirmationsInFlight || (!force && steamConfirmationsLoadedAt !== 0 && !stale)) { return; }
    steamConfirmationsInFlight = true;
    if (announce) { setConfirmationStatus("loading", I18N.confirmationsLoading); }
    try {
        const response = await fetch(CONFIRMATIONS_API, { headers: { "Accept": "application/json" }, cache: "no-store" });
        const payload = await maybeReadJsonResponse(response, I18N.confirmationsLoadFailed);
        if (!response.ok || !payload) {
            setConfirmationStatus("error", (payload && payload.message) || I18N.confirmationsLoadFailed);
            return;
        }
        applyConfirmationSnapshot(payload);
        steamConfirmationsLoadedAt = Date.now();
        if (announce) { setConfirmationStatus(null, ""); }
    } catch (_) {
        setConfirmationStatus("error", I18N.confirmationsLoadFailed);
    } finally {
        steamConfirmationsInFlight = false;
    }
}

async function submitConfirmationAction(button) {
    if (!button || button.disabled) { return; }
    const action = button.dataset.action || "";
    const nonce = button.dataset.nonce || "";
    const actionKind = button.dataset.confirmationActionKind || "";
    if (!action || !nonce) {
        setConfirmationStatus("error", I18N.confirmationMissingNonce);
        return;
    }
    const group = button.closest("[data-confirmation]");
    const buttons = group ? Array.from(group.querySelectorAll("button")) : [button];
    buttons.forEach((candidate) => { candidate.disabled = true; });
    UI.busy(button, true);
    try {
        const body = new URLSearchParams();
        body.set("lang", LANG);
        body.set("nonce", nonce);
        const response = await fetch(action, {
            method: "POST",
            headers: { "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" },
            body: body.toString()
        });
        const payload = await maybeReadJsonResponse(response, I18N.confirmationActionFailed);
        if (!response.ok || !payload || !payload.ok) {
            UI.toast((payload && payload.message) || I18N.confirmationActionFailed, "error");
            return;
        }
        UI.toast(payload.message || (actionKind === "accept" ? I18N.confirmationAccepted : I18N.confirmationDenied), "success");
        await syncSteamConfirmations(true, false);
    } catch (_) {
        UI.toast(I18N.confirmationActionFailed, "error");
    } finally {
        UI.busy(button, false);
        buttons.forEach((candidate) => { candidate.disabled = false; });
    }
}

/* ---------------- Approvals ---------------- */
function setApprovalStatus(kind, message) {
    const root = document.querySelector("[data-role='steam-approvals-status']");
    UI.status(root, kind || "loading", message);
    window.clearTimeout(setApprovalStatus.timer);
    if (kind === "success") {
        setApprovalStatus.timer = window.setTimeout(() => UI.status(root, null, ""), 4500);
    }
}

function renderApprovalLocation(approval) {
    const parts = [approval.city, approval.state, approval.country].filter(Boolean);
    if (parts.length > 0) { return parts.join(", "); }
    return approval.geolocation || null;
}

function renderApprovalEntry(approval) {
    const location = renderApprovalLocation(approval);
    return `<article class="row row--top row--stack-sm" data-approval>
        <span class="avatar avatar--steam">${UI.icon("login")}</span>
        <div class="row__main">
            <p class="row__title"><span>${esc(approval.device_label || "-")}</span><span class="badge">${esc(approval.platform_label || "-")}</span></p>
            <p class="row__meta"><span>${esc(I18N.approvalIp)} · <span class="mono">${esc(approval.ip || "-")}</span></span>${location ? `<span>${esc(I18N.approvalLocation)} · ${esc(location)}</span>` : ""}</p>
        </div>
        <div class="row__aside">
            <button type="button" class="btn btn--success-soft btn--sm" data-action="${esc(approval.approve_action)}" data-approval-action-kind="approve" onclick="submitApprovalAction(this)">${UI.icon("check")}${esc(I18N.approvalApprove)}</button>
            <button type="button" class="btn btn--danger-soft btn--sm" data-action="${esc(approval.deny_action)}" data-approval-action-kind="deny" onclick="submitApprovalAction(this)">${UI.icon("x")}${esc(I18N.approvalDeny)}</button>
        </div>
    </article>`;
}

function renderApprovalAccount(account) {
    const count = account.approval_count || (account.approvals || []).length;
    const body = account.error
        ? `<div class="card__body"><div class="inline-status inline-status--error">${UI.icon("alert")}<span><strong>${esc(I18N.approvalsAccountError)}</strong> · ${esc(account.error)}</span></div></div>`
        : `<div class="list">${(account.approvals || []).map(renderApprovalEntry).join("")}</div>`;
    return `<section class="card" data-approval-account>${accountHead(account, count, "")}${body}</section>`;
}

function applyApprovalSnapshot(snapshot) {
    setRoleText("steam-approvals-ready-accounts", snapshot.ready_account_count ?? 0);
    setRoleText("steam-approvals-total", snapshot.approval_count ?? 0);
    setRoleText("steam-approvals-updated-at", snapshot.generated_at || "-");
    const root = document.querySelector("[data-role='steam-approvals-list']");
    if (!root) { return; }
    if (!Array.isArray(snapshot.accounts) || snapshot.accounts.length === 0) {
        root.innerHTML = emptyBlock("login", I18N.approvalsUnavailable);
        return;
    }
    const active = snapshot.accounts.filter((account) => account.error || (account.approvals || []).length > 0);
    const idle = snapshot.accounts.filter((account) => !account.error && (account.approvals || []).length === 0);
    let html = active.length === 0 ? emptyBlock("check-circle", I18N.approvalsEmpty, "success") : "";
    html += active.map(renderApprovalAccount).join("");
    if (idle.length > 0 && active.length > 0) { html += idleSummary(idle, I18N.approvalsNoneForAccount); }
    root.innerHTML = html;
}

async function syncSteamApprovals(force, announceLoading) {
    const announce = announceLoading !== false;
    const stale = Date.now() - steamApprovalsLoadedAt > STEAM_APPROVALS_REFRESH_INTERVAL_MS;
    if (steamApprovalsInFlight || (!force && steamApprovalsLoadedAt !== 0 && !stale)) { return; }
    steamApprovalsInFlight = true;
    if (announce) { setApprovalStatus("loading", I18N.approvalsLoading); }
    try {
        const response = await fetch(APPROVALS_API, { headers: { "Accept": "application/json" }, cache: "no-store" });
        const payload = await maybeReadJsonResponse(response, I18N.approvalsLoadFailed);
        if (!response.ok || !payload) {
            setApprovalStatus("error", (payload && payload.message) || I18N.approvalsLoadFailed);
            return;
        }
        applyApprovalSnapshot(payload);
        steamApprovalsLoadedAt = Date.now();
        if (announce) { setApprovalStatus(null, ""); }
    } catch (_) {
        setApprovalStatus("error", I18N.approvalsLoadFailed);
    } finally {
        steamApprovalsInFlight = false;
    }
}

async function submitApprovalAction(button) {
    if (!button || button.disabled) { return; }
    const action = button.dataset.action || "";
    const actionKind = button.dataset.approvalActionKind || "";
    if (!action) {
        UI.toast(I18N.approvalActionFailed, "error");
        return;
    }
    const group = button.closest("[data-approval]");
    const buttons = group ? Array.from(group.querySelectorAll("button")) : [button];
    buttons.forEach((candidate) => { candidate.disabled = true; });
    UI.busy(button, true);
    try {
        const body = new URLSearchParams();
        body.set("lang", LANG);
        const response = await fetch(action, {
            method: "POST",
            headers: { "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" },
            body: body.toString()
        });
        const payload = await maybeReadJsonResponse(response, I18N.approvalActionFailed);
        if (!response.ok || !payload || !payload.ok) {
            UI.toast((payload && payload.message) || I18N.approvalActionFailed, "error");
            return;
        }
        UI.toast(payload.message || (actionKind === "approve" ? I18N.approvalApproved : I18N.approvalDenied), "success");
        await syncSteamApprovals(true, false);
    } catch (_) {
        UI.toast(I18N.approvalActionFailed, "error");
    } finally {
        UI.busy(button, false);
        buttons.forEach((candidate) => { candidate.disabled = false; });
    }
}

function visibleDropzone(dropzone) {
    return dropzone && dropzone.isConnected && dropzone.getClientRects().length > 0 ? dropzone : null;
}

function pastedImageFileFromEvent(event) {
    const items = Array.from((event.clipboardData && event.clipboardData.items) || []);
    const imageItem = items.find((item) => item.kind === "file" && item.type.startsWith("image/"));
    return imageItem ? imageItem.getAsFile() : null;
}

function bindSteamApprovalPasteForms() {
    document.querySelectorAll("[data-role='steam-approval-image-form']").forEach((form) => {
        if (form.dataset.pasteBound === "true") { return; }
        form.dataset.pasteBound = "true";
        const fileInput = form.querySelector("input[name='challenge_image']");
        const dropzone = form.querySelector("[data-role='steam-approval-dropzone']");
        const status = form.querySelector("[data-role='steam-approval-paste-status']");
        const fileName = form.querySelector("[data-role='steam-approval-file-name']");
        if (!fileInput || !dropzone || !status || !fileName) { return; }

        const setPasteStatus = (kind, message) => {
            status.textContent = message;
            dropzone.classList.toggle("is-ready", kind === "success");
            dropzone.classList.toggle("is-error", kind === "error");
        };
        const syncSelectedFile = () => {
            const file = fileInput.files && fileInput.files.length > 0 ? fileInput.files[0] : null;
            if (!file) {
                fileName.textContent = "";
                setPasteStatus("neutral", I18N.approvalPastePlaceholder);
                return;
            }
            fileName.textContent = file.name || I18N.approvalPasteLabel;
            setPasteStatus("success", I18N.approvalPasteReady);
        };
        const acceptImageFile = (file) => {
            if (!file) {
                setPasteStatus("error", I18N.approvalPasteError);
                return;
            }
            try {
                const transfer = new DataTransfer();
                transfer.items.add(file);
                fileInput.files = transfer.files;
            } catch (_) {
                setPasteStatus("error", I18N.approvalPasteError);
                return;
            }
            syncSelectedFile();
        };
        dropzone.__steamAcceptImageFile = acceptImageFile;

        dropzone.addEventListener("click", () => { focusedSteamApprovalDropzone = dropzone; fileInput.click(); });
        dropzone.addEventListener("mouseenter", () => { hoveredSteamApprovalDropzone = dropzone; });
        dropzone.addEventListener("mouseleave", () => { if (hoveredSteamApprovalDropzone === dropzone) { hoveredSteamApprovalDropzone = null; } });
        dropzone.addEventListener("focus", () => { focusedSteamApprovalDropzone = dropzone; });
        dropzone.addEventListener("blur", () => { if (focusedSteamApprovalDropzone === dropzone) { focusedSteamApprovalDropzone = null; } });
        dropzone.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                focusedSteamApprovalDropzone = dropzone;
                fileInput.click();
            }
        });
        dropzone.addEventListener("paste", (event) => {
            const file = pastedImageFileFromEvent(event);
            if (!file) {
                setPasteStatus("error", I18N.approvalPasteError);
                return;
            }
            event.preventDefault();
            acceptImageFile(file);
        });
        dropzone.addEventListener("dragover", (event) => { event.preventDefault(); dropzone.classList.add("is-dragging"); });
        dropzone.addEventListener("dragleave", () => dropzone.classList.remove("is-dragging"));
        dropzone.addEventListener("drop", (event) => {
            event.preventDefault();
            dropzone.classList.remove("is-dragging");
            const files = Array.from((event.dataTransfer && event.dataTransfer.files) || []);
            acceptImageFile(files.find((file) => (file.type || "").startsWith("image/")) || null);
        });
        form.addEventListener("submit", (event) => {
            const file = fileInput.files && fileInput.files.length > 0 ? fileInput.files[0] : null;
            if (!file) {
                event.preventDefault();
                setPasteStatus("error", I18N.approvalPasteError);
                dropzone.focus();
            }
        });
        fileInput.addEventListener("change", syncSelectedFile);
        syncSelectedFile();
    });

    if (document.body.dataset.steamApprovalGlobalPasteBound !== "true") {
        document.body.dataset.steamApprovalGlobalPasteBound = "true";
        document.addEventListener("paste", (event) => {
            if (event.defaultPrevented || UI.isEditable(event.target) || UI.isEditable(document.activeElement)) { return; }
            const dropzone = visibleDropzone(hoveredSteamApprovalDropzone) || visibleDropzone(focusedSteamApprovalDropzone);
            if (!dropzone || typeof dropzone.__steamAcceptImageFile !== "function") { return; }
            const file = pastedImageFileFromEvent(event);
            if (!file) { return; }
            event.preventDefault();
            dropzone.__steamAcceptImageFile(file);
        });
    }
}

/* ---------------- Signed-in devices ---------------- */
function setDeviceActionsDisabled(root, disabled) {
    root.querySelectorAll("[data-session-device-action]").forEach((button) => { button.disabled = disabled; });
}

function renderSteamSessionDeviceCard(device) {
    return `<div class="row row--top row--stack-sm">
        <span class="avatar avatar--steam avatar--sm">${UI.icon("phone", "icon--sm")}</span>
        <div class="row__main">
            <p class="row__title"><span>${esc(device.device_label)}</span>${device.is_current ? `<span class="badge badge--success">${esc(I18N.sessionDeviceCurrent)}</span>` : ""}<span class="badge badge--steam">${esc(device.platform_label)}</span></p>
            <p class="row__meta"><span>${esc(I18N.sessionDeviceLastSeen)} · ${esc(device.last_seen_at || "—")}</span><span>${esc(I18N.sessionDeviceFirstSeen)} · ${esc(device.first_seen_at || "—")}</span><span>${esc(I18N.sessionDeviceLocation)} · ${esc(device.location_label || I18N.sessionDeviceUnknownLocation)}</span></p>
            <p class="row__meta mono truncate">${esc(device.token_id)}</p>
        </div>
        <div class="row__aside"><button type="button" class="btn btn--sm btn--danger-soft" data-session-device-action data-session-device-revoke-token="${esc(device.token_id)}">${esc(I18N.sessionDeviceRevoke)}</button></div>
    </div>`;
}

function applySteamSessionDeviceSnapshot(root, snapshot) {
    root.dataset.sessionDevicesLoaded = "true";
    root.dataset.currentTokenId = snapshot.current_token_id || "";
    const list = root.querySelector("[data-session-devices-list]");
    if (list) {
        list.innerHTML = snapshot.devices.length > 0
            ? snapshot.devices.map(renderSteamSessionDeviceCard).join("")
            : `<div class="card__body">${emptyBlock("phone", I18N.sessionDevicesEmpty)}</div>`;
    }
    const othersButton = root.querySelector("[data-session-devices-bulk='others']");
    if (othersButton) { othersButton.disabled = !snapshot.current_token_id || !snapshot.devices.some((device) => !device.is_current); }
    const allButton = root.querySelector("[data-session-devices-bulk='all']");
    if (allButton) { allButton.disabled = snapshot.devices.length === 0; }
}

async function loadSteamSessionDevices(root, force) {
    if (!root || root.dataset.sessionDevicesLoading === "true") { return; }
    const api = root.dataset.sessionDevicesApi;
    if (!api) { return; }
    const status = root.querySelector("[data-session-devices-status]");
    root.dataset.sessionDevicesLoading = "true";
    UI.status(status, "loading", I18N.sessionDevicesLoading);
    setDeviceActionsDisabled(root, true);
    try {
        const url = new URL(api, window.location.origin);
        url.searchParams.set("lang", LANG);
        if (force) { url.searchParams.set("_", String(Date.now())); }
        const response = await fetch(`${url.pathname}${url.search}`, { headers: { "Accept": "application/json" }, cache: "no-store" });
        const data = await readJsonResponse(response, I18N.sessionDevicesLoadFailed);
        if (!response.ok || !data || !data.ok) {
            UI.status(status, "error", (data && data.message) || I18N.sessionDevicesLoadFailed);
            return;
        }
        applySteamSessionDeviceSnapshot(root, data.snapshot || { current_token_id: null, devices: [] });
        UI.status(status, null, "");
    } catch (error) {
        UI.status(status, "error", (error && error.message) || I18N.sessionDevicesLoadFailed);
    } finally {
        root.dataset.sessionDevicesLoading = "false";
        setDeviceActionsDisabled(root, false);
    }
}

async function revokeSteamSessionDevices(root, payload, promptMessage) {
    if (!root) { return; }
    const api = root.dataset.sessionDeviceRevokeApi;
    if (!api) { return; }
    if (promptMessage && !(await UI.confirm(promptMessage))) { return; }
    const status = root.querySelector("[data-session-devices-status]");
    UI.status(status, "loading", I18N.sessionRevokeRunning);
    setDeviceActionsDisabled(root, true);
    try {
        const response = await fetch(api, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ ...payload, lang: LANG })
        });
        const data = await readJsonResponse(response, I18N.sessionRevokeFailed);
        if (!response.ok || !data || !data.ok) {
            UI.status(status, "error", (data && data.message) || I18N.sessionRevokeFailed);
            return;
        }
        if (data.current_device_revoked) {
            UI.status(status, "success", data.message || "");
            window.setTimeout(() => window.location.reload(), 900);
            return;
        }
        await loadSteamSessionDevices(root, true);
        UI.status(status, null, "");
        UI.toast(data.message || "OK", "success");
    } catch (error) {
        UI.status(status, "error", (error && error.message) || I18N.sessionRevokeFailed);
    } finally {
        setDeviceActionsDisabled(root, false);
    }
}

function selectedDeviceRoot() {
    return Array.from(document.querySelectorAll("[data-session-devices-root]")).find((root) => !root.hidden) || null;
}

function bindAccountSwitch(select, attribute, onShow) {
    if (!select) { return; }
    const key = "hg.steam.account";
    const show = (id) => {
        document.querySelectorAll(`[${attribute}]`).forEach((element) => { element.hidden = element.getAttribute(attribute) !== id; });
        if (typeof onShow === "function") { onShow(id); }
    };
    const stored = UI.store.get(key, "session");
    if (stored && Array.from(select.options).some((option) => option.value === stored)) { select.value = stored; }
    show(select.value);
    select.addEventListener("change", () => {
        UI.store.set(key, select.value, "session");
        show(select.value);
    });
}

/* ---------------- Setup wizard ---------------- */
const SETUP_STEP_INDEX = { login: 0, loginCode: 0, email: 0, phone: 0, confirm: 1, transfer: 1, revocation: 2, complete: 3 };
const setupSteps = {};
const setupPhoneSections = {};

function showSetupStep(step) {
    Object.entries(setupSteps).forEach(([name, element]) => { if (element) { element.classList.toggle("is-active", name === step); } });
    const index = SETUP_STEP_INDEX[step] ?? 0;
    document.querySelectorAll("[data-role='setup-steps'] .steps__item").forEach((item, itemIndex) => {
        item.classList.toggle("is-done", itemIndex < index);
        item.classList.toggle("is-current", itemIndex === index);
    });
}

function showSetupPhoneMode(mode) {
    Object.entries(setupPhoneSections).forEach(([name, element]) => { if (element) { element.hidden = name !== mode; } });
}

function configureSetupLoginCodePrompt(data) {
    const kind = data && data.code_kind === "email" ? "email" : "device";
    const byId = (id) => document.getElementById(id);
    byId("setup-login-code-description").textContent = kind === "email" ? I18N.setupLoginCodeEmailDescription : I18N.setupLoginCodeDeviceDescription;
    byId("setup-login-code-label").textContent = I18N.setupLoginCodeLabel;
    const input = byId("setup-login-code-input");
    input.placeholder = I18N.setupLoginCodePlaceholder;
    input.value = "";
    byId("setup-login-code-kind").textContent = kind === "email" ? I18N.setupLoginCodeKindEmail : I18N.setupLoginCodeKindDevice;
    const hint = ((data && data.hint) || "").trim();
    byId("setup-login-code-hint-box").hidden = false;
    byId("setup-login-code-hint-row").hidden = !hint;
    byId("setup-login-code-hint").textContent = hint;
}

function handleSetupStepResponse(data) {
    if (!data || !data.ok) { return false; }
    const byId = (id) => document.getElementById(id);
    switch (data.step) {
        case "login_code":
            configureSetupLoginCodePrompt(data);
            showSetupStep("loginCode");
            return true;
        case "email":
            showSetupStep("email");
            return true;
        case "phone_number":
            showSetupPhoneMode("number");
            showSetupStep("phone");
            return true;
        case "phone_email":
            byId("setup-phone-email-address").textContent = data.confirmation_email || "";
            byId("setup-phone-number-display").textContent = data.phone_number || "";
            showSetupPhoneMode("email");
            showSetupStep("phone");
            return true;
        case "phone_code":
            byId("setup-phone-code-destination").textContent = data.phone_number || "";
            showSetupPhoneMode("code");
            showSetupStep("phone");
            return true;
        case "confirm":
            byId("setup-phone-hint").textContent = `${I18N.setupPhoneHint}: ${data.masked_phone || ""} (${data.verify_channel === "sms" ? I18N.setupConfirmTypeSms : I18N.setupConfirmTypeEmail})`;
            showSetupStep("confirm");
            return true;
        case "transfer":
            byId("setup-transfer-sms-section").hidden = true;
            byId("setup-transfer-start-btn").hidden = false;
            showSetupStep("transfer");
            return true;
        case "complete":
            byId("setup-revocation-code").textContent = data.revocation_code || "";
            showSetupStep("revocation");
            return true;
        default:
            return false;
    }
}

function bindSetupAction(buttonId, statusId, request, options) {
    const button = document.getElementById(buttonId);
    if (!button) { return; }
    const opts = options || {};
    button.addEventListener("click", async () => {
        const payload = request();
        if (payload === null) { return; }
        const statusEl = document.getElementById(statusId);
        UI.busy(button, true);
        showStatus(statusEl, I18N.setupRunning, "loading");
        try {
            const data = await jsonPost(payload.url, payload.body);
            if (typeof opts.custom === "function" && opts.custom(data, statusEl)) { return; }
            if (handleSetupStepResponse(data)) {
                UI.status(statusEl, null, "");
            } else {
                showStatus(statusEl, (data && data.message) || "Error", true);
            }
        } catch (error) {
            showStatus(statusEl, error.message, true);
        } finally {
            UI.busy(button, false);
        }
    });
}

function initSetupWizard() {
    Object.assign(setupSteps, {
        login: document.getElementById("setup-step-login"),
        loginCode: document.getElementById("setup-step-login-code"),
        email: document.getElementById("setup-step-email"),
        phone: document.getElementById("setup-step-phone"),
        confirm: document.getElementById("setup-step-confirm"),
        transfer: document.getElementById("setup-step-transfer"),
        revocation: document.getElementById("setup-step-revocation"),
        complete: document.getElementById("setup-step-complete")
    });
    Object.assign(setupPhoneSections, {
        number: document.getElementById("setup-phone-number-section"),
        email: document.getElementById("setup-phone-email-section"),
        code: document.getElementById("setup-phone-code-section")
    });
    const value = (id) => ((document.getElementById(id) || {}).value || "").trim();

    bindSetupAction("setup-begin-btn", "setup-login-status", () => {
        const username = value("setup-username");
        const password = (document.getElementById("setup-password") || {}).value || "";
        if (!username || !password) { return null; }
        return { url: SETUP_BEGIN_API, body: { steam_username: username, steam_password: password, lang: LANG } };
    });
    bindSetupAction("setup-login-code-btn", "setup-login-code-status", () => {
        const code = value("setup-login-code-input");
        return code ? { url: SETUP_LOGIN_CODE_API, body: { code, lang: LANG } } : null;
    });
    bindSetupAction("setup-email-continue-btn", "setup-email-status", () => ({ url: SETUP_RESUME_API, body: { lang: LANG } }));
    bindSetupAction("setup-phone-begin-btn", "setup-phone-number-status", () => ({ url: SETUP_PHONE_BEGIN_API, body: { phone_number: value("setup-phone-number"), lang: LANG } }));
    bindSetupAction("setup-phone-email-continue-btn", "setup-phone-email-status", () => ({ url: SETUP_RESUME_API, body: { lang: LANG } }));
    bindSetupAction("setup-phone-verify-btn", "setup-phone-code-status", () => ({ url: SETUP_PHONE_VERIFY_API, body: { verification_code: value("setup-phone-code"), lang: LANG } }));
    bindSetupAction("setup-finalize-btn", "setup-confirm-status", () => {
        const code = value("setup-confirm-code");
        return code ? { url: SETUP_FINALIZE_API, body: { confirm_code: code, lang: LANG } } : null;
    });
    bindSetupAction("setup-transfer-start-btn", "setup-transfer-status", () => ({ url: SETUP_TRANSFER_START_API, body: { lang: LANG } }), {
        custom(data, statusEl) {
            if (data && data.ok && data.step === "transfer_sms") {
                document.getElementById("setup-transfer-sms-section").hidden = false;
                document.getElementById("setup-transfer-start-btn").hidden = true;
                UI.status(statusEl, null, "");
                return true;
            }
            return false;
        }
    });
    bindSetupAction("setup-transfer-finish-btn", "setup-transfer-status", () => {
        const sms = value("setup-transfer-sms");
        return sms ? { url: SETUP_TRANSFER_FINISH_API, body: { sms_code: sms, lang: LANG } } : null;
    });

    document.querySelectorAll("#setup-cancel-btn-login-code, #setup-cancel-btn-email, #setup-cancel-btn-phone-number, #setup-cancel-btn-phone-email, #setup-cancel-btn-phone-code, #setup-cancel-btn-confirm, #setup-cancel-btn-transfer").forEach((button) => {
        button.addEventListener("click", async () => {
            try { await jsonPost(SETUP_CANCEL_API, { lang: LANG }); } catch (_) { /* ignore */ }
            showSetupStep("login");
        });
    });

    const revCheckbox = document.getElementById("setup-revocation-checkbox");
    const revContinue = document.getElementById("setup-revocation-continue-btn");
    if (revCheckbox && revContinue) {
        revCheckbox.addEventListener("change", () => { revContinue.disabled = !revCheckbox.checked; });
        revContinue.addEventListener("click", () => showSetupStep("complete"));
    }
    const goToCodes = document.getElementById("setup-go-to-codes-btn");
    if (goToCodes) {
        goToCodes.addEventListener("click", () => {
            syncSteamSnapshot();
            steamPanels.activate("codes", { scroll: true });
        });
    }
}

/* ---------------- Trade restore & zero trust ---------------- */
function showTradeRestoreModal() { UI.openSheet("trade-restore-sheet"); }
function hideTradeRestoreModal() { UI.closeSheet("trade-restore-sheet"); }
function showZeroTrustModal() { UI.openSheet("zero-trust-sheet"); }
function hideZeroTrustModal() { UI.closeSheet("zero-trust-sheet"); }

function resetZeroTrustSheet() {
    const statusEl = document.getElementById("zt-activate-status");
    UI.status(statusEl, null, "");
    const confirmInput = document.getElementById("zt-activate-confirm");
    if (confirmInput) { confirmInput.value = ""; }
    syncZtActivateButton();
}

function syncZtActivateButton() {
    const input = document.getElementById("zt-activate-confirm");
    const button = document.getElementById("zt-activate-submit");
    if (input && button) { button.disabled = input.value.trim() !== "CONFIRM"; }
}

function ztSelectAllAccounts() {
    const checkboxes = Array.from(document.querySelectorAll("#zt-account-list input[type='checkbox']"));
    const allChecked = checkboxes.every((checkbox) => checkbox.checked);
    checkboxes.forEach((checkbox) => { checkbox.checked = !allChecked; });
}

async function activateZeroTrust() {
    const confirmInput = document.getElementById("zt-activate-confirm");
    const statusEl = document.getElementById("zt-activate-status");
    const submitButton = document.getElementById("zt-activate-submit");
    if (!confirmInput || confirmInput.value.trim() !== "CONFIRM") {
        UI.status(statusEl, "error", I18N.ztInvalidConfirmMessage);
        return;
    }
    const accountIds = Array.from(document.querySelectorAll("#zt-account-list input[type='checkbox']:checked")).map((checkbox) => checkbox.value);
    if (accountIds.length === 0) { return; }
    UI.busy(submitButton, true);
    UI.status(statusEl, "loading", I18N.ztActivatingMessage);
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 15000);
    try {
        const resp = await fetch(ZERO_TRUST_ACTIVATE_API, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            signal: controller.signal,
            body: JSON.stringify({ account_ids: accountIds.join(","), confirm_phrase: confirmInput.value.trim(), lang: LANG })
        });
        const data = await readJsonResponse(resp, I18N.ztActivationFailedMessage);
        if (data.ok) {
            UI.status(statusEl, "success", I18N.ztActivatedMessage);
            window.setTimeout(() => window.location.reload(), 800);
            return;
        }
        UI.status(statusEl, "error", data.message || I18N.ztActivationFailedMessage);
    } catch (error) {
        UI.status(statusEl, "error", error && error.name === "AbortError" ? I18N.ztActivationFailedMessage : (error.message || I18N.ztActivationFailedMessage));
    } finally {
        window.clearTimeout(timeoutId);
        UI.busy(submitButton, false);
        syncZtActivateButton();
    }
}

function toggleZeroTrustDeactivation() {
    const panel = document.getElementById("zero-trust-deactivation-panel");
    if (panel) {
        panel.hidden = !panel.hidden;
        if (!panel.hidden) { document.getElementById("zt-deactivate-password").focus(); }
    }
}

function syncZtDeactivateButton() {
    const input = document.getElementById("zt-deactivate-confirm");
    const button = document.getElementById("zt-deactivate-submit");
    if (input && button) { button.disabled = input.value.trim() !== "CONFIRM"; }
}

async function deactivateZeroTrust() {
    const passwordInput = document.getElementById("zt-deactivate-password");
    const totpInput = document.getElementById("zt-deactivate-totp");
    const confirmInput = document.getElementById("zt-deactivate-confirm");
    const statusEl = document.getElementById("zt-deactivate-status");
    const submitButton = document.getElementById("zt-deactivate-submit");
    if (!confirmInput || confirmInput.value.trim() !== "CONFIRM") {
        statusEl.textContent = I18N.ztInvalidConfirmMessage;
        return;
    }
    const password = passwordInput ? passwordInput.value : "";
    if (!password) {
        statusEl.textContent = I18N.ztPasswordRequiredMessage;
        return;
    }
    UI.busy(submitButton, true);
    statusEl.textContent = I18N.ztSweepRunningMessage;
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 15000);
    try {
        const resp = await fetch(ZERO_TRUST_DEACTIVATE_API, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            signal: controller.signal,
            body: JSON.stringify({ account_ids: "all", password, totp_code: totpInput ? totpInput.value.trim() : "", confirm_phrase: confirmInput.value.trim(), lang: LANG })
        });
        const data = await readJsonResponse(resp, I18N.ztDeactivationFailedMessage);
        if (data.ok) {
            statusEl.textContent = I18N.ztDeactivatedMessage;
            window.setTimeout(() => window.location.reload(), 800);
            return;
        }
        statusEl.textContent = data.message || I18N.ztDeactivationFailedMessage;
    } catch (error) {
        statusEl.textContent = error && error.name === "AbortError" ? I18N.ztDeactivationFailedMessage : (error.message || I18N.ztDeactivationFailedMessage);
    } finally {
        window.clearTimeout(timeoutId);
        UI.busy(submitButton, false);
        syncZtDeactivateButton();
    }
}

function toggleZeroTrustLog() {
    const panel = document.getElementById("zero-trust-log-panel");
    if (panel) { panel.hidden = !panel.hidden; }
}

function startZeroTrustPolling() {
    let inFlight = false;
    window.setInterval(async () => {
        if (inFlight) { return; }
        inFlight = true;
        try {
            const resp = await fetch(ZERO_TRUST_SWEEP_API, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify({ lang: LANG })
            });
            const data = await readJsonResponse(resp);
            if (!data.ok) { return; }
            const logEl = document.getElementById("zt-log-entries");
            if (logEl && Array.isArray(data.log)) {
                data.log.forEach((entry) => {
                    const line = document.createElement("p");
                    line.textContent = `[${new Date().toLocaleTimeString()}] ${entry}`;
                    logEl.appendChild(line);
                });
                logEl.scrollTop = logEl.scrollHeight;
            }
            const counterEl = document.getElementById("zt-sweep-counter-value");
            if (counterEl) {
                if (typeof data.sweep_count !== "undefined") {
                    counterEl.textContent = `Sweeps: ${data.sweep_count}`;
                } else if (typeof data.locked_count !== "undefined") {
                    counterEl.textContent = `Locked: ${data.locked_count}`;
                } else {
                    counterEl.textContent = "Active";
                }
            }
        } catch (_) {
            // Sweep poll failed silently.
        } finally {
            inFlight = false;
        }
    }, 5000);
}

/* ---------------- Delegated actions ---------------- */
function resultBox(selector) { return document.querySelector(selector); }

document.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof Element)) { return; }

    const deviceButton = target.closest("[data-session-device-revoke-token]");
    if (deviceButton) {
        await revokeSteamSessionDevices(deviceButton.closest("[data-session-devices-root]"), { scope: "token", token_id: deviceButton.dataset.sessionDeviceRevokeToken || "" }, I18N.sessionRevokePrompt);
        return;
    }
    const bulkDevices = target.closest("[data-session-devices-bulk]");
    if (bulkDevices) {
        const scope = bulkDevices.dataset.sessionDevicesBulk || "";
        await revokeSteamSessionDevices(bulkDevices.closest("[data-session-devices-root]"), { scope }, scope === "others" ? I18N.sessionRevokeOthersPrompt : I18N.sessionRevokeAllPrompt);
        return;
    }
    const refreshDevices = target.closest("[data-session-devices-refresh]");
    if (refreshDevices) {
        loadSteamSessionDevices(refreshDevices.closest("[data-session-devices-root]"), true);
        return;
    }
    if (target.closest("[data-confirmation-refresh]")) { syncSteamConfirmations(true); return; }
    if (target.closest("[data-approval-refresh]")) { syncSteamApprovals(true); return; }

    const removeButton = target.closest("[data-remove-auth]");
    if (removeButton) {
        const accountId = removeButton.dataset.removeAuth;
        const codeInput = document.getElementById(`revocation-code-${accountId}`);
        const code = codeInput ? codeInput.value.trim() : "";
        if (!code) { if (codeInput) { codeInput.focus(); } return; }
        if (!(await UI.confirm(I18N.removeConfirm))) { return; }
        UI.busy(removeButton, true);
        try {
            const data = await jsonPost(`/platforms/steam/accounts/${accountId}/authenticator/remove`, { revocation_code: code, lang: LANG });
            if (data.ok) {
                UI.toast(I18N.removeSuccess, "success");
                window.setTimeout(() => window.location.reload(), 900);
            } else {
                UI.toast(data.message || I18N.removeFailed, "error");
            }
        } catch (error) {
            UI.toast(error.message, "error");
        } finally {
            UI.busy(removeButton, false);
        }
        return;
    }

    const checkButton = target.closest("[data-trade-restore-check]");
    const revertButton = target.closest("[data-trade-restore-revert]");
    if (checkButton || revertButton) {
        const accountId = checkButton ? checkButton.dataset.tradeRestoreCheck : revertButton.dataset.tradeRestoreRevert;
        const statusEl = document.getElementById(`trade-restore-status-${accountId}`);
        if (!statusEl) { return; }
        if (checkButton) {
            UI.busy(checkButton, true);
            showStatus(statusEl, I18N.tradeRestoreCheckRunning, "loading");
            try {
                const resp = await fetch(checkButton.dataset.tradeRestoreCheckApi || `/api/platforms/steam/accounts/${accountId}/trade-restore?lang=${LANG}`, { headers: { "Accept": "application/json" } });
                const data = await readJsonResponse(resp, I18N.tradeRestoreFailed);
                showStatus(statusEl, data.message || I18N.tradeRestoreFailed, !(data.ok && data.can_revert));
            } catch (error) {
                showStatus(statusEl, error.message || I18N.tradeRestoreFailed, true);
            } finally {
                UI.busy(checkButton, false);
            }
            return;
        }
        const confirmInput = document.getElementById(`trade-restore-confirm-${accountId}`);
        const confirmPhrase = confirmInput ? confirmInput.value.trim() : "";
        if (confirmPhrase !== I18N.tradeRestoreConfirmPhrase) {
            showStatus(statusEl, I18N.tradeRestoreInvalidConfirm, true);
            return;
        }
        if (!(await UI.confirm(I18N.tradeRestoreConfirmPrompt))) { return; }
        UI.busy(revertButton, true);
        showStatus(statusEl, I18N.tradeRestoreRunning, "loading");
        try {
            const data = await jsonPost(revertButton.dataset.tradeRestoreRevertApi || `/api/platforms/steam/accounts/${accountId}/trade-restore/revert`, { confirm_phrase: confirmPhrase, lang: LANG });
            showStatus(statusEl, data.message || I18N.tradeRestoreFailed, !data.ok);
        } catch (error) {
            showStatus(statusEl, error.message || I18N.tradeRestoreFailed, true);
        } finally {
            UI.busy(revertButton, false);
        }
        return;
    }

    const statusButton = target.closest("[data-status-check]");
    if (statusButton) {
        const accountId = statusButton.dataset.statusCheck;
        const resultEl = document.getElementById(`status-result-${accountId}`);
        if (!resultEl) { return; }
        UI.busy(statusButton, true);
        UI.status(resultEl, "loading", I18N.statusLoading);
        try {
            const resp = await fetch(`/api/platforms/steam/accounts/${accountId}/status?lang=${LANG}`, { headers: { "Accept": "application/json" } });
            const data = await readJsonResponse(resp, I18N.statusFailed);
            if (data.ok && data.status) {
                const s = data.status;
                resultEl.className = "callout kv-list";
                resultEl.hidden = false;
                resultEl.innerHTML = [
                    [I18N.statusStateLabel, s.guard_state > 0 ? I18N.statusActive : I18N.statusInactive],
                    [I18N.statusDeviceIdLabel, s.bound_device || "—"],
                    [I18N.statusRevocationAttemptsLabel, String(s.remaining_revoke_tries ?? "-")],
                    [I18N.statusVersionLabel, String(s.schema_ver ?? "-")]
                ].map(([label, value]) => `<div class="kv-row"><span class="kv-row__label">${esc(label)}</span><span class="kv-row__value mono">${esc(value)}</span></div>`).join("");
            } else {
                UI.status(resultEl, "error", data.message || I18N.statusFailed);
            }
        } catch (error) {
            UI.status(resultEl, "error", error.message || I18N.statusFailed);
        } finally {
            UI.busy(statusButton, false);
        }
        return;
    }

    const qrButton = target.closest("[data-export-qr]");
    if (qrButton) {
        const accountId = qrButton.dataset.exportQr;
        const resultEl = document.getElementById(`qr-result-${accountId}`);
        if (!resultEl) { return; }
        UI.busy(qrButton, true);
        try {
            const resp = await fetch(`/api/platforms/steam/accounts/${accountId}/export/qr?lang=${LANG}`, { headers: { "Accept": "application/json" } });
            const data = await readJsonResponse(resp, I18N.exportQrFailed);
            if (data.ok) {
                resultEl.className = "stack stack--sm";
                resultEl.hidden = false;
                resultEl.innerHTML = `<div class="qr-box">${data.svg}</div><div class="secret"><span class="secret__value text-xs">${esc(data.uri)}</span><button type="button" class="btn btn--sm" data-copy="${esc(data.uri)}">${UI.icon("copy")}${esc(I18N.copy)}</button></div>`;
                window.clearTimeout(resultEl.__hideTimer);
                resultEl.__hideTimer = window.setTimeout(() => { resultEl.hidden = true; resultEl.innerHTML = ""; }, 60000);
            } else {
                UI.status(resultEl, "error", data.message || I18N.exportQrFailed);
            }
        } catch (error) {
            UI.status(resultEl, "error", error.message || I18N.exportQrFailed);
        } finally {
            UI.busy(qrButton, false);
        }
        return;
    }

    const proxyButton = target.closest("[data-save-proxy]");
    if (proxyButton) {
        const accountId = proxyButton.dataset.saveProxy;
        const proxyInput = document.getElementById(`proxy-url-${accountId}`);
        if (!proxyInput) { return; }
        UI.busy(proxyButton, true);
        try {
            const data = await jsonPost(`/platforms/steam/accounts/${accountId}/proxy`, { proxy_url: proxyInput.value.trim(), lang: LANG });
            UI.toast(data.message || (data.ok ? "OK" : "Error"), data.ok ? "success" : "error");
        } catch (error) {
            UI.toast(error.message, "error");
        } finally {
            UI.busy(proxyButton, false);
        }
        return;
    }

    const phoneButton = target.closest("[data-phone-status]");
    if (phoneButton) {
        const accountId = phoneButton.dataset.phoneStatus;
        const resultEl = resultBox(`[data-phone-status-result="${accountId}"]`);
        if (!resultEl) { return; }
        UI.busy(phoneButton, true);
        UI.status(resultEl, "loading", "…");
        try {
            const resp = await fetch(`/api/platforms/steam/accounts/${encodeURIComponent(accountId)}/phone-status?lang=${LANG}`, { headers: { "Accept": "application/json" } });
            const data = await readJsonResponse(resp, I18N.phoneStatusFailed);
            if (data.ok) {
                UI.status(resultEl, data.has_phone ? "success" : "warning", data.has_phone ? I18N.phoneHasPhone : I18N.phoneNoPhone);
            } else {
                UI.status(resultEl, "error", data.message || I18N.phoneStatusFailed);
            }
        } catch (error) {
            UI.status(resultEl, "error", error.message || I18N.phoneStatusFailed);
        } finally {
            UI.busy(phoneButton, false);
        }
        return;
    }

    const createCodes = target.closest("[data-emergency-codes-create]");
    const destroyCodes = target.closest("[data-emergency-codes-destroy]");
    if (createCodes || destroyCodes) {
        const button = createCodes || destroyCodes;
        const accountId = createCodes ? createCodes.dataset.emergencyCodesCreate : destroyCodes.dataset.emergencyCodesDestroy;
        const resultEl = resultBox(`[data-emergency-codes-result="${accountId}"]`);
        if (!resultEl) { return; }
        UI.busy(button, true);
        UI.status(resultEl, "loading", "…");
        try {
            const resp = await fetch(`/api/platforms/steam/accounts/${encodeURIComponent(accountId)}/emergency-codes${createCodes ? "" : "/destroy"}`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify({ lang: LANG })
            });
            const data = await readJsonResponse(resp, I18N.emergencyCodesFailed);
            if (data.ok && createCodes && data.codes) {
                resultEl.className = "recovery-grid";
                resultEl.hidden = false;
                resultEl.innerHTML = data.codes.map((code) => `<span class="recovery-code">${esc(code)}</span>`).join("");
            } else if (data.ok) {
                UI.status(resultEl, "success", "OK");
            } else {
                UI.status(resultEl, "error", data.message || I18N.emergencyCodesFailed);
            }
        } catch (error) {
            UI.status(resultEl, "error", error.message || I18N.emergencyCodesFailed);
        } finally {
            UI.busy(button, false);
        }
        return;
    }

    const validateButton = target.closest("[data-validate-token]");
    if (validateButton) {
        const accountId = validateButton.dataset.validateToken;
        const inputEl = resultBox(`[data-validate-token-input="${accountId}"]`);
        const resultEl = resultBox(`[data-validate-token-result="${accountId}"]`);
        if (!resultEl || !inputEl) { return; }
        const code = inputEl.value.trim();
        if (!code) { inputEl.focus(); return; }
        UI.busy(validateButton, true);
        UI.status(resultEl, "loading", "…");
        try {
            const resp = await fetch(`/api/platforms/steam/accounts/${encodeURIComponent(accountId)}/validate-token`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify({ code, lang: LANG })
            });
            const data = await readJsonResponse(resp, I18N.validateTokenFailed);
            if (data.ok) {
                UI.status(resultEl, data.valid ? "success" : "error", data.valid ? I18N.validateTokenValid : I18N.validateTokenInvalid);
            } else {
                UI.status(resultEl, "error", data.message || I18N.validateTokenFailed);
            }
        } catch (error) {
            UI.status(resultEl, "error", error.message || I18N.validateTokenFailed);
        } finally {
            UI.busy(validateButton, false);
        }
        return;
    }

    const linkButton = target.closest("[data-link-auth]");
    if (linkButton) {
        const accountId = linkButton.dataset.linkAuth;
        const statusEl = document.getElementById(`link-auth-status-${accountId}`);
        UI.busy(linkButton, true);
        showStatus(statusEl, I18N.setupRunning, "loading");
        try {
            const data = await jsonPost(`/platforms/steam/accounts/${accountId}/authenticator/link`, { lang: LANG });
            if (data.ok && handleSetupStepResponse(data)) {
                UI.status(statusEl, null, "");
                UI.closeSheet(linkButton.closest(".sheet"));
                steamPanels.activate("setup", { scroll: true });
            } else {
                showStatus(statusEl, data.message || "Error", true);
            }
        } catch (error) {
            showStatus(statusEl, error.message, true);
        } finally {
            UI.busy(linkButton, false);
        }
        return;
    }

    const bulkButton = target.closest("[data-bulk-accept], [data-bulk-deny]");
    if (bulkButton) {
        const isAccept = bulkButton.hasAttribute("data-bulk-accept");
        const accountId = isAccept ? bulkButton.dataset.bulkAccept : bulkButton.dataset.bulkDeny;
        if (!(await UI.confirm(isAccept ? I18N.bulkAcceptConfirm : I18N.bulkDenyConfirm, { tone: isAccept ? "neutral" : "danger" }))) { return; }
        UI.busy(bulkButton, true);
        try {
            const data = await jsonPost(`/api/platforms/steam/accounts/${accountId}/confirmations/${isAccept ? "accept-all" : "deny-all"}`, { lang: LANG });
            if (data.ok) {
                UI.toast(data.message || I18N.bulkRunning, "success");
                window.setTimeout(() => syncSteamConfirmations(true, false), 800);
            } else {
                UI.toast(data.message || "Error", "error");
            }
        } catch (error) {
            UI.toast(error.message, "error");
        } finally {
            UI.busy(bulkButton, false);
        }
    }
});

function bindTimeCheck() {
    const button = document.getElementById("time-check-btn");
    if (!button) { return; }
    button.addEventListener("click", async () => {
        const resultEl = document.getElementById("time-check-result");
        const verdictEl = document.getElementById("time-check-verdict");
        const driftEl = document.getElementById("time-check-drift");
        const setVerdict = (message, ok) => {
            verdictEl.textContent = message;
            verdictEl.classList.toggle("text-success", ok);
            verdictEl.classList.toggle("text-danger", !ok);
        };
        UI.busy(button, true);
        try {
            const resp = await fetch(`${TIME_CHECK_API}?lang=${LANG}`, { headers: { "Accept": "application/json" } });
            const data = await readJsonResponse(resp, I18N.timeCheckFailed);
            resultEl.hidden = false;
            if (data.ok) {
                const formatTime = (unix) => (Number(unix) > 0 ? new Date(Number(unix) * 1000).toLocaleString() : String(unix));
                document.getElementById("time-check-server").textContent = formatTime(data.remote_time);
                document.getElementById("time-check-local").textContent = formatTime(data.local_time);
                const withinRange = Math.abs(data.drift_seconds) <= 30;
                driftEl.textContent = `${data.drift_seconds >= 0 ? "+" : ""}${data.drift_seconds}s`;
                driftEl.classList.toggle("text-success", withinRange);
                driftEl.classList.toggle("text-danger", !withinRange);
                setVerdict(withinRange ? I18N.timeCheckOk : I18N.timeCheckWarning, withinRange);
            } else {
                setVerdict(data.message || I18N.timeCheckFailed, false);
            }
        } catch (error) {
            resultEl.hidden = false;
            setVerdict((error && error.message) || I18N.timeCheckFailed, false);
        } finally {
            UI.busy(button, false);
        }
    });
}

function onSteamTab(id) {
    UI.whenActivated(() => {
        if (id === "approvals") { syncSteamApprovals(); }
        if (id === "confirmations") { syncSteamConfirmations(); }
        if (id === "devices") {
            const root = selectedDeviceRoot();
            if (root && root.dataset.sessionDevicesLoaded !== "true") { loadSteamSessionDevices(root); }
        }
    });
}

window.addEventListener("DOMContentLoaded", () => {
    const generatedAt = Number(document.body.dataset.snapshotGeneratedAt || 0);
    if (generatedAt > 0) { steamClockOffset = generatedAt - Date.now() / 1000; }

    steamPanels = UI.panels(document.getElementById("steam-panels"), {
        aliases: { manage: "accounts", issues: "about" },
        initial: document.body.dataset.defaultTab || "codes",
        defaultId: "codes",
        onChange: onSteamTab
    });
    document.querySelectorAll("#steam-panels [data-panels]").forEach((nested) => {
        UI.panels(nested, { hash: false, storageKey: nested.hasAttribute("data-import-panels") ? "hg.steam.import" : undefined });
    });

    bindAccountSwitch(document.querySelector("[data-account-switch='security']"), "data-security-account");
    bindAccountSwitch(document.querySelector("[data-account-switch='devices']"), "data-session-devices-account", () => {
        if (steamPanels && steamPanels.current === "devices") {
            const root = selectedDeviceRoot();
            if (root && root.dataset.sessionDevicesLoaded !== "true") { loadSteamSessionDevices(root); }
        }
    });

    bindSteamApprovalPasteForms();
    initSetupWizard();
    bindTimeCheck();
    document.getElementById("zero-trust-sheet").addEventListener("sheet:close", resetZeroTrustSheet);

    document.querySelectorAll("[data-steam-account]").forEach(syncCodeBar);
    refreshSteamCountdowns();
    window.setInterval(refreshSteamCountdowns, 1000);
    window.setInterval(() => { if (!document.hidden) { syncSteamSnapshot(); } }, 30000);
    window.setInterval(() => {
        if (document.hidden || !steamPanels) { return; }
        if (steamPanels.current === "approvals") { syncSteamApprovals(); }
        if (steamPanels.current === "confirmations") { syncSteamConfirmations(); }
    }, STEAM_CONFIRMATIONS_REFRESH_INTERVAL_MS);
    document.addEventListener("visibilitychange", () => {
        if (document.hidden) { return; }
        syncSteamSnapshot();
        document.querySelectorAll("[data-steam-account]").forEach(syncCodeBar);
    });

    // Nothing that talks to Steam runs while this page is only being prerendered.
    UI.whenActivated(() => {
        if (PREFETCH_CONFIRMATIONS) {
            window.setTimeout(() => syncSteamConfirmations(false, false), 900);
        }
        if (PREFETCH_APPROVALS) {
            window.setTimeout(() => syncSteamApprovals(false, false), 1800);
        }
        if (document.getElementById("zero-trust-banner")) { startZeroTrustPolling(); }
    });
});
