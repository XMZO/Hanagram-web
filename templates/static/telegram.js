// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

let workspaceSyncInFlight = false;

function esc(value) { return UI.escapeHtml(value); }
function seenStorageKey(sessionKey) { return `hanagram_seen_${sessionKey}`; }

function markSessionSeen(sessionKey, latestCodeAt) {
    if (!sessionKey || !latestCodeAt) { return; }
    UI.store.set(seenStorageKey(sessionKey), String(latestCodeAt));
}

function escapeSelectorValue(value) {
    if (window.CSS && typeof window.CSS.escape === "function") { return window.CSS.escape(value); }
    return String(value).replace(/["\\]/g, "\\$&");
}

function findSessionCard(sessionKey) {
    return document.querySelector(`[data-session-card][data-session-key="${escapeSelectorValue(sessionKey)}"]`);
}

function findSessionModal(sessionKey) {
    return document.querySelector(`[data-session-modal][data-session-key="${escapeSelectorValue(sessionKey)}"]`);
}

function statusLabel(kind) {
    if (kind === "connected") { return I18N.statusConnected; }
    if (kind === "connecting") { return I18N.statusConnecting; }
    return I18N.statusError;
}

function statusTone(kind) {
    if (kind === "connected") { return "success"; }
    if (kind === "connecting") { return "warning"; }
    return "danger";
}

function dotClass(kind) {
    return `dot dot--${statusTone(kind)}${kind === "connecting" ? " dot--pulse" : ""}`;
}

function parseUnixTimestamp(value) {
    const parsed = Number(value || 0);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function renderRecentMessages(messages) {
    if (!messages || messages.length === 0) {
        return `<div class="empty empty--compact"><p class="empty__desc">${esc(I18N.noMessages)}</p></div>`;
    }
    return messages.map((message) => `<div class="message">
        <div class="message__head">
            ${message.code ? `<span class="badge badge--success badge--mono">${esc(message.code)}</span>` : "<span></span>"}
            <span class="message__time">${esc(message.received_at)}</span>
        </div>
        <p class="message__text">${esc(message.text)}</p>
    </div>`).join("");
}

function refreshStatusBlock(root, status) {
    const badge = root.querySelector("[data-role='status-badge']");
    if (badge) {
        if (badge.classList.contains("badge")) {
            badge.className = `badge badge--${statusTone(status.kind)}`;
        }
        badge.textContent = statusLabel(status.kind);
    }
    const dot = root.querySelector("[data-role='status-dot']");
    if (dot) { dot.className = dotClass(status.kind); }
    const error = root.querySelector("[data-role='session-error']");
    if (error) {
        error.textContent = status.error || "";
        error.hidden = !status.error;
    }
}

function flashRefresh(card) {
    card.classList.remove("is-flash");
    void card.offsetWidth;
    card.classList.add("is-flash");
    window.setTimeout(() => card.classList.remove("is-flash"), 1400);
}

function resetWorkspaceCodeChip(chip) {
    if (!chip) { return; }
    if (chip.__copyResetTimer) {
        window.clearTimeout(chip.__copyResetTimer);
        chip.__copyResetTimer = undefined;
    }
    chip.classList.remove("is-copied");
    const label = chip.querySelector("[data-role='copy-code-label']");
    if (label) { label.textContent = chip.dataset.label || ""; }
}

function otpVisibilityScopes(root) {
    if (!root) { return []; }
    const scopes = [];
    if (root.matches && root.matches("[data-otp-scope]")) { scopes.push(root); }
    scopes.push(...root.querySelectorAll("[data-otp-scope]"));
    return scopes;
}

function refreshOtpVisibility(root) {
    const nowUnix = Math.floor(Date.now() / 1000);
    otpVisibilityScopes(root || document).forEach((scope) => {
        const expiresAt = parseUnixTimestamp(scope.dataset.latestCodeExpiresAt);
        const latestCode = scope.querySelector("[data-role='latest-code']");
        const visibilityLabel = scope.querySelector("[data-role='otp-visibility-label']");
        const copyButton = scope.querySelector("[data-role='copy-code-chip'], [data-role='recent-activity-code']");
        if (!latestCode && !copyButton && !visibilityLabel) { return; }

        const expired = expiresAt > 0 && nowUnix >= expiresAt;
        if (expired) {
            if (latestCode) { latestCode.textContent = I18N.otpPlaceholder; }
            if (copyButton) {
                copyButton.dataset.code = "";
                copyButton.disabled = true;
                copyButton.classList.add("is-empty");
                if (!latestCode) { copyButton.textContent = I18N.otpPlaceholder; }
                resetWorkspaceCodeChip(copyButton);
            }
            if (scope.classList.contains("otp")) { scope.classList.add("is-empty"); }
            if (visibilityLabel) { visibilityLabel.textContent = I18N.otpHidden; }
            return;
        }

        if (copyButton) {
            const currentCode = copyButton.dataset.code || "";
            copyButton.disabled = !currentCode;
            copyButton.classList.toggle("is-empty", !currentCode);
            if (!latestCode) { copyButton.textContent = currentCode || I18N.otpPlaceholder; }
        }
        if (visibilityLabel) {
            visibilityLabel.textContent = expiresAt > 0
                ? I18N.otpHideCountdown.replace("{countdown}", UI.formatCountdown(expiresAt - nowUnix))
                : "";
        }
    });
}

function toggleMaskedPhone(button) {
    if (!button || button.disabled) { return; }
    const phone = button.dataset.phone || "";
    const maskedPhone = button.dataset.maskedPhone || phone;
    const value = button.querySelector("[data-role='phone-value']");
    if (!value) { return; }
    const reveal = button.dataset.revealed !== "true";
    button.dataset.revealed = reveal ? "true" : "false";
    value.textContent = reveal ? phone : maskedPhone;
    const nextLabel = reveal ? I18N.phoneHide : I18N.phoneReveal;
    button.setAttribute("title", nextLabel);
    button.setAttribute("aria-label", nextLabel);
}

function refreshNewBadges() {
    document.querySelectorAll("[data-session-card]").forEach((card) => {
        const latestCodeAt = card.dataset.latestCodeAt;
        const latestCodeExpiresAt = parseUnixTimestamp(card.dataset.latestCodeExpiresAt);
        const sessionKey = card.dataset.sessionKey;
        const indicator = card.querySelector("[data-new-indicator]");
        if (!indicator) { return; }
        if (!latestCodeAt || !sessionKey) {
            indicator.hidden = true;
            return;
        }
        const hasVisibleCode = latestCodeExpiresAt > 0 && Math.floor(Date.now() / 1000) < latestCodeExpiresAt;
        if (!hasVisibleCode) {
            indicator.hidden = true;
            return;
        }
        const modal = findSessionModal(sessionKey);
        const seenAt = UI.store.get(seenStorageKey(sessionKey));
        const modalOpen = modal && modal.dataset.state === "open";
        indicator.hidden = !((!seenAt || Number(latestCodeAt) > Number(seenAt)) && !modalOpen);
    });
}

function openSessionModal(modalId, sessionKey) {
    const modal = document.getElementById(modalId);
    if (!modal) { return; }
    UI.openSheet(modal);
    const card = findSessionCard(sessionKey);
    if (card) { markSessionSeen(sessionKey, card.dataset.latestCodeAt); }
    refreshNewBadges();
}

function openSessionModalBySessionKey(sessionKey) {
    const card = findSessionCard(sessionKey);
    if (!card || !card.dataset.sessionModalId) { return; }
    openSessionModal(card.dataset.sessionModalId, sessionKey);
}

function closeSessionModal(modalId) {
    UI.closeSheet(modalId);
}

function applySessionCardUpdate(card, session, options) {
    const opts = options || {};
    const previousCodeAt = Number(card.dataset.latestCodeAt || 0);
    const nextCodeAt = Number(session.latest_code_at_unix || 0);
    const hadCodeChange = nextCodeAt && nextCodeAt > previousCodeAt;
    card.dataset.latestCodeAt = session.latest_code_at_unix || "";
    card.dataset.latestCodeExpiresAt = session.latest_code_expires_at_unix || "";
    card.dataset.filterText = `${session.key} ${session.phone} ${session.note || ""}`;

    const set = (role, value) => {
        const element = card.querySelector(`[data-role='${role}']`);
        if (element) { element.textContent = value; }
    };
    set("session-name", session.key);
    set("session-phone", session.phone);
    set("session-note", session.note || I18N.noNote);
    set("latest-code", session.latest_code || I18N.otpPlaceholder);
    set("latest-update", session.latest_message_at || "-");

    const chip = card.querySelector("[data-role='copy-code-chip']");
    if (chip) {
        chip.dataset.code = session.latest_code || "";
        chip.disabled = !session.latest_code;
        chip.classList.toggle("is-empty", !session.latest_code);
        resetWorkspaceCodeChip(chip);
        if (hadCodeChange) {
            chip.classList.remove("is-fresh");
            void chip.offsetWidth;
            chip.classList.add("is-fresh");
        }
    }

    refreshStatusBlock(card, session.status);
    refreshOtpVisibility(card);
    if (hadCodeChange && !opts.silent) { flashRefresh(card); }
}

function applySessionModalUpdate(modal, session) {
    const otpScope = modal.querySelector("[data-otp-scope]");
    if (otpScope) {
        otpScope.dataset.latestCodeExpiresAt = session.latest_code_expires_at_unix || "";
        otpScope.classList.toggle("is-empty", !session.latest_code);
    }
    const set = (role, value) => {
        modal.querySelectorAll(`[data-role='${role}']`).forEach((element) => { element.textContent = value; });
    };
    set("session-name", session.key);
    set("session-phone", session.phone);
    set("session-note", session.note || I18N.noNote);
    set("latest-code", session.latest_code || I18N.otpPlaceholder);
    set("latest-update", session.latest_message_at || "-");

    const renameInput = modal.querySelector("[data-role='rename-input']");
    if (renameInput && document.activeElement !== renameInput) { renameInput.value = session.key; }

    const copyButton = modal.querySelector("[data-role='copy-code']");
    if (copyButton) {
        copyButton.dataset.code = session.latest_code || "";
        copyButton.disabled = !session.latest_code;
    }

    const recentMessages = modal.querySelector("[data-role='recent-messages']");
    if (recentMessages) { recentMessages.innerHTML = renderRecentMessages(session.recent_messages); }

    refreshStatusBlock(modal, session.status);
    refreshOtpVisibility(modal);
}

async function copyCode(button) {
    if (!button || button.disabled) { return; }
    const code = button.dataset.code;
    if (!code) { return; }
    const copied = await UI.copy(code);
    if (!copied) {
        window.prompt(button.dataset.promptLabel || I18N.copyFallback, code);
        return;
    }
    UI.toast(button.dataset.copied || I18N.copied, "success");
    const label = button.querySelector("span");
    if (label) {
        label.textContent = button.dataset.copied || I18N.copied;
        window.setTimeout(() => { label.textContent = button.dataset.label || I18N.copy; }, 1200);
    }
}

async function copyWorkspaceCode(button) {
    const code = button.dataset.code;
    if (!code || button.disabled) { return; }
    const copied = await UI.copy(code);
    if (!copied) {
        UI.toast(I18N.copyFallback, "error");
        return;
    }
    resetWorkspaceCodeChip(button);
    button.classList.add("is-copied");
    const label = button.querySelector("[data-role='copy-code-label']");
    if (label) { label.textContent = button.dataset.copied || I18N.copied; }
    UI.toast(`${button.dataset.copied || I18N.copied} · ${code}`, "success");
    button.__copyResetTimer = window.setTimeout(() => resetWorkspaceCodeChip(button), 1400);
}

async function copyExportString(button) {
    const panel = button.closest("[data-role='export-string-panel']");
    const textarea = panel ? panel.querySelector("textarea") : null;
    if (!textarea || !textarea.value) { return; }
    const copied = await UI.copy(textarea.value);
    if (!copied) {
        window.prompt(I18N.copyFallback, textarea.value);
        return;
    }
    UI.toast(button.dataset.copied || I18N.copied, "success");
    button.textContent = button.dataset.copied || I18N.copied;
    window.setTimeout(() => { button.textContent = button.dataset.label || I18N.exportStringCopy; }, 1200);
}

async function fetchSessionString(button) {
    const panel = button.dataset.target ? document.querySelector(button.dataset.target) : null;
    const exportUrl = button.dataset.exportUrl;
    if (!panel || !exportUrl) { return; }
    const textarea = panel.querySelector("textarea");
    const title = panel.querySelector("[data-role='export-title']");
    const error = panel.querySelector("[data-role='export-error']");
    const copyButton = panel.querySelector("[data-role='copy-string']");

    UI.busy(button, true);
    panel.hidden = false;
    if (title) { title.textContent = I18N.exportStringLoading; }
    if (error) { error.hidden = true; error.textContent = ""; }

    try {
        const response = await fetch(exportUrl, { headers: { "Accept": "application/json" } });
        const payload = await response.json();
        if (!response.ok) { throw new Error(payload.error || I18N.exportStringError); }
        if (title) { title.textContent = I18N.exportStringReady; }
        if (textarea) { textarea.value = payload.session_string || ""; }
        if (copyButton) { copyButton.disabled = !(payload.session_string || ""); }
    } catch (errorObject) {
        if (textarea) { textarea.value = ""; }
        if (copyButton) { copyButton.disabled = true; }
        if (title) { title.textContent = I18N.exportStringError; }
        if (error) {
            error.textContent = errorObject.message || I18N.exportStringError;
            error.hidden = false;
        }
    } finally {
        UI.busy(button, false);
    }
}

function renderAttentionQueue(sessions) {
    const attention = (sessions || []).filter((session) => session.status.kind !== "connected").slice(0, 8);
    return attention.map((session) => {
        const isError = session.status.kind !== "connecting";
        return `<button type="button" class="attention-card${isError ? " attention-card--error" : ""}" onclick="openSessionModalBySessionKey('${esc(session.id)}')">
            <span class="attention-card__title">
                <span class="${isError ? "dot dot--danger" : "dot dot--warning dot--pulse"}"></span>
                <span>${esc(session.key)}</span>
                <span class="badge ${isError ? "badge--danger" : "badge--warning"}">${esc(statusLabel(session.status.kind))}</span>
            </span>
            ${session.status.error ? `<span class="attention-card__error clamp-2">${esc(session.status.error)}</span>` : ""}
            <span class="attention-card__meta mono">${esc(session.phone)} · ${esc(session.latest_message_at || "-")}</span>
        </button>`;
    }).join("");
}

function renderRecentActivity(sessions) {
    const recent = (sessions || []).slice(0, 12);
    if (recent.length === 0) {
        return `<div class="empty empty--compact" style="border:0;border-radius:0"><span class="empty__icon">${UI.icon("activity")}</span><p class="empty__desc">${esc(I18N.recentActivityEmpty)}</p></div>`;
    }
    return recent.map((session) => {
        const maskedPhone = session.masked_phone || session.phone || "";
        const phone = session.phone && session.phone !== maskedPhone
            ? `<button type="button" class="phone-toggle" data-phone="${esc(session.phone)}" data-masked-phone="${esc(maskedPhone)}" data-revealed="false" title="${esc(I18N.phoneReveal)}" aria-label="${esc(I18N.phoneReveal)}" onclick="toggleMaskedPhone(this)">${UI.icon("eye")}<span data-role="phone-value">${esc(maskedPhone)}</span></button>`
            : `<span class="phone-toggle">${esc(maskedPhone)}</span>`;
        return `<div class="activity-item" data-otp-scope data-latest-code-expires-at="${esc(session.latest_code_expires_at_unix || "")}">
            <span class="${dotClass(session.status.kind)}"></span>
            <div class="activity-item__main">
                <p class="row__title"><span>${esc(session.key)}</span>${phone}</p>
                <p class="row__meta"><span class="clamp-1">${esc(session.note || I18N.noNote)}</span><span class="mono">${esc(session.latest_message_at || "-")}</span><span data-role="otp-visibility-label" class="mono"></span></p>
            </div>
            <button type="button" class="activity-item__code" data-role="recent-activity-code" data-code="${esc(session.latest_code || "")}" data-copied="${esc(I18N.copied)}" title="${esc(I18N.copy)}" aria-label="${esc(I18N.copy)}" onclick="copyWorkspaceCode(this)" ${session.latest_code ? "" : "disabled"}>${esc(session.latest_code || I18N.otpPlaceholder)}</button>
            <button type="button" class="btn btn--ghost btn--icon btn--sm" onclick="openSessionModalBySessionKey('${esc(session.id)}')" aria-label="${esc(I18N.openDetails)}" title="${esc(I18N.openDetails)}">${UI.icon("chevron-right")}</button>
        </div>`;
    }).join("");
}

function updateWorkspaceMeta(snapshot) {
    const setAll = (role, value) => document.querySelectorAll(`[data-role='${role}']`).forEach((element) => { element.textContent = value; });
    setAll("total-count", snapshot.total_count);
    setAll("connected-count", snapshot.connected_count);
    setAll("connecting-count", snapshot.connecting_count);
    setAll("error-count", snapshot.error_count);
    setAll("attention-count", snapshot.connecting_count + snapshot.error_count);
    setAll("updated-at", snapshot.generated_at);

    const attentionWrap = document.querySelector("[data-role='attention-wrap']");
    if (attentionWrap) { attentionWrap.hidden = snapshot.connecting_count + snapshot.error_count === 0; }
    document.querySelectorAll("[data-role='attention-list']").forEach((element) => {
        element.innerHTML = renderAttentionQueue(snapshot.sessions);
    });
    document.querySelectorAll("[data-role='recent-activity-list']").forEach((element) => {
        element.innerHTML = renderRecentActivity(snapshot.sessions);
        refreshOtpVisibility(element);
    });
}

function currentPageSessionKeys() {
    return Array.from(document.querySelectorAll("[data-session-card]")).map((element) => element.dataset.sessionKey).sort();
}

function initSessionModal(modal) {
    UI.panels(modal, { hash: false, defaultId: "overview" });
    modal.addEventListener("sheet:close", () => refreshNewBadges());
}

// Sessions were added or removed: re-render only the list and its detail sheets
// from a fresh copy of this page instead of reloading everything.
async function swapSessionMarkup() {
    const response = await fetch(`${window.location.pathname}${window.location.search}`, { headers: { "Accept": "text/html" }, cache: "no-store" });
    if (!response.ok || new URL(response.url).pathname !== window.location.pathname) { return false; }
    const next = new DOMParser().parseFromString(await response.text(), "text/html");
    const nextPanel = next.querySelector("[data-panel='telegram']");
    const currentPanel = document.querySelector("[data-panel='telegram']");
    const nextToolbar = next.querySelector("#telegram-panels > .toolbar");
    const currentToolbar = document.querySelector("#telegram-panels > .toolbar");
    if (!nextPanel || !currentPanel) { return false; }

    const search = currentToolbar ? currentToolbar.querySelector("[data-filter-input]") : null;
    const query = search ? search.value : "";
    currentPanel.replaceChildren(...Array.from(nextPanel.childNodes, (node) => document.importNode(node, true)));
    if (nextToolbar && currentToolbar && !!nextToolbar.querySelector("[data-filter-input]") !== !!search) {
        const freshToolbar = document.importNode(nextToolbar, true);
        currentToolbar.replaceWith(freshToolbar);
        UI.enhance(freshToolbar);
        const freshSearch = freshToolbar.querySelector("[data-filter-input]");
        if (freshSearch) { freshSearch.addEventListener("input", () => UI.refilter(document.getElementById("telegram-panels"))); }
        const controller = document.getElementById("telegram-panels").__panels;
        if (controller) { controller.activate(controller.current, { updateHash: false }); }
    }

    const anchor = document.getElementById("toasts");
    document.querySelectorAll("[data-session-modal]").forEach((modal) => modal.remove());
    next.querySelectorAll("[data-session-modal]").forEach((modal) => {
        const fresh = document.importNode(modal, true);
        anchor.parentNode.insertBefore(fresh, anchor);
        UI.enhance(fresh);
        initSessionModal(fresh);
    });
    if (search) { search.value = query; }
    UI.refilter(document.getElementById("telegram-panels"));
    return true;
}

async function syncWorkspace(forceFull) {
    if (workspaceSyncInFlight || document.hidden) { return; }
    workspaceSyncInFlight = true;
    try {
        const response = await fetch(SNAPSHOT_API, { headers: { "Accept": "application/json" }, cache: "no-store" });
        if (!response.ok) { return; }
        const snapshot = await response.json();
        const currentKeys = currentPageSessionKeys();
        const nextKeys = snapshot.sessions.map((session) => session.id).sort();
        if (currentKeys.join("|") !== nextKeys.join("|")) {
            if (document.querySelector(".sheet[data-state='open']")) { return; }
            if (await swapSessionMarkup()) {
                updateWorkspaceMeta(snapshot);
                refreshNewBadges();
                refreshOtpVisibility();
            }
            return;
        }
        updateWorkspaceMeta(snapshot);
        snapshot.sessions.forEach((session) => {
            const card = findSessionCard(session.id);
            const modal = findSessionModal(session.id);
            if (card) { applySessionCardUpdate(card, session, { silent: forceFull }); }
            if (modal) {
                applySessionModalUpdate(modal, session);
                if (modal.dataset.state === "open") { markSessionSeen(session.id, session.latest_code_at_unix || ""); }
            }
        });
        UI.refilter(document.getElementById("telegram-panels"));
        refreshNewBadges();
    } catch (_) {
        // Ignore transient sync failures.
    } finally {
        workspaceSyncInFlight = false;
    }
}

window.addEventListener("DOMContentLoaded", () => {
    UI.panels(document.getElementById("telegram-panels"), {
        aliases: { sessions: "telegram" },
        defaultId: "telegram"
    });
    document.querySelectorAll("[data-session-modal]").forEach(initSessionModal);
    refreshNewBadges();
    refreshOtpVisibility();

    window.setInterval(() => syncWorkspace(false), TELEGRAM_WORKSPACE_INCREMENTAL_REFRESH_MS);
    window.setInterval(() => syncWorkspace(true), TELEGRAM_WORKSPACE_FULL_REFRESH_MS);
    window.setInterval(() => refreshOtpVisibility(), 1000);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) { syncWorkspace(true); } });
});
