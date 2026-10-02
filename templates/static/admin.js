// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

function adminEsc(value) { return UI.escapeHtml(value); }
function adminInitial(name) { return (Array.from(String(name || "?").trim())[0] || "?").toUpperCase(); }

function adminUserBadges(user, config, large) {
    const size = large ? " badge--lg" : "";
    const badges = [`<span class="badge${user.role === "admin" ? " badge--accent" : ""}${size}">${adminEsc(user.role === "admin" ? config.role_admin_label : config.role_user_label)}</span>`];
    if (user.locked) { badges.push(`<span class="badge badge--danger${size}">${adminEsc(config.locked_badge_label)}</span>`); }
    if (user.banned) { badges.push(`<span class="badge badge--solid-danger${size}">${adminEsc(config.banned_badge_label)}</span>`); }
    return badges.join("");
}

function adminUsersListMarkup(items, selectedUserId, config) {
    if (!Array.isArray(items) || items.length === 0) {
        return `<div class="empty empty--compact" style="border:0;border-radius:0"><p class="empty__desc">${adminEsc(config.no_matches_label)}</p></div>`;
    }
    return items.map((user) => `
        <button type="button" class="row row--interactive${user.id === selectedUserId ? " is-selected" : ""}" data-admin-user-pick="${adminEsc(user.id)}">
            <span class="avatar avatar--sm avatar--round${user.banned || user.locked ? " avatar--danger" : ""}">${adminEsc(adminInitial(user.username))}</span>
            <span class="row__main">
                <span class="row__title"><span>${adminEsc(user.username)}</span>${adminUserBadges(user, config, false)}</span>
                <span class="row__meta"><span class="mono">${adminEsc(user.last_login_ip || "-")}</span><span>${adminEsc(user.last_auth_method || "-")}</span></span>
            </span>
            <span class="row__aside"><span class="count" title="${adminEsc(config.user_active_sessions_label)}">${user.active_sessions}</span>${UI.icon("chevron-right", "icon--sm row__chev")}</span>
        </button>`).join("");
}

function adminUserDetailMarkup(user, config) {
    if (!user) {
        return `<div class="empty"><span class="empty__icon">${UI.icon("user")}</span><p class="empty__desc">${adminEsc(config.select_user_label)}</p></div>`;
    }
    const id = encodeURIComponent(user.id);
    const lang = encodeURIComponent(config.lang);
    const statusBadges = [
        `<span class="badge badge--lg ${user.totp_enabled ? "badge--success" : ""}">${adminEsc(user.totp_enabled ? config.totp_enabled_badge_label : config.totp_missing_badge_label)}</span>`,
        `<span class="badge badge--lg ${!user.password_ready ? "badge--danger" : user.password_reset_required ? "badge--warning" : ""}">${adminEsc(!user.password_ready ? config.password_missing_badge_label : user.password_reset_required ? config.password_reset_badge_label : config.password_ready_badge_label)}</span>`
    ].join("");
    const lastAuth = user.last_auth_at_unix
        ? `<p class="tile__value text-sm">${adminEsc(user.last_auth_method || "-")} · <span class="badge ${user.last_auth_success ? "badge--success" : "badge--danger"}">${adminEsc(user.last_auth_success ? config.audit_success_label : config.audit_failure_label)}</span></p><p class="tile__hint mono">${adminEsc(UI.formatUnix(user.last_auth_at_unix))}</p>`
        : `<p class="tile__value text-sm">-</p>`;
    const ban = user.banned
        ? `<div class="alert alert--danger">${UI.icon("ban")}<div class="alert__body">
            <p class="alert__title">${adminEsc(user.ban_remaining_label ? `${config.ban_remaining_label} ${user.ban_remaining_label}` : config.ban_permanent_label)}</p>
            ${user.ban_until_label ? `<p class="alert__text">${adminEsc(config.ban_until_label)} ${adminEsc(user.ban_until_label)}</p>` : ""}
            ${user.ban_reason ? `<p class="alert__text">${adminEsc(config.ban_reason_label)} ${adminEsc(user.ban_reason)}</p>` : ""}
        </div></div>`
        : "";
    const actions = user.is_admin ? "" : `
        <div class="tool-card">
            <div class="grid grid--tight" style="grid-template-columns:repeat(2,minmax(0,1fr))">
                <form method="post" action="/admin/users/${id}/unlock?lang=${lang}" style="display:flex"><button type="submit" class="btn btn--block">${UI.icon("unlock")}${adminEsc(config.unlock_label)}</button></form>
                <form method="post" action="/admin/users/${id}/sessions/revoke?lang=${lang}" style="display:flex"><button type="submit" class="btn btn--block">${UI.icon("logout")}${adminEsc(config.revoke_sessions_label)}</button></form>
                <form method="post" action="/admin/users/${id}/reset?lang=${lang}" style="display:flex"><button type="submit" class="btn btn--block">${UI.icon("undo")}${adminEsc(config.reset_label)}</button></form>
                <form method="post" data-confirm="${adminEsc(config.delete_confirm_message)}" action="/admin/users/${id}/delete?lang=${lang}" style="display:flex"><button type="submit" class="btn btn--block btn--danger-soft">${UI.icon("trash")}${adminEsc(config.delete_label)}</button></form>
            </div>
        </div>
        <form method="post" action="/admin/users/${id}/ban" class="tool-card tool-card--danger">
            <input type="hidden" name="lang" value="${adminEsc(config.lang)}">
            <div class="grid grid--tight" style="grid-template-columns:minmax(0,0.8fr) minmax(0,1fr)">
                <label class="field"><span class="field__label">${adminEsc(config.ban_duration_value_label)}</span><input type="number" min="1" name="duration_value" class="input"></label>
                <label class="field"><span class="field__label">${adminEsc(config.ban_duration_unit_label)}</span><select name="duration_unit" class="select">${config.ban_duration_options.map((option) => `<option value="${adminEsc(option.value)}">${adminEsc(option.label)}</option>`).join("")}</select></label>
            </div>
            <label class="field"><span class="field__label">${adminEsc(config.ban_reason_label)}</span><input type="text" name="reason" value="${adminEsc(user.ban_reason || "")}" placeholder="${adminEsc(config.ban_reason_placeholder)}" class="input"></label>
            <div class="btn-row">
                <button type="submit" class="btn btn--danger btn--grow">${UI.icon("ban")}${adminEsc(config.ban_label)}</button>
                ${user.banned ? `<button type="submit" formaction="/admin/users/${id}/unban" class="btn btn--success-soft btn--grow">${UI.icon("check")}${adminEsc(config.unban_label)}</button>` : ""}
            </div>
        </form>`;
    return `<div class="stack">
        <div class="card card--pad stack">
            <div class="cluster cluster--nowrap">
                <span class="avatar avatar--lg avatar--round${user.banned || user.locked ? " avatar--danger" : ""}">${adminEsc(adminInitial(user.username))}</span>
                <div class="grow"><p class="card__title truncate" style="font-size:18px">${adminEsc(user.username)}</p><div class="cluster cluster--xs mt-1">${adminUserBadges(user, config, false)}</div></div>
            </div>
            <div class="cluster cluster--xs">${statusBadges}</div>
            <div class="grid grid--tight" style="grid-template-columns:repeat(2,minmax(0,1fr))">
                <div class="tile"><p class="tile__label">${adminEsc(config.user_active_sessions_label)}</p><p class="tile__value tile__value--lg">${user.active_sessions}</p></div>
                <div class="tile"><p class="tile__label">${adminEsc(config.user_recovery_codes_label)}</p><p class="tile__value tile__value--lg">${user.recovery_codes_remaining}</p></div>
                <div class="tile"><p class="tile__label">${adminEsc(config.user_passkeys_label)}</p><p class="tile__value tile__value--lg">${user.passkey_count}</p></div>
                <div class="tile"><p class="tile__label">${adminEsc(config.user_last_ip_label)}</p><p class="tile__value mono text-sm">${adminEsc(user.last_login_ip || "-")}</p></div>
            </div>
            <div class="tile"><p class="tile__label">${adminEsc(config.user_last_auth_label)}</p>${lastAuth}</div>
        </div>
        ${ban}
        ${actions}
    </div>`;
}

function readAdminConfig() {
    const node = document.getElementById("admin-users-config");
    if (!node) { return null; }
    try { return JSON.parse(node.textContent || "null"); } catch (error) { console.error(error); return null; }
}

function attachAdminUserWorkspace() {
    const config = readAdminConfig();
    const form = document.querySelector("[data-admin-users-filter-form]");
    const input = document.querySelector("[data-admin-user-search]");
    const clearButton = document.querySelector("[data-admin-user-clear]");
    const list = document.querySelector("[data-admin-user-results]");
    const detail = document.querySelector("[data-admin-user-detail]");
    const sheetDetail = document.querySelector("[data-admin-user-detail-sheet]");
    const pager = document.querySelector("[data-admin-users-pagination]");
    const pageStates = Array.from(document.querySelectorAll("[data-admin-users-page-state]"));
    if (!config || !input || !list || !detail || !pager) { return; }

    const state = { search: "", page: 1, selectedUserId: "", payload: null, controller: null, debounce: null };
    const inlineDetailVisible = () => detail.offsetParent !== null;

    function renderLoading() {
        list.innerHTML = `<div class="card__body stack stack--sm"><div class="skeleton skeleton-row"></div><div class="skeleton skeleton-row"></div><div class="skeleton skeleton-row"></div></div>`;
    }

    function renderDetail(user) {
        const markup = adminUserDetailMarkup(user, config);
        detail.innerHTML = markup;
        if (sheetDetail) { sheetDetail.innerHTML = markup; }
    }

    function render() {
        const payload = state.payload;
        if (!payload) { renderLoading(); return; }
        document.querySelectorAll("[data-admin-users-filter-count]").forEach((element) => { element.textContent = String(payload.filtered_total); });
        pageStates.forEach((element) => { element.textContent = `${config.page_label} ${payload.page} / ${payload.page_count}`; });
        const items = Array.isArray(payload.items) ? payload.items : [];
        const current = items.find((item) => item.id === state.selectedUserId) || items[0] || null;
        state.selectedUserId = current ? current.id : "";
        list.innerHTML = adminUsersListMarkup(items, state.selectedUserId, config);
        renderDetail(current);
        pager.querySelector("[data-admin-users-prev]").disabled = payload.page <= 1;
        pager.querySelector("[data-admin-users-next]").disabled = payload.page >= payload.page_count;
    }

    async function load() {
        if (state.controller) { state.controller.abort(); }
        const controller = new AbortController();
        state.controller = controller;
        renderLoading();
        const params = new URLSearchParams({ lang: config.lang, page: String(state.page) });
        if (state.search.trim()) { params.set("search", state.search.trim()); }
        try {
            const response = await fetch(`${config.list_endpoint}?${params.toString()}`, { headers: { Accept: "application/json" }, signal: controller.signal });
            if (!response.ok) { throw new Error(`Failed loading users: ${response.status}`); }
            const payload = await response.json();
            if (controller.signal.aborted) { return; }
            state.payload = payload;
            state.page = payload.page || 1;
            if (!payload.items.some((item) => item.id === state.selectedUserId)) {
                state.selectedUserId = payload.items[0] ? payload.items[0].id : "";
            }
            render();
        } catch (error) {
            if (controller.signal.aborted) { return; }
            console.error(error);
            list.innerHTML = adminUsersListMarkup([], "", config);
            renderDetail(null);
        }
    }

    if (form) {
        form.addEventListener("submit", (event) => {
            event.preventDefault();
            state.search = input.value;
            state.page = 1;
            load();
        });
    }
    input.addEventListener("input", () => {
        state.search = input.value;
        state.page = 1;
        window.clearTimeout(state.debounce);
        state.debounce = window.setTimeout(load, 180);
    });
    if (clearButton) {
        clearButton.addEventListener("click", () => {
            input.value = "";
            state.search = "";
            state.page = 1;
            load();
            input.focus();
        });
    }
    list.addEventListener("click", (event) => {
        const button = event.target.closest("[data-admin-user-pick]");
        if (!button) { return; }
        state.selectedUserId = button.dataset.adminUserPick || "";
        render();
        if (!inlineDetailVisible()) { UI.openSheet("admin-user-sheet", button); }
    });
    pager.addEventListener("click", (event) => {
        const action = event.target.closest("[data-admin-users-page-action]");
        if (!action || !state.payload) { return; }
        if (action.dataset.adminUsersPageAction === "previous" && state.payload.page > 1) {
            state.page = state.payload.page - 1;
            load();
        }
        if (action.dataset.adminUsersPageAction === "next" && state.payload.page < state.payload.page_count) {
            state.page = state.payload.page + 1;
            load();
        }
    });
    load();
}

window.addEventListener("DOMContentLoaded", () => {
    const panels = UI.panels(document.getElementById("admin-panels"), {
        aliases: { policy: "registration" },
        storageKey: "hg.admin.panel",
        defaultId: "users"
    });
    document.querySelectorAll("[data-panel-jump]").forEach((link) => {
        link.addEventListener("click", (event) => {
            event.preventDefault();
            panels.activate(link.dataset.panelJump, { scroll: true });
        });
    });

    attachAdminUserWorkspace();

    const auditClear = document.querySelector("[data-admin-audit-clear]");
    const auditSearch = document.querySelector("[data-admin-audit-search]");
    if (auditClear && auditSearch) {
        auditClear.addEventListener("click", () => {
            auditSearch.value = "";
            UI.refilter(auditSearch.closest("[data-filter-scope]"));
            auditSearch.focus();
        });
    }

    document.addEventListener("click", (event) => {
        const row = event.target.closest("[data-admin-audit-row]");
        if (!row) { return; }
        const template = document.getElementById(row.dataset.auditDetail || "");
        const body = document.querySelector("[data-audit-detail-body]");
        if (!template || !body) { return; }
        body.replaceChildren(template.content.cloneNode(true));
        UI.decorateUnix(body);
        const title = document.getElementById("audit-detail-title");
        const label = row.querySelector(".row__title > span");
        if (title) { title.textContent = label ? label.textContent : ""; }
        UI.openSheet("audit-detail-sheet", row);
    });
});
