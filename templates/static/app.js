// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors
// Hanagram UI runtime: sheets, dialogs, toasts, panels, segmented controls, theme.

(function () {
  "use strict";

  const doc = document;
  const root = doc.documentElement;
  const THEME_KEY = "hg-theme";

  const $ = (selector, scope) => (scope || doc).querySelector(selector);
  const $$ = (selector, scope) => Array.from((scope || doc).querySelectorAll(selector));
  const reduceMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const store = {
    get(key, area) {
      try { return window[(area || "local") + "Storage"].getItem(key); } catch (_) { return null; }
    },
    set(key, value, area) {
      try { window[(area || "local") + "Storage"].setItem(key, value); } catch (_) { /* storage unavailable */ }
    },
    remove(key, area) {
      try { window[(area || "local") + "Storage"].removeItem(key); } catch (_) { /* storage unavailable */ }
    }
  };

  // Same page = same canonical URL; POST results are often rendered at the form's action URL.
  const pageKey = () => (doc.body && doc.body.dataset.canonical) || window.location.pathname;

  function label(key, fallback) {
    const value = doc.body && doc.body.dataset ? doc.body.dataset[key] : "";
    return value || fallback || "";
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
    })[char]);
  }

  function icon(name, extraClass) {
    return `<svg class="icon${extraClass ? " " + extraClass : ""}" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
  }

  function ready(fn) {
    if (doc.readyState === "loading") {
      doc.addEventListener("DOMContentLoaded", fn, { once: true });
    } else {
      fn();
    }
  }

  // Pages may be prerendered on hover; defer work with outside effects until shown.
  function whenActivated(fn) {
    if (doc.prerendering) {
      doc.addEventListener("prerenderingchange", () => fn(), { once: true });
    } else {
      fn();
    }
  }

  function formatCountdown(totalSeconds) {
    const remaining = Math.max(0, Math.floor(totalSeconds));
    const hours = Math.floor(remaining / 3600);
    const minutes = Math.floor((remaining % 3600) / 60);
    const seconds = remaining % 60;
    const pad = (n) => String(n).padStart(2, "0");
    return hours > 0 ? `${pad(hours)}:${pad(minutes)}:${pad(seconds)}` : `${pad(minutes)}:${pad(seconds)}`;
  }

  function isEditable(element) {
    if (!element || !(element instanceof HTMLElement)) { return false; }
    if (element.isContentEditable) { return true; }
    const tag = element.tagName.toLowerCase();
    if (tag === "textarea" || tag === "select") { return true; }
    if (tag !== "input") { return false; }
    const type = (element.getAttribute("type") || "text").toLowerCase();
    return !["button", "checkbox", "color", "file", "hidden", "image", "radio", "range", "reset", "submit"].includes(type);
  }

  /* ---------------------------------------------------------------- */
  /* Clipboard                                                        */
  /* ---------------------------------------------------------------- */
  async function copyText(text) {
    if (!text) { return false; }
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function" && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (_) { /* fall through to the legacy path */ }
    }
    const textarea = doc.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;pointer-events:none;";
    doc.body.appendChild(textarea);
    textarea.focus({ preventScroll: true });
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    let copied = false;
    try { copied = doc.execCommand("copy"); } catch (_) { copied = false; }
    doc.body.removeChild(textarea);
    return copied;
  }

  /* ---------------------------------------------------------------- */
  /* Toasts                                                           */
  /* ---------------------------------------------------------------- */
  function toastHost() {
    let host = doc.getElementById("toasts");
    if (!host) {
      host = doc.createElement("div");
      host.id = "toasts";
      host.className = "toasts";
      host.setAttribute("role", "status");
      host.setAttribute("aria-live", "polite");
      doc.body.appendChild(host);
    }
    return host;
  }

  function toast(message, kind, options) {
    if (!message) { return null; }
    const opts = options || {};
    const tone = kind || "info";
    const host = toastHost();
    const iconName = { success: "check-circle", error: "alert", warning: "alert", info: "info" }[tone] || "info";
    const element = doc.createElement("div");
    element.className = `toast toast--${tone}`;
    element.innerHTML = `${icon(iconName)}<span class="toast__msg"></span>`;
    element.querySelector(".toast__msg").textContent = message;
    host.appendChild(element);
    while (host.children.length > 4) { host.firstElementChild.remove(); }

    let removed = false;
    const remove = () => {
      if (removed) { return; }
      removed = true;
      element.classList.add("is-leaving");
      window.setTimeout(() => element.remove(), 260);
    };
    const timer = window.setTimeout(remove, opts.timeout || (tone === "error" ? 5600 : 2600));
    element.addEventListener("click", () => { window.clearTimeout(timer); remove(); });
    return element;
  }

  /* ---------------------------------------------------------------- */
  /* Scroll lock                                                      */
  /* ---------------------------------------------------------------- */
  let scrollLocks = 0;
  function lockScroll() {
    if (scrollLocks === 0) {
      const width = window.innerWidth - root.clientWidth;
      root.style.setProperty("--scrollbar-w", `${Math.max(0, width)}px`);
      root.classList.add("is-scroll-locked");
    }
    scrollLocks += 1;
  }
  function unlockScroll() {
    if (scrollLocks === 0) { return; }
    scrollLocks -= 1;
    if (scrollLocks === 0) { root.classList.remove("is-scroll-locked"); }
  }

  /* ---------------------------------------------------------------- */
  /* Sheets (drawer on desktop, bottom sheet on mobile)               */
  /* ---------------------------------------------------------------- */
  const sheetStack = [];

  function resolveSheet(target) {
    if (!target) { return null; }
    return typeof target === "string" ? doc.getElementById(target) : target;
  }

  function bindSheetDrag(sheet) {
    if (!sheet || sheet.__dragBound) { return; }
    sheet.__dragBound = true;
    const panel = $(".sheet__panel", sheet);
    const handles = [$(".sheet__grab", sheet), $(".sheet__head", sheet)].filter(Boolean);
    if (!panel || handles.length === 0) { return; }
    let startY = 0;
    let delta = 0;
    let startedAt = 0;
    let dragging = false;

    const onDown = (event) => {
      if (window.innerWidth >= 768 || event.button > 0) { return; }
      if (event.target.closest("button, a, input, select, textarea, label, [data-no-drag]")) { return; }
      dragging = true;
      startY = event.clientY;
      delta = 0;
      startedAt = performance.now();
      try { event.currentTarget.setPointerCapture(event.pointerId); } catch (_) { /* ignore */ }
      sheet.classList.add("is-dragging");
    };
    const onMove = (event) => {
      if (!dragging) { return; }
      delta = Math.max(0, event.clientY - startY);
      panel.style.transform = `translate3d(0, ${delta}px, 0)`;
    };
    const onUp = () => {
      if (!dragging) { return; }
      dragging = false;
      sheet.classList.remove("is-dragging");
      const velocity = delta / Math.max(1, performance.now() - startedAt);
      panel.style.transform = "";
      if (delta > 110 || (delta > 24 && velocity > 0.6)) { closeSheet(sheet); }
    };
    handles.forEach((handle) => {
      handle.addEventListener("pointerdown", onDown);
      handle.addEventListener("pointermove", onMove);
      handle.addEventListener("pointerup", onUp);
      handle.addEventListener("pointercancel", onUp);
    });
  }

  function openSheet(target, opener) {
    const sheet = resolveSheet(target);
    if (!sheet || sheet.dataset.state === "open") { return sheet; }
    bindSheetDrag(sheet);
    sheet.__opener = opener || doc.activeElement;
    sheet.removeAttribute("inert");
    sheet.setAttribute("aria-hidden", "false");
    // Force style flush so the enter transition always runs.
    void sheet.offsetWidth;
    sheet.dataset.state = "open";
    sheetStack.push(sheet);
    lockScroll();
    window.setTimeout(() => {
      const focusTarget = $("[autofocus]", sheet) || $(".sheet__panel", sheet);
      if (focusTarget && sheet.dataset.state === "open") { focusTarget.focus({ preventScroll: true }); }
      $$(".seg", sheet).forEach(updateSeg);
    }, 40);
    sheet.dispatchEvent(new CustomEvent("sheet:open", { bubbles: true }));
    return sheet;
  }

  function closeSheet(target) {
    const sheet = resolveSheet(target);
    if (!sheet || sheet.dataset.state !== "open") { return; }
    sheet.dataset.state = "closed";
    sheet.setAttribute("aria-hidden", "true");
    sheet.setAttribute("inert", "");
    const index = sheetStack.indexOf(sheet);
    if (index >= 0) { sheetStack.splice(index, 1); }
    unlockScroll();
    const opener = sheet.__opener;
    if (opener && doc.contains(opener) && typeof opener.focus === "function") {
      opener.focus({ preventScroll: true });
    }
    sheet.dispatchEvent(new CustomEvent("sheet:close", { bubbles: true }));
  }

  /* ---------------------------------------------------------------- */
  /* Confirm dialog                                                   */
  /* ---------------------------------------------------------------- */
  function ensureConfirmSheet() {
    let sheet = doc.getElementById("ui-confirm");
    if (sheet) { return sheet; }
    sheet = doc.createElement("div");
    sheet.id = "ui-confirm";
    sheet.className = "sheet sheet--center sheet--dialog";
    sheet.dataset.state = "closed";
    sheet.setAttribute("aria-hidden", "true");
    sheet.setAttribute("inert", "");
    sheet.setAttribute("role", "alertdialog");
    sheet.setAttribute("aria-modal", "true");
    sheet.innerHTML = `
      <div class="sheet__backdrop" data-act="cancel"></div>
      <div class="sheet__panel" tabindex="-1">
        <div class="sheet__grab"></div>
        <div class="sheet__body">
          <div class="dialog-body">
            <div class="card-icon card-icon--warning" data-role="confirm-icon">${icon("alert")}</div>
            <p class="dialog-body__text" data-role="confirm-text"></p>
          </div>
        </div>
        <div class="sheet__foot">
          <button type="button" class="btn" data-act="cancel"></button>
          <button type="button" class="btn btn--danger" data-act="ok"></button>
        </div>
      </div>`;
    doc.body.appendChild(sheet);
    return sheet;
  }

  function confirmDialog(message, options) {
    const opts = options || {};
    return new Promise((resolve) => {
      const sheet = ensureConfirmSheet();
      const okButton = $("[data-act='ok']", sheet);
      const cancelButton = $(".sheet__foot [data-act='cancel']", sheet);
      const iconBox = $("[data-role='confirm-icon']", sheet);
      $("[data-role='confirm-text']", sheet).textContent = message || "";
      okButton.textContent = opts.okLabel || label("lConfirm", "OK");
      cancelButton.textContent = opts.cancelLabel || label("lCancel", "Cancel");
      const danger = opts.tone !== "neutral";
      okButton.className = `btn ${danger ? "btn--danger" : "btn--primary"}`;
      iconBox.className = `card-icon ${danger ? "card-icon--danger" : "card-icon--accent"}`;

      let settled = false;
      const finish = (value) => {
        if (settled) { return; }
        settled = true;
        sheet.removeEventListener("click", onClick);
        sheet.removeEventListener("sheet:close", onClose);
        closeSheet(sheet);
        resolve(value);
      };
      const onClick = (event) => {
        const act = event.target.closest("[data-act]");
        if (!act) { return; }
        finish(act.dataset.act === "ok");
      };
      const onClose = () => finish(false);
      sheet.addEventListener("click", onClick);
      sheet.addEventListener("sheet:close", onClose);
      openSheet(sheet);
      window.setTimeout(() => (danger ? cancelButton : okButton).focus({ preventScroll: true }), 60);
    });
  }

  /* ---------------------------------------------------------------- */
  /* Popover menus                                                    */
  /* ---------------------------------------------------------------- */
  let openMenuState = null;

  function positionMenu(menu, anchor) {
    const rect = anchor.getBoundingClientRect();
    const width = menu.offsetWidth;
    const height = menu.offsetHeight;
    const pad = 8;
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let top;
    let originY;
    if (vh - rect.bottom >= height + pad || vh - rect.bottom >= rect.top) {
      top = Math.min(rect.bottom + 6, vh - height - pad);
      originY = "top";
    } else {
      top = Math.max(pad, rect.top - height - 6);
      originY = "bottom";
    }
    let left = anchor.dataset.menuAlign === "end" ? rect.right - width : rect.left;
    left = Math.max(pad, Math.min(left, vw - width - pad));
    menu.style.top = `${Math.round(top)}px`;
    menu.style.left = `${Math.round(left)}px`;
    menu.style.setProperty("--menu-origin", `${anchor.dataset.menuAlign === "end" ? "right" : "left"} ${originY}`);
    menu.style.setProperty("--menu-shift", originY === "top" ? "-6px" : "6px");
  }

  function closeMenu() {
    if (!openMenuState) { return; }
    openMenuState.menu.dataset.state = "closed";
    openMenuState.anchor.setAttribute("aria-expanded", "false");
    openMenuState = null;
  }

  function toggleMenu(anchor) {
    const menu = doc.getElementById(anchor.dataset.menuToggle || "");
    if (!menu) { return; }
    if (openMenuState && openMenuState.menu === menu) {
      closeMenu();
      return;
    }
    closeMenu();
    positionMenu(menu, anchor);
    menu.dataset.state = "open";
    anchor.setAttribute("aria-expanded", "true");
    openMenuState = { menu, anchor };
    $$(".seg", menu).forEach(updateSeg);
  }

  /* ---------------------------------------------------------------- */
  /* Segmented controls                                               */
  /* ---------------------------------------------------------------- */
  function updateSeg(seg, instant) {
    if (!seg || !seg.__indicator) { return; }
    const indicator = seg.__indicator;
    const active = $(".seg__btn.is-active", seg);
    if (!active || active.offsetWidth === 0) {
      indicator.style.opacity = "0";
      return;
    }
    if (instant) { indicator.style.transition = "none"; }
    indicator.style.opacity = "1";
    indicator.style.setProperty("--x", `${active.offsetLeft}px`);
    indicator.style.setProperty("--y", `${active.offsetTop}px`);
    indicator.style.setProperty("--w", `${active.offsetWidth}px`);
    indicator.style.setProperty("--h", `${active.offsetHeight}px`);
    if (instant) {
      void indicator.offsetWidth;
      indicator.style.transition = "";
    }
  }

  const segObserver = typeof ResizeObserver === "function"
    ? new ResizeObserver((entries) => entries.forEach((entry) => updateSeg(entry.target, true)))
    : null;

  function initSegs(scope) {
    $$(".seg", scope).forEach((seg) => {
      if (seg.__indicator || !$(".seg__btn", seg)) { return; }
      const indicator = doc.createElement("span");
      indicator.className = "seg__indicator";
      indicator.setAttribute("aria-hidden", "true");
      seg.prepend(indicator);
      seg.__indicator = indicator;
      seg.classList.add("has-indicator");
      updateSeg(seg, true);
      if (segObserver) { segObserver.observe(seg); }
    });
  }

  function revealInScroller(element) {
    if (!element) { return; }
    const scroller = element.parentElement && element.parentElement.closest(".secnav, .seg, .stats");
    if (!scroller || scroller.scrollWidth <= scroller.clientWidth + 2) { return; }
    const rect = element.getBoundingClientRect();
    const box = scroller.getBoundingClientRect();
    const delta = (rect.left + rect.width / 2) - (box.left + box.width / 2);
    scroller.scrollBy({ left: delta, behavior: reduceMotion() ? "auto" : "smooth" });
  }

  /* ---------------------------------------------------------------- */
  /* Panels (hash-aware tab controller)                               */
  /* ---------------------------------------------------------------- */
  // Remembered tabs only come back when the reader returns to a page (reload,
  // back/forward); a fresh visit opens what the link or the server asks for.
  let tabMemory = (() => {
    const entry = performance.getEntriesByType && performance.getEntriesByType("navigation")[0];
    return !!entry && (entry.type === "reload" || entry.type === "back_forward");
  })();

  function currentTabHash() {
    const main = $$("[data-panels]").find((element) => element.__panels && !element.closest(".sheet"));
    return main && main.__panels.current ? `#${main.__panels.current}` : window.location.hash;
  }

  function panels(rootElement, options) {
    const opts = options || {};
    if (!rootElement) { return null; }
    const ownLinks = () => $$("[data-panel-link]", rootElement).filter((link) => link.closest("[data-panels]") === rootElement);
    const ownPanels = () => $$("[data-panel]", rootElement).filter((panel) => panel.closest("[data-panels]") === rootElement);
    const ids = ownPanels().map((panel) => panel.dataset.panel);
    const aliases = opts.aliases || {};
    const useHash = opts.hash !== false;
    // The address bar is left alone (touching it makes browsers flash their
    // loading state); the open tab is remembered per page for reloads instead.
    const memoryKey = useHash ? `hg.panel:${pageKey()}:${rootElement.id || "main"}` : null;
    let current = null;

    const resolve = (raw) => {
      let id = String(raw || "").replace(/^#/, "");
      id = aliases[id] || id;
      return ids.includes(id) ? id : null;
    };

    const scrollIntoPlace = () => {
      const anchor = rootElement.querySelector("[data-panels-anchor]") || rootElement;
      const bar = doc.querySelector(".masthead, .focus__bar");
      const nav = rootElement.querySelector(".secnav");
      const navHeight = nav && getComputedStyle(nav).flexDirection === "row" && getComputedStyle(nav).position === "sticky" ? nav.offsetHeight : 0;
      const offset = (bar ? bar.offsetHeight : 0) + navHeight + 16;
      const top = anchor.getBoundingClientRect().top + window.scrollY - offset;
      if (window.scrollY > top + 4) {
        window.scrollTo({ top: Math.max(0, top), behavior: reduceMotion() ? "auto" : "smooth" });
      }
    };

    function activate(rawId, activateOptions) {
      const aopts = activateOptions || {};
      const id = resolve(rawId) || current || resolve(opts.defaultId) || ids[0];
      if (!id) { return null; }
      const changed = id !== current;
      current = id;
      let activeLink = null;
      ownLinks().forEach((link) => {
        const on = link.dataset.panelLink === id;
        link.classList.toggle("is-active", on);
        if (link.getAttribute("role") === "tab") {
          link.setAttribute("aria-selected", on ? "true" : "false");
        } else if (on) {
          link.setAttribute("aria-current", "page");
        } else {
          link.removeAttribute("aria-current");
        }
        if (on && !activeLink) { activeLink = link; }
      });
      ownPanels().forEach((panel) => panel.classList.toggle("is-active", panel.dataset.panel === id));
      if (opts.storageKey) { store.set(opts.storageKey, id, "session"); }
      if (memoryKey) {
        store.set(memoryKey, JSON.stringify({ id, hash: window.location.hash }), "session");
      }
      const segs = new Set(ownLinks().map((link) => link.closest(".seg")).filter(Boolean));
      segs.forEach((seg) => updateSeg(seg));
      if (activeLink) { revealInScroller(activeLink); }
      if (aopts.scroll && changed) { scrollIntoPlace(); }
      if (changed && typeof opts.onChange === "function") { opts.onChange(id); }
      return id;
    }

    rootElement.addEventListener("click", (event) => {
      const link = event.target.closest("[data-panel-link]");
      if (!link || link.closest("[data-panels]") !== rootElement) { return; }
      if (event.metaKey || event.ctrlKey || event.shiftKey) { return; }
      event.preventDefault();
      activate(link.dataset.panelLink, { scroll: true });
    });

    if (useHash) {
      window.addEventListener("hashchange", () => {
        if (resolve(window.location.hash)) {
          activate(window.location.hash, { updateHash: false, scroll: true });
        }
      });
    }

    rootElement.addEventListener("submit", (event) => {
      if (!opts.storageKey || !current) { return; }
      const panel = event.target.closest("[data-panel]");
      if (panel && panel.closest("[data-panels]") === rootElement) {
        store.set(opts.storageKey, panel.dataset.panel, "session");
      }
    }, true);

    let remembered = null;
    try { remembered = memoryKey ? JSON.parse(store.get(memoryKey, "session") || "null") : null; } catch (_) { remembered = null; }
    // Same URL hash as when the tab was picked: the reader reloaded, keep their tab.
    // A different hash means they followed a deep link, so the link wins.
    const fromMemory = tabMemory && remembered && remembered.hash === window.location.hash ? resolve(remembered.id) : null;
    const initial = (useHash && (fromMemory || resolve(window.location.hash)))
      || resolve(opts.initial)
      || (opts.storageKey && resolve(store.get(opts.storageKey, "session")))
      || resolve(opts.defaultId)
      || ids[0];
    activate(initial, { updateHash: false });

    const controller = {
      activate,
      resolve,
      get current() { return current; }
    };
    rootElement.__panels = controller;
    return controller;
  }

  /* ---------------------------------------------------------------- */
  /* Small helpers                                                    */
  /* ---------------------------------------------------------------- */
  function busy(button, on) {
    if (!button) { return; }
    const enabled = on !== false;
    button.classList.toggle("is-loading", enabled);
    button.disabled = enabled;
    if (enabled) { button.setAttribute("aria-busy", "true"); } else { button.removeAttribute("aria-busy"); }
  }

  function status(element, kind, message) {
    if (!element) { return; }
    if (!message) {
      element.hidden = true;
      element.textContent = "";
      return;
    }
    const tone = kind || "loading";
    element.hidden = false;
    element.className = `inline-status inline-status--${tone}${element.dataset.statusClass ? ` ${element.dataset.statusClass}` : ""}`;
    const glyph = tone === "loading"
      ? "<span class=\"spinner\"></span>"
      : icon(tone === "success" ? "check-circle" : tone === "error" ? "alert" : "info");
    element.innerHTML = `${glyph}<span></span>`;
    element.lastElementChild.textContent = message;
  }

  async function fetchJson(url, options) {
    const opts = options || {};
    const headers = { Accept: "application/json" };
    let body = opts.body;
    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.json);
    } else if (opts.form !== undefined) {
      headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8";
      body = new URLSearchParams(opts.form).toString();
    }
    const response = await fetch(url, {
      method: opts.method || (body !== undefined ? "POST" : "GET"),
      headers,
      body,
      signal: opts.signal,
      cache: "no-store",
      credentials: "same-origin"
    });
    const contentType = response.headers.get("content-type") || "";
    let data = null;
    if (contentType.includes("application/json")) {
      data = await response.json().catch(() => null);
    }
    return { response, ok: response.ok, status: response.status, data };
  }

  function formatUnix(unix) {
    const value = Number(unix);
    if (!Number.isFinite(value) || value <= 0) { return "-"; }
    return new Intl.DateTimeFormat(root.lang || undefined, {
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"
    }).format(new Date(value * 1000));
  }

  function decorateUnix(scope) {
    $$("[data-unix]", scope).forEach((element) => {
      const unix = Number(element.dataset.unix);
      if (!Number.isFinite(unix) || unix <= 0) { return; }
      const rendered = formatUnix(unix);
      element.textContent = rendered;
      element.title = `${rendered} (${unix})`;
    });
  }

  function runFilter(input) {
    const scope = input.closest("[data-filter-scope]") || doc;
    const selector = input.dataset.filterInput;
    if (!selector) { return; }
    const query = input.value.trim().toLowerCase();
    let visible = 0;
    let total = 0;
    $$(selector, scope).forEach((item) => {
      total += 1;
      const haystack = (item.dataset.filterText || item.textContent || "").toLowerCase();
      const match = !query || haystack.includes(query);
      item.hidden = !match;
      if (match) { visible += 1; }
    });
    $$("[data-filter-empty]", scope).forEach((element) => { element.hidden = !query || visible !== 0 || total === 0; });
    $$("[data-filter-count]", scope).forEach((element) => { element.textContent = String(visible); });
  }

  function refilter(scope) {
    $$("[data-filter-input]", scope).forEach(runFilter);
  }

  /* ---------------------------------------------------------------- */
  /* Theme                                                            */
  /* ---------------------------------------------------------------- */
  function currentTheme() {
    const stored = store.get(THEME_KEY);
    return stored === "light" || stored === "dark" ? stored : "system";
  }

  function syncThemeControls(mode) {
    $$("[data-theme-choice]").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.themeChoice === mode);
      button.setAttribute("aria-pressed", button.dataset.themeChoice === mode ? "true" : "false");
    });
    $$("[data-theme-choice]").map((button) => button.closest(".seg")).filter(Boolean).forEach((seg) => updateSeg(seg));
    const meta = $("meta[name='theme-color']");
    if (meta) {
      const bg = getComputedStyle(root).getPropertyValue("--bg").trim();
      if (bg) { meta.setAttribute("content", bg); }
    }
  }

  function applyTheme(mode, origin) {
    const next = mode === "light" || mode === "dark" ? mode : "system";
    store.set(THEME_KEY, next);
    const run = () => {
      if (next === "system") { root.removeAttribute("data-theme"); } else { root.dataset.theme = next; }
      syncThemeControls(next);
    };
    if (typeof doc.startViewTransition !== "function" || reduceMotion()) {
      run();
      return;
    }
    // New ink spreads outward from the control that was pressed.
    const rect = origin && origin.getBoundingClientRect ? origin.getBoundingClientRect() : null;
    const x = rect ? rect.left + rect.width / 2 : window.innerWidth / 2;
    const y = rect ? rect.top + rect.height / 2 : 0;
    const radius = Math.hypot(Math.max(x, window.innerWidth - x), Math.max(y, window.innerHeight - y));
    root.classList.add("is-theme-switching");
    const transition = doc.startViewTransition(run);
    transition.ready.then(() => {
      root.animate(
        { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${radius}px at ${x}px ${y}px)`] },
        { duration: 560, easing: "cubic-bezier(0.16, 1, 0.3, 1)", pseudoElement: "::view-transition-new(root)" }
      );
    }).catch(() => {});
    const done = () => root.classList.remove("is-theme-switching");
    transition.finished.then(done, done);
  }

  /* ---------------------------------------------------------------- */
  /* Global delegation                                                */
  /* ---------------------------------------------------------------- */
  doc.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof Element)) { return; }

    const sheetOpen = target.closest("[data-sheet-open]");
    if (sheetOpen) {
      event.preventDefault();
      openSheet(sheetOpen.dataset.sheetOpen, sheetOpen);
      return;
    }

    const sheetClose = target.closest("[data-sheet-close]");
    if (sheetClose) {
      event.preventDefault();
      closeSheet(sheetClose.dataset.sheetClose || sheetClose.closest(".sheet"));
      return;
    }

    const menuToggle = target.closest("[data-menu-toggle]");
    if (menuToggle) {
      event.preventDefault();
      toggleMenu(menuToggle);
      return;
    }

    const themeChoice = target.closest("[data-theme-choice]");
    if (themeChoice) {
      applyTheme(themeChoice.dataset.themeChoice, themeChoice);
      return;
    }

    const langLink = target.closest("a[data-lang-link]");
    if (langLink) {
      const url = new URL(langLink.getAttribute("href"), window.location.origin);
      const canonical = (doc.body && doc.body.dataset.canonical) || window.location.pathname;
      url.searchParams.set("return_to", `${canonical}${window.location.search}${currentTabHash()}`);
      langLink.setAttribute("href", `${url.pathname}${url.search}`);
      return;
    }

    const copyButton = target.closest("[data-copy], [data-copy-target]");
    if (copyButton) {
      event.preventDefault();
      let text = copyButton.dataset.copy || "";
      if (!text && copyButton.dataset.copyTarget) {
        const source = doc.querySelector(copyButton.dataset.copyTarget);
        text = source ? (source.value !== undefined && source.tagName !== "DIV" ? source.value : source.textContent || "").trim() : "";
      }
      const ok = await copyText(text);
      toast(ok ? label("lCopied", "Copied") : label("lCopyFailed", "Copy failed"), ok ? "success" : "error");
      return;
    }

    const dismiss = target.closest("[data-dismiss]");
    if (dismiss) {
      const box = dismiss.closest(".alert, [data-dismissible]");
      if (box) {
        if (box.dataset.dismissKey) { store.set(`hg.dismiss.${box.dataset.dismissKey}`, "1", "session"); }
        box.classList.add("is-leaving");
        window.setTimeout(() => box.remove(), 280);
      }
      return;
    }

    const clampText = target.closest(".alert--clamp .alert__text");
    if (clampText) {
      clampText.closest(".alert").classList.toggle("is-expanded");
    }
  });

  doc.addEventListener("pointerdown", (event) => {
    if (!openMenuState) { return; }
    if (openMenuState.menu.contains(event.target) || openMenuState.anchor.contains(event.target)) { return; }
    closeMenu();
  });

  window.addEventListener("resize", closeMenu);
  window.addEventListener("scroll", () => { if (openMenuState) { closeMenu(); } }, { passive: true });

  doc.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (openMenuState) {
        closeMenu();
        return;
      }
      const top = sheetStack[sheetStack.length - 1];
      if (top) {
        event.preventDefault();
        closeSheet(top);
      }
      return;
    }
    if (event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey && !isEditable(event.target)) {
      const search = $$("[data-hotkey-search]").find((element) => element.offsetParent !== null);
      if (search) {
        event.preventDefault();
        search.focus();
        search.select();
      }
    }
  });

  // Forms with data-confirm get a styled confirmation dialog.
  doc.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.dataset.confirm) { return; }
    if (form.__confirmed) {
      form.__confirmed = false;
      return;
    }
    event.preventDefault();
    event.stopImmediatePropagation();
    const submitter = event.submitter || null;
    const ok = await confirmDialog(form.dataset.confirm, { tone: form.dataset.confirmTone || "danger" });
    if (!ok) { return; }
    form.__confirmed = true;
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit(submitter && submitter.form === form ? submitter : undefined);
    } else {
      form.submit();
    }
  }, true);

  // Visual feedback for regular form submissions.
  doc.addEventListener("submit", (event) => {
    if (event.defaultPrevented) { return; }
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.hasAttribute("data-no-busy")) { return; }
    const button = event.submitter;
    if (button && button.classList && button.classList.contains("btn")) {
      button.classList.add("is-loading");
    }
  });

  window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
      $$(".btn.is-loading").forEach((button) => button.classList.remove("is-loading"));
    }
  });

  /* ---------------------------------------------------------------- */
  /* Stay in place across POST → redirect → same page                 */
  /* ---------------------------------------------------------------- */
  const RESTORE_KEY = "hg.restore";

  function readRestore() {
    try {
      const saved = JSON.parse(store.get(RESTORE_KEY, "session") || "null");
      return saved && Date.now() - Number(saved.at || 0) <= 20000 ? saved : null;
    } catch (_) {
      return null;
    }
  }

  // A page rendered as the answer to a form post shows its canonical URL, so a
  // refresh reloads the page instead of re-sending the form.
  (function adoptCanonicalUrl() {
    const canonical = doc.body && doc.body.dataset.canonical;
    if (!readRestore() || !canonical || window.location.pathname === canonical) { return; }
    history.replaceState(history.state, "", `${canonical}${window.location.hash}`);
  })();

  doc.addEventListener("submit", (event) => {
    if (event.defaultPrevented) { return; }
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.hasAttribute("data-no-restore")) { return; }
    if ((form.getAttribute("method") || "get").toLowerCase() !== "post") { return; }
    if (form.target && form.target !== "_self") { return; }
    store.set(RESTORE_KEY, JSON.stringify({ page: pageKey(), y: Math.round(window.scrollY), at: Date.now() }), "session");
  });

  function restorePosition() {
    const saved = readRestore();
    store.remove(RESTORE_KEY, "session");
    if (!saved || saved.page !== pageKey()) { return; }
    const top = Math.min(Number(saved.y) || 0, Math.max(0, doc.documentElement.scrollHeight - window.innerHeight));
    if (top <= 0) { return; }
    window.scrollTo({ top, behavior: "instant" });
    // The result banner sits at the top of the page; echo it as a toast when it is out of view.
    const banner = $(".alerts .alert[role='status']");
    const bar = $(".masthead, .focus__bar");
    if (banner && banner.getBoundingClientRect().bottom < (bar ? bar.offsetHeight : 0) + 8) {
      const body = $(".alert__body", banner);
      const text = body ? body.textContent.trim() : "";
      if (text) { toast(text, banner.classList.contains("alert--success") ? "success" : "error"); }
    }
  }

  doc.addEventListener("prerenderingchange", () => {
    const mode = currentTheme();
    if (mode === "system") { root.removeAttribute("data-theme"); } else { root.dataset.theme = mode; }
    syncThemeControls(mode);
  }, { once: true });

  /** Wires up markup that was inserted after load (segments, sheets, timestamps). */
  function enhance(scope) {
    if (!scope) { return; }
    initSegs(scope);
    decorateUnix(scope);
    if (scope.matches && scope.matches(".sheet")) { bindSheetDrag(scope); }
    $$(".sheet", scope).forEach(bindSheetDrag);
  }

  function initDocument() {
    initSegs(doc);
    syncThemeControls(currentTheme());
    decorateUnix(doc);
    $$("[data-filter-input]").forEach((input) => {
      input.addEventListener("input", () => runFilter(input));
      runFilter(input);
    });
    $$("[data-autodismiss]").forEach((element) => {
      const delay = Number(element.dataset.autodismiss) || 4500;
      window.setTimeout(() => {
        element.classList.add("is-leaving");
        window.setTimeout(() => element.remove(), 300);
      }, delay);
    });
    $$(".sheet").forEach(bindSheetDrag);
  }

  ready(() => {
    initDocument();
    // After every page script's DOMContentLoaded handler has picked its panel.
    window.requestAnimationFrame(() => {
      restorePosition();
      restoreReloadScroll();
    });
  });

  /* ---------------------------------------------------------------- */
  /* Soft navigation between the main sections                        */
  /* ---------------------------------------------------------------- */
  // Main sections swap in place: the masthead and tab bar stay on screen, the
  // page content is replaced and its scripts run again. Forms, multi-step
  // flows, downloads and anything unexpected still navigate normally.
  const SOFT_PATHS = new Set(["/", "/platforms/telegram", "/platforms/steam", "/settings", "/settings/notifications", "/admin"]);
  const pageScope = { tracking: false, intervals: new Set(), listeners: [], readyQueue: null };
  const nativeSetInterval = window.setInterval.bind(window);
  const nativeClearInterval = window.clearInterval.bind(window);

  // Polling intervals and window/document listeners belong to the page that
  // registered them and are dropped when it is swapped out.
  window.setInterval = function (handler, delay, ...args) {
    const id = nativeSetInterval(handler, delay, ...args);
    if (pageScope.tracking) { pageScope.intervals.add(id); }
    return id;
  };
  window.clearInterval = function (id) {
    pageScope.intervals.delete(id);
    nativeClearInterval(id);
  };
  [window, doc].forEach((target) => {
    const nativeAdd = target.addEventListener;
    target.addEventListener = function (type, listener, options) {
      if (pageScope.tracking) {
        if (pageScope.readyQueue && (type === "DOMContentLoaded" || type === "load")) {
          pageScope.readyQueue.push(listener);
          return undefined;
        }
        pageScope.listeners.push([target, type, listener, options]);
      }
      return nativeAdd.call(this, type, listener, options);
    };
  });

  function teardownPage() {
    pageScope.listeners.forEach(([target, type, listener, options]) => target.removeEventListener(type, listener, options));
    pageScope.listeners = [];
    pageScope.intervals.forEach((id) => nativeClearInterval(id));
    pageScope.intervals.clear();
    closeMenu();
    sheetStack.length = 0;
    scrollLocks = 0;
    root.classList.remove("is-scroll-locked");
    if (segObserver) { segObserver.disconnect(); }
  }

  const SCROLL_KEY = "hg.scroll:";
  if ("scrollRestoration" in history) { history.scrollRestoration = "manual"; }
  window.addEventListener("pagehide", () => {
    store.set(SCROLL_KEY + window.location.pathname + window.location.search, String(Math.round(window.scrollY)), "session");
  });
  function restoreReloadScroll() {
    const entry = performance.getEntriesByType && performance.getEntriesByType("navigation")[0];
    if (!entry || (entry.type !== "reload" && entry.type !== "back_forward")) { return; }
    const y = Number(store.get(SCROLL_KEY + window.location.pathname + window.location.search, "session") || 0);
    if (y > 0) { window.scrollTo({ top: y, behavior: "instant" }); }
  }

  const pageCacheKey = (url) => `${url.origin}${url.pathname}${url.search}`;
  const prefetched = new Map();

  function fetchPage(href) {
    return fetch(href, { headers: { Accept: "text/html" }, credentials: "same-origin", cache: "no-store" })
      .then(async (response) => ({ ok: response.ok, url: response.url, type: response.headers.get("content-type") || "", html: await response.text() }));
  }

  function prefetchPage(url) {
    const key = pageCacheKey(url);
    const hit = prefetched.get(key);
    if (hit && Date.now() - hit.at < 8000) { return hit.promise; }
    const promise = fetchPage(url.href);
    promise.catch(() => prefetched.delete(key));
    prefetched.set(key, { promise, at: Date.now() });
    return promise;
  }

  function softTarget(link) {
    if (!link || !SOFT_PATHS.has(pageKey()) || typeof DOMParser !== "function") { return null; }
    if (link.target || link.hasAttribute("download") || link.hasAttribute("data-no-soft")) { return null; }
    let url;
    try { url = new URL(link.href, window.location.href); } catch (_) { return null; }
    if (url.origin !== window.location.origin || !SOFT_PATHS.has(url.pathname)) { return null; }
    if (url.pathname === window.location.pathname && url.search === window.location.search) { return null; }
    return url;
  }

  const stylesheetOf = (source) => {
    const link = source.querySelector("link[rel='stylesheet'][href^='/static/']");
    return link ? link.getAttribute("href") : "";
  };
  const navSignature = (element) => $$("[data-nav]", element).map((item) => item.getAttribute("href")).join("|");

  function compatiblePage(next) {
    const body = next.body;
    if (!body || !body.hasAttribute("data-page") || !SOFT_PATHS.has(body.dataset.canonical || "")) { return false; }
    if (next.querySelector("meta[http-equiv='refresh' i]")) { return false; }
    return stylesheetOf(next) === stylesheetOf(doc);
  }

  // Scripts parsed by DOMParser never run; fresh copies do once inserted.
  function revive(scope, loads) {
    $$("script", scope).forEach((old) => {
      const script = doc.createElement("script");
      Array.from(old.attributes).forEach((attr) => script.setAttribute(attr.name, attr.value));
      if (old.src) {
        script.async = false;
        loads.push(new Promise((resolve) => {
          script.addEventListener("load", resolve, { once: true });
          script.addEventListener("error", resolve, { once: true });
        }));
      } else {
        script.textContent = old.textContent;
      }
      old.replaceWith(script);
    });
  }

  function swapDocument(next) {
    const loads = [];
    const imported = (node) => doc.importNode(node, true);
    doc.title = next.title;
    Array.from(doc.body.attributes).forEach((attr) => doc.body.removeAttribute(attr.name));
    Array.from(next.body.attributes).forEach((attr) => doc.body.setAttribute(attr.name, attr.value));

    const app = $(".app");
    const nextApp = $(".app", next);
    const masthead = app && $(".masthead", app);
    const nextMasthead = nextApp && $(".masthead", nextApp);
    if (masthead && nextMasthead && navSignature(masthead) === navSignature(nextMasthead) && $("#main", nextApp)) {
      // Keep the shell element in place so the nav marks can animate between tabs.
      $$("[data-nav]").forEach((item) => { item.classList.remove("is-active"); item.removeAttribute("aria-current"); });
      [".masthead__title", ".masthead__page-actions"].forEach((part) => {
        const current = $(part, masthead);
        const incoming = $(part, nextMasthead);
        if (current && incoming) { current.replaceWith(imported(incoming)); }
      });
      const tabbar = $(".tabbar", app);
      const nextTabbar = $(".tabbar", nextApp);
      if (tabbar && !nextTabbar) { tabbar.remove(); }
      if (nextTabbar && (!tabbar || navSignature(tabbar) !== navSignature(nextTabbar))) {
        const fresh = imported(nextTabbar);
        if (tabbar) { tabbar.replaceWith(fresh); } else { app.appendChild(fresh); }
      }
      const main = imported($("#main", nextApp));
      main.classList.add("is-entering");
      revive(main, loads);
      $("#main", app).replaceWith(main);

      const toasts = doc.getElementById("toasts");
      Array.from(doc.body.childNodes).forEach((node) => { if (node !== app && node !== toasts) { node.remove(); } });
      const outside = doc.createDocumentFragment();
      Array.from(next.body.childNodes).forEach((node) => {
        if (node === nextApp || node.id === "toasts") { return; }
        outside.appendChild(imported(node));
      });
      revive(outside, loads);
      if (toasts) { doc.body.insertBefore(outside, toasts); } else { doc.body.appendChild(outside); }
    } else {
      const fragment = doc.createDocumentFragment();
      Array.from(next.body.childNodes).forEach((node) => fragment.appendChild(imported(node)));
      revive(fragment, loads);
      doc.body.replaceChildren(fragment);
      const main = doc.getElementById("main");
      if (main) { main.classList.add("is-entering"); }
    }
    return Promise.all(loads);
  }

  let progressEl = null;
  let progressTimer = 0;
  function progressStart() {
    window.clearTimeout(progressTimer);
    progressTimer = window.setTimeout(() => {
      if (!progressEl) {
        progressEl = doc.createElement("div");
        progressEl.className = "nav-progress";
        progressEl.setAttribute("aria-hidden", "true");
        root.appendChild(progressEl);
      }
      void progressEl.offsetWidth;
      progressEl.classList.add("is-running");
    }, 120);
  }
  function progressDone() {
    window.clearTimeout(progressTimer);
    if (!progressEl) { return; }
    const element = progressEl;
    progressEl = null;
    element.classList.add("is-done");
    window.setTimeout(() => element.remove(), 360);
  }

  let renderedUrl = window.location.pathname + window.location.search;
  let navToken = 0;

  function runQueued(listeners) {
    listeners.forEach((listener) => {
      try {
        const event = new Event("DOMContentLoaded");
        if (typeof listener === "function") {
          listener.call(doc, event);
        } else if (listener && typeof listener.handleEvent === "function") {
          listener.handleEvent(event);
        }
      } catch (error) {
        window.setTimeout(() => { throw error; }, 0);
      }
    });
  }

  async function softNavigate(url, options) {
    const opts = options || {};
    const token = (navToken += 1);
    progressStart();
    let page = null;
    try { page = await (opts.push === false ? fetchPage(url.href) : prefetchPage(url)); } catch (_) { page = null; }
    prefetched.clear();
    if (token !== navToken) { return; }
    const next = page && page.ok && page.type.includes("text/html") ? new DOMParser().parseFromString(page.html, "text/html") : null;
    if (!next || !compatiblePage(next)) {
      window.location.assign(page && page.url ? page.url : url.href);
      return;
    }
    const finalUrl = new URL(page.url || url.href, window.location.href);
    const target = `${finalUrl.pathname}${finalUrl.search}${url.hash}`;
    if (opts.push !== false) {
      history.replaceState({ ...(history.state || {}), hgScroll: Math.round(window.scrollY) }, "");
      history.pushState({ hgSoft: true }, "", target);
    } else if (`${window.location.pathname}${window.location.search}${window.location.hash}` !== target) {
      history.replaceState(history.state, "", target);
    }
    renderedUrl = finalUrl.pathname + finalUrl.search;

    teardownPage();
    tabMemory = opts.push === false;
    pageScope.readyQueue = [];
    await swapDocument(next);
    const queued = pageScope.readyQueue;
    pageScope.readyQueue = null;
    initDocument();
    runQueued(queued);
    window.scrollTo({ top: opts.scroll || 0, behavior: "instant" });
    progressDone();
  }

  doc.addEventListener("click", (event) => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) { return; }
    const link = event.target instanceof Element ? event.target.closest("a[href]") : null;
    const url = softTarget(link);
    if (!url) { return; }
    event.preventDefault();
    softNavigate(url);
  });

  let hoverTimer = 0;
  doc.addEventListener("pointerover", (event) => {
    const link = event.target instanceof Element ? event.target.closest("a[href]") : null;
    const url = softTarget(link);
    if (!url) { return; }
    window.clearTimeout(hoverTimer);
    hoverTimer = window.setTimeout(() => prefetchPage(url), event.pointerType === "mouse" ? 80 : 0);
  }, { passive: true });
  doc.addEventListener("pointerout", () => window.clearTimeout(hoverTimer), { passive: true });

  window.addEventListener("popstate", (event) => {
    const target = window.location.pathname + window.location.search;
    if (target === renderedUrl) { return; }
    if (!SOFT_PATHS.has(window.location.pathname)) {
      window.location.reload();
      return;
    }
    softNavigate(new URL(window.location.href), { push: false, scroll: (event.state && event.state.hgScroll) || 0 });
  });

  window.UI = {
    $,
    $$,
    store,
    label,
    escapeHtml,
    icon,
    ready,
    whenActivated,
    enhance,
    copy: copyText,
    toast,
    confirm: confirmDialog,
    openSheet,
    closeSheet,
    panels,
    initSegs,
    updateSeg,
    busy,
    status,
    fetchJson,
    formatUnix,
    decorateUnix,
    refilter,
    formatCountdown,
    isEditable,
    applyTheme
  };

  // From here on, listeners and intervals are registered by page scripts.
  pageScope.tracking = true;
})();
