// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

function base64UrlToBuffer(value) {
    const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const binary = window.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
}

function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    bytes.forEach((value) => { binary += String.fromCharCode(value); });
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function mapPublicKeyCreationOptions(options) {
    const publicKey = { ...options };
    publicKey.challenge = base64UrlToBuffer(publicKey.challenge);
    publicKey.user = { ...publicKey.user, id: base64UrlToBuffer(publicKey.user.id) };
    if (Array.isArray(publicKey.excludeCredentials)) {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map((credential) => ({
            ...credential,
            id: base64UrlToBuffer(credential.id)
        }));
    }
    return publicKey;
}

function serializeRegistrationCredential(credential) {
    const response = credential.response;
    const attestationObject = response.attestationObject;
    const clientDataJSON = response.clientDataJSON;
    const authenticatorData = typeof response.getAuthenticatorData === "function" ? response.getAuthenticatorData() : null;
    const publicKey = typeof response.getPublicKey === "function" ? response.getPublicKey() : null;
    const publicKeyAlgorithm = typeof response.getPublicKeyAlgorithm === "function" ? response.getPublicKeyAlgorithm() : null;
    if (!attestationObject || !clientDataJSON || !authenticatorData || !publicKey || typeof publicKeyAlgorithm !== "number") {
        throw new Error("incomplete-passkey-registration-response");
    }
    return {
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment || null,
        response: {
            attestationObject: bufferToBase64Url(attestationObject),
            clientDataJSON: bufferToBase64Url(clientDataJSON),
            authenticatorData: bufferToBase64Url(authenticatorData),
            publicKey: bufferToBase64Url(publicKey),
            publicKeyAlgorithm,
            transports: typeof response.getTransports === "function" ? response.getTransports() : []
        },
        clientExtensionResults: credential.getClientExtensionResults()
    };
}

function describePasskeyCreateError(error, button) {
    if (!(error instanceof Error)) { return button ? button.dataset.failed : ""; }
    if (error.message === "incomplete-passkey-registration-response") { return (button && button.dataset.incompleteResponse) || error.message; }
    if (error.name === "NotAllowedError") { return (button && button.dataset.notAllowed) || error.message || ""; }
    return error.message || (button ? button.dataset.failed : "") || "";
}

window.addEventListener("DOMContentLoaded", () => {
    const PANEL_KEY = "hg.settings.panel";
    const panelsRoot = document.getElementById("settings-panels");
    const restricted = panelsRoot && panelsRoot.dataset.restricted === "true";
    UI.panels(panelsRoot, {
        aliases: { security: restricted ? "password" : "overview", access: "idle" },
        storageKey: PANEL_KEY,
        initial: restricted ? "password" : undefined,
        defaultId: "overview"
    });

    const template = document.querySelector("[data-template-input]");
    document.querySelectorAll("[data-insert-placeholder]").forEach((chip) => {
        chip.addEventListener("click", () => {
            if (!template) { return; }
            const token = chip.dataset.insertPlaceholder || "";
            const start = template.selectionStart ?? template.value.length;
            const end = template.selectionEnd ?? template.value.length;
            template.setRangeText(token, start, end, "end");
            template.focus();
        });
    });

    const passkeyForm = document.querySelector("[data-passkey-register-form]");
    if (!passkeyForm) { return; }
    const feedback = document.getElementById("passkey-feedback");
    const button = passkeyForm.querySelector("[data-passkey-register-button]");
    const nameInput = passkeyForm.querySelector('input[name="passkey_label"]');
    const langInput = passkeyForm.querySelector('input[name="lang"]');
    const setFeedback = (message, isError) => UI.status(feedback, isError ? "error" : "loading", message);

    passkeyForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        UI.store.set(PANEL_KEY, "passkeys", "session");
        if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
            setFeedback(button ? button.dataset.unsupported : "", true);
            return;
        }
        if (!nameInput || !nameInput.value.trim()) {
            setFeedback(button ? button.dataset.missingLabel : "", true);
            if (nameInput) { nameInput.focus(); }
            return;
        }
        setFeedback(button ? button.dataset.starting : "", false);
        UI.busy(button, true);
        try {
            const optionsResponse = await fetch(passkeyForm.dataset.optionsAction, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify({ label: nameInput.value, lang: langInput ? langInput.value : null })
            });
            const optionsPayload = await optionsResponse.json().catch(() => ({}));
            if (!optionsResponse.ok) { throw new Error(optionsPayload.error || (button ? button.dataset.failed : "")); }

            setFeedback(button ? button.dataset.awaiting : "", false);
            const credential = await navigator.credentials.create({ publicKey: mapPublicKeyCreationOptions(optionsPayload.options.publicKey) });
            if (!credential) { throw new Error(button ? button.dataset.failed : ""); }

            const finishResponse = await fetch(passkeyForm.dataset.finishAction, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify({
                    registration_id: optionsPayload.registration_id,
                    credential: serializeRegistrationCredential(credential),
                    lang: langInput ? langInput.value : null
                })
            });
            const finishPayload = await finishResponse.json().catch(() => ({}));
            if (!finishResponse.ok) { throw new Error(finishPayload.error || (button ? button.dataset.failed : "")); }

            setFeedback("", false);
            const destination = new URL(finishPayload.redirect_to || "/settings#passkeys", window.location.href);
            if (destination.hash === "#security") { destination.hash = "#passkeys"; }
            if (destination.pathname === window.location.pathname && destination.search === window.location.search) {
                window.location.hash = destination.hash;
                window.location.reload();
            } else {
                window.location.assign(destination.toString());
            }
        } catch (error) {
            setFeedback(describePasskeyCreateError(error, button), true);
        } finally {
            UI.busy(button, false);
        }
    });
});
