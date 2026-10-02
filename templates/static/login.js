// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Hanagram-web contributors

(function () {
    const AUTH_PANE_STORAGE_KEY = "hanagram-login-pane";

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

    function mapPublicKeyRequestOptions(options) {
        const publicKey = { ...options };
        publicKey.challenge = base64UrlToBuffer(publicKey.challenge);
        if (Array.isArray(publicKey.allowCredentials)) {
            publicKey.allowCredentials = publicKey.allowCredentials.map((credential) => ({
                ...credential,
                id: base64UrlToBuffer(credential.id)
            }));
        }
        return publicKey;
    }

    function serializeAuthenticationCredential(credential) {
        return {
            id: credential.id,
            rawId: bufferToBase64Url(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
                clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                signature: bufferToBase64Url(credential.response.signature),
                userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null
            },
            clientExtensionResults: credential.getClientExtensionResults()
        };
    }

    window.addEventListener("DOMContentLoaded", () => {
        const feedback = document.getElementById("login-feedback");
        const tabs = Array.from(document.querySelectorAll("[data-auth-tab]"));
        const panes = Array.from(document.querySelectorAll("[data-auth-pane]"));
        const totpBlock = document.querySelector("[data-totp-block]");
        const recoveryBlock = document.querySelector("[data-recovery-block]");
        const mfaInput = document.querySelector('input[name="mfa_code"]');
        const recoveryInput = document.querySelector('input[name="recovery_code"]');
        const passkeyButton = document.querySelector("[data-passkey-login]");
        const langInput = document.querySelector('input[name="lang"]');

        const setFeedback = (message, isError) => UI.status(feedback, isError ? "error" : "loading", message);

        function setAuthPane(paneId, persist) {
            tabs.forEach((tab) => {
                const active = tab.dataset.authTab === paneId;
                tab.classList.toggle("is-active", active);
                tab.setAttribute("aria-selected", active ? "true" : "false");
            });
            panes.forEach((pane) => pane.classList.toggle("is-active", pane.dataset.authPane === paneId));
            UI.updateSeg(document.querySelector("[data-auth-tabs]"));
            if (persist) { UI.store.set(AUTH_PANE_STORAGE_KEY, paneId); }
        }

        function showRecoveryMode(showRecovery) {
            totpBlock.hidden = showRecovery;
            recoveryBlock.hidden = !showRecovery;
            mfaInput.disabled = showRecovery;
            recoveryInput.disabled = !showRecovery;
            if (showRecovery) {
                mfaInput.value = "";
                recoveryInput.focus();
            } else {
                recoveryInput.value = "";
                mfaInput.focus();
            }
        }

        tabs.forEach((tab) => tab.addEventListener("click", () => setAuthPane(tab.dataset.authTab || "password", true)));
        const stored = UI.store.get(AUTH_PANE_STORAGE_KEY);
        setAuthPane(tabs.some((tab) => tab.dataset.authTab === stored) ? stored : "password", false);

        document.querySelector("[data-recovery-toggle]").addEventListener("click", () => showRecoveryMode(true));
        document.querySelector("[data-recovery-back]").addEventListener("click", () => showRecoveryMode(false));

        if (!passkeyButton) { return; }
        passkeyButton.addEventListener("click", async () => {
            if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
                setFeedback(passkeyButton.dataset.unsupported, true);
                return;
            }
            UI.busy(passkeyButton, true);
            setFeedback(passkeyButton.dataset.starting, false);
            try {
                const optionsResponse = await fetch("/login/passkey/options", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "Accept": "application/json" },
                    body: JSON.stringify({ lang: langInput ? langInput.value : null })
                });
                const optionsPayload = await optionsResponse.json().catch(() => ({}));
                if (!optionsResponse.ok) {
                    throw new Error(optionsPayload.error || passkeyButton.dataset.failed);
                }

                setFeedback(passkeyButton.dataset.awaiting, false);
                const credential = await navigator.credentials.get({
                    publicKey: mapPublicKeyRequestOptions(optionsPayload.options.publicKey)
                });
                if (!credential) { throw new Error(passkeyButton.dataset.failed); }

                const finishResponse = await fetch("/login/passkey/finish", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "Accept": "application/json" },
                    body: JSON.stringify({
                        request_id: optionsPayload.request_id,
                        credential: serializeAuthenticationCredential(credential),
                        lang: langInput ? langInput.value : null
                    })
                });
                const finishPayload = await finishResponse.json().catch(() => ({}));
                if (!finishResponse.ok) {
                    throw new Error(finishPayload.error || passkeyButton.dataset.failed);
                }
                window.location.href = finishPayload.redirect_to || "/";
            } catch (error) {
                setFeedback(error instanceof Error ? error.message : passkeyButton.dataset.failed, true);
            } finally {
                UI.busy(passkeyButton, false);
            }
        });
    });
})();
