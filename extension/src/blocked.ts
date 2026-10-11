/**
 * SentinelX Blocked Page Controller
 * Displays blocked event context, prevents open redirects, and manages controlled overrides.
 */

import { escapeHtml, isValidWebUrl } from "./utils.js";

// DOM Elements
const targetDomainEl = document.getElementById("target-domain") as HTMLElement;
const matchedRuleEl = document.getElementById("matched-rule") as HTMLElement;
const ruleSeverityEl = document.getElementById("rule-severity") as HTMLElement;
const threatReasonEl = document.getElementById("threat-reason") as HTMLElement;
const btnBackSafety = document.getElementById("btn-back-safety") as HTMLButtonElement;
const btnCloseTab = document.getElementById("btn-close-tab") as HTMLButtonElement;
const btnToggleOverride = document.getElementById("btn-toggle-override") as HTMLButtonElement;
const overrideContent = document.getElementById("override-content") as HTMLElement;
const overrideArrow = document.getElementById("override-arrow") as HTMLElement;
const chkAcknowledge = document.getElementById("chk-acknowledge") as HTMLInputElement;
const btnUnblockProceed = document.getElementById("btn-unblock-proceed") as HTMLButtonElement;
const btnOpenSettings = document.getElementById("btn-open-settings") as HTMLButtonElement;

let currentBlockedDomain = "";
let currentOriginalUrl = "";

/**
 * Initialize page with event context from URL parameters or service worker session storage.
 */
async function initBlockedPage(): Promise<void> {
  const urlParams = new URLSearchParams(window.location.search);
  const paramDomain = urlParams.get("domain");
  const paramRule = urlParams.get("rule");
  const paramReason = urlParams.get("reason");
  const paramUrl = urlParams.get("url");

  if (paramDomain) {
    currentBlockedDomain = paramDomain;
    currentOriginalUrl = paramUrl || `https://${paramDomain}`;
    renderEventDetails({
      domain: paramDomain,
      ruleName: paramRule || "High-Confidence Threat Rule",
      reason: paramReason === "strict_allowlist"
        ? "Strict Allowlist mode is active and this domain has not been explicitly approved."
        : "Matched local threat indicator signature.",
      severity: "CRITICAL",
    });
    return;
  }

  // Fallback: Query background service worker for last blocked event in this tab
  try {
    chrome.runtime.sendMessage({ action: "GET_LAST_BLOCKED" }, (response) => {
      if (response && response.event) {
        const event = response.event;
        currentBlockedDomain = event.domain;
        currentOriginalUrl = event.url;
        renderEventDetails({
          domain: event.domain,
          ruleName: event.ruleName,
          reason: event.reason,
          severity: "CRITICAL",
        });
      } else {
        renderEventDetails({
          domain: "Suspicious Host",
          ruleName: "Local Security Policy",
          reason: "Navigation was aborted by browser security policy.",
          severity: "HIGH",
        });
      }
    });
  } catch {
    renderEventDetails({
      domain: "Unverified Host",
      ruleName: "Policy Enforcement",
      reason: "Navigation blocked by SentinelX security rule.",
      severity: "HIGH",
    });
  }
}

function renderEventDetails(info: {
  domain: string;
  ruleName: string;
  reason: string;
  severity: string;
}): void {
  targetDomainEl.textContent = info.domain;
  matchedRuleEl.textContent = info.ruleName;
  threatReasonEl.textContent = info.reason;
  ruleSeverityEl.textContent = `${info.severity} RISK`;
}

// Event Listeners

// Return to safety (navigation back or standard blank page)
btnBackSafety.addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "https://www.google.com";
  }
});

// Close Tab
btnCloseTab.addEventListener("click", () => {
  window.close();
});

// Accordion toggle
btnToggleOverride.addEventListener("click", () => {
  const isHidden = overrideContent.style.display === "none";
  overrideContent.style.display = isHidden ? "block" : "none";
  overrideArrow.textContent = isHidden ? "▲" : "▼";
});

// Checkbox enable/disable unblock button
chkAcknowledge.addEventListener("change", () => {
  btnUnblockProceed.disabled = !chkAcknowledge.checked || !currentBlockedDomain;
});

// Unblock and Proceed with open-redirect safeguards
btnUnblockProceed.addEventListener("click", async () => {
  if (!chkAcknowledge.checked || !currentBlockedDomain) {
    return;
  }

  const confirmProceed = window.confirm(
    `Are you sure you want to unblock "${currentBlockedDomain}"?\n\n` +
      "This domain will be added to your local allowlist. Never enter sensitive passwords or credentials on unfamiliar sites."
  );

  if (!confirmProceed) {
    return;
  }

  // Request background service worker to add domain to allowlist and sync DNR
  chrome.runtime.sendMessage(
    { action: "ADD_ALLOWLIST", domain: currentBlockedDomain },
    (response) => {
      if (response && response.success) {
        // Safe navigation validation: Only permit http or https
        let dest = currentOriginalUrl;
        if (!isValidWebUrl(dest)) {
          dest = `https://${currentBlockedDomain}`;
        }
        window.location.href = dest;
      } else {
        alert("Failed to update allowlist. Please review your settings.");
      }
    }
  );
});

// Open Settings view
btnOpenSettings.addEventListener("click", () => {
  window.location.href = "popup.html?view=settings";
});

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  initBlockedPage();
});
