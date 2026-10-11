/**
 * SentinelX Blocked Page Controller
 * Displays blocked / warning event context, prevents open redirects,
 * enforces central risk policy, and manages controlled user overrides.
 */

import { isValidWebUrl } from "./utils.js";

// DOM Elements
const alertCardEl = document.getElementById("alert-card") as HTMLElement;
const hazardIconEl = document.getElementById("hazard-icon") as HTMLElement;
const alertHeadingEl = document.getElementById("alert-heading") as HTMLElement;
const alertSubheadingEl = document.getElementById("alert-subheading") as HTMLElement;
const targetDomainEl = document.getElementById("target-domain") as HTMLElement;
const targetUrlEl = document.getElementById("target-url") as HTMLElement;
const matchedRuleEl = document.getElementById("matched-rule") as HTMLElement;
const ruleSeverityEl = document.getElementById("rule-severity") as HTMLElement;
const threatReasonEl = document.getElementById("threat-reason") as HTMLElement;

const btnBackSafety = document.getElementById("btn-back-safety") as HTMLButtonElement;
const btnProceedWarning = document.getElementById("btn-proceed-warning") as HTMLButtonElement;
const btnCloseTab = document.getElementById("btn-close-tab") as HTMLButtonElement;

const overrideSection = document.getElementById("override-section") as HTMLElement;
const btnToggleOverride = document.getElementById("btn-toggle-override") as HTMLButtonElement;
const overrideContent = document.getElementById("override-content") as HTMLElement;
const overrideArrow = document.getElementById("override-arrow") as HTMLElement;
const chkAcknowledge = document.getElementById("chk-acknowledge") as HTMLInputElement;
const btnUnblockProceed = document.getElementById("btn-unblock-proceed") as HTMLButtonElement;
const btnOpenSettings = document.getElementById("btn-open-settings") as HTMLButtonElement;

let currentBlockedDomain = "";
let currentOriginalUrl = "";
let currentType: "block" | "warning" = "block";

/**
 * Initialize page with event context from URL parameters or service worker session storage.
 */
async function initBlockedPage(): Promise<void> {
  const urlParams = new URLSearchParams(window.location.search);
  const paramDomain = urlParams.get("domain");
  const paramRule = urlParams.get("rule");
  const paramReason = urlParams.get("reason");
  const paramUrl = urlParams.get("url");
  const paramType = urlParams.get("type");
  const paramScore = urlParams.get("score");

  currentType = paramType === "warning" ? "warning" : "block";

  if (paramDomain) {
    currentBlockedDomain = paramDomain;
    currentOriginalUrl = paramUrl || `https://${paramDomain}`;
    renderEventDetails({
      domain: paramDomain,
      url: currentOriginalUrl,
      ruleName: paramRule || (currentType === "warning" ? "Elevated Risk Policy (Score 80-89)" : "High-Confidence Threat Rule"),
      reason: paramReason === "strict_allowlist"
        ? "Strict Allowlist mode is active and this domain has not been explicitly approved."
        : (paramReason || (currentType === "warning" ? "URL exhibits suspicious indicators or unverified credentials." : "Matched local high-confidence threat indicator signature.")),
      severity: currentType === "warning" ? "WARNING" : "CRITICAL",
      score: paramScore ? parseInt(paramScore, 10) : (currentType === "warning" ? 85 : 95),
      type: currentType,
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
        currentType = event.type || "block";
        renderEventDetails({
          domain: event.domain,
          url: event.url,
          ruleName: event.ruleName,
          reason: event.reason,
          severity: currentType === "warning" ? "WARNING" : "CRITICAL",
          score: event.riskScore || (currentType === "warning" ? 85 : 95),
          type: currentType,
        });
      } else {
        renderEventDetails({
          domain: "Suspicious Host",
          url: "N/A",
          ruleName: "Local Security Policy",
          reason: "Navigation was intercepted by SentinelX browser security policy.",
          severity: "HIGH",
          score: 90,
          type: "block",
        });
      }
    });
  } catch {
    renderEventDetails({
      domain: "Unverified Host",
      url: "N/A",
      ruleName: "Policy Enforcement",
      reason: "Navigation blocked by SentinelX security rule.",
      severity: "HIGH",
      score: 90,
      type: "block",
    });
  }
}

function renderEventDetails(info: {
  domain: string;
  url?: string;
  ruleName: string;
  reason: string;
  severity: string;
  score: number;
  type: "block" | "warning";
}): void {
  targetDomainEl.textContent = info.domain;
  if (targetUrlEl) {
    targetUrlEl.textContent = info.url || `https://${info.domain}`;
    targetUrlEl.title = info.url || info.domain;
  }
  matchedRuleEl.textContent = info.ruleName;
  threatReasonEl.textContent = info.reason;

  if (info.type === "warning") {
    alertCardEl.className = "alert-card mode-warning";
    hazardIconEl.className = "hazard-circle warning";
    hazardIconEl.textContent = "⚠️";
    alertHeadingEl.textContent = "Warning: Elevated Risk Detected";
    alertSubheadingEl.textContent =
      "SentinelX intercepted this page because it exhibits substantial suspicious anomalies (Risk Score 80–89). Review the risk explanation before choosing to proceed.";
    ruleSeverityEl.className = "severity-tag warning";
    ruleSeverityEl.textContent = `SUSPICIOUS (Score: ${info.score}/100)`;
    btnProceedWarning.style.display = "inline-flex";
  } else {
    alertCardEl.className = "alert-card mode-block";
    hazardIconEl.className = "hazard-circle";
    hazardIconEl.textContent = "⛔";
    alertHeadingEl.textContent = "Website Blocked for Your Protection";
    alertSubheadingEl.textContent =
      "SentinelX aborted this connection before any data was sent or received. The target matches high-confidence phishing indicators, malware patterns, or strict local security policies.";
    ruleSeverityEl.className = "severity-tag critical";
    ruleSeverityEl.textContent = `CRITICAL RISK (${info.score >= 90 ? "90+" : info.score})`;
    btnProceedWarning.style.display = "none";
  }
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

// Proceed anyway on warning interstitial
btnProceedWarning.addEventListener("click", () => {
  if (!currentBlockedDomain) return;

  const confirmProceed = window.confirm(
    `PROCEED TO UNVERIFIED WEBSITE?\n\nTarget: ${currentBlockedDomain}\n\n` +
      "This site has suspicious indicators. Never enter passwords, banking details, or download unknown files."
  );

  if (confirmProceed) {
    let dest = currentOriginalUrl;
    if (!isValidWebUrl(dest) || dest.includes(chrome.runtime.id)) {
      dest = `https://${currentBlockedDomain}`;
    }
    // Set temporary session bypass in background service worker to prevent redirect loop
    chrome.runtime.sendMessage(
      { action: "ALLOW_SESSION_BYPASS", domain: currentBlockedDomain },
      () => {
        window.location.href = dest;
      }
    );
  }
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
        let dest = currentOriginalUrl;
        if (!isValidWebUrl(dest) || dest.includes(chrome.runtime.id)) {
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
