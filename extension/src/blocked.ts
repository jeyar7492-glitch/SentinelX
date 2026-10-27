/**
 * SentinelX Blocked & Warning Interstitial Controller
 * Manages full-page glassmorphism alerts for Block, Suspicious Warning,
 * and Unknown Publisher modes with safety countdowns and strict single-use bypasses.
 */

import { isValidWebUrl, escapeHtml } from "./utils.js";
import { normalizeDomain } from "./threat-manager.js";

// DOM Elements
const alertCardEl = document.getElementById("alert-card") as HTMLElement;
const hazardIconEl = document.getElementById("hazard-icon") as HTMLElement;
const interstitialBadgeEl = document.getElementById("interstitial-badge") as HTMLElement;
const riskScorePillEl = document.getElementById("risk-score-pill") as HTMLElement;
const alertHeadingEl = document.getElementById("alert-heading") as HTMLElement;
const alertSubheadingEl = document.getElementById("alert-subheading") as HTMLElement;
const targetDomainEl = document.getElementById("target-domain") as HTMLElement;
const targetUrlEl = document.getElementById("target-url") as HTMLElement;
const matchedRuleEl = document.getElementById("matched-rule") as HTMLElement;

const unknownPublisherCardEl = document.getElementById("unknown-publisher-card") as HTMLElement;
const signalsSectionEl = document.getElementById("signals-section") as HTMLElement;
const signalCountBadgeEl = document.getElementById("signal-count-badge") as HTMLElement;
const signalsListEl = document.getElementById("signals-list") as HTMLElement;

const countdownBarEl = document.getElementById("countdown-bar") as HTMLElement;
const countdownTextEl = document.getElementById("countdown-text") as HTMLElement;

const btnBackSafety = document.getElementById("btn-back-safety") as HTMLButtonElement;
const btnProceedWarning = document.getElementById("btn-proceed-warning") as HTMLButtonElement;
const btnCloseTab = document.getElementById("btn-close-tab") as HTMLButtonElement;
const btnOpenSettings = document.getElementById("btn-open-settings") as HTMLButtonElement;
const themeToggleBtn = document.getElementById("theme-toggle-btn") as HTMLButtonElement;
const themeToggleIcon = document.getElementById("theme-toggle-icon") as HTMLElement;

let currentBlockedDomain = "";
let currentOriginalUrl = "";
let currentType: "block" | "warning" | "unknown_publisher" = "block";
let countdownInterval: number | null = null;

interface SignalItem {
  name: string;
  category?: string;
  description: string;
  severity?: string;
  evidenceType?: "confirmed" | "heuristic" | "inconclusive";
}

/**
 * Apply color theme to document root
 */
function applyTheme(theme: "dark" | "light"): void {
  document.documentElement.setAttribute("data-theme", theme);
  if (themeToggleIcon) {
    themeToggleIcon.textContent = theme === "light" ? "☀️" : "🌙";
  }
}

/**
 * Initialize theme from stored settings or prefers-color-scheme
 */
async function initTheme(): Promise<void> {
  try {
    const result = await chrome.storage.local.get("sentinel_settings");
    const storedTheme = result.sentinel_settings?.theme;
    if (storedTheme === "light" || storedTheme === "dark") {
      applyTheme(storedTheme);
      return;
    }
  } catch {
    // Ignore storage error
  }
  const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
  applyTheme(prefersLight ? "light" : "dark");
}

themeToggleBtn?.addEventListener("click", async () => {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "light" ? "dark" : "light";
  applyTheme(next);
  try {
    const result = await chrome.storage.local.get("sentinel_settings");
    const settings = result.sentinel_settings || {};
    settings.theme = next;
    await chrome.storage.local.set({ sentinel_settings: settings });
  } catch {
    // Ignore
  }
});

/**
 * Initialize page with event context from URL parameters or service worker session storage.
 */
async function initBlockedPage(): Promise<void> {
  await initTheme();

  const urlParams = new URLSearchParams(window.location.search);
  const paramDomain = urlParams.get("domain");
  const paramRule = urlParams.get("rule");
  const paramReason = urlParams.get("reason");
  const paramUrl = urlParams.get("url");
  const paramType = urlParams.get("type");
  const paramScore = urlParams.get("score");

  if (paramType === "unknown_publisher" || paramType === "unknown") {
    currentType = "unknown_publisher";
  } else if (paramType === "warning") {
    currentType = "warning";
  } else {
    currentType = "block";
  }

  if (paramDomain) {
    currentBlockedDomain = paramDomain;
    currentOriginalUrl = paramUrl || `https://${paramDomain}`;
    renderEventDetails({
      domain: paramDomain,
      url: currentOriginalUrl,
      ruleName: paramRule || (
        currentType === "unknown_publisher"
          ? "Publisher Identity Unavailable"
          : currentType === "warning"
          ? "Elevated Risk Policy (Score 80-89)"
          : "High-Confidence Threat Signature"
      ),
      reason: paramReason === "strict_allowlist"
        ? "Strict Allowlist mode is active and this domain has not been explicitly approved."
        : (paramReason || (
            currentType === "unknown_publisher"
              ? "The publisher or website identity cannot be verified against local directories. This website is unverified, not automatically malicious."
              : currentType === "warning"
              ? "URL exhibits suspicious indicators or unverified credentials."
              : "Matched local high-confidence threat indicator signature."
          )),
      severity: currentType === "unknown_publisher" ? "UNVERIFIED" : currentType === "warning" ? "WARNING" : "CRITICAL",
      score: paramScore ? parseInt(paramScore, 10) : (currentType === "unknown_publisher" ? 15 : currentType === "warning" ? 85 : 95),
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
        currentType = event.type === "unknown_publisher" ? "unknown_publisher" : event.type === "warning" ? "warning" : "block";
        renderEventDetails({
          domain: event.domain,
          url: event.url,
          ruleName: event.ruleName,
          reason: event.reason,
          severity: currentType === "unknown_publisher" ? "UNVERIFIED" : currentType === "warning" ? "WARNING" : "CRITICAL",
          score: event.riskScore || (currentType === "unknown_publisher" ? 15 : currentType === "warning" ? 85 : 95),
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

/**
 * Start 3-second safety countdown before enabling Continue button
 */
function startSafetyCountdown(buttonLabel: string): void {
  if (countdownInterval !== null) {
    window.clearInterval(countdownInterval);
    countdownInterval = null;
  }

  countdownBarEl.style.display = "flex";
  btnProceedWarning.style.display = "inline-flex";
  btnProceedWarning.disabled = true;

  let remaining = 3;
  countdownTextEl.textContent = `Safety delay active: ${remaining}s remaining before continue option unlocks`;
  btnProceedWarning.textContent = `${buttonLabel} (${remaining}s)`;

  countdownInterval = window.setInterval(() => {
    remaining--;
    if (remaining > 0) {
      countdownTextEl.textContent = `Safety delay active: ${remaining}s remaining before continue option unlocks`;
      btnProceedWarning.textContent = `${buttonLabel} (${remaining}s)`;
    } else {
      if (countdownInterval !== null) {
        window.clearInterval(countdownInterval);
        countdownInterval = null;
      }
      countdownBarEl.style.display = "none";
      btnProceedWarning.disabled = false;
      btnProceedWarning.textContent = buttonLabel;
      // IMPORTANT: DO NOT automatically open or navigate! Explicit user action is required.
    }
  }, 1000);
}

function parseReasonIntoSignals(reason: string, score: number): SignalItem[] {
  const signals: SignalItem[] = [];
  if (!reason) return signals;

  const parts = reason.split(/\.\s+/).filter(Boolean);
  for (const part of parts) {
    const text = part.trim();
    if (!text) continue;

    let evidenceType: "confirmed" | "heuristic" | "inconclusive" = "heuristic";
    let name = "Suspicious Indicator";

    if (text.toLowerCase().includes("unencrypted http") || text.toLowerCase().includes("plain http")) {
      evidenceType = "confirmed";
      name = "Unencrypted Plaintext HTTP Transport";
    } else if (text.toLowerCase().includes("raw ip address") || text.toLowerCase().includes("raw ip")) {
      evidenceType = "confirmed";
      name = "Direct IP Address Addressing (No Domain)";
    } else if (text.toLowerCase().includes("credential embedding") || text.toLowerCase().includes("@ symbol")) {
      evidenceType = "confirmed";
      name = "Host Authority Disguise / Userinfo Spoofing";
    } else if (text.toLowerCase().includes("punycode") || text.toLowerCase().includes("xn--")) {
      evidenceType = "confirmed";
      name = "Internationalized Domain Lookalike (Punycode)";
    } else if (text.toLowerCase().includes("brand impersonation")) {
      evidenceType = "heuristic";
      name = "Brand Keyword Impersonation on Unrelated Domain";
    } else if (text.toLowerCase().includes("high-abuse top-level domain") || text.toLowerCase().includes("tld")) {
      evidenceType = "heuristic";
      name = "High-Risk Disposable Top-Level Domain";
    } else if (text.toLowerCase().includes("subdomain")) {
      evidenceType = "heuristic";
      name = "Excessive Subdomain Stacking / Obfuscation";
    } else if (text.toLowerCase().includes("sensitive authentication") || text.toLowerCase().includes("login path")) {
      evidenceType = "heuristic";
      name = "Sensitive Login/Credential Path on Unverified Host";
    } else if (text.toLowerCase().includes("redirect parameter") || text.toLowerCase().includes("open redirect")) {
      evidenceType = "heuristic";
      name = "Potential Open Redirect Parameter";
    } else if (text.toLowerCase().includes("length")) {
      evidenceType = "inconclusive";
      name = "Abnormally Long URL Structure";
    }

    signals.push({
      name,
      description: text.endsWith(".") ? text : `${text}.`,
      evidenceType,
    });
  }

  if (signals.length === 0) {
    signals.push({
      name: score >= 90 ? "High-Risk Threat Signature" : "Elevated Risk Anomaly",
      description: reason,
      evidenceType: score >= 90 ? "confirmed" : "heuristic",
    });
  }

  return signals;
}

function renderSignals(signals: SignalItem[]): void {
  signalsListEl.innerHTML = "";
  signalCountBadgeEl.textContent = `${signals.length} ${signals.length === 1 ? "Signal" : "Signals"}`;

  signals.forEach((signal) => {
    const card = document.createElement("div");
    const eType = signal.evidenceType || "heuristic";
    card.className = `signal-card evidence-${eType}`;

    card.innerHTML = `
      <div class="signal-top-row">
        <span class="signal-name">${escapeHtml(signal.name)}</span>
        <div class="signal-tags">
          <span class="evidence-tag ${eType}">${eType}</span>
        </div>
      </div>
      <p class="signal-desc">${escapeHtml(signal.description)}</p>
    `;

    signalsListEl.appendChild(card);
  });
}

function renderEventDetails(info: {
  domain: string;
  url?: string;
  ruleName: string;
  reason: string;
  severity: string;
  score: number;
  type: "block" | "warning" | "unknown_publisher";
}): void {
  targetDomainEl.textContent = info.domain;
  if (targetUrlEl) {
    targetUrlEl.textContent = info.url || `https://${info.domain}`;
    targetUrlEl.title = info.url || info.domain;
  }
  matchedRuleEl.textContent = info.ruleName;

  // 1. Unknown Publisher Interstitial
  if (info.type === "unknown_publisher") {
    alertCardEl.className = "alert-card mode-unknown-publisher";
    hazardIconEl.textContent = "🛡️";
    interstitialBadgeEl.className = "interstitial-badge unknown";
    interstitialBadgeEl.textContent = "UNVERIFIED PUBLISHER";
    riskScorePillEl.textContent = `SCORE: ${info.score}/100`;

    alertHeadingEl.textContent = "Unverified Website Publisher";
    alertSubheadingEl.textContent =
      "Publisher identity unavailable — this website is unverified, not automatically malicious. Caution is advised before sharing any credentials or downloading files.";

    unknownPublisherCardEl.style.display = "flex";
    signalsSectionEl.style.display = "none";

    // Start 3-second visible countdown before enabling Continue
    startSafetyCountdown("Continue to Unverified Website");
    return;
  }

  // 2. Suspicious Website Warning (Score 80–89)
  if (info.type === "warning") {
    alertCardEl.className = "alert-card mode-warning";
    hazardIconEl.textContent = "⚠️";
    interstitialBadgeEl.className = "interstitial-badge warning";
    interstitialBadgeEl.textContent = "SUSPICIOUS DESTINATION";
    riskScorePillEl.textContent = `SCORE: ${info.score}/100`;

    alertHeadingEl.textContent = "Warning: Elevated Risk Detected";
    alertSubheadingEl.textContent =
      "SentinelX intercepted this navigation because the destination displays significant suspicious indicators (Score 80–89). Review the evidence below before deciding to proceed.";

    unknownPublisherCardEl.style.display = "none";
    signalsSectionEl.style.display = "flex";

    const signals = parseReasonIntoSignals(info.reason, info.score);
    renderSignals(signals);

    // Start 3-second visible countdown for explicit delayed continue
    startSafetyCountdown("Proceed Anyway (I Understand the Risks)");
    return;
  }

  // 3. High-Risk Block Page (Score 90+)
  alertCardEl.className = "alert-card mode-block";
  hazardIconEl.textContent = "⛔";
  interstitialBadgeEl.className = "interstitial-badge critical";
  interstitialBadgeEl.textContent = "CRITICAL THREAT BLOCKED";
  riskScorePillEl.textContent = `SCORE: ${info.score}/100`;

  alertHeadingEl.textContent = "Website Blocked for Your Protection";
  alertSubheadingEl.textContent =
    "SentinelX aborted this connection before any data was sent or received. The target matches high-confidence threat signatures or security policies. Connection blocked to prevent credential harvesting and malware infection.";

  unknownPublisherCardEl.style.display = "none";
  signalsSectionEl.style.display = "flex";

  const signals = parseReasonIntoSignals(info.reason, info.score);
  renderSignals(signals);

  // High-confidence threats do NOT expose an unrestricted bypass by default
  countdownBarEl.style.display = "none";
  btnProceedWarning.style.display = "none";
}

// Navigation Actions

// Safe Return Action
btnBackSafety.addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "https://www.google.com";
  }
});

// Close Tab Action
btnCloseTab.addEventListener("click", () => {
  window.close();
});

// Proceed to Website (Delayed explicit continue action for Warning and Unknown Publisher)
btnProceedWarning.addEventListener("click", () => {
  if (!currentBlockedDomain) return;

  const confirmPrompt = currentType === "unknown_publisher"
    ? `CONTINUE TO UNVERIFIED WEBSITE?\n\nTarget Domain: ${currentBlockedDomain}\n\n` +
      "Publisher identity is unavailable. Never enter sensitive passwords, banking details, or financial accounts on unverified websites."
    : `PROCEED TO SUSPICIOUS WEBSITE?\n\nTarget Domain: ${currentBlockedDomain}\n\n` +
      "This destination exhibits confirmed suspicious anomalies. Phishing kits routinely harvest credentials. Proceed with extreme caution.";

  const userConfirmed = window.confirm(confirmPrompt);
  if (!userConfirmed) return;

  let dest = currentOriginalUrl;
  if (!isValidWebUrl(dest) || dest.includes(chrome.runtime.id)) {
    dest = `https://${currentBlockedDomain}`;
  }

  // Authorize single-use tab-scoped navigation transition (15s window, does NOT grant permanent trust)
  chrome.runtime.sendMessage(
    {
      action: "ALLOW_ONE_TIME_BYPASS",
      domain: currentBlockedDomain,
      url: dest,
    },
    () => {
      window.location.href = dest;
    }
  );
});

// Open Settings in Popup/Dashboard
btnOpenSettings.addEventListener("click", () => {
  window.location.href = chrome.runtime.getURL("popup.html?view=settings");
});

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  initBlockedPage();
});
