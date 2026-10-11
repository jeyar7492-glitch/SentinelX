/**
 * SentinelX Chrome Extension - Popup Controller
 * Manages active tab scanning, local backend communication, protection settings,
 * and dynamic pre-navigation rule management.
 */

import { AnalyzeResponse, HealthResponse } from "./types.js";
import { escapeHtml, isValidWebUrl, truncateUrl } from "./utils.js";
import { normalizeDomain, isValidDomain, ProtectionSettings, ThreatRule } from "./threat-manager.js";

const BACKEND_BASE_URL = "http://127.0.0.1:8000";

// Navigation Elements
const navScanBtn = document.getElementById("nav-scan") as HTMLButtonElement;
const navSettingsBtn = document.getElementById("nav-settings") as HTMLButtonElement;
const viewScanner = document.getElementById("view-scanner") as HTMLElement;
const viewSettings = document.getElementById("view-settings") as HTMLElement;

// Scanner Elements
const backendStatusEl = document.getElementById("backend-status") as HTMLElement;
const backendStatusTextEl = document.getElementById("backend-status-text") as HTMLElement;
const urlInputEl = document.getElementById("url-input") as HTMLInputElement;
const scanBtnEl = document.getElementById("scan-btn") as HTMLButtonElement;
const scanCurrentBtnEl = document.getElementById("scan-current-btn") as HTMLButtonElement;
const loadingStateEl = document.getElementById("loading-state") as HTMLElement;
const errorCardEl = document.getElementById("error-card") as HTMLElement;
const errorMessageEl = document.getElementById("error-message") as HTMLElement;
const resultsContainerEl = document.getElementById("results-container") as HTMLElement;

// Results elements
const currentUrlTextEl = document.getElementById("current-url-text") as HTMLElement;
const quickBlockBar = document.getElementById("quick-block-bar") as HTMLElement;
const btnQuickBlock = document.getElementById("btn-quick-block") as HTMLButtonElement;
const riskScoreValueEl = document.getElementById("risk-score-value") as HTMLElement;
const riskScoreBarEl = document.getElementById("risk-score-bar") as HTMLElement;
const statusBadgeEl = document.getElementById("status-badge") as HTMLElement;
const resultSummaryEl = document.getElementById("result-summary") as HTMLElement;
const httpBadgeEl = document.getElementById("http-badge") as HTMLElement;
const httpSummaryEl = document.getElementById("http-summary") as HTMLElement;
const httpExplanationEl = document.getElementById("http-explanation") as HTMLElement;
const rulesContainerEl = document.getElementById("rules-container") as HTMLElement;
const safeIndicatorsContainerEl = document.getElementById("safe-indicators-container") as HTMLElement;

// Settings Elements
const dnrStatusPill = document.getElementById("dnr-status-pill") as HTMLElement;
const modeStandardRadio = document.getElementById("mode-standard") as HTMLInputElement;
const modeStrictRadio = document.getElementById("mode-strict") as HTMLInputElement;
const modeDisabledRadio = document.getElementById("mode-disabled") as HTMLInputElement;
const manageDomainInput = document.getElementById("manage-domain-input") as HTMLInputElement;
const btnAddBlock = document.getElementById("btn-add-block") as HTMLButtonElement;
const btnAddAllow = document.getElementById("btn-add-allow") as HTMLButtonElement;
const customBlocklistContainer = document.getElementById("custom-blocklist-container") as HTMLElement;
const allowlistContainer = document.getElementById("allowlist-container") as HTMLElement;
const customBlockCountEl = document.getElementById("custom-block-count") as HTMLElement;
const allowlistCountEl = document.getElementById("allowlist-count") as HTMLElement;
const systemRulesCountEl = document.getElementById("system-rules-count") as HTMLElement;

let lastScannedUrl = "";

/**
 * Check if local backend is running on 127.0.0.1:8000
 */
async function checkBackendHealth(): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    const response = await fetch(`${BACKEND_BASE_URL}/health`, {
      method: "GET",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (response.ok) {
      const data: HealthResponse = await response.json();
      backendStatusEl.className = "status-indicator online";
      backendStatusTextEl.textContent = `Local Core Active (${data.host_restriction})`;
      return true;
    }
  } catch {
    // Backend unreachable
  }

  backendStatusEl.className = "status-indicator offline";
  backendStatusTextEl.textContent = "Backend Offline (127.0.0.1:8000)";
  return false;
}

/**
 * Tab switching controller
 */
function switchView(targetView: "scan" | "settings"): void {
  if (targetView === "scan") {
    navScanBtn.classList.add("active");
    navSettingsBtn.classList.remove("active");
    viewScanner.style.display = "flex";
    viewSettings.style.display = "none";
  } else {
    navSettingsBtn.classList.add("active");
    navScanBtn.classList.remove("active");
    viewScanner.style.display = "none";
    viewSettings.style.display = "flex";
    loadSettingsView();
  }
}

navScanBtn.addEventListener("click", () => switchView("scan"));
navSettingsBtn.addEventListener("click", () => switchView("settings"));

/**
 * Perform analysis of a URL via the local backend
 */
async function analyzeUrl(targetUrl: string): Promise<void> {
  if (!isValidWebUrl(targetUrl)) {
    showError(
      "Invalid or unsupported URL. SentinelX scans http:// and https:// URLs. Internal browser pages (chrome://, about:) cannot be scanned."
    );
    return;
  }

  setLoading(true);
  hideError();

  const isHealthy = await checkBackendHealth();
  if (!isHealthy) {
    setLoading(false);
    showError(
      "Local SentinelX backend is not reachable. Start the backend by running:\n\n" +
        ".venv/bin/python backend/run.py\n\nin your project directory."
    );
    return;
  }

  try {
    const response = await fetch(`${BACKEND_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: targetUrl }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `Server returned HTTP ${response.status}`);
    }

    const data: AnalyzeResponse = await response.json();
    lastScannedUrl = targetUrl;
    renderResults(data);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error during scan.";
    showError(`Analysis failed: ${message}`);
  } finally {
    setLoading(false);
  }
}

/**
 * Render analysis results to the popup UI
 */
function renderResults(data: AnalyzeResponse): void {
  resultsContainerEl.style.display = "block";

  // URL Display
  currentUrlTextEl.textContent = truncateUrl(data.url, 58);
  currentUrlTextEl.title = data.url;

  // Score & Classification
  riskScoreValueEl.textContent = `${data.risk_score}/100`;
  riskScoreBarEl.style.width = `${Math.min(Math.max(data.risk_score, 5), 100)}%`;

  // Colors & badges
  statusBadgeEl.className = "classification-badge";
  riskScoreBarEl.className = "score-bar-fill";

  if (data.classification === "SAFE") {
    statusBadgeEl.classList.add("safe");
    riskScoreBarEl.classList.add("safe");
    statusBadgeEl.textContent = "SAFE";
    quickBlockBar.style.display = "none";
  } else if (data.classification === "SUSPICIOUS") {
    statusBadgeEl.classList.add("suspicious");
    riskScoreBarEl.classList.add("suspicious");
    statusBadgeEl.textContent = "SUSPICIOUS";
    quickBlockBar.style.display = "none";
  } else {
    statusBadgeEl.classList.add("high-risk");
    riskScoreBarEl.classList.add("high-risk");
    statusBadgeEl.textContent = "HIGH RISK";

    // Offer quick promotion to DNR pre-navigation blocklist
    quickBlockBar.style.display = "flex";
    btnQuickBlock.disabled = false;
    btnQuickBlock.textContent = "⛔ Add to Pre-Navigation Blocklist";
  }

  resultSummaryEl.textContent = data.summary;

  // HTTP vs HTTPS Deep-Dive Explainer
  httpBadgeEl.className = "protocol-badge";
  if (data.http_analysis.is_encrypted) {
    httpBadgeEl.classList.add("encrypted");
    httpBadgeEl.textContent = "HTTPS (TLS)";
  } else {
    httpBadgeEl.classList.add("insecure");
    httpBadgeEl.textContent = "HTTP (Plaintext)";
  }

  httpSummaryEl.textContent = data.http_analysis.summary;
  httpExplanationEl.textContent = data.http_analysis.detailed_explanation;

  // Triggered Rules
  rulesContainerEl.innerHTML = "";
  if (data.triggered_rules.length === 0) {
    rulesContainerEl.innerHTML = `
      <div class="empty-rules-box">
        <span class="icon">🛡️</span>
        <p>No suspicious indicators or phishing patterns triggered.</p>
      </div>
    `;
  } else {
    data.triggered_rules.forEach((rule) => {
      const ruleCard = document.createElement("div");
      ruleCard.className = `rule-item severity-${rule.severity.toLowerCase()}`;
      ruleCard.innerHTML = `
        <div class="rule-header">
          <span class="rule-name">${escapeHtml(rule.name)}</span>
          <span class="rule-penalty">+${rule.penalty}</span>
        </div>
        <div class="rule-meta">
          <span class="rule-category">${escapeHtml(rule.category)}</span>
          <span class="rule-severity-tag ${rule.severity.toLowerCase()}">${rule.severity}</span>
        </div>
        <div class="rule-desc">${escapeHtml(rule.description)}</div>
      `;
      rulesContainerEl.appendChild(ruleCard);
    });
  }

  // Safe Indicators
  safeIndicatorsContainerEl.innerHTML = "";
  if (data.safe_indicators.length > 0) {
    data.safe_indicators.forEach((indicator) => {
      const indEl = document.createElement("div");
      indEl.className = "indicator-item";
      indEl.innerHTML = `<span class="check">✓</span> <span>${escapeHtml(indicator)}</span>`;
      safeIndicatorsContainerEl.appendChild(indEl);
    });
  }
}

// Quick Block Button action
btnQuickBlock.addEventListener("click", () => {
  if (!lastScannedUrl) return;
  const domain = normalizeDomain(lastScannedUrl);
  if (!domain || !isValidDomain(domain)) {
    alert("Cannot block: Invalid domain structure or safeguard host.");
    return;
  }

  chrome.runtime.sendMessage({ action: "ADD_CUSTOM_BLOCK", domain }, (response) => {
    if (response && response.success) {
      btnQuickBlock.disabled = true;
      btnQuickBlock.textContent = "✓ Enforced in Pre-Navigation DNR";
    } else {
      alert("Failed to block domain: " + (response?.error || "Unknown error"));
    }
  });
});

function setLoading(isLoading: boolean): void {
  loadingStateEl.style.display = isLoading ? "flex" : "none";
  scanBtnEl.disabled = isLoading;
  scanCurrentBtnEl.disabled = isLoading;
  if (isLoading) {
    resultsContainerEl.style.display = "none";
  }
}

function showError(msg: string): void {
  errorMessageEl.textContent = msg;
  errorCardEl.style.display = "block";
}

function hideError(): void {
  errorCardEl.style.display = "none";
}

/**
 * Fetch and scan the active tab URL
 */
async function scanActiveTab(): Promise<void> {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentTab = tabs[0];
    if (currentTab && currentTab.url) {
      urlInputEl.value = currentTab.url;
      await analyzeUrl(currentTab.url);
    } else {
      showError("Could not detect active tab URL. Enter a URL manually in the box above.");
    }
  } catch {
    showError("Failed to query active tab. Check extension permissions.");
  }
}

// Scanner Event Listeners
scanBtnEl.addEventListener("click", () => {
  const customUrl = urlInputEl.value.trim();
  if (customUrl) {
    analyzeUrl(customUrl);
  } else {
    showError("Please enter a URL to analyze.");
  }
});

scanCurrentBtnEl.addEventListener("click", () => {
  scanActiveTab();
});

urlInputEl.addEventListener("keydown", (e: KeyboardEvent) => {
  if (e.key === "Enter") {
    scanBtnEl.click();
  }
});

/* =========================================================================
   SETTINGS & PROTECTION RULES CONTROLLER
   ========================================================================= */

async function loadSettingsView(): Promise<void> {
  chrome.runtime.sendMessage({ action: "GET_SETTINGS" }, (settingsRes) => {
    if (settingsRes && settingsRes.success) {
      const settings: ProtectionSettings = settingsRes.settings;

      // Update Radio state
      if (settings.mode === "STANDARD") {
        modeStandardRadio.checked = true;
        dnrStatusPill.className = "pill-active";
        dnrStatusPill.textContent = "Standard DNR Active";
      } else if (settings.mode === "STRICT_ALLOWLIST") {
        modeStrictRadio.checked = true;
        dnrStatusPill.className = "pill-active strict-highlight";
        dnrStatusPill.textContent = "Strict Allowlist Enforcing";
      } else {
        modeDisabledRadio.checked = true;
        dnrStatusPill.className = "pill-disabled";
        dnrStatusPill.textContent = "Protection Disabled";
      }

      renderDomainChips(settings);
    }
  });

  chrome.runtime.sendMessage({ action: "GET_RULES" }, (rulesRes) => {
    if (rulesRes && rulesRes.success) {
      const rules: ThreatRule[] = rulesRes.threatRules || [];
      systemRulesCountEl.textContent = String(rules.length);
    }
  });
}

function renderDomainChips(settings: ProtectionSettings): void {
  // Custom blocklist chips
  customBlockCountEl.textContent = String(settings.customBlocklist.length);
  customBlocklistContainer.innerHTML = "";
  if (settings.customBlocklist.length === 0) {
    customBlocklistContainer.innerHTML = '<span class="empty-list-note">No custom blocked domains.</span>';
  } else {
    settings.customBlocklist.forEach((domain) => {
      const chip = document.createElement("span");
      chip.className = "domain-chip block-chip";
      chip.innerHTML = `
        <span>${escapeHtml(domain)}</span>
        <button class="btn-chip-delete" title="Remove block" data-domain="${escapeHtml(domain)}">×</button>
      `;
      chip.querySelector(".btn-chip-delete")?.addEventListener("click", () => {
        removeDomain(domain, "block");
      });
      customBlocklistContainer.appendChild(chip);
    });
  }

  // Allowlist chips
  allowlistCountEl.textContent = String(settings.allowlist.length);
  allowlistContainer.innerHTML = "";
  if (settings.allowlist.length === 0) {
    allowlistContainer.innerHTML = '<span class="empty-list-note">No allowlist overrides.</span>';
  } else {
    settings.allowlist.forEach((domain) => {
      const chip = document.createElement("span");
      chip.className = "domain-chip allow-chip";
      chip.innerHTML = `
        <span>${escapeHtml(domain)}</span>
        <button class="btn-chip-delete" title="Remove allow" data-domain="${escapeHtml(domain)}">×</button>
      `;
      chip.querySelector(".btn-chip-delete")?.addEventListener("click", () => {
        removeDomain(domain, "allow");
      });
      allowlistContainer.appendChild(chip);
    });
  }
}

// Protection Mode Radio Handlers
[modeStandardRadio, modeStrictRadio, modeDisabledRadio].forEach((radio) => {
  radio.addEventListener("change", () => {
    const selectedMode = (document.querySelector('input[name="protection-mode"]:checked') as HTMLInputElement)
      ?.value;

    if (selectedMode === "STRICT_ALLOWLIST") {
      const confirmStrict = window.confirm(
        "ENABLE STRICT ALLOWLIST MODE?\n\n" +
          "Warning: Strict Allowlist mode blocks ALL websites except those on your Approved Allowlist.\n" +
          "This may disrupt general web browsing. Only enable if you intend to restrict browsing to approved sites."
      );
      if (!confirmStrict) {
        modeStandardRadio.checked = true;
        return;
      }
    }

    chrome.runtime.sendMessage(
      {
        action: "UPDATE_SETTINGS",
        settings: {
          mode: selectedMode,
          protectionEnabled: selectedMode !== "DISABLED",
        },
      },
      () => {
        loadSettingsView();
      }
    );
  });
});

// Add to Blocklist
btnAddBlock.addEventListener("click", () => {
  const domain = normalizeDomain(manageDomainInput.value);
  if (!isValidDomain(domain)) {
    alert("Invalid domain syntax or safeguard host.");
    return;
  }

  chrome.runtime.sendMessage({ action: "ADD_CUSTOM_BLOCK", domain }, (response) => {
    if (response && response.success) {
      manageDomainInput.value = "";
      loadSettingsView();
    } else {
      alert(response?.error || "Failed to add domain to blocklist.");
    }
  });
});

// Add to Allowlist
btnAddAllow.addEventListener("click", () => {
  const domain = normalizeDomain(manageDomainInput.value);
  if (!isValidDomain(domain)) {
    alert("Invalid domain syntax or safeguard host.");
    return;
  }

  chrome.runtime.sendMessage({ action: "ADD_ALLOWLIST", domain }, (response) => {
    if (response && response.success) {
      manageDomainInput.value = "";
      loadSettingsView();
    } else {
      alert(response?.error || "Failed to add domain to allowlist.");
    }
  });
});

function removeDomain(domain: string, type: "block" | "allow"): void {
  const action = type === "block" ? "REMOVE_CUSTOM_BLOCK" : "REMOVE_ALLOWLIST";
  chrome.runtime.sendMessage({ action, domain }, () => {
    loadSettingsView();
  });
}

// Initialize on popup open
document.addEventListener("DOMContentLoaded", async () => {
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get("view") === "settings") {
    switchView("settings");
  } else {
    await checkBackendHealth();
    await scanActiveTab();
  }
});
