/**
 * SentinelX Chrome Extension - Popup Controller (v2.0)
 * Manages active tab scanning, local FastAPI core communication,
 * scan history, central risk policy thresholds, and dynamic DNR rules.
 */

import { AnalyzeResponse, HealthResponse, ScanHistoryItem } from "./types.js";
import { escapeHtml, isValidWebUrl, truncateUrl } from "./utils.js";
import { normalizeDomain, isValidDomain, ProtectionSettings, ThreatRule } from "./threat-manager.js";
import { evaluateUrlLocally } from "./local-analyzer.js";

const BACKEND_BASE_URL = "http://127.0.0.1:8000";

// Navigation Elements
const navScanBtn = document.getElementById("nav-scan") as HTMLButtonElement;
const navHistoryBtn = document.getElementById("nav-history") as HTMLButtonElement;
const navSettingsBtn = document.getElementById("nav-settings") as HTMLButtonElement;

const viewScanner = document.getElementById("view-scanner") as HTMLElement;
const viewHistory = document.getElementById("view-history") as HTMLElement;
const viewSettings = document.getElementById("view-settings") as HTMLElement;

// Header & Global Status Elements
const backendStatusEl = document.getElementById("backend-status") as HTMLElement;
const backendStatusTextEl = document.getElementById("backend-status-text") as HTMLElement;
const globalProtectionBanner = document.getElementById("global-protection-banner") as HTMLElement;
const protectionStatusLabel = document.getElementById("protection-status-label") as HTMLElement;
const modeBadgePill = document.getElementById("mode-badge-pill") as HTMLElement;

// Scanner View Elements
const activeTabDomainEl = document.getElementById("active-tab-domain") as HTMLElement;
const scanCurrentBtnEl = document.getElementById("scan-current-btn") as HTMLButtonElement;
const urlInputEl = document.getElementById("url-input") as HTMLInputElement;
const scanBtnEl = document.getElementById("scan-btn") as HTMLButtonElement;
const loadingStateEl = document.getElementById("loading-state") as HTMLElement;
const errorCardEl = document.getElementById("error-card") as HTMLElement;
const errorTitleEl = document.getElementById("error-title") as HTMLElement;
const errorMessageEl = document.getElementById("error-message") as HTMLElement;
const offlineRecoveryBox = document.getElementById("offline-recovery-box") as HTMLElement;
const resultsContainerEl = document.getElementById("results-container") as HTMLElement;

// Result Elements
const currentUrlTextEl = document.getElementById("current-url-text") as HTMLElement;
const scanTimeTextEl = document.getElementById("scan-time-text") as HTMLElement;
const quickBlockBar = document.getElementById("quick-block-bar") as HTMLElement;
const btnQuickBlock = document.getElementById("btn-quick-block") as HTMLButtonElement;
const riskScoreValueEl = document.getElementById("risk-score-value") as HTMLElement;
const riskScoreBarEl = document.getElementById("risk-score-bar") as HTMLElement;
const statusBadgeEl = document.getElementById("status-badge") as HTMLElement;
const actionPillEl = document.getElementById("action-pill") as HTMLElement;
const resultSummaryEl = document.getElementById("result-summary") as HTMLElement;
const confidenceTextEl = document.getElementById("confidence-text") as HTMLElement;
const flagCountPill = document.getElementById("flag-count-pill") as HTMLElement;
const rulesContainerEl = document.getElementById("rules-container") as HTMLElement;
const httpBadgeEl = document.getElementById("http-badge") as HTMLElement;
const httpSummaryEl = document.getElementById("http-summary") as HTMLElement;
const httpExplanationEl = document.getElementById("http-explanation") as HTMLElement;
const safeIndicatorsContainerEl = document.getElementById("safe-indicators-container") as HTMLElement;

// History View Elements
const historyItemsContainer = document.getElementById("history-items-container") as HTMLElement;
const btnClearHistory = document.getElementById("btn-clear-history") as HTMLButtonElement;

// Settings View Elements
const dnrStatusPill = document.getElementById("dnr-status-pill") as HTMLElement;
const modeStandardRadio = document.getElementById("mode-standard") as HTMLInputElement;
const modeStrictRadio = document.getElementById("mode-strict") as HTMLInputElement;
const modeDisabledRadio = document.getElementById("mode-disabled") as HTMLInputElement;
const inputBlockThreshold = document.getElementById("input-block-threshold") as HTMLInputElement;
const inputWarnThreshold = document.getElementById("input-warn-threshold") as HTMLInputElement;
const btnSaveThresholds = document.getElementById("btn-save-thresholds") as HTMLButtonElement;
const manageDomainInput = document.getElementById("manage-domain-input") as HTMLInputElement;
const btnAddBlock = document.getElementById("btn-add-block") as HTMLButtonElement;
const btnAddAllow = document.getElementById("btn-add-allow") as HTMLButtonElement;
const customBlocklistContainer = document.getElementById("custom-blocklist-container") as HTMLElement;
const allowlistContainer = document.getElementById("allowlist-container") as HTMLElement;
const customBlockCountEl = document.getElementById("custom-block-count") as HTMLElement;
const allowlistCountEl = document.getElementById("allowlist-count") as HTMLElement;
const systemRulesCountEl = document.getElementById("system-rules-count") as HTMLElement;
const btnPingBackend = document.getElementById("btn-ping-backend") as HTMLButtonElement;
const healthBackendVal = document.getElementById("health-backend-val") as HTMLElement;

let lastScannedUrl = "";

/**
 * Check if local FastAPI backend is responsive on 127.0.0.1:8000
 */
async function checkBackendHealth(): Promise<boolean> {
  backendStatusEl.className = "status-indicator checking";
  backendStatusTextEl.textContent = "Checking Core...";

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
      backendStatusTextEl.textContent = `Online (${data.host_restriction})`;
      healthBackendVal.textContent = "127.0.0.1:8000 (Active)";
      healthBackendVal.className = "health-v highlight-green";
      return true;
    }
  } catch {
    // Unreachable
  }

  backendStatusEl.className = "status-indicator degraded";
  backendStatusTextEl.textContent = "Offline (Local Engine Active)";
  healthBackendVal.textContent = "127.0.0.1:8000 (Offline)";
  healthBackendVal.className = "health-v";
  return false;
}

/**
 * Tab Navigation Controller
 */
function switchView(target: "scan" | "history" | "settings"): void {
  [navScanBtn, navHistoryBtn, navSettingsBtn].forEach((b) => b.classList.remove("active"));
  viewScanner.style.display = "none";
  viewHistory.style.display = "none";
  viewSettings.style.display = "none";

  if (target === "scan") {
    navScanBtn.classList.add("active");
    viewScanner.style.display = "flex";
  } else if (target === "history") {
    navHistoryBtn.classList.add("active");
    viewHistory.style.display = "flex";
    loadHistoryView();
  } else {
    navSettingsBtn.classList.add("active");
    viewSettings.style.display = "flex";
    loadSettingsView();
  }
}

navScanBtn.addEventListener("click", () => switchView("scan"));
navHistoryBtn.addEventListener("click", () => switchView("history"));
navSettingsBtn.addEventListener("click", () => switchView("settings"));

/**
 * Perform analysis of a URL via the local backend
 */
async function analyzeUrl(targetUrl: string): Promise<void> {
  if (!isValidWebUrl(targetUrl)) {
    showError(
      "Unsupported URL Scheme",
      "SentinelX scans http:// and https:// web URLs.\nInternal browser pages (chrome://, about:, extensions) are protected by browser sandbox boundaries.",
      false
    );
    return;
  }

  setLoading(true);
  hideError();

  const isHealthy = await checkBackendHealth();
  if (!isHealthy) {
    // Graceful degraded mode: Evaluate via in-extension local heuristic engine!
    try {
      globalProtectionBanner.className = "protection-banner degraded";
      protectionStatusLabel.textContent = "Degraded Mode (Local In-Browser Heuristics Active)";
      modeBadgePill.textContent = "DEGRADED (LOCAL)";

      const localData = evaluateUrlLocally(targetUrl);
      lastScannedUrl = targetUrl;
      renderResults(localData, true);

      // Save to scan history
      const historyItem: ScanHistoryItem = {
        id: String(Date.now()),
        url: localData.url,
        domain: localData.hostname || normalizeDomain(localData.url),
        risk_score: localData.risk_score,
        verdict: localData.verdict || "unknown",
        recommended_action: localData.recommended_action || "PROCEED_WITH_CAUTION",
        timestamp: new Date().toISOString(),
        detection_reasons: localData.detection_reasons || [],
      };
      chrome.runtime.sendMessage({ action: "SAVE_SCAN_RESULT", item: historyItem });

      if (localData.risk_score >= 90 && historyItem.domain) {
        chrome.runtime.sendMessage({
          action: "ADD_DISCOVERED_THREAT",
          domain: historyItem.domain,
          name: `Automated Local Block (${historyItem.domain})`,
          category: "Phishing / Malicious Indicator",
          description: localData.summary,
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Local heuristic evaluation failed.";
      showError("Analysis Failed", msg, false);
    } finally {
      setLoading(false);
    }
    return;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    const response = await fetch(`${BACKEND_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: targetUrl }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `Server returned HTTP ${response.status}`);
    }

    const data: AnalyzeResponse = await response.json();
    lastScannedUrl = targetUrl;
    renderResults(data, false);

    // Save scan to local history via service worker
    const historyItem: ScanHistoryItem = {
      id: String(Date.now()),
      url: data.url,
      domain: data.hostname || normalizeDomain(data.url),
      risk_score: data.risk_score,
      verdict: data.verdict || (data.risk_score >= 80 ? "dangerous" : data.risk_score >= 30 ? "suspicious" : "safe"),
      recommended_action: data.recommended_action || (data.risk_score >= 90 ? "BLOCK" : data.risk_score >= 80 ? "WARN_INTERSTITIAL" : "ALLOW"),
      timestamp: new Date().toISOString(),
      detection_reasons: data.detection_reasons || [],
    };
    chrome.runtime.sendMessage({ action: "SAVE_SCAN_RESULT", item: historyItem });

    // If threat score >= 90, automatically promote to local threat rules for pre-navigation blocking
    if (data.risk_score >= 90 && historyItem.domain) {
      chrome.runtime.sendMessage({
        action: "ADD_DISCOVERED_THREAT",
        domain: historyItem.domain,
        name: `Automated Heuristic Block (${historyItem.domain})`,
        category: "Phishing / Malicious Indicator",
        description: data.summary,
      });
    }
  } catch (err: unknown) {
    // If backend fetch failed unexpectedly during request, fallback to local analyzer!
    console.warn("[SentinelX] Backend request failed, falling back to local analyzer:", err);
    try {
      globalProtectionBanner.className = "protection-banner degraded";
      protectionStatusLabel.textContent = "Degraded Mode (Fallback to In-Browser Engine)";
      const fallbackData = evaluateUrlLocally(targetUrl);
      lastScannedUrl = targetUrl;
      renderResults(fallbackData, true);
    } catch {
      const message = err instanceof Error ? err.message : "Analysis request timed out or failed.";
      showError("Analysis Failed", message, false);
    }
  } finally {
    setLoading(false);
  }
}

/**
 * Render structured analysis results to the popup UI
 */
function renderResults(data: AnalyzeResponse, isDegraded = false): void {
  resultsContainerEl.style.display = "flex";

  // URL & Timestamp
  currentUrlTextEl.textContent = truncateUrl(data.url, 52);
  currentUrlTextEl.title = data.url;
  scanTimeTextEl.textContent = new Date().toLocaleTimeString();

  // Score & Meter
  riskScoreValueEl.textContent = String(data.risk_score);
  riskScoreBarEl.style.width = `${Math.min(Math.max(data.risk_score, 5), 100)}%`;

  // Determine Verdict & Action classes
  let verdict = data.verdict || (data.risk_score >= 90 ? "dangerous" : data.risk_score >= 80 ? "suspicious" : data.risk_score < 30 ? "safe" : "unknown");
  let action = data.recommended_action || (data.risk_score >= 90 ? "BLOCK" : data.risk_score >= 80 ? "WARN_INTERSTITIAL" : "ALLOW");

  // In degraded mode: NEVER label unverified sites as safe!
  if (isDegraded && verdict === "safe" && data.risk_score < 30) {
    verdict = "unknown";
    action = "PROCEED_WITH_CAUTION";
  }

  statusBadgeEl.className = "classification-badge";
  riskScoreBarEl.className = "score-bar-fill";
  actionPillEl.className = "action-pill";

  if (verdict === "dangerous" || data.risk_score >= 90) {
    statusBadgeEl.classList.add("dangerous");
    riskScoreBarEl.classList.add("dangerous");
    actionPillEl.classList.add("block");
    statusBadgeEl.textContent = "DANGEROUS";
    actionPillEl.textContent = "BLOCK";
    quickBlockBar.style.display = "flex";
    btnQuickBlock.disabled = false;
    btnQuickBlock.textContent = "+ Add to Pre-Navigation DNR Blocklist";
  } else if (verdict === "suspicious" || data.risk_score >= 80) {
    statusBadgeEl.classList.add("suspicious");
    riskScoreBarEl.classList.add("suspicious");
    actionPillEl.classList.add("warn");
    statusBadgeEl.textContent = "SUSPICIOUS";
    actionPillEl.textContent = "WARN";
    quickBlockBar.style.display = "none";
  } else if (verdict === "unknown") {
    statusBadgeEl.classList.add("unknown");
    riskScoreBarEl.classList.add("unknown");
    actionPillEl.classList.add("warn");
    statusBadgeEl.textContent = "UNKNOWN";
    actionPillEl.textContent = "UNVERIFIED";
    quickBlockBar.style.display = "none";
  } else {
    statusBadgeEl.classList.add("safe");
    riskScoreBarEl.classList.add("safe");
    actionPillEl.classList.add("allow");
    statusBadgeEl.textContent = "SAFE";
    actionPillEl.textContent = "ALLOW";
    quickBlockBar.style.display = "none";
  }

  resultSummaryEl.textContent = isDegraded ? `[DEGRADED MODE - OFFLINE] ${data.summary}` : data.summary;
  confidenceTextEl.textContent = isDegraded
    ? "DEGRADED (Backend Offline - In-Browser Local Heuristics)"
    : (data.confidence || "Transparent Local Heuristics");

  // Flag Count Pill
  const ruleCount = data.triggered_rules ? data.triggered_rules.length : 0;
  flagCountPill.textContent = `${ruleCount} ${ruleCount === 1 ? "Flag" : "Flags"}`;

  // HTTP vs HTTPS Explainer
  httpBadgeEl.className = "protocol-badge";
  if (data.http_analysis.is_encrypted) {
    httpBadgeEl.classList.add("encrypted");
    httpBadgeEl.textContent = "HTTPS (TLS Active)";
  } else {
    httpBadgeEl.classList.add("insecure");
    httpBadgeEl.textContent = "HTTP (Plaintext Insecure)";
  }
  httpSummaryEl.textContent = data.http_analysis.summary;
  httpExplanationEl.textContent = data.http_analysis.detailed_explanation;

  // Triggered Rules list
  rulesContainerEl.innerHTML = "";
  if (ruleCount === 0) {
    rulesContainerEl.innerHTML = `
      <div class="empty-rules-box">
        <span>🛡️</span>
        <p>No suspicious indicators or phishing signatures triggered.</p>
      </div>
    `;
  } else {
    data.triggered_rules.forEach((rule) => {
      const item = document.createElement("div");
      item.className = `rule-item severity-${rule.severity.toLowerCase()}`;
      item.innerHTML = `
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
      rulesContainerEl.appendChild(item);
    });
  }

  // Safe Indicators
  safeIndicatorsContainerEl.innerHTML = "";
  if (data.safe_indicators && data.safe_indicators.length > 0) {
    data.safe_indicators.forEach((indicator) => {
      const el = document.createElement("div");
      el.className = "indicator-item";
      el.innerHTML = `<span class="check">✓</span> <span>${escapeHtml(indicator)}</span>`;
      safeIndicatorsContainerEl.appendChild(el);
    });
  }
}

// Quick Block Action
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

function showError(title: string, msg: string, isOffline = false): void {
  errorTitleEl.textContent = title;
  errorMessageEl.textContent = msg;
  offlineRecoveryBox.style.display = isOffline ? "block" : "none";
  errorCardEl.style.display = "block";
}

function hideError(): void {
  errorCardEl.style.display = "none";
}

/**
 * Fetch and scan active browser tab
 */
async function scanActiveTab(): Promise<void> {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentTab = tabs[0];
    if (currentTab && currentTab.url) {
      try {
        const urlObj = new URL(currentTab.url);
        activeTabDomainEl.textContent = urlObj.hostname;
      } catch {
        activeTabDomainEl.textContent = "Current Tab";
      }

      urlInputEl.value = currentTab.url;
      await analyzeUrl(currentTab.url);
    } else {
      activeTabDomainEl.textContent = "None";
      showError("No Active Tab Detected", "Enter a URL manually in the input above.", false);
    }
  } catch {
    showError("Tab Query Failed", "Failed to query active tab. Check extension permissions.", false);
  }
}

scanBtnEl.addEventListener("click", () => {
  const customUrl = urlInputEl.value.trim();
  if (customUrl) {
    analyzeUrl(customUrl);
  } else {
    showError("Input Required", "Please enter a web URL (http:// or https://) to analyze.", false);
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
   HISTORY CONTROLLER
   ========================================================================= */

function loadHistoryView(): void {
  chrome.runtime.sendMessage({ action: "GET_SCAN_HISTORY" }, (res) => {
    if (res && res.success) {
      const history: ScanHistoryItem[] = res.history || [];
      renderHistoryItems(history);
    }
  });
}

function renderHistoryItems(items: ScanHistoryItem[]): void {
  historyItemsContainer.innerHTML = "";
  if (items.length === 0) {
    historyItemsContainer.innerHTML = `
      <div class="empty-rules-box">
        <span>🕒</span>
        <p>No recent scans recorded. Active scans will appear here.</p>
      </div>
    `;
    return;
  }

  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "history-item";
    const timeFormatted = new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    row.innerHTML = `
      <div class="history-item-left">
        <span class="history-domain">${escapeHtml(item.domain)}</span>
        <span class="history-time">${timeFormatted} • ${item.recommended_action}</span>
      </div>
      <div class="history-item-right">
        <span class="history-score classification-badge ${item.verdict}">${item.risk_score}</span>
      </div>
    `;
    row.addEventListener("click", () => {
      urlInputEl.value = item.url;
      switchView("scan");
      analyzeUrl(item.url);
    });
    historyItemsContainer.appendChild(row);
  });
}

btnClearHistory.addEventListener("click", () => {
  if (confirm("Clear all locally stored scan history?")) {
    chrome.runtime.sendMessage({ action: "CLEAR_SCAN_HISTORY" }, () => {
      loadHistoryView();
    });
  }
});

/* =========================================================================
   SETTINGS & PROTECTION RULES CONTROLLER
   ========================================================================= */

async function loadSettingsView(): Promise<void> {
  chrome.runtime.sendMessage({ action: "GET_SETTINGS" }, (settingsRes) => {
    if (settingsRes && settingsRes.success) {
      const settings: ProtectionSettings = settingsRes.settings;

      // Update Radio state & Banner
      if (settings.mode === "STANDARD") {
        modeStandardRadio.checked = true;
        dnrStatusPill.className = "pill-active";
        dnrStatusPill.textContent = "Standard DNR Active";
        globalProtectionBanner.className = "protection-banner active";
        protectionStatusLabel.textContent = "Real-Time Protection Active";
        modeBadgePill.textContent = "STANDARD DNR";
      } else if (settings.mode === "STRICT_ALLOWLIST") {
        modeStrictRadio.checked = true;
        dnrStatusPill.className = "pill-active strict-highlight";
        dnrStatusPill.textContent = "Strict Allowlist Enforcing";
        globalProtectionBanner.className = "protection-banner active";
        protectionStatusLabel.textContent = "Strict Allowlist Active (Blocked all others)";
        modeBadgePill.textContent = "STRICT ALLOWLIST";
      } else {
        modeDisabledRadio.checked = true;
        dnrStatusPill.className = "pill-disabled";
        dnrStatusPill.textContent = "Protection Disabled";
        globalProtectionBanner.className = "protection-banner disabled";
        protectionStatusLabel.textContent = "Protection Disabled (Browser Unprotected)";
        modeBadgePill.textContent = "DISABLED";
      }

      // Populate Threshold inputs
      inputBlockThreshold.value = String(settings.blockThreshold || 90);
      inputWarnThreshold.value = String(settings.warnThreshold || 80);

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

// Mode Selection Handlers
[modeStandardRadio, modeStrictRadio, modeDisabledRadio].forEach((radio) => {
  radio.addEventListener("change", () => {
    const selectedMode = (document.querySelector('input[name="protection-mode"]:checked') as HTMLInputElement)
      ?.value;

    if (selectedMode === "STRICT_ALLOWLIST") {
      const confirmStrict = window.confirm(
        "ENABLE STRICT ALLOWLIST MODE?\n\n" +
          "Warning: Strict Allowlist mode blocks ALL websites except those explicitly added to your Approved Allowlist.\n" +
          "This will disrupt general web browsing. Only enable if you intend to restrict browsing to approved sites."
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

// Save Thresholds
btnSaveThresholds.addEventListener("click", () => {
  const bVal = parseInt(inputBlockThreshold.value, 10);
  const wVal = parseInt(inputWarnThreshold.value, 10);

  if (isNaN(bVal) || bVal < 85 || bVal > 100) {
    alert("Block threshold must be between 85 and 100.");
    return;
  }
  if (isNaN(wVal) || wVal < 60 || wVal >= bVal) {
    alert(`Warning threshold must be between 60 and ${bVal - 1}.`);
    return;
  }

  chrome.runtime.sendMessage(
    {
      action: "UPDATE_SETTINGS",
      settings: {
        blockThreshold: bVal,
        warnThreshold: wVal,
      },
    },
    () => {
      alert("Risk policy thresholds updated successfully.");
      loadSettingsView();
    }
  );
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

// Test Ping Button
btnPingBackend.addEventListener("click", async () => {
  btnPingBackend.textContent = "Pinging...";
  const isOnline = await checkBackendHealth();
  btnPingBackend.textContent = isOnline ? "✓ Online" : "✗ Offline";
  setTimeout(() => {
    btnPingBackend.textContent = "Test Ping";
  }, 2000);
});

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
