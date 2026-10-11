/**
 * SentinelX Background Service Worker
 * Manages declarativeNetRequest dynamic rules, navigation interception,
 * local threat database persistence, scan history, and secure internal messaging.
 */

import {
  compileDnrRules,
  isValidDomain,
  matchesDomainBoundary,
  normalizeDomain,
  ProtectionSettings,
  SAFEGUARD_HOSTS,
  SEED_THREAT_RULES,
  ThreatRule,
} from "./threat-manager.js";
import { ScanHistoryItem } from "./types.js";
import { evaluateUrlLocally } from "./local-analyzer.js";
import { isValidWebUrl } from "./utils.js";

export const DEFAULT_SETTINGS: ProtectionSettings = {
  protectionEnabled: true,
  mode: "STANDARD",
  blockHighConfidence: true,
  warnSuspicious: true,
  blockThreshold: 90,
  warnThreshold: 80,
  allowlist: [],
  customBlocklist: [],
};

// In-memory / session tracking for blocked navigation events
export interface BlockedEvent {
  url: string;
  domain: string;
  ruleName: string;
  ruleId: number;
  reason: string;
  type: "block" | "warning";
  riskScore: number;
  timestamp: string;
}

// In-memory session bypass to prevent redirect loops when user explicitly proceeds
const sessionBypasses = new Map<string, number>();

export function addSessionBypass(domain: string, tabId?: number): void {
  const norm = normalizeDomain(domain);
  const expiry = Date.now() + 5 * 60 * 1000; // 5 minute bypass
  sessionBypasses.set(norm, expiry);
  if (tabId) {
    sessionBypasses.set(`${tabId}:${norm}`, expiry);
  }
}

export function isSessionBypassed(domain: string, tabId?: number): boolean {
  const norm = normalizeDomain(domain);
  const now = Date.now();
  if (tabId && sessionBypasses.has(`${tabId}:${norm}`)) {
    if (sessionBypasses.get(`${tabId}:${norm}`)! > now) return true;
    sessionBypasses.delete(`${tabId}:${norm}`);
  }
  if (sessionBypasses.has(norm)) {
    if (sessionBypasses.get(norm)! > now) return true;
    sessionBypasses.delete(norm);
  }
  return false;
}

/**
 * Retrieve current protection settings from storage.
 */
export async function getSettings(): Promise<ProtectionSettings> {
  const result = await chrome.storage.local.get("sentinel_settings");
  if (result.sentinel_settings) {
    return { ...DEFAULT_SETTINGS, ...result.sentinel_settings };
  }
  await chrome.storage.local.set({ sentinel_settings: DEFAULT_SETTINGS });
  return DEFAULT_SETTINGS;
}

/**
 * Save protection settings to storage and update DNR engine.
 */
export async function saveSettings(settings: ProtectionSettings): Promise<void> {
  await chrome.storage.local.set({ sentinel_settings: settings });
  await syncDnrRules();
}

/**
 * Retrieve current threat rules from storage.
 */
export async function getThreatRules(): Promise<ThreatRule[]> {
  const result = await chrome.storage.local.get("sentinel_threat_rules");
  if (Array.isArray(result.sentinel_threat_rules) && result.sentinel_threat_rules.length > 0) {
    return result.sentinel_threat_rules;
  }
  await chrome.storage.local.set({ sentinel_threat_rules: SEED_THREAT_RULES });
  return SEED_THREAT_RULES;
}

/**
 * Retrieve scan history from local storage (capped at 50 entries).
 */
export async function getScanHistory(): Promise<ScanHistoryItem[]> {
  const result = await chrome.storage.local.get("sentinel_scan_history");
  return Array.isArray(result.sentinel_scan_history) ? result.sentinel_scan_history : [];
}

/**
 * Add an item to scan history.
 */
export async function addScanHistory(item: ScanHistoryItem): Promise<void> {
  const history = await getScanHistory();
  // Filter out duplicate domain entries, keep latest at top
  const filtered = history.filter((h) => h.domain !== item.domain);
  filtered.unshift(item);
  const capped = filtered.slice(0, 50);
  await chrome.storage.local.set({ sentinel_scan_history: capped });
}

/**
 * Clear all scan history.
 */
export async function clearScanHistory(): Promise<void> {
  await chrome.storage.local.set({ sentinel_scan_history: [] });
}

/**
 * Synchronize Chrome's declarativeNetRequest dynamic rules with current settings and threat rules.
 */
export async function syncDnrRules(): Promise<void> {
  try {
    const [settings, threatRules] = await Promise.all([getSettings(), getThreatRules()]);

    const compiledRules = compileDnrRules(threatRules, settings);

    // Get all existing dynamic rule IDs to replace them atomically
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const existingRuleIds = existingRules.map((r) => r.id);

    // Atomic update of DNR dynamic rules
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingRuleIds,
      addRules: compiledRules,
    });

    console.log(
      `[SentinelX] DNR sync complete. Active dynamic rules: ${compiledRules.length} (Mode: ${settings.mode})`
    );
  } catch (err) {
    console.error("[SentinelX] Failed to sync declarativeNetRequest dynamic rules:", err);
  }
}

/**
 * Find matching threat rule for a given target domain.
 */
export async function findMatchingRule(targetDomain: string): Promise<ThreatRule | null> {
  const [settings, threatRules] = await Promise.all([getSettings(), getThreatRules()]);
  const normTarget = normalizeDomain(targetDomain);

  // Check allowlist first: if allowed, never treat as matching threat rule
  for (const allowed of settings.allowlist) {
    if (matchesDomainBoundary(normTarget, allowed)) {
      return null;
    }
  }

  // Check system threat rules
  for (const rule of threatRules) {
    if (matchesDomainBoundary(normTarget, rule.domain)) {
      return rule;
    }
  }

  // Check custom user blocklist
  for (const custom of settings.customBlocklist) {
    if (matchesDomainBoundary(normTarget, custom)) {
      return {
        id: 10000,
        domain: custom,
        name: "User Custom Blocklist",
        category: "User Policy",
        severity: "HIGH",
        confidence: "HIGH",
        source: "USER",
        description: "Domain manually blocked in extension settings.",
        createdAt: new Date().toISOString(),
      };
    }
  }

  return null;
}

/**
 * Web Navigation listener: Records blocked events in session storage
 * to provide rich context to blocked.html when DNR intercepts or redirects navigation.
 */
chrome.webNavigation?.onBeforeNavigate?.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only top-level main_frame navigations

  try {
    if (!details.url || !isValidWebUrl(details.url)) return;

    let urlObj: URL;
    try {
      urlObj = new URL(details.url);
    } catch {
      return;
    }

    if (urlObj.protocol !== "http:" && urlObj.protocol !== "https:") return;

    const domain = urlObj.hostname.toLowerCase();
    if (!domain || SAFEGUARD_HOSTS.has(domain)) return;

    // Prevent redirect loops: ignore if already on internal blocked page
    if (details.url.includes(chrome.runtime.id)) return;

    const settings = await getSettings();
    if (!settings.protectionEnabled || settings.mode === "DISABLED") return;

    // Check if user explicitly allowed navigation in this session
    if (isSessionBypassed(domain, details.tabId)) return;

    // Check user allowlist
    for (const allowed of settings.allowlist) {
      if (matchesDomainBoundary(domain, allowed)) {
        return;
      }
    }

    // In Strict Allowlist Mode:
    if (settings.mode === "STRICT_ALLOWLIST") {
      const isAllowed = settings.allowlist.some((a) => matchesDomainBoundary(domain, a));
      if (!isAllowed) {
        const event: BlockedEvent = {
          url: details.url,
          domain,
          ruleName: "Strict Allowlist Enforcement",
          ruleId: 99999,
          reason: "Strict allowlist mode is enabled and this domain is not on your approved allowlist.",
          type: "block",
          riskScore: 100,
          timestamp: new Date().toISOString(),
        };
        await chrome.storage.session.set({
          [`blocked_${details.tabId}`]: event,
          lastBlockedEvent: event,
        });
        const blockedUrl = chrome.runtime.getURL(
          `/blocked.html?type=block&domain=${encodeURIComponent(domain)}&score=100&url=${encodeURIComponent(details.url)}&reason=strict_allowlist`
        );
        chrome.tabs.update(details.tabId, { url: blockedUrl });
      }
      return;
    }

    // Standard Mode:
    // 1. Check existing threat rules or custom blocklist
    const matchedRule = await findMatchingRule(domain);
    if (matchedRule) {
      const event: BlockedEvent = {
        url: details.url,
        domain,
        ruleName: matchedRule.name,
        ruleId: matchedRule.id,
        reason: matchedRule.description,
        type: "block",
        riskScore: matchedRule.severity === "CRITICAL" ? 100 : 90,
        timestamp: new Date().toISOString(),
      };
      await chrome.storage.session.set({
        [`blocked_${details.tabId}`]: event,
        lastBlockedEvent: event,
      });
      const blockedUrl = chrome.runtime.getURL(
        `/blocked.html?type=block&domain=${encodeURIComponent(domain)}&score=${event.riskScore}&url=${encodeURIComponent(details.url)}&rule=${encodeURIComponent(matchedRule.name)}&reason=${encodeURIComponent(matchedRule.description)}`
      );
      chrome.tabs.update(details.tabId, { url: blockedUrl });
      return;
    }

    // 2. Real-time in-extension heuristic evaluation of live web browsing!
    const evaluation = evaluateUrlLocally(details.url, settings.blockThreshold, settings.warnThreshold);

    if (evaluation.verdict === "dangerous" || evaluation.risk_score >= settings.blockThreshold) {
      const event: BlockedEvent = {
        url: details.url,
        domain,
        ruleName: evaluation.triggered_rules[0]?.name || "Heuristic Critical Threat",
        ruleId: 90000 + Math.floor(Math.random() * 9999),
        reason: (evaluation.detection_reasons || []).join(" ") || evaluation.summary,
        type: "block",
        riskScore: evaluation.risk_score,
        timestamp: new Date().toISOString(),
      };
      await chrome.storage.session.set({
        [`blocked_${details.tabId}`]: event,
        lastBlockedEvent: event,
      });

      // Automatically register discovered high-risk domain into DNR dynamic rules
      const threatRules = await getThreatRules();
      if (!threatRules.some((r) => r.domain === domain)) {
        threatRules.push({
          id: event.ruleId,
          domain,
          name: event.ruleName,
          category: "Heuristic Block",
          severity: "CRITICAL",
          confidence: "HIGH",
          source: "HEURISTIC",
          description: event.reason,
          createdAt: new Date().toISOString(),
        });
        await chrome.storage.local.set({ sentinel_threat_rules: threatRules });
        await syncDnrRules();
      }

      await addScanHistory({
        id: String(Date.now()),
        url: details.url,
        domain,
        risk_score: evaluation.risk_score,
        verdict: "dangerous",
        recommended_action: "BLOCK",
        timestamp: new Date().toISOString(),
        detection_reasons: evaluation.detection_reasons || [],
      });

      const blockedUrl = chrome.runtime.getURL(
        `/blocked.html?type=block&domain=${encodeURIComponent(domain)}&score=${evaluation.risk_score}&url=${encodeURIComponent(details.url)}&rule=${encodeURIComponent(event.ruleName)}&reason=${encodeURIComponent(event.reason)}`
      );
      chrome.tabs.update(details.tabId, { url: blockedUrl });
      return;
    }

    if (evaluation.verdict === "suspicious" && evaluation.risk_score >= settings.warnThreshold) {
      if (settings.warnSuspicious) {
        const warningEvent: BlockedEvent = {
          url: details.url,
          domain,
          ruleName: evaluation.triggered_rules[0]?.name || "Elevated Risk Warning",
          ruleId: 88888,
          reason: (evaluation.detection_reasons || []).join(" ") || evaluation.summary,
          type: "warning",
          riskScore: evaluation.risk_score,
          timestamp: new Date().toISOString(),
        };
        await chrome.storage.session.set({
          [`blocked_${details.tabId}`]: warningEvent,
          lastBlockedEvent: warningEvent,
        });

        await addScanHistory({
          id: String(Date.now()),
          url: details.url,
          domain,
          risk_score: evaluation.risk_score,
          verdict: "suspicious",
          recommended_action: "WARN_INTERSTITIAL",
          timestamp: new Date().toISOString(),
          detection_reasons: evaluation.detection_reasons || [],
        });

        const warningUrl = chrome.runtime.getURL(
          `/blocked.html?type=warning&domain=${encodeURIComponent(domain)}&score=${evaluation.risk_score}&url=${encodeURIComponent(details.url)}&rule=${encodeURIComponent(warningEvent.ruleName)}&reason=${encodeURIComponent(warningEvent.reason)}`
        );
        chrome.tabs.update(details.tabId, { url: warningUrl });
        return;
      }
    }
  } catch {
    // Non-fatal navigation tracking error
  }
});

/**
 * Handle secure internal messages between popup / options / blocked pages and the service worker.
 * Webpages CANNOT send messages (restricted to extension origin).
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) {
    sendResponse({ error: "Unauthorized sender" });
    return false;
  }

  (async () => {
    switch (message.action) {
      case "GET_SETTINGS": {
        const settings = await getSettings();
        sendResponse({ success: true, settings });
        break;
      }

      case "UPDATE_SETTINGS": {
        const current = await getSettings();
        const updated: ProtectionSettings = { ...current, ...message.settings };
        await saveSettings(updated);
        sendResponse({ success: true, settings: updated });
        break;
      }

      case "GET_RULES": {
        const [rules, settings] = await Promise.all([getThreatRules(), getSettings()]);
        sendResponse({
          success: true,
          threatRules: rules,
          customBlocklist: settings.customBlocklist,
          allowlist: settings.allowlist,
        });
        break;
      }

      case "ADD_CUSTOM_BLOCK": {
        const domain = normalizeDomain(message.domain);
        if (!isValidDomain(domain)) {
          sendResponse({ success: false, error: "Invalid domain syntax or safeguard host." });
          return;
        }

        const settings = await getSettings();
        if (!settings.customBlocklist.includes(domain)) {
          settings.customBlocklist.push(domain);
          settings.allowlist = settings.allowlist.filter((d) => d !== domain);
          await saveSettings(settings);
        }
        sendResponse({ success: true, settings });
        break;
      }

      case "REMOVE_CUSTOM_BLOCK": {
        const domain = normalizeDomain(message.domain);
        const settings = await getSettings();
        settings.customBlocklist = settings.customBlocklist.filter((d) => d !== domain);
        await saveSettings(settings);
        sendResponse({ success: true, settings });
        break;
      }

      case "ADD_ALLOWLIST": {
        const domain = normalizeDomain(message.domain);
        if (!isValidDomain(domain)) {
          sendResponse({ success: false, error: "Invalid domain syntax or safeguard host." });
          return;
        }

        const settings = await getSettings();
        if (!settings.allowlist.includes(domain)) {
          settings.allowlist.push(domain);
          settings.customBlocklist = settings.customBlocklist.filter((d) => d !== domain);
          await saveSettings(settings);
        }
        sendResponse({ success: true, settings });
        break;
      }

      case "REMOVE_ALLOWLIST": {
        const domain = normalizeDomain(message.domain);
        const settings = await getSettings();
        settings.allowlist = settings.allowlist.filter((d) => d !== domain);
        await saveSettings(settings);
        sendResponse({ success: true, settings });
        break;
      }

      case "ADD_DISCOVERED_THREAT": {
        const domain = normalizeDomain(message.domain);
        if (isValidDomain(domain)) {
          const rules = await getThreatRules();
          if (!rules.some((r) => r.domain === domain)) {
            const newRule: ThreatRule = {
              id: Date.now() % 100000,
              domain,
              name: message.name || "Automated Threat Detection",
              category: message.category || "Heuristic Analysis",
              severity: "CRITICAL",
              confidence: "HIGH",
              source: "HEURISTIC",
              description: message.description || "Identified as high risk by SentinelX security engine.",
              createdAt: new Date().toISOString(),
            };
            rules.push(newRule);
            await chrome.storage.local.set({ sentinel_threat_rules: rules });
            await syncDnrRules();
          }
        }
        sendResponse({ success: true });
        break;
      }

      case "GET_LAST_BLOCKED": {
        const tabId = sender.tab?.id;
        const result = await chrome.storage.session.get(
          tabId ? [`blocked_${tabId}`, "lastBlockedEvent"] : ["lastBlockedEvent"]
        );
        const event = (tabId && result[`blocked_${tabId}`]) || result.lastBlockedEvent || null;
        sendResponse({ success: true, event });
        break;
      }

      case "GET_SCAN_HISTORY": {
        const history = await getScanHistory();
        sendResponse({ success: true, history });
        break;
      }

      case "SAVE_SCAN_RESULT": {
        if (message.item) {
          await addScanHistory(message.item);
        }
        sendResponse({ success: true });
        break;
      }

      case "CLEAR_SCAN_HISTORY": {
        await clearScanHistory();
        sendResponse({ success: true });
        break;
      }

      case "SYNC_DNR_RULES": {
        await syncDnrRules();
        sendResponse({ success: true });
        break;
      }

      case "ALLOW_SESSION_BYPASS": {
        const domain = normalizeDomain(message.domain);
        if (domain) {
          addSessionBypass(domain, sender.tab?.id);
        }
        sendResponse({ success: true });
        break;
      }

      default:
        sendResponse({ error: "Unknown action" });
    }
  })();

  return true; // Keep message channel open for async response
});

// Extension lifecycle hooks
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[SentinelX] Initializing security rules on install...");
  await syncDnrRules();
});

chrome.runtime.onStartup.addListener(async () => {
  console.log("[SentinelX] Restoring security rules on browser startup...");
  await syncDnrRules();
});
