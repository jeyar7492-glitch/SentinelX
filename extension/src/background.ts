/**
 * SentinelX Background Service Worker
 * Manages declarativeNetRequest dynamic rules, navigation interception,
 * local threat database persistence, and secure internal messaging.
 */

import {
  compileDnrRules,
  isValidDomain,
  matchesDomainBoundary,
  normalizeDomain,
  ProtectionSettings,
  SEED_THREAT_RULES,
  ThreatRule,
} from "./threat-manager.js";

export const DEFAULT_SETTINGS: ProtectionSettings = {
  protectionEnabled: true,
  mode: "STANDARD",
  blockHighConfidence: true,
  warnSuspicious: true,
  allowlist: [],
  customBlocklist: [],
};

// In-memory / session tracking for blocked navigation events
interface BlockedEvent {
  url: string;
  domain: string;
  ruleName: string;
  ruleId: number;
  reason: string;
  timestamp: string;
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
 * Synchronize Chrome's declarativeNetRequest dynamic rules with current settings and threat rules.
 */
export async function syncDnrRules(): Promise<void> {
  try {
    const [settings, threatRules] = await Promise.all([getSettings(), getThreatRules()]);

    const compiledRules = compileDnrRules(threatRules, settings);

    // Get all existing dynamic rule IDs to remove them
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

  // Check allowlist first
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
 * to provide context to blocked.html when DNR redirects.
 */
chrome.webNavigation?.onBeforeNavigate?.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only top-level main_frame navigations

  try {
    const urlObj = new URL(details.url);
    if (urlObj.protocol !== "http:" && urlObj.protocol !== "https:") return;

    const domain = urlObj.hostname;
    const settings = await getSettings();

    if (!settings.protectionEnabled || settings.mode === "DISABLED") return;

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
          timestamp: new Date().toISOString(),
        };
        await chrome.storage.session.set({ [`blocked_${details.tabId}`]: event, lastBlockedEvent: event });
      }
      return;
    }

    // Standard Mode:
    const matchedRule = await findMatchingRule(domain);
    if (matchedRule) {
      const event: BlockedEvent = {
        url: details.url,
        domain,
        ruleName: matchedRule.name,
        ruleId: matchedRule.id,
        reason: matchedRule.description,
        timestamp: new Date().toISOString(),
      };
      await chrome.storage.session.set({ [`blocked_${details.tabId}`]: event, lastBlockedEvent: event });
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
  // Enforce internal-only message validation
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
          // Remove from allowlist if previously present
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
          // Remove from custom blocklist if present
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
        // Automatically promoted from high-confidence backend analysis
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

      case "SYNC_DNR_RULES": {
        await syncDnrRules();
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
