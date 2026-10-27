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
  warnUnknownPublisher: false,
  blockThreshold: 90,
  warnThreshold: 80,
  allowlist: [],
  customBlocklist: [],
  theme: "dark",
};

// In-memory / session tracking for blocked navigation events
export interface BlockedEvent {
  url: string;
  domain: string;
  ruleName: string;
  ruleId: number;
  reason: string;
  type: "block" | "warning" | "unknown_publisher";
  riskScore: number;
  timestamp: string;
}

// Bounded in-memory evaluation cache (max 100 entries, 60s TTL)
interface CacheEntry {
  eval: ReturnType<typeof evaluateUrlLocally>;
  expiresAt: number;
}
const evaluationCache = new Map<string, CacheEntry>();

export function getCachedEvaluation(url: string, blockThreshold = 90, warnThreshold = 80): ReturnType<typeof evaluateUrlLocally> {
  const now = Date.now();
  const cached = evaluationCache.get(url);
  if (cached && cached.expiresAt > now) {
    return cached.eval;
  }
  const result = evaluateUrlLocally(url, blockThreshold, warnThreshold);
  if (evaluationCache.size >= 100) {
    const oldestKey = evaluationCache.keys().next().value;
    if (oldestKey) evaluationCache.delete(oldestKey);
  }
  evaluationCache.set(url, { eval: result, expiresAt: now + 60000 });
  return result;
}

export function setCachedEvaluation(url: string, result: ReturnType<typeof evaluateUrlLocally>, ttlMs = 60000): void {
  const now = Date.now();
  if (evaluationCache.size >= 100) {
    const oldestKey = evaluationCache.keys().next().value;
    if (oldestKey) evaluationCache.delete(oldestKey);
  }
  evaluationCache.set(url, { eval: result, expiresAt: now + ttlMs });
}

export function hasCachedEvaluation(url: string): boolean {
  const cached = evaluationCache.get(url);
  return Boolean(cached && cached.expiresAt > Date.now());
}

export function clearEvaluationCache(): void {
  evaluationCache.clear();
}

// Track redirect chains per tab (tabId -> list of redirected URLs)
const tabRedirectChains = new Map<number, string[]>();

/**
 * Normalizes a URL for precise single-navigation matching.
 * Trims whitespace, lowercases scheme & host, strips trailing slash from root/path.
 */
export function normalizeUrlForBypass(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== "string") return "";
  try {
    const u = new URL(rawUrl.trim());
    const scheme = u.protocol.toLowerCase();
    const host = u.hostname.toLowerCase();
    const port = u.port ? `:${u.port}` : "";
    let pathname = u.pathname || "/";
    if (pathname.length > 1 && pathname.endsWith("/")) {
      pathname = pathname.slice(0, -1);
    }
    return `${scheme}//${host}${port}${pathname}${u.search}`;
  } catch {
    return rawUrl.trim().toLowerCase();
  }
}

export interface OneTimeBypassEntry {
  tabId: number;
  normalizedUrl: string;
  normalizedDomain: string;
  expiresAt: number;
}

// Scoped strictly to tabId:normalizedUrl or tabId:domain:normalizedDomain.
// Entries are SINGLE-USE and expire in 15 seconds.
const oneTimeNavigationBypasses = new Map<string, OneTimeBypassEntry>();

// In-flight deduplication tracker to prevent duplicate events in the same navigation from looping.
const inFlightNavigationRedirects = new Map<string, number>();

/**
 * Register a strict one-time navigation bypass for a single tab transition.
 * Never grants global or multi-minute domain immunity.
 */
export function addOneTimeBypass(url: string, tabId?: number, domain?: string): void {
  if (tabId === undefined || tabId === null) return;
  const targetUrl = url ? normalizeUrlForBypass(url) : "";
  let targetDomain = domain ? normalizeDomain(domain) : "";
  if (!targetDomain && url) {
    try {
      targetDomain = normalizeDomain(new URL(url).hostname);
    } catch {
      targetDomain = "";
    }
  }
  const expiresAt = Date.now() + 15 * 1000; // 15 seconds single-use transition window

  const entry: OneTimeBypassEntry = {
    tabId,
    normalizedUrl: targetUrl,
    normalizedDomain: targetDomain,
    expiresAt,
  };

  if (targetUrl) {
    oneTimeNavigationBypasses.set(`${tabId}:${targetUrl}`, entry);
  }
  if (targetDomain) {
    oneTimeNavigationBypasses.set(`${tabId}:domain:${targetDomain}`, entry);
  }
}

/**
 * Check and IMMEDIATELY CONSUME a one-time navigation bypass.
 * If a matching, non-expired one-time bypass exists for this tab and URL/domain,
 * it is deleted immediately and returns true.
 * All subsequent checks for repeat visits, reloads, or new tabs return false.
 */
export function consumeOneTimeBypass(url: string, tabId?: number): boolean {
  if (tabId === undefined || tabId === null) return false;
  const now = Date.now();
  const targetUrl = normalizeUrlForBypass(url);
  let domain = "";
  try {
    domain = normalizeDomain(new URL(url).hostname);
  } catch {
    domain = "";
  }

  const urlKey = `${tabId}:${targetUrl}`;
  const domainKey = domain ? `${tabId}:domain:${domain}` : "";

  let matched = false;

  if (oneTimeNavigationBypasses.has(urlKey)) {
    const entry = oneTimeNavigationBypasses.get(urlKey)!;
    if (entry.expiresAt > now) {
      matched = true;
    }
  } else if (domainKey && oneTimeNavigationBypasses.has(domainKey)) {
    const entry = oneTimeNavigationBypasses.get(domainKey)!;
    if (entry.expiresAt > now && (!entry.normalizedUrl || entry.normalizedUrl === targetUrl)) {
      matched = true;
    }
  }

  // Always consume and delete any pending tokens for this tab upon use
  oneTimeNavigationBypasses.delete(urlKey);
  if (domainKey) {
    oneTimeNavigationBypasses.delete(domainKey);
  }

  return matched;
}

/**
 * Legacy compatibility functions.
 */
export function addSessionBypass(domain: string, tabId?: number, url?: string): void {
  addOneTimeBypass(url || `https://${domain}`, tabId, domain);
}

export function isSessionBypassed(domain: string, tabId?: number, url?: string): boolean {
  return consumeOneTimeBypass(url || `https://${domain}`, tabId);
}

/**
 * Clean up tab-scoped in-flight and bypass entries.
 */
export function clearTabState(tabId: number): void {
  for (const [key, entry] of oneTimeNavigationBypasses.entries()) {
    if (entry.tabId === tabId) {
      oneTimeNavigationBypasses.delete(key);
    }
  }
  for (const key of inFlightNavigationRedirects.keys()) {
    if (key.startsWith(`${tabId}:`)) {
      inFlightNavigationRedirects.delete(key);
    }
  }
  tabRedirectChains.delete(tabId);
}

export function clearInFlightRedirect(tabId: number): void {
  for (const key of inFlightNavigationRedirects.keys()) {
    if (key.startsWith(`${tabId}:`)) {
      inFlightNavigationRedirects.delete(key);
    }
  }
}

export function clearAllBypasses(): void {
  oneTimeNavigationBypasses.clear();
  inFlightNavigationRedirects.clear();
  tabRedirectChains.clear();
  clearEvaluationCache();
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
  clearEvaluationCache();
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
if (typeof chrome !== "undefined" && chrome.webNavigation?.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
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

    // Check if user explicitly authorized this single navigation transition in this tab
    if (consumeOneTimeBypass(details.url, details.tabId)) {
      return;
    }

    // Check user allowlist
    for (const allowed of settings.allowlist) {
      if (matchesDomainBoundary(domain, allowed)) {
        return;
      }
    }

    // Deduplication check for in-flight interception on this exact tab and URL
    const inFlightKey = `${details.tabId}:${normalizeUrlForBypass(details.url)}`;
    const inFlightExpiry = inFlightNavigationRedirects.get(inFlightKey);
    if (inFlightExpiry && inFlightExpiry > Date.now()) {
      return;
    }

    // In Strict Allowlist Mode:
    if (settings.mode === "STRICT_ALLOWLIST") {
      const isAllowed = settings.allowlist.some((a) => matchesDomainBoundary(domain, a));
      if (!isAllowed) {
        inFlightNavigationRedirects.set(inFlightKey, Date.now() + 1500);
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
      inFlightNavigationRedirects.set(inFlightKey, Date.now() + 1500);
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

    // 2. Real-time in-extension heuristic evaluation of live web browsing (with bounded caching)!
    const evaluation = getCachedEvaluation(details.url, settings.blockThreshold, settings.warnThreshold);

    if (evaluation.verdict === "dangerous" || evaluation.risk_score >= settings.blockThreshold) {
      inFlightNavigationRedirects.set(inFlightKey, Date.now() + 1500);
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
        eventType: "block",
        ruleName: event.ruleName,
      });

      const blockedUrl = chrome.runtime.getURL(
        `/blocked.html?type=block&domain=${encodeURIComponent(domain)}&score=${evaluation.risk_score}&url=${encodeURIComponent(details.url)}&rule=${encodeURIComponent(event.ruleName)}&reason=${encodeURIComponent(event.reason)}`
      );
      chrome.tabs.update(details.tabId, { url: blockedUrl });
      return;
    }

    if (evaluation.verdict === "suspicious" && evaluation.risk_score >= settings.warnThreshold) {
      if (settings.warnSuspicious) {
        inFlightNavigationRedirects.set(inFlightKey, Date.now() + 1500);
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
          eventType: "warning",
          ruleName: warningEvent.ruleName,
        });

        const warningUrl = chrome.runtime.getURL(
          `/blocked.html?type=warning&domain=${encodeURIComponent(domain)}&score=${evaluation.risk_score}&url=${encodeURIComponent(details.url)}&rule=${encodeURIComponent(warningEvent.ruleName)}&reason=${encodeURIComponent(warningEvent.reason)}`
        );
        chrome.tabs.update(details.tabId, { url: warningUrl });
        return;
      }
    }

    // 3. Unknown Publisher Warning:
    // When enabled in settings, intercept unverified domains where publisher identity is unavailable
    if (settings.warnUnknownPublisher && evaluation.verdict === "unknown") {
      inFlightNavigationRedirects.set(inFlightKey, Date.now() + 1500);
      const unknownEvent: BlockedEvent = {
        url: details.url,
        domain,
        ruleName: "Publisher Identity Unavailable",
        ruleId: 77777,
        reason: "The publisher or website identity cannot be verified against local directories. This website is unverified, not automatically malicious.",
        type: "unknown_publisher",
        riskScore: evaluation.risk_score,
        timestamp: new Date().toISOString(),
      };
      await chrome.storage.session.set({
        [`blocked_${details.tabId}`]: unknownEvent,
        lastBlockedEvent: unknownEvent,
      });

      await addScanHistory({
        id: String(Date.now()),
        url: details.url,
        domain,
        risk_score: evaluation.risk_score,
        verdict: "unknown",
        recommended_action: "UNABLE_TO_VERIFY",
        timestamp: new Date().toISOString(),
        detection_reasons: ["Publisher identity unavailable: domain is not cataloged in local verified directory."],
        eventType: "unknown_publisher",
        ruleName: "Publisher Identity Unavailable",
      });

      const unknownUrl = chrome.runtime.getURL(
        `/blocked.html?type=unknown_publisher&domain=${encodeURIComponent(domain)}&score=${evaluation.risk_score}&url=${encodeURIComponent(details.url)}&rule=${encodeURIComponent(unknownEvent.ruleName)}&reason=${encodeURIComponent(unknownEvent.reason)}`
      );
      chrome.tabs.update(details.tabId, { url: unknownUrl });
      return;
    }
  } catch {
    // Non-fatal navigation tracking error
  }
  });
}

/**
 * Handle secure internal messages between popup / options / blocked pages and the service worker.
 * Webpages CANNOT send messages (restricted to extension origin).
 */
if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
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

      case "ALLOW_SESSION_BYPASS":
      case "ALLOW_ONE_TIME_BYPASS": {
        const domain = message.domain ? normalizeDomain(message.domain) : "";
        const url = message.url || "";
        const tabId = sender.tab?.id;
        if (domain || url) {
          addOneTimeBypass(url || (domain ? `https://${domain}` : ""), tabId, domain);
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
}

// Extension lifecycle hooks
if (typeof chrome !== "undefined") {
  chrome.runtime?.onInstalled?.addListener(async () => {
    console.log("[SentinelX] Initializing security rules on install...");
    await syncDnrRules();
  });

  chrome.runtime?.onStartup?.addListener(async () => {
    console.log("[SentinelX] Restoring security rules on browser startup...");
    await syncDnrRules();
  });

  // Clean up tab-scoped bypasses and deduplication state when tab closes
  chrome.tabs?.onRemoved?.addListener((tabId) => {
    clearTabState(tabId);
  });

  // Clear in-flight navigation markers and track redirect chains once a main-frame navigation commits
  chrome.webNavigation?.onCommitted?.addListener((details) => {
    if (details.frameId === 0) {
      clearInFlightRedirect(details.tabId);
      if (details.transitionQualifiers && (details.transitionQualifiers.includes("server_redirect") || details.transitionQualifiers.includes("client_redirect"))) {
        const chain = tabRedirectChains.get(details.tabId) || [];
        chain.push(details.url);
        if (chain.length > 10) chain.shift();
        tabRedirectChains.set(details.tabId, chain);
      }
    }
  });
}
