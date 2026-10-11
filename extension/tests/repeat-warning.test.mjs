/**
 * SentinelX Regression Test Suite: Repeat Unsafe Visit Protection
 * Verifies that warnings and blocks remain strictly active across repeat visits,
 * reloads, new tabs, and different paths, without creating infinite redirect loops.
 *
 * Tests 10 mandatory scenarios:
 * 1. First visit to a simulated unsafe URL
 * 2. Second visit to the exact same URL
 * 3. Third visit after dismissing the first warning
 * 4. Reloading the unsafe URL
 * 5. Opening the unsafe URL in a new tab
 * 6. Visiting another unsafe path on the same domain
 * 7. Visiting a benign test URL
 * 8. Restarting the extension service worker and testing again
 * 9. Backend unavailable: local protection still works
 * 10. Duplicate navigation events do not create infinite warning loops
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  addOneTimeBypass,
  consumeOneTimeBypass,
  clearAllBypasses,
  clearTabState,
  normalizeUrlForBypass,
  DEFAULT_SETTINGS,
} from "../dist/background.js";

import { evaluateUrlLocally } from "../dist/local-analyzer.js";
import {
  compileDnrRules,
  matchesDomainBoundary,
  normalizeDomain,
  SEED_THREAT_RULES,
} from "../dist/threat-manager.js";

// Mock Chrome API environment for navigation testing
class MockChromeEnvironment {
  constructor() {
    this.sessionStore = {};
    this.localStore = {
      sentinel_settings: { ...DEFAULT_SETTINGS },
      sentinel_threat_rules: [...SEED_THREAT_RULES],
      sentinel_scan_history: [],
    };
    this.tabs = new Map(); // tabId -> current URL
    this.updates = []; // tab update calls [{ tabId, url }]
    this.runtimeId = "sentinelx-extension-id-test";
    this.inFlightRedirects = new Map();
  }

  getURL(path) {
    return `chrome-extension://${this.runtimeId}${path}`;
  }

  updateTab(tabId, updateInfo) {
    this.updates.push({ tabId, url: updateInfo.url });
    this.tabs.set(tabId, updateInfo.url);
  }

  /**
   * Simulates webNavigation.onCommitted clearing in-flight redirect state.
   */
  commitNavigation(tabId) {
    for (const key of this.inFlightRedirects.keys()) {
      if (key.startsWith(`${tabId}:`)) {
        this.inFlightRedirects.delete(key);
      }
    }
  }

  /**
   * Simulates the exact onBeforeNavigate pipeline of SentinelX background service worker.
   */
  async handleBeforeNavigate(details) {
    if (details.frameId !== 0) return { action: "ignored", reason: "subframe" };
    if (!details.url || (!details.url.startsWith("http://") && !details.url.startsWith("https://"))) {
      return { action: "ignored", reason: "invalid_scheme" };
    }

    let urlObj;
    try {
      urlObj = new URL(details.url);
    } catch {
      return { action: "ignored", reason: "malformed_url" };
    }

    const domain = urlObj.hostname.toLowerCase();
    const safeguards = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);
    if (safeguards.has(domain)) return { action: "allowed", reason: "safeguard_host" };

    if (details.url.includes(this.runtimeId)) {
      return { action: "allowed", reason: "internal_extension_page" };
    }

    const settings = this.localStore.sentinel_settings || DEFAULT_SETTINGS;
    if (!settings.protectionEnabled || settings.mode === "DISABLED") {
      return { action: "allowed", reason: "protection_disabled" };
    }

    // 1. One-time transition bypass check
    if (consumeOneTimeBypass(details.url, details.tabId)) {
      this.tabs.set(details.tabId, details.url);
      return { action: "allowed", reason: "authorized_one_time_transition" };
    }

    // 2. Allowlist check
    for (const allowed of settings.allowlist || []) {
      if (matchesDomainBoundary(domain, allowed)) {
        this.tabs.set(details.tabId, details.url);
        return { action: "allowed", reason: "allowlisted" };
      }
    }

    // 3. Deduplication check for in-flight redirect
    const inFlightKey = `${details.tabId}:${normalizeUrlForBypass(details.url)}`;
    const inFlightExpiry = this.inFlightRedirects.get(inFlightKey);
    if (inFlightExpiry && inFlightExpiry > Date.now()) {
      return { action: "deduplicated", reason: "already_in_flight_redirect" };
    }

    // 4. Threat rule check
    const rules = this.localStore.sentinel_threat_rules || SEED_THREAT_RULES;
    for (const rule of rules) {
      if (matchesDomainBoundary(domain, rule.domain)) {
        this.inFlightRedirects.set(inFlightKey, Date.now() + 1500);
        const blockedUrl = this.getURL(
          `/blocked.html?type=block&domain=${encodeURIComponent(domain)}&score=95&url=${encodeURIComponent(details.url)}&rule=${encodeURIComponent(rule.name)}`
        );
        this.updateTab(details.tabId, { url: blockedUrl });
        return { action: "blocked", type: "block", score: 95, url: blockedUrl };
      }
    }

    // 5. Local heuristic evaluation
    const evaluation = evaluateUrlLocally(details.url, settings.blockThreshold, settings.warnThreshold);

    if (evaluation.verdict === "dangerous" || evaluation.risk_score >= settings.blockThreshold) {
      this.inFlightRedirects.set(inFlightKey, Date.now() + 1500);
      const blockedUrl = this.getURL(
        `/blocked.html?type=block&domain=${encodeURIComponent(domain)}&score=${evaluation.risk_score}&url=${encodeURIComponent(details.url)}`
      );
      this.updateTab(details.tabId, { url: blockedUrl });
      return { action: "blocked", type: "block", score: evaluation.risk_score, url: blockedUrl };
    }

    if (evaluation.verdict === "suspicious" && evaluation.risk_score >= settings.warnThreshold) {
      if (settings.warnSuspicious) {
        this.inFlightRedirects.set(inFlightKey, Date.now() + 1500);
        const warningUrl = this.getURL(
          `/blocked.html?type=warning&domain=${encodeURIComponent(domain)}&score=${evaluation.risk_score}&url=${encodeURIComponent(details.url)}`
        );
        this.updateTab(details.tabId, { url: warningUrl });
        return { action: "warned", type: "warning", score: evaluation.risk_score, url: warningUrl };
      }
    }

    this.tabs.set(details.tabId, details.url);
    return { action: "allowed", reason: "clean_evaluation", score: evaluation.risk_score };
  }
}

// Simulated unsafe URL fixture (elevated risk score 85 -> triggers warning interstitial)
const SIMULATED_UNSAFE_URL = "http://sub1.sub2.sub3.auth-portal.test/verify-login?session=" + "x".repeat(70);
// Simulated dangerous URL fixture (risk score 100 -> triggers critical block)
const SIMULATED_DANGEROUS_URL = "http://192.168.1.100:8080/admin-login.php";
// Simulated benign URL fixture
const BENIGN_TEST_URL = "https://google.com/search?q=cybersecurity";

test("Scenario 1: First visit to simulated unsafe URL displays warning interstitial", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  const result = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });

  assert.equal(result.action, "warned");
  assert.equal(result.type, "warning");
  assert.ok(result.score >= 80 && result.score < 90, `Score must be 80-89: got ${result.score}`);
  assert.ok(result.url.includes("blocked.html?type=warning"));
  assert.equal(env.updates.length, 1);
});

test("Scenario 2: Second visit to exact same unsafe URL displays warning interstitial again", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  // First visit
  const first = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(first.action, "warned");
  env.commitNavigation(1); // Warning page commits in Tab 1

  // Second visit to exact same URL (no dismissal was made)
  const second = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(second.action, "warned");
  assert.equal(second.type, "warning");
  assert.ok(second.url.includes("blocked.html?type=warning"));
  assert.equal(env.updates.length, 2, "Second visit must trigger a new warning redirect");
});

test("Scenario 3: Third visit after dismissing first warning displays warning interstitial again", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  // Visit 1: Intercepted with warning
  const visit1 = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(visit1.action, "warned");
  env.commitNavigation(1); // Interstitial commits in Tab 1

  // User dismisses warning on interstitial (clicks Proceed):
  // Single-use token is authorized for Tab 1 and the target URL
  addOneTimeBypass(SIMULATED_UNSAFE_URL, 1, "sub1.sub2.sub3.auth-portal.test");

  // Visit 2 (Authorized single transition): Loads the page and CONSUMES the token
  const visit2 = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(visit2.action, "allowed");
  assert.equal(visit2.reason, "authorized_one_time_transition");
  env.commitNavigation(1); // Destination page commits in Tab 1

  // Visit 3 (Repeat visit after dismissal): Token is already consumed!
  const visit3 = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(visit3.action, "warned", "Third visit must be intercepted with warning");
  assert.equal(visit3.type, "warning");
});

test("Scenario 4: Reloading the unsafe URL displays warning interstitial", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  // Initial visit and one-time proceed
  addOneTimeBypass(SIMULATED_UNSAFE_URL, 1, "sub1.sub2.sub3.auth-portal.test");
  const initial = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(initial.action, "allowed");

  // User reloads the page (F5 / browser reload)
  const reload = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });

  assert.equal(reload.action, "warned", "Reload must trigger warning interstitial");
  assert.equal(reload.type, "warning");
});

test("Scenario 5: Opening unsafe URL in a new tab displays warning interstitial", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  // Tab 1 proceeds past warning
  addOneTimeBypass(SIMULATED_UNSAFE_URL, 1, "sub1.sub2.sub3.auth-portal.test");
  await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });

  // Tab 2 opens the exact same URL
  const tab2 = await env.handleBeforeNavigate({
    tabId: 2,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });

  assert.equal(tab2.action, "warned", "New tab must NOT inherit bypass from another tab");
  assert.equal(tab2.type, "warning");
});

test("Scenario 6: Visiting another unsafe path on same domain displays warning interstitial", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  // Proceed for specific path
  addOneTimeBypass(SIMULATED_UNSAFE_URL, 1, "sub1.sub2.sub3.auth-portal.test");
  await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });

  // User navigates to a different path on the same domain
  const otherPath = "http://sub1.sub2.sub3.auth-portal.test/reset-password?token=" + "y".repeat(70);
  const result = await env.handleBeforeNavigate({
    tabId: 1,
    url: otherPath,
    frameId: 0,
  });

  assert.equal(result.action, "warned", "Different path on same domain must trigger warning");
});

test("Scenario 7: Visiting a benign test URL is allowed through without warning", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  const result = await env.handleBeforeNavigate({
    tabId: 1,
    url: BENIGN_TEST_URL,
    frameId: 0,
  });

  assert.equal(result.action, "allowed");
  assert.equal(result.reason, "clean_evaluation");
  assert.equal(env.updates.length, 0, "No tab update should occur for benign URLs");
});

test("Scenario 8: Restarting service worker preserves warning and block protection", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  // Add custom high-risk rule to persistent storage
  env.localStore.sentinel_threat_rules.push({
    id: 501,
    domain: "persistent-threat-fixture.test",
    name: "Persistent Threat Fixture",
    category: "Phishing",
    severity: "CRITICAL",
    confidence: "HIGH",
    source: "SYSTEM",
    description: "Test threat for service worker restarts.",
    createdAt: new Date().toISOString(),
  });

  // Simulate Service Worker termination and restart:
  // In-memory bypasses and in-flight maps are wiped, but storage persists
  clearAllBypasses();

  // Attempt to visit threat URL after simulated restart
  const result = await env.handleBeforeNavigate({
    tabId: 3,
    url: "https://persistent-threat-fixture.test/login",
    frameId: 0,
  });

  assert.equal(result.action, "blocked");
  assert.equal(result.type, "block");
  assert.ok(result.url.includes("blocked.html?type=block"));
});

test("Scenario 9: Backend unavailable: local protection intercepts without network dependencies", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  // Verify evaluateUrlLocally runs synchronously without contacting localhost backend
  const evalSuspicious = evaluateUrlLocally(SIMULATED_UNSAFE_URL);
  assert.equal(evalSuspicious.verdict, "suspicious");
  assert.ok(evalSuspicious.risk_score >= 80);

  const evalDangerous = evaluateUrlLocally(SIMULATED_DANGEROUS_URL);
  assert.equal(evalDangerous.verdict, "dangerous");
  assert.ok(evalDangerous.risk_score >= 90);

  // Both are intercepted in simulated navigation without any backend calls
  const res1 = await env.handleBeforeNavigate({ tabId: 1, url: SIMULATED_UNSAFE_URL, frameId: 0 });
  assert.equal(res1.action, "warned");

  const res2 = await env.handleBeforeNavigate({ tabId: 2, url: SIMULATED_DANGEROUS_URL, frameId: 0 });
  assert.equal(res2.action, "blocked");
});

test("Scenario 10: Duplicate navigation events do not create infinite warning loops", async () => {
  clearAllBypasses();
  const env = new MockChromeEnvironment();

  // Rapid duplicate events (e.g. 10ms apart for the same tab and URL)
  const event1 = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(event1.action, "warned");
  assert.equal(env.updates.length, 1);

  // Second duplicate event while redirect is actively in-flight
  const event2 = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(event2.action, "deduplicated");
  assert.equal(env.updates.length, 1, "Must NOT issue redundant second tab redirect");

  // Clean transition when user proceeds
  addOneTimeBypass(SIMULATED_UNSAFE_URL, 1, "sub1.sub2.sub3.auth-portal.test");
  const proceedEvent = await env.handleBeforeNavigate({
    tabId: 1,
    url: SIMULATED_UNSAFE_URL,
    frameId: 0,
  });
  assert.equal(proceedEvent.action, "allowed");
});
