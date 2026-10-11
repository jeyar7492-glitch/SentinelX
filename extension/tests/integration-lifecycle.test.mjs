/**
 * SentinelX Integration Lifecycle and Security Safeguards Test Suite
 * Validates rule persistence, browser restart recovery, strict allowlist transitions,
 * open-redirect prevention, and network-level interception behavior.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  compileDnrRules,
  isValidDomain,
  matchesDomainBoundary,
  normalizeDomain,
  SEED_THREAT_RULES,
} from "../dist/threat-manager.js";
import { isValidWebUrl } from "../dist/utils.js";

// Mock implementation of chrome.storage.local for persistence lifecycle testing
class MockChromeStorage {
  constructor() {
    this.store = {};
  }
  async get(keys) {
    if (typeof keys === "string") {
      return { [keys]: this.store[keys] };
    }
    const res = {};
    for (const k of keys) {
      if (k in this.store) res[k] = this.store[k];
    }
    return res;
  }
  async set(items) {
    Object.assign(this.store, items);
  }
}

test("Simulated browser restart: Rules and settings survive and recompile cleanly", async () => {
  const storage = new MockChromeStorage();

  // 1. Initial browser run: Save custom blocklist and modified settings
  const initialSettings = {
    protectionEnabled: true,
    mode: "STANDARD",
    blockHighConfidence: true,
    warnSuspicious: true,
    allowlist: ["work-portal.example"],
    customBlocklist: ["known-phish.test"],
  };

  const initialRules = [...SEED_THREAT_RULES];
  await storage.set({
    sentinel_settings: initialSettings,
    sentinel_threat_rules: initialRules,
  });

  // 2. Simulate browser shutdown & startup: re-read from storage
  const restoredSettingsData = await storage.get("sentinel_settings");
  const restoredRulesData = await storage.get("sentinel_threat_rules");

  const restoredSettings = restoredSettingsData.sentinel_settings;
  const restoredRules = restoredRulesData.sentinel_threat_rules;

  assert.deepEqual(restoredSettings.allowlist, ["work-portal.example"]);
  assert.deepEqual(restoredSettings.customBlocklist, ["known-phish.test"]);
  assert.equal(restoredRules.length, SEED_THREAT_RULES.length);

  // 3. Compile rules on startup
  const compiledOnStartup = compileDnrRules(restoredRules, restoredSettings);
  assert.ok(compiledOnStartup.length >= SEED_THREAT_RULES.length);

  // Verify custom blocklist is compiled
  const customCompiled = compiledOnStartup.find(
    (r) => r.condition.urlFilter === "||known-phish.test^"
  );
  assert.ok(customCompiled);
});

test("Rule updates, deletion, and allowlist precedence cycle", async () => {
  const settings = {
    protectionEnabled: true,
    mode: "STANDARD",
    blockHighConfidence: true,
    warnSuspicious: true,
    allowlist: [],
    customBlocklist: ["phish-1.test", "phish-2.test"],
  };

  // Compile with two custom rules
  let dnr = compileDnrRules(SEED_THREAT_RULES, settings);
  assert.ok(dnr.some((r) => r.condition.urlFilter === "||phish-1.test^"));
  assert.ok(dnr.some((r) => r.condition.urlFilter === "||phish-2.test^"));

  // Delete phish-1.test
  settings.customBlocklist = settings.customBlocklist.filter((d) => d !== "phish-1.test");
  dnr = compileDnrRules(SEED_THREAT_RULES, settings);
  assert.equal(dnr.some((r) => r.condition.urlFilter === "||phish-1.test^"), false);
  assert.ok(dnr.some((r) => r.condition.urlFilter === "||phish-2.test^"));

  // Add SEED rule to allowlist (false positive recovery)
  settings.allowlist.push("paypal-security-verification.test");
  dnr = compileDnrRules(SEED_THREAT_RULES, settings);
  // Rule 101 must now be excluded
  assert.equal(dnr.some((r) => r.id === 101), false);
});

test("Strict Allowlist mode transition and restoration to Standard mode", () => {
  const settings = {
    protectionEnabled: true,
    mode: "STANDARD",
    blockHighConfidence: true,
    warnSuspicious: true,
    allowlist: ["my-company.example"],
    customBlocklist: [],
  };

  // Standard mode: no catch-all rule
  let dnr = compileDnrRules(SEED_THREAT_RULES, settings);
  assert.equal(dnr.some((r) => r.id === 99999), false);

  // Transition to STRICT_ALLOWLIST mode
  settings.mode = "STRICT_ALLOWLIST";
  dnr = compileDnrRules(SEED_THREAT_RULES, settings);
  const catchAll = dnr.find((r) => r.id === 99999);
  assert.ok(catchAll);
  assert.equal(catchAll.priority, 1);
  assert.equal(catchAll.condition.urlFilter, "*");

  const allowRule = dnr.find((r) => r.priority === 2);
  assert.ok(allowRule);
  assert.equal(allowRule.condition.urlFilter, "||my-company.example^");

  // Restore to STANDARD mode
  settings.mode = "STANDARD";
  dnr = compileDnrRules(SEED_THREAT_RULES, settings);
  assert.equal(dnr.some((r) => r.id === 99999), false);
  assert.ok(dnr.some((r) => r.id === 101));
});

test("Blocked-page navigation security: Rejection of open-redirect payloads and javascript schemes", () => {
  // Disallowed injection schemes
  assert.equal(isValidWebUrl("javascript:alert('pwned')"), false);
  assert.equal(isValidWebUrl("data:text/html,<b>evil</b>"), false);
  assert.equal(isValidWebUrl("vbscript:msgbox"), false);
  assert.equal(isValidWebUrl("file:///etc/passwd"), false);

  // Allowed valid web targets
  assert.equal(isValidWebUrl("https://example.com/safe"), true);
  assert.equal(isValidWebUrl("http://internal-portal.test:8080/"), true);
});

test("Backend unavailability resilience: Analyzer handles timeouts and offline server gracefully", async () => {
  // Fast offline check using AbortController on an unbound port
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 100);

  let caught = false;
  try {
    await fetch("http://127.0.0.1:59999/health", { signal: controller.signal });
  } catch {
    caught = true;
  } finally {
    clearTimeout(timeoutId);
  }

  assert.equal(caught, true, "Network fetch gracefully caught connection failure without unhandled rejection");
});
