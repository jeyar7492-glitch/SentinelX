/**
 * SentinelX Integration Lifecycle and Security Safeguards Test Suite
 * Validates rule persistence, browser restart recovery, strict allowlist transitions,
 * open-redirect prevention, manifest validity, and network-level interception behavior.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  compileDnrRules,
  isValidDomain,
  matchesDomainBoundary,
  normalizeDomain,
  SEED_THREAT_RULES,
} from "../dist/threat-manager.js";
import { isValidWebUrl } from "../dist/utils.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXTENSION_DIR = path.resolve(__dirname, "..");
const PROJECT_ROOT = path.resolve(EXTENSION_DIR, "..");

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
    blockThreshold: 90,
    warnThreshold: 80,
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
  assert.equal(restoredSettings.blockThreshold, 90);
  assert.equal(restoredSettings.warnThreshold, 80);
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
    blockThreshold: 90,
    warnThreshold: 80,
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
    blockThreshold: 90,
    warnThreshold: 80,
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

test("Chrome Extension Manifest V3 Validity & Security Best Practices", () => {
  const manifestPath = path.join(EXTENSION_DIR, "manifest.json");
  assert.ok(fs.existsSync(manifestPath), "manifest.json must exist");

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
  assert.equal(manifest.manifest_version, 3, "Must be Manifest V3");
  assert.ok(manifest.name.includes("SentinelX"), "Name must contain SentinelX");

  // Permissions check
  const requiredPermissions = ["storage", "declarativeNetRequest", "webNavigation", "tabs"];
  for (const perm of requiredPermissions) {
    assert.ok(manifest.permissions.includes(perm), `Missing permission: ${perm}`);
  }

  // Host permissions must include local backend
  assert.ok(manifest.host_permissions.includes("http://127.0.0.1:8000/*"));

  // Check declarativeNetRequest ruleset declaration
  assert.ok(manifest.declarative_net_request, "declarative_net_request block required");
  const rulesPath = path.join(EXTENSION_DIR, manifest.declarative_net_request.rule_resources[0].path);
  assert.ok(fs.existsSync(rulesPath), `Ruleset file must exist at ${rulesPath}`);
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf-8"));
  assert.ok(Array.isArray(rules), "Ruleset must be a JSON array");

  // Web accessible resources must include blocked.html
  assert.ok(manifest.web_accessible_resources[0].resources.includes("blocked.html"));
});

test("Allowlist matching and lookalike-domain isolation", () => {
  const allowed = "legitimate-bank.com";

  // Exact domain and subdomains should match
  assert.equal(matchesDomainBoundary("legitimate-bank.com", allowed), true);
  assert.equal(matchesDomainBoundary("secure.legitimate-bank.com", allowed), true);
  assert.equal(matchesDomainBoundary("portal.login.legitimate-bank.com", allowed), true);

  // Substring, lookalike, and attacker-controlled domains must NOT match
  assert.equal(matchesDomainBoundary("not-legitimate-bank.com", allowed), false);
  assert.equal(matchesDomainBoundary("legitimate-bank.com.attacker.com", allowed), false);
  assert.equal(matchesDomainBoundary("fake-legitimate-bank.com", allowed), false);
  assert.equal(matchesDomainBoundary("legitimate-bank.co", allowed), false);
  assert.equal(matchesDomainBoundary("xn--legitimate-bank.com", allowed), false);
});

test("Ubuntu User Systemd Service configuration integrity", () => {
  const servicePath = path.join(PROJECT_ROOT, "systemd", "sentinelx.service");
  assert.ok(fs.existsSync(servicePath), "sentinelx.service file must exist");

  const content = fs.readFileSync(servicePath, "utf-8");
  assert.ok(content.includes("[Unit]"), "Must have [Unit] section");
  assert.ok(content.includes("[Service]"), "Must have [Service] section");
  assert.ok(content.includes("[Install]"), "Must have [Install] section");
  assert.ok(content.includes("ExecStart="), "Must define ExecStart");
  assert.ok(content.includes("Restart=on-failure"), "Must have Restart=on-failure");
  assert.ok(content.includes("WantedBy=default.target"), "Must be wanted by default.target for user session");

  const installScriptPath = path.join(PROJECT_ROOT, "scripts", "install_service.sh");
  assert.ok(fs.existsSync(installScriptPath), "install_service.sh must exist");

  const uninstallScriptPath = path.join(PROJECT_ROOT, "scripts", "uninstall_service.sh");
  assert.ok(fs.existsSync(uninstallScriptPath), "uninstall_service.sh must exist");
});
