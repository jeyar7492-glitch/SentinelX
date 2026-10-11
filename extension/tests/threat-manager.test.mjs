import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeDomain,
  isValidDomain,
  matchesDomainBoundary,
  generateDnrUrlFilter,
  compileDnrRules,
  SEED_THREAT_RULES,
  SAFEGUARD_HOSTS,
} from "../dist/threat-manager.js";

test("normalizeDomain handles various URL formats, schemes, credentials, and ports", () => {
  assert.equal(normalizeDomain("https://EXAMPLE.COM/login"), "example.com");
  assert.equal(normalizeDomain("http://user:pass@bank-login.test:8080/auth?param=1#sec"), "bank-login.test");
  assert.equal(normalizeDomain("sub.portal.co.uk:443/"), "sub.portal.co.uk");
  assert.equal(normalizeDomain("  trailing-space.org/  "), "trailing-space.org");
  assert.equal(normalizeDomain("domain.with.trailing.dot."), "domain.with.trailing.dot");
});

test("normalizeDomain handles IDN Punycode domains cleanly", () => {
  // Russian Cyrillic domain 'россия.рф' -> Punycode
  const punycode = normalizeDomain("https://xn--p1acf.xn--p1ai/path");
  assert.equal(punycode, "xn--p1acf.xn--p1ai");
});

test("isValidDomain validates legitimate domains and rejects broad/malformed inputs", () => {
  assert.equal(isValidDomain("example.com"), true);
  assert.equal(isValidDomain("sub.domain.co.uk"), true);
  assert.equal(isValidDomain("192.168.1.100"), true);
  assert.equal(isValidDomain("phish-target.test"), true);

  // Dangerous wildcards, empty strings, and malformed dots must be rejected
  assert.equal(isValidDomain(""), false);
  assert.equal(isValidDomain("*"), false);
  assert.equal(isValidDomain("."), false);
  assert.equal(isValidDomain(".startdot.com"), false);
  assert.equal(isValidDomain("enddot.com."), false);

  // Critical safeguard hosts must be rejected from blocklists
  assert.equal(isValidDomain("localhost"), false);
  assert.equal(isValidDomain("127.0.0.1"), false);
  assert.equal(isValidDomain("::1"), false);
});

test("matchesDomainBoundary accurately detects subdomains and prevents substring collisions", () => {
  const rule = "paypal-security-verification.test";

  // Exact match
  assert.equal(matchesDomainBoundary("paypal-security-verification.test", rule), true);
  assert.equal(matchesDomainBoundary("https://paypal-security-verification.test/signin", rule), true);

  // Subdomain matches
  assert.equal(matchesDomainBoundary("login.paypal-security-verification.test", rule), true);
  assert.equal(matchesDomainBoundary("a.b.c.paypal-security-verification.test", rule), true);

  // CRITICAL: Substring-only collisions must NOT match
  assert.equal(matchesDomainBoundary("notpaypal-security-verification.test", rule), false);
  assert.equal(matchesDomainBoundary("fake-paypal-security-verification.test", rule), false);
  assert.equal(matchesDomainBoundary("paypal-security-verification.test.attacker.com", false), false);
});

test("generateDnrUrlFilter constructs boundary-safe filter string", () => {
  assert.equal(generateDnrUrlFilter("phish-target.test"), "||phish-target.test^");
  assert.equal(generateDnrUrlFilter("HTTPS://Sub.Target.Org:8080/path"), "||sub.target.org^");
});

test("compileDnrRules compiles high-confidence rules in Standard mode", () => {
  const settings = {
    protectionEnabled: true,
    mode: "STANDARD",
    blockHighConfidence: true,
    warnSuspicious: true,
    allowlist: [],
    customBlocklist: ["custom-threat.test"],
  };

  const dnrRules = compileDnrRules(SEED_THREAT_RULES, settings);
  assert.ok(dnrRules.length >= SEED_THREAT_RULES.length + 1);

  // Check that all compiled rules use the redirect action and boundary urlFilter
  const rule1 = dnrRules.find((r) => r.id === 101);
  assert.ok(rule1);
  assert.equal(rule1.action.type, "redirect");
  assert.equal(rule1.condition.urlFilter, "||paypal-security-verification.test^");
  assert.deepEqual(rule1.condition.resourceTypes, ["main_frame"]);

  // Verify custom blocklist entry is included
  const customRule = dnrRules.find((r) => r.condition.urlFilter === "||custom-threat.test^");
  assert.ok(customRule);
});

test("compileDnrRules respects allowlist exclusions", () => {
  const settings = {
    protectionEnabled: true,
    mode: "STANDARD",
    blockHighConfidence: true,
    warnSuspicious: true,
    allowlist: ["paypal-security-verification.test"], // Explicitly allowed
    customBlocklist: [],
  };

  const dnrRules = compileDnrRules(SEED_THREAT_RULES, settings);
  // Allowed domain must not be in block rules
  const allowedRule = dnrRules.find((r) => r.id === 101);
  assert.equal(allowedRule, undefined);
});

test("compileDnrRules returns empty when protection is disabled", () => {
  const settings = {
    protectionEnabled: false,
    mode: "DISABLED",
    blockHighConfidence: true,
    warnSuspicious: true,
    allowlist: [],
    customBlocklist: ["custom-threat.test"],
  };

  const dnrRules = compileDnrRules(SEED_THREAT_RULES, settings);
  assert.equal(dnrRules.length, 0);
});

test("compileDnrRules compiles inverted rules in Strict Allowlist mode", () => {
  const settings = {
    protectionEnabled: true,
    mode: "STRICT_ALLOWLIST",
    blockHighConfidence: true,
    warnSuspicious: true,
    allowlist: ["trusted-work-portal.example"],
    customBlocklist: [],
  };

  const dnrRules = compileDnrRules(SEED_THREAT_RULES, settings);

  // Catch-all block rule
  const catchAll = dnrRules.find((r) => r.id === 99999);
  assert.ok(catchAll);
  assert.equal(catchAll.priority, 1);
  assert.equal(catchAll.condition.urlFilter, "*");

  // Allow rule for approved domain
  const allowRule = dnrRules.find((r) => r.priority === 2);
  assert.ok(allowRule);
  assert.equal(allowRule.action.type, "allow");
  assert.equal(allowRule.condition.urlFilter, "||trusted-work-portal.example^");
});
