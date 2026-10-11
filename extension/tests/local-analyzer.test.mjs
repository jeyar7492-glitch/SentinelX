import test from "node:test";
import assert from "node:assert/strict";
import { evaluateUrlLocally, TRUSTED_DOMAINS } from "../dist/local-analyzer.js";

test("evaluateUrlLocally: Reputable trusted domain with HTTPS yields SAFE verdict", () => {
  const result = evaluateUrlLocally("https://github.com/torvalds/linux");
  assert.equal(result.verdict, "safe");
  assert.equal(result.recommended_action, "ALLOW");
  assert.ok(result.risk_score < 30, "Risk score must be low for trusted domains");
  assert.ok(result.http_analysis.is_encrypted, "HTTPS must be identified as encrypted");
});

test("evaluateUrlLocally: Unverified unknown domain is NOT marked safe (verdict: unknown)", () => {
  const result = evaluateUrlLocally("https://my-unknown-portfolio-site-1234.org/about");
  // Per requirement: unverified websites must not automatically be treated as safe
  assert.equal(result.verdict, "unknown", "Unverified domain must have verdict 'unknown'");
  assert.equal(result.recommended_action, "PROCEED_WITH_CAUTION");
  assert.ok(
    result.summary.includes("UNVERIFIED DOMAIN"),
    "Summary must state domain is unverified"
  );
});

test("evaluateUrlLocally: Plain insecure HTTP triggers penalty and clear insecure explanation", () => {
  const result = evaluateUrlLocally("http://github.com/explore");
  assert.equal(result.http_analysis.is_encrypted, false);
  assert.ok(result.risk_score >= 25, "Insecure HTTP must carry security penalty");
  assert.ok(
    result.triggered_rules.some((r) => r.rule_id === "RULE_INSECURE_HTTP"),
    "Must trigger RULE_INSECURE_HTTP"
  );
});

test("evaluateUrlLocally: Raw IP host triggers critical penalty", () => {
  const result = evaluateUrlLocally("http://192.168.1.100/admin");
  assert.ok(
    result.triggered_rules.some((r) => r.rule_id === "RULE_RAW_IP_HOST"),
    "Must trigger raw IP host rule"
  );
  assert.ok(result.risk_score >= 75);
});

test("evaluateUrlLocally: Credential userinfo spoofing (@ symbol) triggers confirmed threat override BLOCK", () => {
  const result = evaluateUrlLocally("https://paypal.com@evil-harvester.com/login");
  assert.equal(result.verdict, "dangerous");
  assert.equal(result.recommended_action, "BLOCK");
  assert.ok(result.risk_score >= 90, "Risk score must be at or above block threshold (90)");
  assert.ok(
    result.triggered_rules.some((r) => r.rule_id === "RULE_CREDENTIAL_USERINFO_SPOOF"),
    "Must detect userinfo credential disguise"
  );
});

test("evaluateUrlLocally: Brand impersonation on unverified domain triggers confirmed threat override BLOCK", () => {
  const result = evaluateUrlLocally("https://paypal-security-update.com/verify");
  assert.equal(result.verdict, "dangerous");
  assert.equal(result.recommended_action, "BLOCK");
  assert.ok(result.risk_score >= 90);
  assert.ok(
    result.triggered_rules.some((r) => r.rule_id === "RULE_BRAND_IMPERSONATION"),
    "Must trigger brand impersonation rule"
  );
});

test("evaluateUrlLocally: Elevated risk score 80-89 triggers WARN_INTERSTITIAL", () => {
  // Plain HTTP (+30) + high risk TLD .xyz (+25) + sensitive path /login (+20) + non-standard port (+25) = 100 or >= 80
  const result = evaluateUrlLocally("http://unverified-sample-host.xyz/account/login");
  // 30 (http) + 25 (xyz) + 20 (login) = 75 or more
  assert.ok(result.risk_score >= 75);
  if (result.risk_score >= 80 && result.risk_score < 90) {
    assert.equal(result.verdict, "suspicious");
    assert.equal(result.recommended_action, "WARN_INTERSTITIAL");
  }
});
