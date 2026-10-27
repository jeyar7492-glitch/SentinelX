/**
 * SentinelX Local In-Extension Heuristic Analyzer
 * Provides sub-millisecond, zero-cost, local-first risk scoring inside the Chrome Extension.
 * Enforces the central risk policy during real-time web navigation and popup scans.
 */

import {
  AnalyzeResponse,
  HttpAnalysis,
  RecommendedAction,
  RiskClassification,
  RuleSeverity,
  TriggeredRule,
  Verdict,
} from "./types.js";
import { normalizeDomain, SAFEGUARD_HOSTS } from "./threat-manager.js";

export const TRUSTED_DOMAINS: Set<string> = new Set([
  "google.com",
  "www.google.com",
  "github.com",
  "www.github.com",
  "microsoft.com",
  "www.microsoft.com",
  "apple.com",
  "www.apple.com",
  "amazon.com",
  "www.amazon.com",
  "wikipedia.org",
  "en.wikipedia.org",
  "mozilla.org",
  "www.mozilla.org",
  "python.org",
  "www.python.org",
  "ubuntu.com",
  "www.ubuntu.com",
  "cloudflare.com",
  "www.cloudflare.com",
  "stackoverflow.com",
  "www.stackoverflow.com",
]);

export const TARGET_BRANDS: Set<string> = new Set([
  "paypal",
  "chase",
  "wellsfargo",
  "bankofamerica",
  "citibank",
  "apple",
  "microsoft",
  "google",
  "netflix",
  "amazon",
  "facebook",
  "instagram",
  "dropbox",
  "binance",
  "coinbase",
  "walmart",
  "steam",
  "roblox",
  "outlook",
  "yahoo",
  "icloud",
  "metamask",
]);

export const HIGH_RISK_TLDS: Set<string> = new Set([
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "top",
  "xyz",
  "buzz",
  "club",
  "work",
  "icu",
  "fit",
  "surf",
  "monster",
  "click",
  "link",
  "cam",
  "rest",
]);

export const SENSITIVE_PATH_KEYWORDS: Set<string> = new Set([
  "login",
  "signin",
  "sign-in",
  "log-in",
  "verify",
  "verification",
  "account-update",
  "security-check",
  "reset-password",
  "confirm-identity",
  "recover-account",
  "banking",
  "wallet-connect",
  "seedphrase",
]);

export const REDIRECT_PARAMS: Set<string> = new Set([
  "redirect",
  "redirect_to",
  "redirect_url",
  "url",
  "return",
  "return_to",
  "next",
  "dest",
  "destination",
  "target",
  "continue",
  "goto",
]);

function isIpAddress(host: string): boolean {
  const clean = host.replace(/[\[\]]/g, "");
  // IPv4 pattern
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) {
    const parts = clean.split(".").map(Number);
    return parts.every((p) => p >= 0 && p <= 255);
  }
  // IPv6 check
  if (clean.includes(":") && /^[0-9a-fA-F:]+$/.test(clean)) {
    return true;
  }
  return false;
}

function extractBaseDomain(host: string): { domainName: string; tld: string; subdomains: string[] } {
  const clean = host.toLowerCase().replace(/\.+$/, "");
  const parts = clean.split(".");
  if (parts.length <= 1) {
    return { domainName: clean, tld: "", subdomains: [] };
  }

  const twoPartTlds = new Set(["co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "co.nz", "com.br"]);
  if (parts.length >= 3 && twoPartTlds.has(`${parts[parts.length - 2]}.${parts[parts.length - 1]}`)) {
    return {
      domainName: parts[parts.length - 3],
      tld: `${parts[parts.length - 2]}.${parts[parts.length - 1]}`,
      subdomains: parts.slice(0, -3),
    };
  }

  return {
    domainName: parts[parts.length - 2],
    tld: parts[parts.length - 1],
    subdomains: parts.slice(0, -2),
  };
}

/**
 * Perform transparent heuristic evaluation of a URL locally in TypeScript.
 */
export function evaluateUrlLocally(rawUrl: string, blockThreshold = 90, warnThreshold = 80): AnalyzeResponse {
  const url = rawUrl.trim();
  let urlObj: URL;
  try {
    urlObj = new URL(url);
  } catch {
    throw new Error("Invalid URL syntax.");
  }

  const scheme = urlObj.protocol.replace(":", "").toLowerCase();
  const hostname = urlObj.hostname.toLowerCase();
  const port = urlObj.port ? parseInt(urlObj.port, 10) : null;
  const path = urlObj.pathname;
  const query = urlObj.search;

  const triggeredRules: TriggeredRule[] = [];
  const safeIndicators: string[] = [];
  const detectionReasons: string[] = [];
  let totalPenalty = 0;
  let hasConfirmedThreatOverride = false;

  // 1. Protocol security
  let httpAnalysis: HttpAnalysis;
  if (scheme === "http") {
    totalPenalty += 30;
    const msg = "Unencrypted HTTP connection: traffic is vulnerable to plaintext eavesdropping and MITM tampering.";
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_INSECURE_HTTP",
      category: "Protocol Security",
      name: "Unencrypted HTTP Connection",
      description: msg,
      severity: "HIGH",
      penalty: 30,
      evidence_type: "confirmed",
      source: "local_heuristic",
      confidence: "HIGH",
    });
    httpAnalysis = {
      scheme: "http",
      is_encrypted: false,
      summary: "Insecure Connection (Plaintext HTTP)",
      detailed_explanation: "HTTP transmits data in plaintext without encryption. Never submit credentials on HTTP pages.",
    };
  } else if (scheme === "https") {
    safeIndicators.push("Encrypted transport: Connection uses TLS/HTTPS.");
    httpAnalysis = {
      scheme: "https",
      is_encrypted: true,
      summary: "Encrypted Transport (TLS Active) — Verification Required",
      detailed_explanation: "HTTPS encrypts data in transit. Remember: HTTPS is not proof of website safety or authenticity.",
    };
  } else {
    totalPenalty += 25;
    const msg = `Non-standard protocol scheme ('${scheme}'). Standard web traffic uses HTTP or HTTPS.`;
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_UNEXPECTED_SCHEME",
      category: "Protocol Security",
      name: "Non-Standard Web Scheme",
      description: msg,
      severity: "MEDIUM",
      penalty: 25,
      evidence_type: "confirmed",
      source: "local_heuristic",
      confidence: "HIGH",
    });
    httpAnalysis = {
      scheme,
      is_encrypted: false,
      summary: `Non-Standard Protocol (${scheme})`,
      detailed_explanation: "This URL uses a protocol outside typical secure web browsing standards.",
    };
  }

  // 2. Raw IP address check
  if (hostname && isIpAddress(hostname)) {
    totalPenalty += 45;
    const msg = `Raw IP address host ('${hostname}'): points directly to an IP rather than a registered domain name.`;
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_RAW_IP_HOST",
      category: "Host & Network",
      name: "Raw IP Address as Destination Host",
      description: msg,
      severity: "CRITICAL",
      penalty: 45,
      evidence_type: "confirmed",
      source: "local_heuristic",
      confidence: "HIGH",
    });
  } else if (hostname) {
    safeIndicators.push("Standard domain name addressing (no raw IP host).");
  }

  // 3. Credential Userinfo Spoofing (@ symbol)
  if (urlObj.username || urlObj.password || rawUrl.includes("@")) {
    totalPenalty += 70;
    hasConfirmedThreatOverride = true;
    const msg = "Credential embedding / Userinfo spoofing (@ symbol): deceptive host authority disguise.";
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_CREDENTIAL_USERINFO_SPOOF",
      category: "URL Structure & Deception",
      name: "Credential Embedding / Host Disguise (@ Symbol)",
      description: msg,
      severity: "CRITICAL",
      penalty: 70,
      evidence_type: "confirmed",
      source: "local_heuristic",
      confidence: "HIGH",
    });
  }

  // 4. Non-standard ports
  if (port && port !== 80 && port !== 443) {
    const isLocal = SAFEGUARD_HOSTS.has(hostname);
    const penalty = isLocal ? 10 : 25;
    totalPenalty += penalty;
    const msg = `Non-standard web port (:${port}): traffic directed to custom port instead of standard 80/443.`;
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_NON_STANDARD_PORT",
      category: "Network Configuration",
      name: `Non-Standard Web Port (:${port})`,
      description: msg,
      severity: isLocal ? "LOW" : "MEDIUM",
      penalty,
      evidence_type: "confirmed",
      source: "local_heuristic",
      confidence: "HIGH",
    });
  } else {
    safeIndicators.push("Standard web communication ports used (80/443).");
  }

  // 5. Punycode IDN homograph
  if (hostname.includes("xn--")) {
    totalPenalty += 45;
    const msg = "Punycode/IDN indicator ('xn--'): domain contains lookalike characters vulnerable to homograph attacks.";
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_PUNYCODE_HOMOGRAPH",
      category: "Domain & Identity",
      name: "Punycode / IDN Homograph Indicator ('xn--')",
      description: msg,
      severity: "CRITICAL",
      penalty: 45,
      evidence_type: "confirmed",
      source: "local_heuristic",
      confidence: "HIGH",
    });
  }

  // Extract base domain
  const { domainName, tld, subdomains } = extractBaseDomain(hostname);
  const registeredDomain = tld ? `${domainName}.${tld}` : domainName;

  const isTrustedDomain =
    TRUSTED_DOMAINS.has(hostname) ||
    TRUSTED_DOMAINS.has(registeredDomain) ||
    Array.from(TRUSTED_DOMAINS).some((td) => hostname.endsWith(`.${td}`));

  if (isTrustedDomain) {
    safeIndicators.push(`Recognized established domain name: '${registeredDomain}'.`);
  }

  // 6. High risk TLD
  if (HIGH_RISK_TLDS.has(tld) && !isTrustedDomain) {
    totalPenalty += 25;
    const msg = `High-abuse top-level domain (.${tld}): statistically associated with disposable scam domains.`;
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_HIGH_RISK_TLD",
      category: "Domain Reputation",
      name: `High-Abuse Top Level Domain (.${tld})`,
      description: msg,
      severity: "MEDIUM",
      penalty: 25,
      evidence_type: "heuristic",
      source: "reputation_list",
      confidence: "MEDIUM",
    });
  }

  // 7. Brand impersonation
  if (!isTrustedDomain) {
    let brandDetected: string | null = null;
    for (const brand of TARGET_BRANDS) {
      if (hostname.includes(brand)) {
        if (domainName === brand) continue;
        brandDetected = brand;
        break;
      }
    }

    if (brandDetected) {
      totalPenalty += 50;
      hasConfirmedThreatOverride = true;
      const msg = `Brand impersonation: hostname contains trusted brand '${brandDetected}' on unrelated domain '${registeredDomain}'.`;
      detectionReasons.push(msg);
      triggeredRules.push({
        rule_id: "RULE_BRAND_IMPERSONATION",
        category: "Identity & Phishing",
        name: `Target Brand Keyword Impersonation ('${brandDetected}')`,
        description: msg,
        severity: "CRITICAL",
        penalty: 50,
        evidence_type: "heuristic",
        source: "local_heuristic",
        confidence: "HIGH",
      });
    }
  }

  // 8. Excessive subdomains
  if (subdomains.length >= 3 && !isTrustedDomain) {
    totalPenalty += 25;
    const msg = `Excessive subdomain depth: nested subdomains ('${subdomains.join(".")}') obscure the true domain.`;
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_EXCESSIVE_SUBDOMAINS",
      category: "URL Structure",
      name: "Excessive Subdomain Depth",
      description: msg,
      severity: "MEDIUM",
      penalty: 25,
      evidence_type: "heuristic",
      source: "local_heuristic",
      confidence: "MEDIUM",
    });
  }

  // 9. Sensitive action keywords in path
  const lowerPath = path.toLowerCase();
  const matchedKeywords: string[] = [];
  for (const kw of SENSITIVE_PATH_KEYWORDS) {
    if (lowerPath.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }
  if (matchedKeywords.length > 0 && !isTrustedDomain) {
    totalPenalty += 20;
    const msg = `Sensitive authentication path (${matchedKeywords.slice(0, 2).join(", ")}) on unverified domain.`;
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_SENSITIVE_PATH_ACTION",
      category: "Behavioral Indication",
      name: "Sensitive Account/Login Path on Unverified Host",
      description: msg,
      severity: "MEDIUM",
      penalty: 20,
      evidence_type: "heuristic",
      source: "local_heuristic",
      confidence: "MEDIUM",
    });
  }

  // 10. Open redirect parameters
  if (query) {
    const searchParams = new URLSearchParams(query);
    const matchedParams: string[] = [];
    for (const [key, val] of searchParams.entries()) {
      if (REDIRECT_PARAMS.has(key.toLowerCase())) {
        const decoded = decodeURIComponent(val).toLowerCase();
        if (decoded.startsWith("http://") || decoded.startsWith("https://") || decoded.startsWith("//")) {
          matchedParams.push(`${key}=${val.slice(0, 30)}`);
          break;
        }
      }
    }
    if (matchedParams.length > 0) {
      totalPenalty += 20;
      const msg = `Open redirect parameter (${matchedParams.join(", ")}): may bounce visitors to an unverified target.`;
      detectionReasons.push(msg);
      triggeredRules.push({
        rule_id: "RULE_OPEN_REDIRECT_PARAMETER",
        category: "URL Obfuscation & Redirection",
        name: "Potential Open Redirect / URL Parameter Forwarding",
        description: msg,
        severity: "MEDIUM",
        penalty: 20,
        evidence_type: "heuristic",
        source: "local_heuristic",
        confidence: "MEDIUM",
      });
    }
  }

  // 11. Abnormal length
  if (url.length > 200) {
    totalPenalty += 20;
    const msg = `Abnormally long URL (${url.length} chars): frequently used to hide encoded parameters.`;
    detectionReasons.push(msg);
    triggeredRules.push({
      rule_id: "RULE_EXTREME_URL_LENGTH",
      category: "Obfuscation",
      name: `Excessive URL Length (${url.length} characters)`,
      description: msg,
      severity: "LOW",
      penalty: 20,
      evidence_type: "inconclusive",
      source: "local_heuristic",
      confidence: "LOW",
    });
  } else if (url.length > 120) {
    totalPenalty += 10;
    triggeredRules.push({
      rule_id: "RULE_LONG_URL",
      category: "Obfuscation",
      name: `Elevated URL Length (${url.length} characters)`,
      description: "URL is longer than typical addresses, warranting closer inspection.",
      severity: "LOW",
      penalty: 10,
      evidence_type: "inconclusive",
      source: "local_heuristic",
      confidence: "LOW",
    });
  }


  // Discount score for recognized trusted domains
  if (isTrustedDomain && !triggeredRules.some((r) => r.severity === "CRITICAL")) {
    totalPenalty = Math.min(totalPenalty, scheme === "http" ? 25 : 15);
  }

  let riskScore = Math.min(Math.max(totalPenalty, 0), 100);

  if (hasConfirmedThreatOverride && riskScore < blockThreshold) {
    riskScore = Math.max(riskScore, blockThreshold);
  }

  // Policy mapping
  let verdict: Verdict;
  let recommendedAction: RecommendedAction;
  let confidence: string;
  let classification: RiskClassification;
  let summary: string;

  if (riskScore >= blockThreshold) {
    verdict = "dangerous";
    recommendedAction = "BLOCK";
    confidence = "HIGH (Confirmed malicious indicators or critical risk patterns)";
    classification = "HIGH RISK";
    summary =
      "CRITICAL THREAT DETECTED: Multiple high-confidence phishing, credential theft, or structural deception indicators were identified. Connection blocked to protect your credentials and device.";
  } else if (riskScore >= warnThreshold) {
    verdict = "suspicious";
    recommendedAction = "WARN_INTERSTITIAL";
    confidence = "MEDIUM (Significant suspicious anomalies observed)";
    classification = "HIGH RISK";
    summary =
      "ELEVATED RISK DETECTED: URL exhibits substantial suspicious patterns warranting a warning interstitial before proceeding. Review the explanation before entering credentials.";
  } else if (riskScore >= 30) {
    verdict = "suspicious";
    recommendedAction = "PROCEED_WITH_CAUTION";
    confidence = "MEDIUM (Suspicious indicators detected)";
    classification = "SUSPICIOUS";
    summary =
      "SUSPICIOUS ANOMALIES IDENTIFIED: This URL exhibits elevated risk factors such as plain HTTP, unusual domain characteristics, or sensitive actions on an unverified site. Proceed with caution.";
  } else if (isTrustedDomain && riskScore < 30) {
    verdict = "safe";
    recommendedAction = "ALLOW";
    confidence = "HIGH (Established reputable domain with clean indicators)";
    classification = "SAFE";
    summary =
      "LOW STRUCTURAL RISK: Verified established domain with no detected threat patterns. Remember that transport encryption (HTTPS) does not guarantee website trustworthiness.";
  } else {
    verdict = "unknown";
    recommendedAction = "PROCEED_WITH_CAUTION";
    confidence = "LOW (Domain reputation unverified locally; lack of detected evidence is not proof of safety)";
    classification = "SAFE";
    summary =
      "UNVERIFIED DOMAIN (NO DETECTED THREATS): No known phishing signatures were matched, but this domain is not on your verified list. Lack of detected evidence is not proof of safety.";
  }

  triggeredRules.forEach((r) => {
    if (!r.id) r.id = r.rule_id;
  });

  return {
    url,
    normalized_url: `${scheme}://${hostname}${port && port !== 80 && port !== 443 ? `:${port}` : ""}${path}${query}`,
    hostname,
    risk_score: riskScore,
    verdict,
    confidence,
    detection_reasons: detectionReasons,
    recommended_action: recommendedAction,
    classification,
    summary,
    http_analysis: httpAnalysis,
    triggered_rules: triggeredRules,
    safe_indicators: safeIndicators,
    analyzed_at: new Date().toISOString(),
    engine_version: "2.0.0-realtime",
  };
}
