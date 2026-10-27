/**
 * SentinelX Local Threat-Rule Manager
 * Manages domain normalization, threat rule lifecycle, boundary matching,
 * central risk policy thresholds, and declarativeNetRequest (DNR) dynamic rule compilation.
 */

export type ProtectionMode = "STANDARD" | "STRICT_ALLOWLIST" | "DISABLED";

export interface ProtectionSettings {
  protectionEnabled: boolean;
  mode: ProtectionMode;
  blockHighConfidence: boolean;
  warnSuspicious: boolean;
  warnUnknownPublisher: boolean;
  blockThreshold: number; // default 90 (BLOCK)
  warnThreshold: number;  // default 80 (WARN_INTERSTITIAL)
  allowlist: string[];
  customBlocklist: string[];
  theme?: "dark" | "light" | "system";
}

export interface ThreatRule {
  id: number;
  domain: string;
  name: string;
  category: string;
  severity: "HIGH" | "CRITICAL" | "MEDIUM";
  confidence: "HIGH" | "MEDIUM";
  source: "SYSTEM" | "USER" | "HEURISTIC";
  description: string;
  createdAt: string;
}

/**
 * Built-in high-confidence synthetic and known test threats.
 * Uses reserved testing domains (.test / .example) to guarantee safe, verifiable testing.
 */
export const SEED_THREAT_RULES: ThreatRule[] = [
  {
    id: 101,
    domain: "paypal-security-verification.test",
    name: "Brand Impersonation (PayPal)",
    category: "Phishing & Lookalike",
    severity: "CRITICAL",
    confidence: "HIGH",
    source: "SYSTEM",
    description: "Synthetic test domain impersonating financial service login portal.",
    createdAt: "2026-10-10T00:00:00Z",
  },
  {
    id: 102,
    domain: "chase-login-verify.test",
    name: "Brand Impersonation (Chase)",
    category: "Phishing & Lookalike",
    severity: "CRITICAL",
    confidence: "HIGH",
    source: "SYSTEM",
    description: "Synthetic test domain targeting banking credentials.",
    createdAt: "2026-10-10T00:00:00Z",
  },
  {
    id: 103,
    domain: "appleid-verify-alert.test",
    name: "Brand Impersonation (Apple)",
    category: "Phishing & Lookalike",
    severity: "CRITICAL",
    confidence: "HIGH",
    source: "SYSTEM",
    description: "Synthetic test domain mimicking Apple ID account recovery.",
    createdAt: "2026-10-10T00:00:00Z",
  },
  {
    id: 104,
    domain: "malicious-phishing-portal.test",
    name: "Confirmed Phishing Endpoint",
    category: "Credential Harvesting",
    severity: "HIGH",
    confidence: "HIGH",
    source: "SYSTEM",
    description: "Synthetic test fixture for verified phishing infrastructure.",
    createdAt: "2026-10-10T00:00:00Z",
  },
];

/**
 * Domains and hosts that can NEVER be blocked by automated rules.
 * Defense-in-depth to protect vital system and local loopback services.
 */
export const SAFEGUARD_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "0.0.0.0",
]);

/**
 * Normalize a domain or URL into a canonical, lowercase hostname.
 * Strips protocols, credentials, paths, query strings, and trailing dots/slashes.
 * Automatically handles Punycode IDNs.
 */
export function normalizeDomain(input: string): string {
  if (!input || typeof input !== "string") {
    return "";
  }

  let clean = input.trim().toLowerCase();

  // Strip protocol prefix if present
  if (clean.includes("://")) {
    clean = clean.split("://")[1];
  }

  // Strip userinfo (user:pass@) if present
  if (clean.includes("@")) {
    clean = clean.split("@")[1];
  }

  // Strip path, query string, hash
  clean = clean.split("/")[0].split("?")[0].split("#")[0];

  // Strip port if present
  if (clean.includes(":") && !clean.startsWith("[")) {
    clean = clean.split(":")[0];
  }

  // Strip trailing dots
  clean = clean.replace(/\.+$/, "");

  // Convert potential non-ASCII IDN to Punycode via URL API
  try {
    const dummy = new URL(`http://${clean}`);
    clean = dummy.hostname;
  } catch {
    // If not a full URL parseable string, keep cleaned
  }

  return clean;
}

/**
 * Validate that a normalized domain has a legitimate structure
 * and does not represent an accidental broad wildcard (e.g. "*", ".", or empty string).
 */
export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) {
    return false;
  }

  // Prohibit dangerous wildcards or empty segments
  if (domain === "*" || domain === "." || domain.startsWith(".") || domain.endsWith(".")) {
    return false;
  }

  // Prohibit safeguard hosts from being added to blocklist
  if (SAFEGUARD_HOSTS.has(domain)) {
    return false;
  }

  // Check valid hostname characters (alphanumeric, hyphens, dots, or brackets for IPv6)
  const domainRegex = /^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,63}|localhost|\[[0-9a-fA-F:]+\]|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;
  return domainRegex.test(domain);
}

/**
 * Test whether a given target domain matches a rule domain.
 * Enforces strict boundary matching:
 * - Matches exact domain (example.com == example.com)
 * - Matches subdomains (sub.example.com matches example.com)
 * - NEVER matches partial substrings (notexample.com does NOT match example.com)
 */
export function matchesDomainBoundary(targetHost: string, ruleDomain: string): boolean {
  const normTarget = normalizeDomain(targetHost);
  const normRule = normalizeDomain(ruleDomain);

  if (!normTarget || !normRule) {
    return false;
  }

  if (normTarget === normRule) {
    return true;
  }

  // Subdomain match: target ends with '.rule'
  return normTarget.endsWith("." + normRule);
}

/**
 * Generate DNR urlFilter matching the domain and subdomains with strict boundary delimiters.
 * Syntax: "||domain.com^"
 * - "||" matches the beginning of the domain or any subdomain prefix.
 * - "^" matches separator character (path separator '/', port ':', query '?', or end of URL).
 */
export function generateDnrUrlFilter(domain: string): string {
  const norm = normalizeDomain(domain);
  return `||${norm}^`;
}

/**
 * Compile threat rules and settings into Chrome declarativeNetRequest rules.
 */
export function compileDnrRules(
  threatRules: ThreatRule[],
  settings: ProtectionSettings
): chrome.declarativeNetRequest.Rule[] {
  if (!settings.protectionEnabled || settings.mode === "DISABLED") {
    return [];
  }

  const dnrRules: chrome.declarativeNetRequest.Rule[] = [];
  const normalizedAllowlist = new Set(
    settings.allowlist.map((d) => normalizeDomain(d)).filter(Boolean)
  );

  // 1. In Strict Allowlist Mode:
  // - Priority 1: Catch-all block rule on all main_frame navigations
  // - Priority 2: Allow rules for explicitly approved allowlist domains
  if (settings.mode === "STRICT_ALLOWLIST") {
    // Catch-all block rule redirecting to safe interstitial
    dnrRules.push({
      id: 99999,
      priority: 1,
      action: {
        type: "redirect" as chrome.declarativeNetRequest.RuleActionType,
        redirect: {
          extensionPath: "/blocked.html?type=block&reason=strict_allowlist",
        },
      },
      condition: {
        urlFilter: "*",
        resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType],
      },
    });

    // Allow rules for allowlist entries
    let allowId = 20000;
    for (const allowed of normalizedAllowlist) {
      if (isValidDomain(allowed)) {
        dnrRules.push({
          id: allowId++,
          priority: 2,
          action: {
            type: "allow" as chrome.declarativeNetRequest.RuleActionType,
          },
          condition: {
            urlFilter: generateDnrUrlFilter(allowed),
            resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType],
          },
        });
      }
    }

    return dnrRules;
  }

  // 2. Standard Protection Mode:
  // Compile high-confidence threat rules and custom blocklist
  const blockedDomains = new Map<string, ThreatRule>();

  // Add system threat rules
  for (const rule of threatRules) {
    const norm = normalizeDomain(rule.domain);
    if (isValidDomain(norm) && !normalizedAllowlist.has(norm)) {
      if (settings.blockHighConfidence && rule.confidence === "HIGH") {
        blockedDomains.set(norm, rule);
      }
    }
  }

  // Add user custom blocklist
  let customIdCounter = 10000;
  for (const customDomain of settings.customBlocklist) {
    const norm = normalizeDomain(customDomain);
    if (isValidDomain(norm) && !normalizedAllowlist.has(norm) && !blockedDomains.has(norm)) {
      blockedDomains.set(norm, {
        id: customIdCounter++,
        domain: norm,
        name: "User Blocklist Entry",
        category: "Custom Policy",
        severity: "HIGH",
        confidence: "HIGH",
        source: "USER",
        description: "Manually blocked domain in SentinelX settings.",
        createdAt: new Date().toISOString(),
      });
    }
  }

  // Build DNR dynamic rules
  for (const [domain, rule] of blockedDomains.entries()) {
    dnrRules.push({
      id: rule.id,
      priority: 1,
      action: {
        type: "redirect" as chrome.declarativeNetRequest.RuleActionType,
        redirect: {
          extensionPath: `/blocked.html?type=block&domain=${encodeURIComponent(domain)}&rule=${encodeURIComponent(rule.name)}&id=${rule.id}`,
        },
      },
      condition: {
        urlFilter: generateDnrUrlFilter(domain),
        resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType],
      },
    });
  }

  return dnrRules;
}
