"""
SentinelX URL Security Analyzer Engine
Zero-cost, local-only transparent heuristic analysis for phishing and URL anomalies.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlsplit

from .models import (
    AnalyzeResponse,
    HttpAnalysis,
    RiskClassification,
    RuleSeverity,
    TriggeredRule,
)
from .rules import (
    HIGH_RISK_TLDS,
    REDIRECT_PARAMS,
    SENSITIVE_PATH_KEYWORDS,
    TARGET_BRANDS,
    TRUSTED_DOMAINS,
)


def _is_ip_address(host: str) -> bool:
    """Check if the host is a raw IPv4 or IPv6 address."""
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    # Check for dword / octal / hex encoded IP addresses (e.g., 0x7f000001 or 2130706433)
    if clean_host.isdigit():
        return True
    if clean_host.startswith("0x") and re.fullmatch(r"0x[0-9a-fA-F]+", clean_host):
        return True

    return False


def _extract_base_domain(host: str) -> tuple[str, str, list[str]]:
    """
    Extract TLD, effective second-level domain name, and subdomains.
    Returns: (domain_name, tld, subdomains_list)
    """
    clean_host = host.lower().strip(".")
    parts = clean_host.split(".")
    if len(parts) <= 1:
        return clean_host, "", []

    tld = parts[-1]
    # Handle common two-part TLDs (e.g., .co.uk, .com.au, .gov.uk)
    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "co.nz", "com.br"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
        domain_name = parts[-3]
        subdomains = parts[:-3]
        tld = f"{parts[-2]}.{parts[-1]}"
    else:
        domain_name = parts[-2]
        subdomains = parts[:-2]

    return domain_name, tld, subdomains


def analyze_url(raw_url: str) -> AnalyzeResponse:
    """
    Analyze a given URL against SentinelX's transparent heuristic security rules.
    Runs entirely locally without external network requests.
    """
    url = raw_url.strip()
    parsed = urlsplit(url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path
    query = parsed.query

    triggered_rules: list[TriggeredRule] = []
    safe_indicators: list[str] = []
    total_penalty = 0

    # ---------------------------------------------------------
    # 1. HTTP vs HTTPS Transport Analysis (Crucial Security Nuance)
    # ---------------------------------------------------------
    if scheme == "http":
        penalty = 30
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_INSECURE_HTTP",
                category="Protocol Security",
                name="Unencrypted HTTP Connection",
                description=(
                    "The connection uses plain HTTP instead of HTTPS. All transmitted data (including passwords, "
                    "form submissions, and session identifiers) is unencrypted and vulnerable to local network "
                    "interception, eavesdropping, and Man-in-the-Middle (MITM) tampering."
                ),
                severity=RuleSeverity.HIGH,
                penalty=penalty,
            )
        )
        http_analysis = HttpAnalysis(
            scheme="http",
            is_encrypted=False,
            summary="Insecure Connection (Plaintext HTTP)",
            detailed_explanation=(
                "HTTP does not provide encryption or server authentication. Any adversary on your Wi-Fi network, "
                "local router, or ISP can read and alter page contents in transit. Never enter credentials or sensitive "
                "data on plain HTTP pages."
            ),
        )
    elif scheme == "https":
        safe_indicators.append("Encrypted transport: Connection uses TLS/HTTPS.")
        http_analysis = HttpAnalysis(
            scheme="https",
            is_encrypted=True,
            summary="Encrypted Transport (TLS Active) — Verification Required",
            detailed_explanation=(
                "HTTPS encrypts traffic in transit between your browser and the server, protecting against local "
                "eavesdropping. CRITICAL SECURITY NOTICE: HTTPS alone is NOT proof of safety or authenticity. "
                "Modern phishing sites routinely obtain free, valid SSL/TLS certificates (e.g., Let's Encrypt, Cloudflare) "
                "to display the padlock icon. You must always verify the actual domain name and sender identity."
            ),
        )
    else:
        penalty = 25
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_UNEXPECTED_SCHEME",
                category="Protocol Security",
                name="Non-Standard Web Scheme",
                description=f"URL uses an unusual protocol scheme ('{scheme}'). Standard web traffic uses HTTP or HTTPS.",
                severity=RuleSeverity.MEDIUM,
                penalty=penalty,
            )
        )
        http_analysis = HttpAnalysis(
            scheme=scheme,
            is_encrypted=False,
            summary=f"Non-Standard Protocol ({scheme})",
            detailed_explanation="This URL uses a protocol outside typical secure web browsing standards.",
        )

    # ---------------------------------------------------------
    # 2. Raw IP Address Hostname Detection
    # ---------------------------------------------------------
    if hostname and _is_ip_address(hostname):
        penalty = 45
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_RAW_IP_HOST",
                category="Host & Network",
                name="Raw IP Address as Destination Host",
                description=(
                    f"The URL points directly to an IP address ('{hostname}') rather than a registered domain name. "
                    "Legitimate consumer services and organizations use registered domain names. Attackers use raw IPs "
                    "to bypass domain-based blocklists and avoid domain registration oversight."
                ),
                severity=RuleSeverity.CRITICAL,
                penalty=penalty,
            )
        )
    elif hostname:
        safe_indicators.append("Standard domain name addressing (no raw IP host).")

    # ---------------------------------------------------------
    # 3. Credential Embedding / URL Userinfo Spoofing (@ symbol)
    # ---------------------------------------------------------
    # Check if '@' exists in authority part before path
    if "@" in netloc or parsed.username or parsed.password:
        penalty = 70
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_CREDENTIAL_USERINFO_SPOOF",
                category="URL Structure & Deception",
                name="Credential Embedding / Host Disguise (@ Symbol)",
                description=(
                    "The URL includes userinfo credentials or an '@' symbol in the host authority. In URL syntax, "
                    "browsers connect to the host AFTER the '@' symbol, while ignoring text preceding it. Threat actors "
                    "use this syntax to trick users into believing they are visiting a trusted site (e.g., 'https://paypal.com@evil-site.com')."
                ),
                severity=RuleSeverity.CRITICAL,
                penalty=penalty,
            )
        )

    # ---------------------------------------------------------
    # 4. Non-Standard Web Ports
    # ---------------------------------------------------------
    if port and port not in (80, 443):
        # Allow common local development ports without extreme penalty if host is localhost, otherwise penalize
        is_local = hostname in ("localhost", "127.0.0.1", "::1")
        penalty = 10 if is_local else 25
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_NON_STANDARD_PORT",
                category="Network Configuration",
                name=f"Non-Standard Web Port (:{port})",
                description=(
                    f"The URL specifies custom port {port} instead of standard web ports (80 for HTTP, 443 for HTTPS). "
                    "Attackers often host malware or phishing portals on non-standard ports to bypass corporate firewalls "
                    "or standard web proxies."
                ),
                severity=RuleSeverity.LOW if is_local else RuleSeverity.MEDIUM,
                penalty=penalty,
            )
        )
    else:
        safe_indicators.append("Standard web communication ports used (80/443).")

    # ---------------------------------------------------------
    # 5. Internationalized Domain Names / Punycode (IDN Homograph)
    # ---------------------------------------------------------
    if "xn--" in hostname:
        penalty = 45
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_PUNYCODE_HOMOGRAPH",
                category="Domain & Identity",
                name="Punycode / IDN Homograph Indicator ('xn--')",
                description=(
                    "The domain name uses Punycode encoding ('xn--'), indicating Internationalized Domain Name characters. "
                    "Attackers use homograph attacks with characters from Cyrillic, Greek, or other scripts that look "
                    "identical to Latin letters (e.g., Cyrillic 'а' vs Latin 'a') to mimic brand domains."
                ),
                severity=RuleSeverity.CRITICAL,
                penalty=penalty,
            )
        )

    # Extract domain components
    domain_name, tld, subdomains = _extract_base_domain(hostname)
    registered_domain = f"{domain_name}.{tld}" if tld else domain_name

    # Check for known reputable domains
    is_trusted_domain = (
        hostname in TRUSTED_DOMAINS
        or registered_domain in TRUSTED_DOMAINS
        or any(hostname.endswith("." + td) for td in TRUSTED_DOMAINS)
    )

    if is_trusted_domain:
        safe_indicators.append(f"Recognized established domain name: '{registered_domain}'.")

    # ---------------------------------------------------------
    # 6. High-Risk / Frequently Abused TLDs
    # ---------------------------------------------------------
    if tld in HIGH_RISK_TLDS and not is_trusted_domain:
        penalty = 25
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_HIGH_RISK_TLD",
                category="Domain Reputation",
                name=f"High-Abuse Top Level Domain (.{tld})",
                description=(
                    f"The domain uses the '.{tld}' top-level domain. This TLD is statistically overrepresented in "
                    "disposable phishing kits, malware delivery networks, and bulk-registered scam infrastructure "
                    "due to low acquisition costs or lax registrar verification."
                ),
                severity=RuleSeverity.MEDIUM,
                penalty=penalty,
            )
        )

    # ---------------------------------------------------------
    # 7. Brand Typosquatting & Impersonation
    # ---------------------------------------------------------
    # Search for high-profile brand keywords in domain, subdomains, and host
    if not is_trusted_domain:
        brand_detected: str | None = None
        for brand in TARGET_BRANDS:
            # Check if brand appears in hostname, but domain is NOT the brand itself
            if brand in hostname:
                # If the registered domain is literally the brand (e.g. paypal.com), that's legitimate
                if domain_name == brand:
                    continue
                # Brand appears as a prefix/suffix or in subdomain (e.g., paypal-security.com, login.paypal.verify-site.com)
                brand_detected = brand
                break

        if brand_detected:
            penalty = 50
            total_penalty += penalty
            triggered_rules.append(
                TriggeredRule(
                    rule_id="RULE_BRAND_IMPERSONATION",
                    category="Identity & Phishing",
                    name=f"Target Brand Keyword Impersonation ('{brand_detected}')",
                    description=(
                        f"The domain or subdomains contain the brand name '{brand_detected}', but the site is hosted "
                        f"on an unrelated domain ('{registered_domain}'). Attackers craft deceptive lookalike domains "
                        "(e.g., 'paypal-security-update.com' or 'appleid.verify-support.com') to harvest user credentials."
                    ),
                    severity=RuleSeverity.CRITICAL,
                    penalty=penalty,
                )
            )

    # ---------------------------------------------------------
    # 8. Excessive Subdomain Depth (Subdomain Stacking)
    # ---------------------------------------------------------
    if len(subdomains) >= 3 and not is_trusted_domain:
        penalty = 25
        total_penalty += penalty
        subdomain_str = ".".join(subdomains)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_EXCESSIVE_SUBDOMAINS",
                category="URL Structure",
                name="Excessive Subdomain Depth",
                description=(
                    f"The host has multiple nested subdomain levels ('{subdomain_str}'). Phishers stack subdomains "
                    "to push the real destination domain off the visible portion of browser address bars or mobile screens."
                ),
                severity=RuleSeverity.MEDIUM,
                penalty=penalty,
            )
        )

    # ---------------------------------------------------------
    # 9. Sensitive Action Keywords in Path on Untrusted Domains
    # ---------------------------------------------------------
    lower_path = path.lower()
    matched_action_keywords = [
        kw for kw in SENSITIVE_PATH_KEYWORDS
        if kw in lower_path
    ]
    if matched_action_keywords and not is_trusted_domain:
        # Increase penalty if coupled with suspicious TLD or brand or unencrypted HTTP
        penalty = 20
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_SENSITIVE_PATH_ACTION",
                category="Behavioral Indication",
                name="Sensitive Account/Login Path on Unverified Host",
                description=(
                    f"The URL path contains sensitive action keywords ({', '.join(matched_action_keywords[:3])}) "
                    f"hosted on an unrecognized or non-whitelisted domain ('{registered_domain}'). Exercise extreme caution "
                    "before entering any passwords or personal information."
                ),
                severity=RuleSeverity.MEDIUM,
                penalty=penalty,
            )
        )

    # ---------------------------------------------------------
    # 10. Open Redirect / External Target Query Parameters
    # ---------------------------------------------------------
    if query:
        parsed_params = parse_qs(query)
        detected_redirect_params = []
        for param, values in parsed_params.items():
            param_lower = param.lower()
            if param_lower in REDIRECT_PARAMS:
                for val in values:
                    decoded = unquote(val).lower()
                    if decoded.startswith("http://") or decoded.startswith("https://") or decoded.startswith("//"):
                        detected_redirect_params.append(f"{param}={val[:30]}")
                        break

        if detected_redirect_params:
            penalty = 20
            total_penalty += penalty
            triggered_rules.append(
                TriggeredRule(
                    rule_id="RULE_OPEN_REDIRECT_PARAMETER",
                    category="URL Obfuscation & Redirection",
                    name="Potential Open Redirect / URL Parameter Forwarding",
                    description=(
                        f"The query string contains URL redirection parameter(s): {', '.join(detected_redirect_params)}. "
                        "Open redirects allow attackers to use trusted domain links to secretly bounce visitors "
                        "to a malicious destination."
                    ),
                    severity=RuleSeverity.MEDIUM,
                    penalty=penalty,
                )
            )

    # ---------------------------------------------------------
    # 11. Abnormal URL Length & Obfuscation
    # ---------------------------------------------------------
    url_len = len(url)
    if url_len > 200:
        penalty = 20
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_EXTREME_URL_LENGTH",
                category="Obfuscation",
                name=f"Excessive URL Length ({url_len} characters)",
                description=(
                    "The URL is unusually long (>200 characters). Attackers use oversized URLs to hide malicious "
                    "parameters, embed encoded payloads, or disguise redirection targets."
                ),
                severity=RuleSeverity.LOW,
                penalty=penalty,
            )
        )
    elif url_len > 120:
        penalty = 10
        total_penalty += penalty
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_LONG_URL",
                category="Obfuscation",
                name=f"Elevated URL Length ({url_len} characters)",
                description="The URL is longer than typical website addresses, warranting closer inspection.",
                severity=RuleSeverity.LOW,
                penalty=penalty,
            )
        )

    # ---------------------------------------------------------
    # 12. Character Obfuscation (Multiple Hex / Octal encodings)
    # ---------------------------------------------------------
    if "%" in url:
        hex_encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", url)
        if len(hex_encoded_matches) >= 5:
            penalty = 15
            total_penalty += penalty
            triggered_rules.append(
                TriggeredRule(
                    rule_id="RULE_HEAVY_URL_ENCODING",
                    category="Obfuscation",
                    name="Heavy Percent-Encoding Detected",
                    description=(
                        f"The URL contains {len(hex_encoded_matches)} percent-encoded characters. While common in some "
                        "complex APIs, heavy URL encoding is also used to obscure suspicious keywords and bypass keyword filters."
                    ),
                    severity=RuleSeverity.LOW,
                    penalty=penalty,
                )
            )

    # ---------------------------------------------------------
    # Final Score Normalization & Classification
    # ---------------------------------------------------------
    # If the domain is recognized as trusted and has no critical brand impersonation or IP flags, discount score
    if is_trusted_domain and not any(r.severity == RuleSeverity.CRITICAL for r in triggered_rules):
        # Allow trusted domains with safe posture to stay in SAFE zone unless plain HTTP is present
        total_penalty = min(total_penalty, 25 if scheme == "http" else 15)

    risk_score = min(max(total_penalty, 0), 100)

    if risk_score >= 70:
        classification = RiskClassification.HIGH_RISK
        summary = (
            "CRITICAL THREAT INDICATORS DETECTED: Multiple high-risk phishing, credential harvesting, or "
            "structural deception patterns were identified. Do NOT submit credentials or personal information."
        )
    elif risk_score >= 30:
        classification = RiskClassification.SUSPICIOUS
        summary = (
            "SUSPICIOUS ANOMALIES IDENTIFIED: This URL exhibits elevated risk factors such as plain HTTP, "
            "unusual domain characteristics, or sensitive actions on an unverified site. Verify the sender."
        )
    else:
        classification = RiskClassification.SAFE
        summary = (
            "LOW STRUCTURAL RISK: No high-risk phishing indicators or deceptive structural anomalies were detected. "
            "Always stay vigilant and remember that HTTPS does not guarantee website trustworthiness."
        )

    return AnalyzeResponse(
        url=url,
        risk_score=risk_score,
        classification=classification,
        summary=summary,
        http_analysis=http_analysis,
        triggered_rules=triggered_rules,
        safe_indicators=safe_indicators,
        analyzed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        engine_version="1.0.0-phase1",
    )
