"""
SentinelX URL Security Analyzer Engine
Zero-cost, local-only transparent heuristic analysis for phishing and URL anomalies.
Implements central documented risk policy and structured explanations.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlsplit

from .models import (
    AnalyzeResponse,
    EvidenceSource,
    EvidenceType,
    HttpAnalysis,
    RecommendedAction,
    RiskClassification,
    RiskPolicyConfig,
    RuleSeverity,
    TriggeredRule,
    Verdict,
)
from .rules import (
    HIGH_RISK_TLDS,
    REDIRECT_PARAMS,
    SENSITIVE_PATH_KEYWORDS,
    TARGET_BRANDS,
    TRUSTED_DOMAINS,
)

# Central default policy instance
DEFAULT_POLICY = RiskPolicyConfig(block_threshold=90, warn_threshold=80, allow_override_on_warning=True)


def _is_ip_address(host: str) -> bool:
    """Check if the host is a raw IPv4 or IPv6 address or encoded integer/hex IP."""
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
    # Handle common two-part TLDs (e.g., .co.uk, .gov.uk, .com.au)
    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "co.nz", "com.br"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
        domain_name = parts[-3]
        subdomains = parts[:-3]
        tld = f"{parts[-2]}.{parts[-1]}"
    else:
        domain_name = parts[-2]
        subdomains = parts[:-2]
        tld = parts[-1]

    return domain_name, tld, subdomains


def analyze_url(raw_url: str, policy: RiskPolicyConfig = DEFAULT_POLICY) -> AnalyzeResponse:
    """
    Analyze a given URL against SentinelX's transparent heuristic security rules.
    Runs entirely locally without external network requests.
    Returns structured risk decision conforming to the central risk policy.
    """
    url = raw_url.strip()
    parsed = urlsplit(url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path
    query = parsed.query

    # Normalized URL representation (lowercase scheme and host, stripped trailing spaces)
    norm_netloc = hostname
    if port and port not in (80, 443):
        norm_netloc = f"{hostname}:{port}"
    normalized_url = f"{scheme}://{norm_netloc}{path or '/'}"
    if query:
        normalized_url += f"?{query}"

    triggered_rules: list[TriggeredRule] = []
    safe_indicators: list[str] = []
    detection_reasons: list[str] = []
    total_penalty = 0
    has_confirmed_threat_override = False

    # ---------------------------------------------------------
    # 1. HTTP vs HTTPS Transport Analysis (Crucial Security Nuance)
    # ---------------------------------------------------------
    if scheme == "http":
        penalty = 30
        total_penalty += penalty
        reason_msg = "Unencrypted HTTP connection: traffic is vulnerable to plaintext eavesdropping and MITM tampering."
        detection_reasons.append(reason_msg)
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
                evidence_type=EvidenceType.CONFIRMED,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="HIGH",
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
        reason_msg = f"Non-standard protocol scheme ('{scheme}'). Standard web traffic uses HTTP or HTTPS."
        detection_reasons.append(reason_msg)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_UNEXPECTED_SCHEME",
                category="Protocol Security",
                name="Non-Standard Web Scheme",
                description=reason_msg,
                severity=RuleSeverity.MEDIUM,
                penalty=penalty,
                evidence_type=EvidenceType.CONFIRMED,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="HIGH",
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
        reason_msg = f"Raw IP address host ('{hostname}'): points directly to an IP rather than a registered domain name."
        detection_reasons.append(reason_msg)
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
                evidence_type=EvidenceType.CONFIRMED,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="HIGH",
            )
        )
    elif hostname:
        safe_indicators.append("Standard domain name addressing (no raw IP host).")

    # ---------------------------------------------------------
    # 3. Credential Embedding / URL Userinfo Spoofing (@ symbol)
    # ---------------------------------------------------------
    if "@" in netloc or parsed.username or parsed.password:
        penalty = 70
        total_penalty += penalty
        has_confirmed_threat_override = True
        reason_msg = "Credential embedding / Userinfo spoofing (@ symbol): deceptive host authority disguise."
        detection_reasons.append(reason_msg)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_CREDENTIAL_USERINFO_SPOOF",
                category="URL Structure & Deception",
                name="Credential Embedding / Host Disguise (@ Symbol)",
                description=(
                    "The URL includes userinfo credentials or an '@' symbol in the host authority. In URL syntax, "
                    "browsers connect to the host AFTER the '@' symbol, while ignoring text preceding it. Threat actors "
                    "use this syntax to trick users into believing they are visiting a trusted site."
                ),
                severity=RuleSeverity.CRITICAL,
                penalty=penalty,
                evidence_type=EvidenceType.CONFIRMED,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="HIGH",
            )
        )

    # ---------------------------------------------------------
    # 4. Non-Standard Web Ports
    # ---------------------------------------------------------
    if port and port not in (80, 443):
        is_local = hostname in ("localhost", "127.0.0.1", "::1")
        penalty = 10 if is_local else 25
        total_penalty += penalty
        reason_msg = f"Non-standard web port (:{port}): traffic directed to custom port instead of 80/443."
        detection_reasons.append(reason_msg)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_NON_STANDARD_PORT",
                category="Network Configuration",
                name=f"Non-Standard Web Port (:{port})",
                description=(
                    f"The URL specifies custom port {port} instead of standard web ports (80 for HTTP, 443 for HTTPS). "
                    "Attackers often host malware or phishing portals on non-standard ports to bypass corporate firewalls."
                ),
                severity=RuleSeverity.LOW if is_local else RuleSeverity.MEDIUM,
                penalty=penalty,
                evidence_type=EvidenceType.CONFIRMED,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="HIGH",
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
        reason_msg = "Punycode/IDN indicator ('xn--'): domain contains lookalike characters vulnerable to homograph attacks."
        detection_reasons.append(reason_msg)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_PUNYCODE_HOMOGRAPH",
                category="Domain & Identity",
                name="Punycode / IDN Homograph Indicator ('xn--')",
                description=(
                    "The domain name uses Punycode encoding ('xn--'), indicating Internationalized Domain Name characters. "
                    "Attackers use homograph attacks with characters from Cyrillic or other scripts that look "
                    "identical to Latin letters to mimic brand domains."
                ),
                severity=RuleSeverity.CRITICAL,
                penalty=penalty,
                evidence_type=EvidenceType.CONFIRMED,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="HIGH",
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
        reason_msg = f"High-abuse top-level domain (.{tld}): statistically associated with disposable scam domains."
        detection_reasons.append(reason_msg)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_HIGH_RISK_TLD",
                category="Domain Reputation",
                name=f"High-Abuse Top Level Domain (.{tld})",
                description=(
                    f"The domain uses the '.{tld}' top-level domain. This TLD is statistically overrepresented in "
                    "disposable phishing kits and scam infrastructure."
                ),
                severity=RuleSeverity.MEDIUM,
                penalty=penalty,
                evidence_type=EvidenceType.HEURISTIC,
                source=EvidenceSource.REPUTATION_LIST,
                confidence="MEDIUM",
            )
        )

    # ---------------------------------------------------------
    # 7. Brand Typosquatting & Impersonation
    # ---------------------------------------------------------
    if not is_trusted_domain:
        brand_detected: str | None = None
        for brand in TARGET_BRANDS:
            if brand in hostname:
                if domain_name == brand:
                    continue
                brand_detected = brand
                break

        if brand_detected:
            penalty = 50
            total_penalty += penalty
            has_confirmed_threat_override = True
            reason_msg = f"Brand impersonation: hostname contains trusted brand '{brand_detected}' on unrelated domain '{registered_domain}'."
            detection_reasons.append(reason_msg)
            triggered_rules.append(
                TriggeredRule(
                    rule_id="RULE_BRAND_IMPERSONATION",
                    category="Identity & Phishing",
                    name=f"Target Brand Keyword Impersonation ('{brand_detected}')",
                    description=(
                        f"The domain or subdomains contain the brand name '{brand_detected}', but the site is hosted "
                        f"on an unrelated domain ('{registered_domain}'). Attackers craft deceptive lookalike domains "
                        "to harvest credentials."
                    ),
                    severity=RuleSeverity.CRITICAL,
                    penalty=penalty,
                    evidence_type=EvidenceType.HEURISTIC,
                    source=EvidenceSource.LOCAL_HEURISTIC,
                    confidence="HIGH",
                )
            )

    # ---------------------------------------------------------
    # 8. Excessive Subdomain Depth (Subdomain Stacking)
    # ---------------------------------------------------------
    if len(subdomains) >= 3 and not is_trusted_domain:
        penalty = 25
        total_penalty += penalty
        subdomain_str = ".".join(subdomains)
        reason_msg = f"Excessive subdomain depth: nested subdomains ('{subdomain_str}') obscure the true domain."
        detection_reasons.append(reason_msg)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_EXCESSIVE_SUBDOMAINS",
                category="URL Structure",
                name="Excessive Subdomain Depth",
                description=(
                    f"The host has multiple nested subdomain levels ('{subdomain_str}'). Phishers stack subdomains "
                    "to push the real destination domain off the visible portion of browser address bars."
                ),
                severity=RuleSeverity.MEDIUM,
                penalty=penalty,
                evidence_type=EvidenceType.HEURISTIC,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="MEDIUM",
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
        penalty = 20
        total_penalty += penalty
        reason_msg = f"Sensitive authentication path ({', '.join(matched_action_keywords[:2])}) on unverified domain."
        detection_reasons.append(reason_msg)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_SENSITIVE_PATH_ACTION",
                category="Behavioral Indication",
                name="Sensitive Account/Login Path on Unverified Host",
                description=(
                    f"The URL path contains sensitive action keywords ({', '.join(matched_action_keywords[:3])}) "
                    f"hosted on an unrecognized or non-whitelisted domain ('{registered_domain}')."
                ),
                severity=RuleSeverity.MEDIUM,
                penalty=penalty,
                evidence_type=EvidenceType.HEURISTIC,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="MEDIUM",
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
            reason_msg = f"Open redirect parameter ({', '.join(detected_redirect_params)}): may bounce visitors to an unverified target."
            detection_reasons.append(reason_msg)
            triggered_rules.append(
                TriggeredRule(
                    rule_id="RULE_OPEN_REDIRECT_PARAMETER",
                    category="URL Obfuscation & Redirection",
                    name="Potential Open Redirect / URL Parameter Forwarding",
                    description=(
                        f"The query string contains URL redirection parameter(s): {', '.join(detected_redirect_params)}. "
                        "Open redirects allow attackers to use trusted domain links to bounce visitors to malicious sites."
                    ),
                    severity=RuleSeverity.MEDIUM,
                    penalty=penalty,
                    evidence_type=EvidenceType.HEURISTIC,
                    source=EvidenceSource.LOCAL_HEURISTIC,
                    confidence="MEDIUM",
                )
            )

    # ---------------------------------------------------------
    # 11. Abnormal URL Length & Obfuscation
    # ---------------------------------------------------------
    url_len = len(url)
    if url_len > 200:
        penalty = 20
        total_penalty += penalty
        reason_msg = f"Abnormally long URL ({url_len} chars): frequently used to hide encoded parameters or obfuscated targets."
        detection_reasons.append(reason_msg)
        triggered_rules.append(
            TriggeredRule(
                rule_id="RULE_EXTREME_URL_LENGTH",
                category="Obfuscation",
                name=f"Excessive URL Length ({url_len} characters)",
                description=reason_msg,
                severity=RuleSeverity.LOW,
                penalty=penalty,
                evidence_type=EvidenceType.INCONCLUSIVE,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="LOW",
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
                evidence_type=EvidenceType.INCONCLUSIVE,
                source=EvidenceSource.LOCAL_HEURISTIC,
                confidence="LOW",
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
            reason_msg = f"Heavy percent-encoding ({len(hex_encoded_matches)} sequences): potential keyword obfuscation."
            detection_reasons.append(reason_msg)
            triggered_rules.append(
                TriggeredRule(
                    rule_id="RULE_HEAVY_URL_ENCODING",
                    category="Obfuscation",
                    name="Heavy Percent-Encoding Detected",
                    description=reason_msg,
                    severity=RuleSeverity.LOW,
                    penalty=penalty,
                    evidence_type=EvidenceType.INCONCLUSIVE,
                    source=EvidenceSource.LOCAL_HEURISTIC,
                    confidence="LOW",
                )
            )

    # ---------------------------------------------------------
    # Final Score & Central Risk Policy Decision
    # ---------------------------------------------------------
    if is_trusted_domain and not any(r.severity == RuleSeverity.CRITICAL for r in triggered_rules):
        total_penalty = min(total_penalty, 25 if scheme == "http" else 15)

    risk_score = min(max(total_penalty, 0), 100)

    # Confirmed threat override: brand impersonation or userinfo spoofing immediately enforces dangerous verdict
    if has_confirmed_threat_override and risk_score < policy.block_threshold:
        risk_score = max(risk_score, policy.block_threshold)

    # Evaluate against central thresholds
    if risk_score >= policy.block_threshold:
        verdict = Verdict.DANGEROUS
        recommended_action = RecommendedAction.BLOCK
        confidence = "HIGH (Confirmed malicious indicators or critical risk patterns)"
        classification = RiskClassification.HIGH_RISK
        summary = (
            "CRITICAL THREAT DETECTED: Multiple high-confidence phishing, credential theft, or structural "
            "deception indicators were identified. Connection blocked to protect your credentials and device."
        )
    elif risk_score >= policy.warn_threshold:
        verdict = Verdict.SUSPICIOUS
        recommended_action = RecommendedAction.WARN_INTERSTITIAL
        confidence = "MEDIUM (Significant suspicious anomalies observed)"
        classification = RiskClassification.HIGH_RISK
        summary = (
            "ELEVATED RISK DETECTED: URL exhibits substantial suspicious patterns warranting a warning interstitial "
            "before proceeding. Review the explanation before entering credentials."
        )
    elif risk_score >= 30:
        verdict = Verdict.SUSPICIOUS
        recommended_action = RecommendedAction.PROCEED_WITH_CAUTION
        confidence = "MEDIUM (Suspicious indicators detected)"
        classification = RiskClassification.SUSPICIOUS
        summary = (
            "SUSPICIOUS ANOMALIES IDENTIFIED: This URL exhibits elevated risk factors such as plain HTTP, "
            "unusual domain characteristics, or sensitive actions on an unverified site. Proceed with caution."
        )
    elif is_trusted_domain and risk_score < 30:
        verdict = Verdict.SAFE
        recommended_action = RecommendedAction.ALLOW
        confidence = "HIGH (Established reputable domain with clean indicators)"
        classification = RiskClassification.SAFE
        summary = (
            "LOW STRUCTURAL RISK: Verified established domain with no detected threat patterns. "
            "Remember that transport encryption (HTTPS) does not guarantee total website safety."
        )
    else:
        # Unknown / Unverified domain with score < 30
        verdict = Verdict.UNKNOWN
        recommended_action = RecommendedAction.PROCEED_WITH_CAUTION
        confidence = "LOW (Domain reputation unverified locally; lack of detected evidence is not proof of safety)"
        classification = RiskClassification.SAFE
        summary = (
            "UNVERIFIED DOMAIN (NO DETECTED THREATS): No known phishing signatures were matched, but this domain "
            "is not on your verified list. Lack of detected evidence is not proof of safety."
        )

    return AnalyzeResponse(
        url=url,
        normalized_url=normalized_url,
        hostname=hostname,
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence,
        detection_reasons=detection_reasons,
        recommended_action=recommended_action,
        classification=classification,
        summary=summary,
        http_analysis=http_analysis,
        triggered_rules=triggered_rules,
        safe_indicators=safe_indicators,
        analyzed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        engine_version="2.0.0-realtime",
    )
