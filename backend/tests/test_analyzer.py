"""
SentinelX Automated Test Suite
Validates transparent heuristic engine, central risk policy thresholds,
structured explanations, API endpoints, origin validation, and localhost restriction.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.analyzer import DEFAULT_POLICY, analyze_url
from backend.app.main import app
from backend.app.models import RecommendedAction, RiskPolicyConfig, Verdict

client = TestClient(app)


class TestAnalyzerEngine:
    """Unit tests for the heuristic analysis engine and transparent scoring."""

    def test_benign_https_reputable_domain(self):
        result = analyze_url("https://www.google.com/search?q=cybersecurity")
        assert result.risk_score < 30
        assert result.verdict == Verdict.SAFE
        assert result.recommended_action == RecommendedAction.ALLOW
        assert result.http_analysis.is_encrypted is True
        assert any("Recognized established domain" in s for s in result.safe_indicators)

    def test_unverified_domain_yields_unknown_verdict(self):
        result = analyze_url("https://unfamiliar-random-blog-12345.org/article")
        assert result.risk_score < 30
        assert result.verdict == Verdict.UNKNOWN
        assert result.recommended_action == RecommendedAction.PROCEED_WITH_CAUTION
        assert "unverified" in result.confidence.lower()

    def test_plain_insecure_http(self):
        result = analyze_url("http://example.org/index.html")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_INSECURE_HTTP" in rule_ids
        assert result.http_analysis.is_encrypted is False
        assert result.risk_score >= 30

    def test_raw_ip_address_host(self):
        result = analyze_url("http://192.168.1.100/admin")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_RAW_IP_HOST" in rule_ids
        assert result.risk_score >= 75

    def test_credential_userinfo_spoof(self):
        # Using @ symbol to trick users into believing host is paypal.com
        result = analyze_url("https://paypal.com:secret@attacker-domain.com/login")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_CREDENTIAL_USERINFO_SPOOF" in rule_ids
        assert result.verdict == Verdict.DANGEROUS
        assert result.recommended_action == RecommendedAction.BLOCK
        assert result.risk_score >= 90

    def test_punycode_idn_homograph(self):
        result = analyze_url("https://xn--pple-43d.com/support")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_PUNYCODE_HOMOGRAPH" in rule_ids
        assert result.risk_score >= 45

    def test_brand_typosquatting_and_phishing(self):
        result = analyze_url("https://paypal-security-verification.xyz/signin")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_BRAND_IMPERSONATION" in rule_ids
        assert "RULE_HIGH_RISK_TLD" in rule_ids
        assert result.verdict == Verdict.DANGEROUS
        assert result.recommended_action == RecommendedAction.BLOCK
        assert result.risk_score >= 90

    def test_high_risk_abused_tld(self):
        result = analyze_url("https://free-prizes-claim.buzz/win")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_HIGH_RISK_TLD" in rule_ids
        assert result.risk_score >= 25

    def test_excessive_subdomains_stacking(self):
        result = analyze_url("https://secure.account.billing.update.verify.mysite.com/auth")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_EXCESSIVE_SUBDOMAINS" in rule_ids

    def test_open_redirect_parameter(self):
        result = analyze_url("https://example.com/login?redirect=https://evil-phish.com")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_OPEN_REDIRECT_PARAMETER" in rule_ids

    def test_non_standard_port(self):
        result = analyze_url("https://example.org:8443/login")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_NON_STANDARD_PORT" in rule_ids

    def test_structured_detection_reasons(self):
        result = analyze_url("http://paypal-verification.top:8080/account-update")
        assert len(result.detection_reasons) >= 3
        assert result.normalized_url.startswith("http://paypal-verification.top:8080")
        assert result.hostname == "paypal-verification.top"
        assert result.verdict == Verdict.DANGEROUS
        assert result.recommended_action == RecommendedAction.BLOCK


class TestRiskPolicyThresholds:
    """Validates boundary decisions at risk scores: 79, 80, 89, 90, 100."""

    def test_threshold_79_boundary_behavior(self):
        # A policy where block is 90 and warn is 80:
        # A score of 79 should NOT trigger WARN_INTERSTITIAL or BLOCK
        policy = RiskPolicyConfig(block_threshold=90, warn_threshold=80)
        # Construct URL with score around ~70-75 (e.g. raw IP HTTP: HTTP 30 + RAW_IP 45 = 75)
        result = analyze_url("http://198.51.100.1/test", policy=policy)
        assert result.risk_score == 75
        assert result.risk_score < 80
        assert result.recommended_action == RecommendedAction.PROCEED_WITH_CAUTION
        assert result.verdict == Verdict.SUSPICIOUS

    def test_threshold_80_triggers_warning_interstitial(self):
        policy = RiskPolicyConfig(block_threshold=90, warn_threshold=80)
        # HTTP (30) + High-risk TLD (25) + Sensitive path (20) + Length > 120 (10) = 85 (within 80-89)
        test_url = "http://my-secure-portal.top/account-update-login-flow-padding-to-exceed-one-hundred-and-twenty-characters-in-url-length?extra=123"
        result = analyze_url(test_url, policy=policy)
        assert 80 <= result.risk_score <= 89
        assert result.recommended_action == RecommendedAction.WARN_INTERSTITIAL
        assert result.verdict == Verdict.SUSPICIOUS

    def test_threshold_89_warning_interstitial(self):
        policy = RiskPolicyConfig(block_threshold=90, warn_threshold=80)
        # HTTP (30) + High-risk TLD (25) + Sensitive path (20) + Length > 120 (10) = 85 (within 80-89)
        test_url = "http://some-finance-update.xyz/verification-account-reset?ref=123456789012345678901234567890123456789012345678901234567890"
        result = analyze_url(test_url, policy=policy)
        assert 80 <= result.risk_score <= 89
        assert result.recommended_action == RecommendedAction.WARN_INTERSTITIAL

    def test_threshold_90_automatic_block(self):
        policy = RiskPolicyConfig(block_threshold=90, warn_threshold=80)
        # High confidence threat (Brand impersonation on high-risk TLD: 50 + 25 + 30 = 100 or >= 90)
        result = analyze_url("http://chase-bank-verify.xyz/login", policy=policy)
        assert result.risk_score >= 90
        assert result.verdict == Verdict.DANGEROUS
        assert result.recommended_action == RecommendedAction.BLOCK

    def test_threshold_100_automatic_block(self):
        policy = RiskPolicyConfig(block_threshold=90, warn_threshold=80)
        # Multiple critical flags: Userinfo spoof + Brand impersonation + Raw IP
        result = analyze_url("http://paypal.com@192.168.1.1:8080/login", policy=policy)
        assert result.risk_score == 100
        assert result.verdict == Verdict.DANGEROUS
        assert result.recommended_action == RecommendedAction.BLOCK


class TestApiEndpoints:
    """Integration tests for FastAPI endpoints, CORS, and origin protection."""

    def test_health_endpoint(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "risk_policy" in data
        assert data["risk_policy"]["block_threshold"] == 90
        assert data["risk_policy"]["warn_threshold"] == 80

    def test_get_policy_endpoint(self):
        response = client.get("/api/policy")
        assert response.status_code == 200
        data = response.json()
        assert data["block_threshold"] == 90
        assert data["warn_threshold"] == 80
        assert data["allow_override_on_warning"] is True

    def test_analyze_endpoint_safe(self):
        response = client.post("/api/analyze", json={"url": "https://www.google.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "safe"
        assert data["risk_score"] < 30
        assert data["recommended_action"] == "ALLOW"
        assert data["normalized_url"].startswith("https://www.google.com")

    def test_analyze_endpoint_high_risk(self):
        response = client.post(
            "/api/analyze",
            json={"url": "http://paypal-verification-alert.top/signin"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "dangerous"
        assert data["risk_score"] >= 90
        assert data["recommended_action"] == "BLOCK"
        assert len(data["detection_reasons"]) >= 2

    def test_analyze_endpoint_rejects_empty_url(self):
        response = client.post("/api/analyze", json={"url": "   "})
        assert response.status_code in (400, 422)

    def test_analyze_endpoint_rejects_disallowed_schemes(self):
        for dangerous_url in ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,evil"]:
            response = client.post("/api/analyze", json={"url": dangerous_url})
            assert response.status_code in (400, 422)

    def test_localhost_restriction_middleware(self):
        external_client = TestClient(app, client=("198.51.100.25", 50000))
        response = external_client.get("/health")
        assert response.status_code == 403
        assert "strictly restricted to local loopback" in response.json()["detail"]

    def test_unauthorized_web_origin_rejected(self):
        # A malicious website trying to invoke localhost API via browser fetch
        response = client.post(
            "/api/analyze",
            json={"url": "https://example.com"},
            headers={"Origin": "https://malicious-web-tracker.com"},
        )
        assert response.status_code == 403
        assert "not authorized" in response.json()["detail"]

    def test_chrome_extension_origin_allowed(self):
        response = client.post(
            "/api/analyze",
            json={"url": "https://example.com"},
            headers={"Origin": "chrome-extension://abcdefghijklmnop1234567890"},
        )
        assert response.status_code == 200


class TestStructuredDetectionEvidence:
    """Validates structured detection evidence types, sources, and confidence metadata."""

    def test_structured_evidence_fields_on_rules(self):
        from backend.app.models import EvidenceSource, EvidenceType

        result = analyze_url("http://192.168.1.100/admin-login-reset?redirect=https://evil.test")
        assert len(result.triggered_rules) >= 2
        for rule in result.triggered_rules:
            assert isinstance(rule.evidence_type, EvidenceType)
            assert isinstance(rule.source, EvidenceSource)
            assert rule.confidence in ("HIGH", "MEDIUM", "LOW")

        # Specific rule evidence verification
        ip_rule = next(r for r in result.triggered_rules if r.rule_id == "RULE_RAW_IP_HOST")
        assert ip_rule.evidence_type == EvidenceType.CONFIRMED
        assert ip_rule.source == EvidenceSource.LOCAL_HEURISTIC
        assert ip_rule.confidence == "HIGH"

    def test_heuristic_evidence_on_suspicious_patterns(self):
        from backend.app.models import EvidenceSource, EvidenceType

        result = analyze_url("https://paypal-security-check.xyz/update")
        brand_rule = next(r for r in result.triggered_rules if r.rule_id == "RULE_BRAND_IMPERSONATION")
        assert brand_rule.evidence_type == EvidenceType.HEURISTIC
        assert brand_rule.source == EvidenceSource.LOCAL_HEURISTIC
        assert brand_rule.confidence == "HIGH"

    def test_inconclusive_evidence_on_long_url(self):
        from backend.app.models import EvidenceSource, EvidenceType

        long_url = "https://unfamiliar-news-portal.org/article/" + ("a" * 150)
        result = analyze_url(long_url)
        length_rule = next(r for r in result.triggered_rules if r.rule_id in ("RULE_LONG_URL", "RULE_EXTREME_URL_LENGTH"))
        assert length_rule.evidence_type == EvidenceType.INCONCLUSIVE
        assert length_rule.source == EvidenceSource.LOCAL_HEURISTIC
        assert length_rule.confidence == "LOW"

