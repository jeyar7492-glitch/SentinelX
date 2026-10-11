"""
Automated Test Suite for SentinelX URL Security Analyzer and Local API
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.analyzer import analyze_url
from backend.app.main import app
from backend.app.models import RiskClassification, RuleSeverity

client = TestClient(app)


class TestAnalyzerEngine:
    def test_benign_https_reputable_domain(self):
        result = analyze_url("https://github.com/torvalds/linux")
        assert result.classification == RiskClassification.SAFE
        assert result.risk_score < 30
        assert result.http_analysis.is_encrypted is True
        assert result.http_analysis.scheme == "https"
        # Must include the educational HTTPS nuance statement
        assert "NOT proof of safety" in result.http_analysis.detailed_explanation
        assert any("Recognized established domain name" in ind for ind in result.safe_indicators)

    def test_plain_insecure_http(self):
        result = analyze_url("http://example-blog.org/news/article-1")
        assert result.http_analysis.is_encrypted is False
        assert result.http_analysis.scheme == "http"
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_INSECURE_HTTP" in rule_ids
        assert result.risk_score >= 30

    def test_raw_ip_address_host(self):
        result = analyze_url("http://192.168.1.1/admin/login")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_RAW_IP_HOST" in rule_ids
        assert result.classification == RiskClassification.HIGH_RISK
        assert result.risk_score >= 70

    def test_credential_userinfo_spoof(self):
        # URL abusing the @ symbol to disguise destination host
        result = analyze_url("https://paypal.com@malicious-harvesting-site.com/auth")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_CREDENTIAL_USERINFO_SPOOF" in rule_ids
        assert result.classification == RiskClassification.HIGH_RISK

    def test_punycode_idn_homograph(self):
        # Punycode spoofing apple.com
        result = analyze_url("https://xn--pple-43d.com/store")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_PUNYCODE_HOMOGRAPH" in rule_ids
        assert result.risk_score >= 45

    def test_brand_typosquatting_and_phishing(self):
        # Attackers crafting deceptive domains with target brands
        result = analyze_url("https://paypal-security-verification.com/signin")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_BRAND_IMPERSONATION" in rule_ids
        assert "RULE_SENSITIVE_PATH_ACTION" in rule_ids
        assert result.classification == RiskClassification.HIGH_RISK

    def test_high_risk_abused_tld(self):
        result = analyze_url("http://secure-account-center.top/")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_HIGH_RISK_TLD" in rule_ids
        assert "RULE_INSECURE_HTTP" in rule_ids
        assert result.risk_score >= 50

    def test_excessive_subdomains_stacking(self):
        result = analyze_url("https://portal.account.verify.update.evil-domain.com/index.html")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_EXCESSIVE_SUBDOMAINS" in rule_ids

    def test_open_redirect_parameter(self):
        result = analyze_url("https://example-portal.com/login?redirect=https://evil-attacker.com/steal")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_OPEN_REDIRECT_PARAMETER" in rule_ids

    def test_non_standard_port(self):
        result = analyze_url("http://external-site.org:8888/dashboard")
        rule_ids = [r.rule_id for r in result.triggered_rules]
        assert "RULE_NON_STANDARD_PORT" in rule_ids


class TestApiEndpoints:
    def test_health_endpoint(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "SentinelX" in data["service"]
        assert "127.0.0.1" in data["host_restriction"]

    def test_analyze_endpoint_safe(self):
        payload = {"url": "https://www.wikipedia.org/"}
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "SAFE"
        assert data["risk_score"] < 30
        assert data["http_analysis"]["scheme"] == "https"
        assert data["http_analysis"]["is_encrypted"] is True

    def test_analyze_endpoint_high_risk(self):
        payload = {"url": "http://192.168.1.100/chase-login-verify/account"}
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "HIGH RISK"
        assert data["risk_score"] >= 70
        assert len(data["triggered_rules"]) >= 2

    def test_analyze_endpoint_rejects_empty_url(self):
        response = client.post("/api/analyze", json={"url": "   "})
        assert response.status_code in (400, 422)

    def test_analyze_endpoint_rejects_disallowed_schemes(self):
        # Prevent javascript:, file:, or data: injection
        for dangerous_url in ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,evil"]:
            response = client.post("/api/analyze", json={"url": dangerous_url})
            assert response.status_code in (400, 422)

    def test_localhost_restriction_middleware(self):
        # Client host simulated as external IP should receive 403 Forbidden
        external_client = TestClient(app, client=("198.51.100.25", 50000))
        response = external_client.get("/health")
        assert response.status_code == 403
        assert "strictly restricted to local loopback" in response.json()["detail"]
