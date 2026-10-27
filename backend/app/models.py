"""
SentinelX Pydantic Data Models & Central Risk Policy
Defines request schemas, response schemas, and structured risk policy types.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class Verdict(str, Enum):
    """
    Central Risk Verdicts:
    - safe: Verified safe or established domain with clean indicators
    - unknown: Unfamiliar domain or insufficient evidence; uncertainty applies
    - suspicious: Elevated risk (score 80-89) or suspicious heuristic signals
    - dangerous: High risk (score 90-100) or confirmed malicious indicator
    """
    SAFE = "safe"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class RecommendedAction(str, Enum):
    BLOCK = "BLOCK"
    WARN_INTERSTITIAL = "WARN_INTERSTITIAL"
    PROCEED_WITH_CAUTION = "PROCEED_WITH_CAUTION"
    ALLOW = "ALLOW"
    UNABLE_TO_VERIFY = "UNABLE_TO_VERIFY"


class RiskClassification(str, Enum):
    """Legacy classification preserved for backward compatibility."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"


class RuleSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskPolicyConfig(BaseModel):
    """Central documented risk thresholds."""
    block_threshold: int = Field(default=90, ge=85, le=100, description="Score >= block_threshold triggers automatic BLOCK.")
    warn_threshold: int = Field(default=80, ge=60, le=89, description="Score >= warn_threshold triggers WARN_INTERSTITIAL.")
    allow_override_on_warning: bool = Field(default=True, description="Whether users may bypass a warning interstitial.")


class AnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The URL to analyze. Must be a valid web URL."
    )

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("URL cannot be empty or whitespace only.")
        # Reject non-http/https schemes that might be internal browser schemes or dangerous schemes
        lower_scheme = trimmed.split(":", 1)[0].lower() if ":" in trimmed else ""
        if lower_scheme not in ("http", "https"):
            raise ValueError(f"Only http and https URLs are supported (received: '{lower_scheme or 'none'}').")
        return trimmed


class HttpAnalysis(BaseModel):
    scheme: str
    is_encrypted: bool
    summary: str
    detailed_explanation: str


class EvidenceType(str, Enum):
    """Classification of evidence backing a detection signal."""
    CONFIRMED = "confirmed"
    HEURISTIC = "heuristic"
    INCONCLUSIVE = "inconclusive"


class EvidenceSource(str, Enum):
    """Origin source of the detection signal."""
    LOCAL_HEURISTIC = "local_heuristic"
    REPUTATION_LIST = "reputation_list"
    VERIFIED_SIGNATURE = "verified_signature"


class TriggeredRule(BaseModel):
    rule_id: str
    category: str
    name: str
    description: str
    severity: RuleSeverity
    penalty: int
    evidence_type: EvidenceType = EvidenceType.HEURISTIC
    source: EvidenceSource = EvidenceSource.LOCAL_HEURISTIC
    confidence: str = "MEDIUM"


class AnalyzeResponse(BaseModel):
    # Primary structured decision outputs
    url: str
    normalized_url: str
    hostname: str
    risk_score: int = Field(..., ge=0, le=100, description="Risk Score (0-100). Not a calibrated probability.")
    verdict: Verdict
    confidence: str
    detection_reasons: List[str] = Field(default_factory=list)
    recommended_action: RecommendedAction

    # Explanations and legacy compatibility
    classification: RiskClassification
    summary: str
    http_analysis: HttpAnalysis
    triggered_rules: List[TriggeredRule] = Field(default_factory=list)
    safe_indicators: List[str] = Field(default_factory=list)
    analyzed_at: str
    engine_version: str = "2.0.0-realtime"


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    host_restriction: str
    risk_policy: RiskPolicyConfig
