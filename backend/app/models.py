from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class RiskClassification(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"


class RuleSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


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


class TriggeredRule(BaseModel):
    rule_id: str
    category: str
    name: str
    description: str
    severity: RuleSeverity
    penalty: int


class AnalyzeResponse(BaseModel):
    url: str
    risk_score: int
    classification: RiskClassification
    summary: str
    http_analysis: HttpAnalysis
    triggered_rules: List[TriggeredRule] = Field(default_factory=list)
    safe_indicators: List[str] = Field(default_factory=list)
    analyzed_at: str
    engine_version: str = "1.0.0-phase1"


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    host_restriction: str
