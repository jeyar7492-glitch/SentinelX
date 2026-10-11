"""
SentinelX Local API Server
Zero-cost, local-only cybersecurity MVP backend restricted to 127.0.0.1 (localhost).
Enforces loopback-only client verification, origin protection against unauthorized websites,
and structured risk policy responses.
"""

import re
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .analyzer import DEFAULT_POLICY, analyze_url
from .models import AnalyzeRequest, AnalyzeResponse, HealthResponse, RiskPolicyConfig

app = FastAPI(
    title="SentinelX Security Core",
    description="Local-only heuristic URL security and phishing detection engine.",
    version="2.0.0-realtime",
    docs_url="/docs",
    redoc_url=None,
)

# Strict CORS: only permit Chrome Extensions and local loopback origins
ALLOWED_ORIGIN_REGEX = re.compile(r"^(chrome-extension://[a-z0-9]+|http://(127\.0\.0\.1|localhost)(:\d+)?)$")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension://.*|http://(127\.0\.0\.1|localhost)(:\d+)?)$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def enforce_security_boundary(request: Request, call_next):
    """
    Defense-in-depth security boundary:
    1. Reject any non-loopback clients (must be 127.0.0.1 / localhost).
    2. Protect against unauthorized external web pages attempting to query the local API via CSRF / browser fetch.
    """
    client_host = request.client.host if request.client else None
    allowed_hosts = {"127.0.0.1", "::1", "localhost", "testclient"}
    if client_host and client_host not in allowed_hosts:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "detail": "Access forbidden: SentinelX is strictly restricted to local loopback interface (localhost)."
            },
        )

    # Origin validation: If browser Origin header is present, it must be extension or loopback
    origin = request.headers.get("origin")
    if origin and not ALLOWED_ORIGIN_REGEX.match(origin):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "detail": "Access forbidden: Web page origin is not authorized to query SentinelX local security core."
            },
        )

    return await call_next(request)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health and security status check",
)
async def health_check() -> HealthResponse:
    """Verify backend responsiveness, localhost enforcement, and active risk policy."""
    return HealthResponse(
        status="healthy",
        service="SentinelX Core Security Engine",
        version="2.0.0-realtime",
        host_restriction="127.0.0.1 (loopback only)",
        risk_policy=DEFAULT_POLICY,
    )


@app.get(
    "/api/policy",
    response_model=RiskPolicyConfig,
    tags=["System"],
    summary="Retrieve central documented risk thresholds",
)
async def get_risk_policy() -> RiskPolicyConfig:
    """Return central documented risk policy thresholds."""
    return DEFAULT_POLICY


@app.post(
    "/api/analyze",
    response_model=AnalyzeResponse,
    tags=["Security Analysis"],
    summary="Analyze URL for suspicious patterns and phishing indicators",
)
async def analyze_url_endpoint(payload: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze a URL using SentinelX transparent heuristic rules.
    - Passive analysis only (does not fetch or execute the destination).
    - Zero data collection: URLs are not logged, stored, or sent to external servers.
    """
    try:
        result = analyze_url(payload.url)
        return result
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(exc)}",
        )
