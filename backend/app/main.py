"""
SentinelX Local API Server
Zero-cost, local-only cybersecurity MVP backend restricted to 127.0.0.1 (localhost).
"""

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .analyzer import analyze_url
from .models import AnalyzeRequest, AnalyzeResponse, HealthResponse

app = FastAPI(
    title="SentinelX Security Core",
    description="Local-only heuristic URL security and phishing detection engine.",
    version="1.0.0-phase1",
    docs_url="/docs",
    redoc_url=None,
)

# Strict CORS: only permit Chrome Extensions and local browser dev requests
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension://.*|http://(127\.0\.0\.1|localhost)(:\d+)?)$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def enforce_localhost_only(request: Request, call_next):
    """
    Defense-in-depth: Reject any non-loopback clients.
    Even if the socket is bound to 127.0.0.1, explicitly verify client host.
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
    return await call_next(request)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health and security status check",
)
async def health_check() -> HealthResponse:
    """Verify backend responsiveness and localhost enforcement."""
    return HealthResponse(
        status="healthy",
        service="SentinelX Core Security Engine",
        version="1.0.0-phase1",
        host_restriction="127.0.0.1 (loopback only)",
    )


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
