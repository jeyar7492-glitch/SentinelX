#!/usr/bin/env python3
"""
SentinelX Local Server Runner
Starts Uvicorn explicitly bound to 127.0.0.1:8000.
"""

import os
import sys

# Ensure project root is in Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import uvicorn

if __name__ == "__main__":
    print("=" * 65)
    print("  SentinelX Phase 1 - Local Cybersecurity Security Backend")
    print("  Host: 127.0.0.1 (Strict Localhost Loopback)")
    print("  Port: 8000")
    print("  Zero External Calls | Zero Data Collection | Local Heuristics")
    print("=" * 65)
    uvicorn.run(
        "backend.app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info",
    )
