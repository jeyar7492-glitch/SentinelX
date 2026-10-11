#!/usr/bin/env bash
# SentinelX - System Status & Diagnostics Suite
# Checks systemd service status, port binding, API health, venv, and extension build artifacts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVICE_NAME="sentinelx.service"

echo "=========================================================="
echo "  SentinelX - Diagnostics & Health Verification"
echo "  Target: 127.0.0.1:8000 | Host: Ubuntu Linux"
echo "=========================================================="

FAILED=0

# 1. Check Python virtual environment
echo -n "[1/5] Checking Python Virtual Environment (.venv)... "
if [ -x "${PROJECT_ROOT}/.venv/bin/python" ]; then
  PYTHON_VER="$("${PROJECT_ROOT}/.venv/bin/python" --version 2>&1)"
  echo "OK (${PYTHON_VER})"
else
  echo "FAIL: .venv/bin/python not found or not executable"
  FAILED=$((FAILED + 1))
fi

# 2. Check Ubuntu systemd user service status
echo -n "[2/5] Checking Ubuntu Systemd User Service (${SERVICE_NAME})... "
if systemctl --user is-active --quiet "${SERVICE_NAME}"; then
  SVC_STATUS="$(systemctl --user is-active "${SERVICE_NAME}")"
  SVC_ENABLED="$(systemctl --user is-enabled "${SERVICE_NAME}" 2>/dev/null || echo "unknown")"
  echo "OK (${SVC_STATUS}, autostart: ${SVC_ENABLED})"
else
  echo "WARN: Service not active"
  if [ -f "${HOME}/.config/systemd/user/${SERVICE_NAME}" ]; then
    echo "       Service is installed but not currently running."
  else
    echo "       Service is not installed yet. Run: ./scripts/install_service.sh"
  fi
  FAILED=$((FAILED + 1))
fi

# 3. Check socket binding (127.0.0.1:8000)
echo -n "[3/5] Checking Loopback Socket Binding (127.0.0.1:8000)... "
if ss -tlpn | grep -q ":8000"; then
  echo "OK (Port 8000 listening on loopback)"
else
  echo "FAIL: Nothing listening on port 8000"
  FAILED=$((FAILED + 1))
fi

# 4. Check FastAPI Health Endpoint
echo -n "[4/5] Checking Local API Endpoint (GET http://127.0.0.1:8000/health)... "
HEALTH_RESPONSE="$(curl -s --connect-timeout 2 http://127.0.0.1:8000/health || echo "")"
if [ -n "${HEALTH_RESPONSE}" ] && echo "${HEALTH_RESPONSE}" | grep -q '"status":"healthy"'; then
  VERSION="$(echo "${HEALTH_RESPONSE}" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)"
  echo "OK (Health: healthy, Core Version: ${VERSION})"
else
  echo "FAIL: Unable to retrieve healthy status from backend API"
  FAILED=$((FAILED + 1))
fi

# 5. Check Chrome Extension Build Status
echo -n "[5/5] Checking Extension Compilation (extension/dist)... "
if [ -f "${PROJECT_ROOT}/extension/dist/background.js" ] && [ -f "${PROJECT_ROOT}/extension/dist/popup.js" ]; then
  echo "OK (TypeScript compiled artifacts present)"
else
  echo "FAIL: extension/dist/ artifacts missing. Run 'cd extension && npm run build'"
  FAILED=$((FAILED + 1))
fi

echo "=========================================================="
if [ ${FAILED} -eq 0 ]; then
  echo ">>> ALL DIAGNOSTIC CHECKS PASSED: SentinelX is healthy and operational! <<<"
  exit 0
else
  echo ">>> ${FAILED} DIAGNOSTIC CHECK(S) FAILED OR WARNED. Review output above. <<<"
  exit 1
fi
