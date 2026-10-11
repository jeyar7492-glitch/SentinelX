#!/usr/bin/env bash
# SentinelX - Ubuntu User Systemd Service Uninstaller
set -euo pipefail

SERVICE_NAME="sentinelx.service"
USER_SYSTEMD_DIR="${HOME}/.config/systemd/user"

echo "=========================================================="
echo "  SentinelX - Removing Ubuntu User Systemd Service"
echo "=========================================================="

if systemctl --user is-active --quiet "${SERVICE_NAME}"; then
  echo "[1/3] Stopping ${SERVICE_NAME}..."
  systemctl --user stop "${SERVICE_NAME}"
fi

echo "[2/3] Disabling ${SERVICE_NAME}..."
systemctl --user disable "${SERVICE_NAME}" 2>/dev/null || true

if [ -f "${USER_SYSTEMD_DIR}/${SERVICE_NAME}" ]; then
  rm -f "${USER_SYSTEMD_DIR}/${SERVICE_NAME}"
fi

echo "[3/3] Reloading user daemon..."
systemctl --user daemon-reload

echo ">>> SentinelX service successfully removed. <<<"
