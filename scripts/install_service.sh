#!/usr/bin/env bash
# SentinelX - Ubuntu Automatic User Startup Installer
# Configures systemd --user service so SentinelX starts automatically at login/boot.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVICE_NAME="sentinelx.service"
USER_SYSTEMD_DIR="${HOME}/.config/systemd/user"

echo "=========================================================="
echo "  SentinelX - Installing Ubuntu User Systemd Service"
echo "  Project Root: ${PROJECT_ROOT}"
echo "=========================================================="

# Ensure user systemd directory exists
mkdir -p "${USER_SYSTEMD_DIR}"

# Install service file
cp "${PROJECT_ROOT}/systemd/${SERVICE_NAME}" "${USER_SYSTEMD_DIR}/${SERVICE_NAME}"

# Reload systemd user daemon
echo "[1/4] Reloading systemd user daemon..."
systemctl --user daemon-reload

# Enable service for autostart
echo "[2/4] Enabling ${SERVICE_NAME} for user session..."
systemctl --user enable "${SERVICE_NAME}"

# Start or restart service
echo "[3/4] Starting ${SERVICE_NAME}..."
systemctl --user restart "${SERVICE_NAME}"

# Verify active status
echo "[4/4] Verifying service responsiveness..."
sleep 1.5

if systemctl --user is-active --quiet "${SERVICE_NAME}"; then
  echo ">>> SUCCESS: SentinelX backend is running and enabled on user startup! <<<"
  echo "Status check:  systemctl --user status ${SERVICE_NAME}"
  echo "Service logs:  journalctl --user -u ${SERVICE_NAME} -f"
else
  echo ">>> ERROR: Service failed to start. Inspecting logs: <<<"
  journalctl --user -u "${SERVICE_NAME}" -n 20 --no-pager
  exit 1
fi
