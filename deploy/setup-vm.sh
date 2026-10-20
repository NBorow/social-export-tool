#!/usr/bin/env bash
# One-time VM setup: installs the ig-export systemd service and lets the deploy
# runner (running as the same user) restart it without a password.
# Usage: sudo ./deploy/setup-vm.sh [app_dir] [user]
set -euo pipefail

APP_DIR="${1:-/home/nick/NCinstagramdl}"
RUN_USER="${2:-${SUDO_USER:-nick}}"
SERVICE=ig-export
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo." >&2
  exit 1
fi
if [ ! -x "$APP_DIR/venv/bin/python" ]; then
  echo "No venv at $APP_DIR/venv. Create it first." >&2
  exit 1
fi

sed -e "s#@APP_DIR@#$APP_DIR#g" -e "s#@USER@#$RUN_USER#g" \
  "$HERE/ig-export.service" > "/etc/systemd/system/$SERVICE.service"

SYSTEMCTL="$(command -v systemctl)"
SUDOERS_TMP="$(mktemp)"
echo "$RUN_USER ALL=(root) NOPASSWD: $SYSTEMCTL restart $SERVICE" > "$SUDOERS_TMP"
visudo -cf "$SUDOERS_TMP"
install -m 0440 "$SUDOERS_TMP" "/etc/sudoers.d/$SERVICE"
rm -f "$SUDOERS_TMP"

systemctl daemon-reload
systemctl enable "$SERVICE"
echo "Installed $SERVICE for $RUN_USER in $APP_DIR (enabled; resumes any unfinished job at boot)."
