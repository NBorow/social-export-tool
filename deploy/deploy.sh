#!/usr/bin/env bash
# Deploy a checkout into the live app folder, then gracefully restart the
# background job if it's running (it finishes the current post, then resumes).
# Usage: deploy/deploy.sh <checkout_dir> [app_dir]
# config.txt, presets.json, cookies, the DB and the run state are untracked,
# so they are never touched.
set -euo pipefail

SRC="$(cd "${1:?usage: deploy.sh <checkout_dir> [app_dir]}" && pwd)"
APP_DIR="${2:-$HOME/NCinstagramdl}"
SERVICE=ig-export
PY="$APP_DIR/venv/bin/python"

cd "$SRC"
REV="$(git rev-parse --short HEAD)"
echo "Deploying $REV to $APP_DIR"

# 1. Refuse code that doesn't even compile; the live copy stays as it was
"$PY" -m py_compile social_export_tool.py db.py

# 2. First deploy over a hand-copied install: back up what's about to be replaced
if [ ! -f "$APP_DIR/.deployed_rev" ]; then
  BACKUP="$APP_DIR/predeploy-backup-$(date +%Y%m%d-%H%M%S)"
  git ls-files | while IFS= read -r f; do
    if [ -f "$APP_DIR/$f" ]; then
      mkdir -p "$BACKUP/$(dirname "$f")"
      cp -p "$APP_DIR/$f" "$BACKUP/$f"
    fi
  done
  echo "First deploy: previous files backed up to $BACKUP"
fi

# 3. Copy tracked files only
git archive HEAD | tar -x -C "$APP_DIR"

# 4. Dependencies; downloaders always go to latest since Instagram breaks them often
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
"$APP_DIR/venv/bin/pip" install -q -U yt-dlp gallery-dl

echo "$REV $(date -Iseconds)" > "$APP_DIR/.deployed_rev"

# 5. Graceful restart, only if the job is running (don't revive a stopped one)
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
  echo "Restarting $SERVICE (current post finishes first)..."
  sudo -n "$(command -v systemctl)" restart "$SERVICE"
else
  echo "$SERVICE not running; nothing to restart."
fi
echo "Deployed $REV"
