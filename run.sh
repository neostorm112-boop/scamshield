#!/usr/bin/env bash
# One-command launcher: venv + dependencies + Chromium for snapshots + app on 127.0.0.1:${PORT:-8000}.
# Reads ./.env only if it exists (never printed). The database is created in data/ on first start.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  PY=""
  for c in python3.12 /opt/homebrew/bin/python3.12 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info[:2] < (3, 12))' 2>/dev/null; then PY="$c"; break; fi
  done
  if [ -z "$PY" ]; then
    echo "Python 3.12 or newer is required and was not found." >&2
    echo "  macOS:          brew install python@3.12" >&2
    echo "  Ubuntu/Debian:  sudo apt install python3.12 python3.12-venv  (Ubuntu 22.04: add ppa:deadsnakes/ppa first)" >&2
    exit 1
  fi
  echo "First start: creating .venv and installing dependencies and Chromium (1-3 minutes, mostly silent)..." >&2
  "$PY" -m venv .venv || { echo "Could not create .venv. On Ubuntu/Debian install python3.12-venv." >&2; exit 1; }
fi
FIND=""
[ -d wheelhouse ] && FIND="--find-links wheelhouse/"
# shellcheck disable=SC2086
# offline restart must not fail when the venv already has the app (live watchdog restarts)
.venv/bin/pip install -q $FIND -r requirements.txt || { [ -x .venv/bin/uvicorn ] && echo "pip install failed, using the existing .venv" >&2; }
# Chromium for page snapshots; a no-op when already cached, non-fatal when offline (snapshots then show "Not checked")
.venv/bin/python -m playwright install chromium >/dev/null 2>&1 || echo "warning: Chromium install failed; page snapshots will be unavailable" >&2
if [ "$(uname -s)" = Linux ] && [ ! -f .venv/.chromium-deps-hint ]; then
  echo "Linux: if page snapshots show 'Not checked', install Chromium's system libraries once:" >&2
  echo "  sudo .venv/bin/python -m playwright install-deps chromium" >&2
  touch .venv/.chromium-deps-hint
fi
if [ -f .env ]; then set -a; . ./.env; set +a; fi
export SCAMSHIELD_DATA_DIR="${SCAMSHIELD_DATA_DIR:-data}"
mkdir -p "$SCAMSHIELD_DATA_DIR"
echo "ScamShield: open http://127.0.0.1:${PORT:-8000}  (Ctrl+C to stop)" >&2
exec .venv/bin/uvicorn scamshield.app:app --host 127.0.0.1 --port "${PORT:-8000}"
