#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -x .venv/bin/ruff ] || [ ! -x .venv/bin/pytest ]; then
  [ -d .venv ] || "$(command -v python3.12 || echo /opt/homebrew/bin/python3.12)" -m venv .venv
  .venv/bin/pip install -q -r requirements-dev.txt
fi
.venv/bin/ruff check .
.venv/bin/pytest -q
