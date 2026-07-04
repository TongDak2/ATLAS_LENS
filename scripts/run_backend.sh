#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "error: Python interpreter not found: $PYTHON_BIN" >&2
  echo "Set PYTHON_BIN to a Python 3.12+ binary, e.g. PYTHON_BIN=/opt/homebrew/bin/python3" >&2
  exit 127
fi
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit(f"error: Python 3.12+ is required, got {sys.version.split()[0]}")
PY
if [ ! -d .venv ]; then
  "$PYTHON_BIN" -m venv .venv
fi
source .venv/bin/activate
pip install -q -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8787
