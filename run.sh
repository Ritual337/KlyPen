#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -x ".venv/bin/python" ]]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/python -m pip install -r requirements.txt
fi
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example; review it before adding optional keys."
fi
echo "KlyPen will be available at http://127.0.0.1:8000"
echo "Press Ctrl+C to stop."
exec .venv/bin/python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
