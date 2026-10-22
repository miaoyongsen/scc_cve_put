#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT/backend"
if [ ! -f .env ]; then echo "Missing backend/.env. Run ./install.sh first."; exit 1; fi
if [ ! -f ../frontend/dist/index.html ]; then echo "Missing compiled UI. Run ./install.sh first."; exit 1; fi
if [ ! -x .venv/bin/uvicorn ]; then echo "Missing Python dependencies. Run ./install.sh first."; exit 1; fi
set -a
source .env
set +a
: "${API_TOKEN:?Set API_TOKEN in backend/.env}"
echo "SCC CVE: http://0.0.0.0:${PORT:-8000} (use your server IP in browser)"
exec .venv/bin/uvicorn app.core:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}" --workers 1
