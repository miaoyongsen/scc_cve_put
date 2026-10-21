#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -d .venv ]; then python3 -m venv .venv; fi
. .venv/bin/activate
pip install -r requirements.txt
: "${API_TOKEN:?Set API_TOKEN to a long random secret}"
exec uvicorn app.core:app --host 127.0.0.1 --port "${PORT:-8000}"
