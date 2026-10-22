#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
command -v python3 >/dev/null || { echo "Please install Python 3.9+"; exit 1; }
command -v npm >/dev/null || { echo "Please install Node.js 20+ and npm"; exit 1; }
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
(cd frontend && npm install && npm run build)
if [ ! -f backend/.env ]; then
  token="$(backend/.venv/bin/python -c 'import secrets;print(secrets.token_hex(32))')"
  printf 'DATABASE_URL=sqlite:///./cve.db\nAPI_TOKEN=%s\nAUTO_COLLECT=true\nWECHAT_WEBHOOK_URL=\n' "$token" > backend/.env
  chmod 600 backend/.env
  echo "Created backend/.env with a new API token. Keep it private."
else
  echo "Existing backend/.env preserved."
fi
echo "Installation complete. Run ./start.sh"
