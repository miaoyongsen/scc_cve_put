# Simple Linux deployment (single port)

From the repository root:

```bash
git pull
bash install.sh
bash start.sh
```

Open `http://SERVER_IP:8000/login`. Use the `API_TOKEN` in `backend/.env` to sign in. The Vue production build is served by FastAPI on the same port; port 5173 and Nginx are not needed.

Existing `backend/.env` and SQLite databases are preserved by `install.sh`. Python dependencies and the Vue bundle are rebuilt. `AUTO_COLLECT=true` enables hourly polling, starting one hour after process startup. Keep a single application process (`--workers 1`) to avoid duplicate collectors.

For localhost-only testing: `HOST=127.0.0.1 bash start.sh`, then use SSH port forwarding. **The current token-in-browser login is a test-only implementation. Do not expose this app directly to the public internet without TLS and proper access control.** The crawler adapter and original nine WatchVuln collectors are not implemented yet. RSS support has not been end-to-end verified.

If `bash install.sh` fails, check `node --version` (Node 20+) and `python3 --version`. If you change the frontend, rerun `bash install.sh` to rebuild it.
