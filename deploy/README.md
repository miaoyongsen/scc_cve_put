# Linux deployment notes (not production-ready)

Target: Debian/Ubuntu, Python 3.11+, Node.js 20+, Nginx, SQLite. No MySQL or Docker.

The repository currently lacks the WatchVuln provider adapters and a completed login flow; this guide is for staging the API and UI, **not** for deploying an operational vulnerability notifier.

1. Create an unprivileged user `scccve` and application directory `/opt/scc-cve`.
2. Create `/var/lib/scc-cve` owned by `scccve`; use `DATABASE_URL=sqlite:////var/lib/scc-cve/cve.db`.
3. Install Python dependencies in `backend/.venv` and build frontend with `npm ci` (after lockfile generation) or `npm install && npm run build`.
4. Store `API_TOKEN` and other secrets in `/etc/scc-cve/scc-cve.env`, mode 0600, readable by the service user. Never commit it.
5. Copy `scc-cve.service` to `/etc/systemd/system/`; enable/start with systemctl.
6. Configure Nginx using `nginx.conf` as a starting point. Add HTTPS and a proper authentication scheme before exposing to the internet.

SQLite online backups: `sqlite3 /var/lib/scc-cve/cve.db ".backup '/var/lib/scc-cve/backup.db'"`.

**Caution:** The current frontend uses a temporary browser-stored API token. Do not expose this staging build publicly. A proper login and session implementation is still required.
