# Python backend (migration in progress)

Run: `pip install -r requirements.txt && API_TOKEN=<strong-secret> uvicorn app.core:app --reload`

Implemented: SQLAlchemy vulnerability model, paginated listing and detail API, bearer-token protection. API paths mirror the original Go service.

**Not yet implemented:** WatchVuln source adapters, value filter, scheduled crawling, CVE deduplication, bot/email notifications, AI analysis, login and original Vue frontend. The refresh API intentionally returns HTTP 503. Do not treat this as a complete migration or enable it in production.

The original Go source is used as the reference only; it has not been modified.
