"""Single-process hourly polling loop. Run only one worker instance."""
import logging
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from .collector import collect_configured_sources

log=logging.getLogger(__name__)
_stop=threading.Event()
_thread=None
last_run=None
last_result=None

def loop():
    global last_run,last_result
    # Start after one hour; operators can use '立即采集' for the initial run.
    while not _stop.wait(3600):
        try:
            last_result=collect_configured_sources()
            last_run=datetime.now(timezone.utc).isoformat()
            log.info("Hourly source collection completed: %s",last_result)
        except Exception:
            log.exception("Hourly collection failed")

@asynccontextmanager
async def lifespan(app):
    global _thread
    if os.getenv("AUTO_COLLECT","false").lower()=="true":
        _stop.clear()
        _thread=threading.Thread(target=loop,name="cve-hourly-collector",daemon=True)
        _thread.start()
    try:
        yield
    finally:
        _stop.set()
        if _thread: _thread.join(timeout=5)
