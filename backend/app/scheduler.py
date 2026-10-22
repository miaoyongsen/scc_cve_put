"""Single-process scheduled RSS polling with live-configurable interval."""
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

log=logging.getLogger(__name__)
_stop=threading.Event()
_changed=threading.Event()
_thread=None
last_run=None
last_result=None

def wakeup():
    """Apply new interval without restarting the server."""
    _changed.set()

def loop():
    global last_run,last_result
    from .collection_config import interval_minutes
    from .collector import collect_configured_sources
    next_run=time.monotonic()+interval_minutes()*60
    while not _stop.is_set():
        remaining=max(0,next_run-time.monotonic())
        if _changed.wait(timeout=min(remaining,1)):
            _changed.clear()
            next_run=time.monotonic()+interval_minutes()*60
            continue
        if _stop.is_set():break
        if time.monotonic()<next_run:continue
        try:
            last_result=collect_configured_sources()
            last_run=datetime.now(timezone.utc).isoformat()
            log.info("RSS collection completed: %s",last_result)
        except Exception:
            log.exception("RSS collection failed")
        next_run=time.monotonic()+interval_minutes()*60

@asynccontextmanager
async def lifespan(app):
    global _thread
    if os.getenv("AUTO_COLLECT","false").lower()=="true":
        _stop.clear()
        _changed.clear()
        _thread=threading.Thread(target=loop,name="cve-rss-collector",daemon=True)
        _thread.start()
    try:
        yield
    finally:
        _stop.set()
        _changed.set()
        if _thread:_thread.join(timeout=5)
