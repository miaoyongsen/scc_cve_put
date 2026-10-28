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
    from .collection_config import interval_minutes, article_interval_minutes
    from .collector import collect_configured_sources
    intervals={"vulnerability":interval_minutes,"article":article_interval_minutes}
    next_runs={kind:time.monotonic()+getter()*60 for kind,getter in intervals.items()}
    while not _stop.is_set():
        now=time.monotonic()
        remaining=max(0,min(next_runs.values())-now)
        if _changed.wait(timeout=min(remaining,1)):
            _changed.clear()
            next_runs={kind:time.monotonic()+getter()*60 for kind,getter in intervals.items()}
            continue
        if _stop.is_set():break
        for kind,getter in intervals.items():
            if time.monotonic()<next_runs[kind]:continue
            try:
                last_result=collect_configured_sources(mode=kind)
                last_run=datetime.now(timezone.utc).isoformat()
                log.info("%s collection completed: %s",kind,last_result)
            except Exception:
                log.exception("%s collection failed",kind)
            finally:
                next_runs[kind]=time.monotonic()+getter()*60

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
