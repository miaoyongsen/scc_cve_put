"""Single-process scheduled RSS polling with live-configurable interval."""
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

log=logging.getLogger(__name__)
_stop=threading.Event()
_changed=threading.Event()
_thread=None
_archive_thread=None
last_run=None
last_result=None
_state_lock=threading.Lock()
_state={kind:{"running":False,"last_started":None,"last_finished":None,"next_run":None,"last_error":None} for kind in ("vulnerability","article")}

def _iso():
    return datetime.now(timezone.utc).isoformat()

def _set_state(kind,**values):
    with _state_lock:_state[kind].update(values)

def scheduler_status():
    from .collection_config import interval_minutes,article_interval_minutes
    with _state_lock:
        state={k:dict(v) for k,v in _state.items()}
    return {"enabled":os.getenv("AUTO_COLLECT","false").lower()=="true",
            "thread_alive":bool(_thread and _thread.is_alive()),
            "server_time":_iso(),
            "interval_minutes":{"vulnerability":interval_minutes(),"article":article_interval_minutes()},
            "tasks":state}


def wakeup():
    """Apply new interval without restarting the server."""
    _changed.set()

def loop():
    global last_run,last_result
    from .collection_config import interval_minutes, article_interval_minutes
    from .collector import collect_configured_sources
    intervals={"vulnerability":interval_minutes,"article":article_interval_minutes}
    next_runs={kind:time.monotonic()+getter()*60 for kind,getter in intervals.items()}
    for kind,getter in intervals.items():
        _set_state(kind,next_run=(datetime.now(timezone.utc)+timedelta(minutes=getter())).isoformat())
    while not _stop.is_set():
        now=time.monotonic()
        remaining=max(0,min(next_runs.values())-now)
        if _changed.wait(timeout=min(remaining,1)):
            _changed.clear()
            next_runs={kind:time.monotonic()+getter()*60 for kind,getter in intervals.items()}
            for kind,getter in intervals.items():_set_state(kind,next_run=(datetime.now(timezone.utc)+timedelta(minutes=getter())).isoformat())
            continue
        if _stop.is_set():break
        for kind,getter in intervals.items():
            if time.monotonic()<next_runs[kind]:continue
            _set_state(kind,running=True,last_started=_iso(),last_error=None)
            try:
                last_result=collect_configured_sources(mode=kind)
                last_run=datetime.now(timezone.utc).isoformat()
                log.info("%s collection completed: %s",kind,last_result)
            except Exception as exc:
                _set_state(kind,last_error=str(exc)[:500])
                log.exception("%s collection failed",kind)
                try:
                    from .error_alert import send_error_alert
                    send_error_alert(kind+" 定时采集",str(exc))
                except Exception:
                    log.exception("Failed to notify scheduled collection error")
            finally:
                next_runs[kind]=time.monotonic()+getter()*60
                _set_state(kind,running=False,last_finished=_iso(),next_run=(datetime.now(timezone.utc)+timedelta(minutes=getter())).isoformat())


def archive_loop():
    """Daily retention check; independent of AUTO_COLLECT."""
    from .db_archive import archive_logs
    while not _stop.is_set():
        # Run at next local 03:00; avoid maintenance on each app startup.
        from datetime import timedelta
        now=datetime.now().astimezone()
        target=now.replace(hour=3,minute=0,second=0,microsecond=0)
        if target<=now:target+=timedelta(days=1)
        if _stop.wait((target-now).total_seconds()):break
        try:
            result=archive_logs()
            log.info("SQLite archive result: %s",result)
        except Exception:
            log.exception("Scheduled SQLite archive failed")

@asynccontextmanager
async def lifespan(app):
    global _thread,_archive_thread
    _stop.clear()
    _archive_thread=threading.Thread(target=archive_loop,name="sqlite-log-archiver",daemon=True)
    _archive_thread.start()
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
        if _archive_thread:_archive_thread.join(timeout=5)
