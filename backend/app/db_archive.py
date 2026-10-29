"""Conservative SQLite log archiving: never touches intelligence, dedup or settings."""
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote
from sqlalchemy import text
from .core import engine

log=logging.getLogger(__name__)
_lock=threading.Lock()
RETENTION_DAYS=90
BATCH_SIZE=500

def _db_path():
    if engine.dialect.name!="sqlite":
        raise RuntimeError("归档仅支持 SQLite")
    name=engine.url.database
    if not name or name==":memory:":
        raise RuntimeError("内存数据库不支持归档")
    return Path(unquote(name)).resolve()

def _archive_dir():
    return _db_path().parent/"archive"

def stats():
    path=_db_path()
    with engine.connect() as conn:
        runs=conn.execute(text("SELECT COUNT(*) FROM collection_runs")).scalar()
        records=conn.execute(text("SELECT COUNT(*) FROM run_records")).scalar()
        vulns=conn.execute(text("SELECT COUNT(*) FROM vulnerabilities")).scalar()
    folder=_archive_dir()
    archives=sorted(folder.glob("logs_????-??.sqlite3")) if folder.exists() else []
    return {"database_bytes":path.stat().st_size if path.exists() else 0,
            "archive_bytes":sum(x.stat().st_size for x in archives),
            "archive_files":len(archives),"vulnerabilities":vulns,
            "collection_runs":runs,"run_records":records,
            "retention_days":RETENTION_DAYS,"archive_dir":str(folder)}

def archive_logs():
    """Copy old finished runs and their records, then remove from live DB atomically.

    Archive files are SQLite databases with original IDs, so retries are idempotent.
    No vulnerability, crawler finding, AI analysis or review row is ever removed.
    """
    if not _lock.acquire(blocking=False):
        return {"status":"busy"}
    try:
        cutoff=(datetime.now(timezone.utc)-timedelta(days=RETENTION_DAYS)).replace(tzinfo=None).isoformat(sep=" ")
        folder=_archive_dir()
        folder.mkdir(parents=True,exist_ok=True)
        total_runs=total_records=0
        # A run and all of its records are copied together. Orphan records are
        # intentionally kept rather than risk removing potentially useful history.
        while True:
            with engine.begin() as conn:
                runs=conn.execute(text("""SELECT id,started_at,ended_at,mode,status,summary
                    FROM collection_runs WHERE ended_at IS NOT NULL
                    AND started_at < :cutoff AND status != 'running'
                    ORDER BY id LIMIT :limit"""),{"cutoff":cutoff,"limit":BATCH_SIZE}).mappings().all()
                if not runs:break
                ids=[x["id"] for x in runs]
                # Group by UTC start month; do not assume all rows share a month.
                groups={}
                for row in runs:
                    month=str(row["started_at"])[:7]
                    if len(month)!=7 or month[4]!="-":
                        raise ValueError("Invalid collection run date: "+str(row["started_at"]))
                    groups.setdefault(month,[]).append(row)
                for month,group in groups.items():
                    archive=folder/("logs_"+month+".sqlite3")
                    with sqlite3.connect(str(archive),timeout=30) as target:
                        target.execute("""CREATE TABLE IF NOT EXISTS collection_runs
                            (id INTEGER PRIMARY KEY,started_at TEXT,ended_at TEXT,
                             mode TEXT,status TEXT,summary TEXT)""")
                        target.execute("""CREATE TABLE IF NOT EXISTS run_records
                            (id INTEGER PRIMARY KEY,created_at TEXT,source TEXT,title TEXT,
                             cve TEXT,tier TEXT,status TEXT,detail TEXT,url TEXT,run_id INTEGER)""")
                        run_ids=[row["id"] for row in group]
                        records=[]
                        for rid in run_ids:
                            records.extend(conn.execute(text("""SELECT id,created_at,source,title,cve,tier,
                                status,detail,url,run_id FROM run_records WHERE run_id=:id"""),
                                {"id":rid}).mappings().all())
                        target.executemany("INSERT OR REPLACE INTO collection_runs VALUES (?,?,?,?,?,?)",
                            [tuple(row[k] for k in ("id","started_at","ended_at","mode","status","summary")) for row in group])
                        target.executemany("INSERT OR REPLACE INTO run_records VALUES (?,?,?,?,?,?,?,?,?,?)",
                            [tuple(row[k] for k in ("id","created_at","source","title","cve","tier","status","detail","url","run_id")) for row in records])
                        # Commit archive first. If deletion fails, retry safely re-copies IDs.
                        target.commit()
                        copied_runs=target.execute("SELECT COUNT(*) FROM collection_runs WHERE id IN ("+",".join("?" for _ in run_ids)+")",run_ids).fetchone()[0]
                        if copied_runs!=len(run_ids):
                            raise RuntimeError("Archive verification failed: missing collection runs")
                        if records:
                            record_ids=[record["id"] for record in records]
                            copied_records=target.execute("SELECT COUNT(*) FROM run_records WHERE id IN ("+",".join("?" for _ in record_ids)+")",record_ids).fetchone()[0]
                            if copied_records!=len(record_ids):
                                raise RuntimeError("Archive verification failed: missing run records")
                        for rid in run_ids:
                            conn.execute(text("DELETE FROM run_records WHERE run_id=:id"),{"id":rid})
                            conn.execute(text("DELETE FROM collection_runs WHERE id=:id"),{"id":rid})
                        total_records+=len(records)
                        total_runs+=len(group)
        return {"status":"ok","archived_runs":total_runs,"archived_records":total_records,**stats()}
    except Exception as exc:
        log.exception("SQLite log archive failed")
        try:
            from .error_alert import send_error_alert
            send_error_alert("SQLite 日志自动归档",str(exc))
        except Exception:
            log.exception("Archive failure alert failed")
        raise
    finally:
        _lock.release()
