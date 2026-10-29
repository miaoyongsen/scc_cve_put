"""Python CVE API and persistence. Provider adapters are intentionally pending parity verification."""
import os
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Text, Boolean, DateTime, Integer, select, func, or_, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cve.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})

def _disclosure_timestamp(value):
    """Normalize RSS RFC2822 dates and ISO8601 dates for reliable sorting."""
    if not value:
        return None
    value = str(value).strip()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (ValueError, TypeError, IndexError, OverflowError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


if engine.dialect.name == "sqlite":
    @event.listens_for(engine, "connect")
    def _register_disclosure_timestamp(dbapi_connection, connection_record):
        dbapi_connection.create_function("disclosure_timestamp", 1, _disclosure_timestamp, deterministic=True)

class Base(DeclarativeBase): pass
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(300), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="")
    cve: Mapped[str] = mapped_column(String(40), default="", index=True)
    disclosure: Mapped[str] = mapped_column(String(20), default="")
    solutions: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="[]")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    github_search: Mapped[str] = mapped_column(Text, default="[]")
    source: Mapped[str] = mapped_column("from", String(100), default="")
    reason: Mapped[str] = mapped_column(Text, default="[]")
    pushed: Mapped[bool] = mapped_column(Boolean, default=False)
    content_type: Mapped[str] = mapped_column(String(30), default="vulnerability", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class RunRecord(Base):
    __tablename__="run_records"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    source: Mapped[str]=mapped_column(String(120),default="")
    title: Mapped[str]=mapped_column(String(500),default="")
    cve: Mapped[str]=mapped_column(String(50),default="")
    tier: Mapped[str]=mapped_column(String(30),default="")
    status: Mapped[str]=mapped_column(String(30),default="")
    detail: Mapped[str]=mapped_column(Text,default="")
    url: Mapped[str]=mapped_column(Text,default="")
    run_id: Mapped[int]=mapped_column(Integer,nullable=True,index=True)

class CollectionRun(Base):
    __tablename__="collection_runs"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    started_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    ended_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=True)
    mode: Mapped[str]=mapped_column(String(30),default="")
    status: Mapped[str]=mapped_column(String(30),default="running")
    summary: Mapped[str]=mapped_column(Text,default="{}")

from contextvars import ContextVar
_active_run=ContextVar("collection_run_id",default=None)

def begin_run(mode):
    with Session(engine) as db:
        row=CollectionRun(mode=mode)
        db.add(row);db.commit();db.refresh(row)
        return row.id

def finish_run(run_id,status,summary):
    import json
    with Session(engine) as db:
        row=db.get(CollectionRun,run_id)
        if row:
            row.ended_at=datetime.now(timezone.utc)
            row.status=status
            row.summary=json.dumps(summary,ensure_ascii=False,default=str)
            db.commit()
    if status in ("失败","部分失败"):
        try:
            from .error_alert import alert_run_errors
            alert_run_errors(row.mode if row else "采集任务",status,summary)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Error alert processing failed")

def log_run(item,tier,status,detail=""):
    import logging
    try:
        refs=item.get("references") or []
        url=item.get("url") or (refs[0] if isinstance(refs,list) and refs else "")
        with Session(engine) as db:
            db.add(RunRecord(source=str(item.get("from") or item.get("source") or "")[:120],
                title=str(item.get("title") or "")[:500],cve=str(item.get("cve") or "")[:50],
                tier=tier,status=status,detail=str(detail)[:2000],url=str(url)[:2000],run_id=_active_run.get()))
            db.commit()
    except Exception:
        logging.getLogger(__name__).exception("Failed to save run history")

Base.metadata.create_all(engine)
from sqlalchemy import inspect, text
if "run_id" not in {c["name"] for c in inspect(engine).get_columns("run_records")}:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE run_records ADD COLUMN run_id INTEGER"))
if "content_type" not in {c["name"] for c in inspect(engine).get_columns("vulnerabilities")}:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN content_type VARCHAR(30) NOT NULL DEFAULT 'vulnerability'"))
app = FastAPI(title="SCC CVE Push", version="0.1.0")

def auth(authorization: Optional[str] = Header(None)):
    expected = os.getenv("API_TOKEN")
    if not expected or authorization != "Bearer " + expected:
        raise HTTPException(401, "Unauthorized")

def serialize(v):
    import json
    return {**{k: getattr(v, k) for k in ("id","key","title","description","severity","cve","disclosure","solutions","pushed","content_type","first_seen","last_seen")}, "from":v.source, **{k:json.loads(getattr(v,k) or "[]") for k in ("references","tags","github_search","reason")}}




@app.get("/api/v1/database/stats",dependencies=[Depends(auth)])
def database_stats():
    from .db_archive import stats
    return {"code":0,"data":stats()}

@app.post("/api/v1/database/archive",dependencies=[Depends(auth)])
def database_archive():
    from .db_archive import archive_logs
    return {"code":0,"data":archive_logs()}

@app.get("/api/v1/collection-runs",dependencies=[Depends(auth)])
def collection_runs(page:int=1,size:int=20):
    import json
    page=max(1,page);size=min(100,max(1,size))
    with Session(engine) as db:
        total=db.scalar(select(func.count()).select_from(CollectionRun))
        runs=db.scalars(select(CollectionRun).order_by(CollectionRun.id.desc()).offset((page-1)*size).limit(size)).all()
        return {"code":0,"data":{"total":total,"page":page,"list":[{
            "id":r.id,"started_at":r.started_at,"ended_at":r.ended_at,
            "mode":r.mode,"status":r.status,"summary":json.loads(r.summary or "{}")
        } for r in runs]}}

@app.get("/api/v1/collection-runs/{run_id}",dependencies=[Depends(auth)])
def collection_run_detail(run_id:int):
    import json
    with Session(engine) as db:
        r=db.get(CollectionRun,run_id)
        if not r:raise HTTPException(404,"运行记录不存在")
        rows=db.scalars(select(RunRecord).where(RunRecord.run_id==run_id).order_by(RunRecord.id)).all()
        return {"code":0,"data":{"id":r.id,"started_at":r.started_at,"ended_at":r.ended_at,
            "mode":r.mode,"status":r.status,"summary":json.loads(r.summary or "{}"),
            "items":[{"id":x.id,"source":x.source,"title":x.title,"cve":x.cve,
                "tier":x.tier,"status":x.status,"detail":x.detail,"url":x.url} for x in rows]}}

@app.get("/api/v1/run-records", dependencies=[Depends(auth)])
def list_run_records(page:int=1,size:int=30,tier:str="",status:str="",q:str=""):
    page=max(page,1);size=min(max(size,1),100)
    with Session(engine) as db:
        stmt=select(RunRecord)
        if tier:stmt=stmt.where(RunRecord.tier==tier)
        if status:stmt=stmt.where(RunRecord.status==status)
        if q:stmt=stmt.where(or_(RunRecord.title.contains(q),RunRecord.cve.contains(q),RunRecord.source.contains(q)))
        total=db.scalar(select(func.count()).select_from(stmt.subquery()))
        rows=db.scalars(stmt.order_by(RunRecord.id.desc()).offset((page-1)*size).limit(size)).all()
        return {"code":0,"data":{"total":total,"page":page,"size":size,"list":[{
            "id":x.id,"created_at":x.created_at,"source":x.source,"title":x.title,
            "cve":x.cve,"tier":x.tier,"status":x.status,"detail":x.detail,"url":x.url} for x in rows]}}

@app.get("/api/v1/vulnerabilities", dependencies=[Depends(auth)])
def list_vulnerabilities(page:int=1,size:int=20,severity:str="",source:str="",q:str="",grouped:bool=False,sort_by:str="disclosure",sort_order:str="desc"):
    page=max(page,1);size=min(max(size,1),500)
    sortable={"disclosure":Vulnerability.disclosure,"first_seen":Vulnerability.first_seen,"last_seen":Vulnerability.last_seen,"severity":Vulnerability.severity,"title":Vulnerability.title,"cve":Vulnerability.cve,"source":Vulnerability.source}
    sort_column=sortable.get(sort_by,Vulnerability.disclosure)
    sort_order="asc" if sort_order=="asc" else "desc"
    # SQLite stores disclosure as text; date/time ISO strings can be sorted chronologically.
    if sort_by=="disclosure":
        sort_column=(func.disclosure_timestamp(Vulnerability.disclosure)
                     if engine.dialect.name=="sqlite" else Vulnerability.disclosure)
    ordering=(sort_column.asc() if sort_order=="asc" else sort_column.desc()).nullslast()
    with Session(engine) as db:
        stmt=select(Vulnerability)
        if severity: stmt=stmt.where(Vulnerability.severity==severity)
        if source: stmt=stmt.where(Vulnerability.source==source)
        if q:
            like=f"%{q}%"
            stmt=stmt.where(or_(Vulnerability.title.like(like),Vulnerability.cve.like(like),Vulnerability.key.like(like)))
        if grouped:
            # Group across the entire filtered result, not merely the current page.
            # The earliest first_seen record is the parent; CVE-less items stay separate.
            from sqlalchemy import case
            group_key=case((Vulnerability.cve!="",func.upper(Vulnerability.cve)),else_=func.concat("ID-",Vulnerability.id)) if engine.dialect.name!="sqlite" else case((Vulnerability.cve!="",func.upper(Vulnerability.cve)),else_=("ID-" + func.cast(Vulnerability.id,String)))
            ranked=select(
                Vulnerability.id.label("vid"),
                func.row_number().over(partition_by=group_key,order_by=(Vulnerability.first_seen.asc(),Vulnerability.id.asc())).label("rn"),
                func.count().over(partition_by=group_key).label("group_count")
            )
            # Apply search filters to the grouping result, keeping all matching sources.
            ranked=ranked.where(*stmt._where_criteria).subquery()
            parents=select(Vulnerability,ranked.c.group_count).join(ranked,Vulnerability.id==ranked.c.vid).where(ranked.c.rn==1)
            total=db.scalar(select(func.count()).select_from(parents.subquery()))
            records=db.execute(parents.order_by(ordering,Vulnerability.id.desc()).offset((page-1)*size).limit(size)).all()
            return {"code":0,"data":{"list":[{**serialize(v),"group_count":count} for v,count in records],"total":total,"page":page,"size":size},"message":"success"}
        total=db.scalar(select(func.count()).select_from(stmt.subquery()))
        rows=db.scalars(stmt.order_by(ordering,Vulnerability.id.desc()).offset((page-1)*size).limit(size)).all()
        return {"code":0,"data":{"list":[serialize(x) for x in rows],"total":total,"page":page,"size":size},"message":"success"}

@app.get("/api/v1/vulnerabilities/{vuln_id}/related", dependencies=[Depends(auth)])
def related_vulnerabilities(vuln_id:int):
    with Session(engine) as db:
        parent=db.get(Vulnerability,vuln_id)
        if not parent:raise HTTPException(404,"Not found")
        if not parent.cve:return {"code":0,"data":[],"message":"success"}
        rows=db.scalars(select(Vulnerability).where(
            func.upper(Vulnerability.cve)==parent.cve.upper(),Vulnerability.id!=vuln_id
        ).order_by(Vulnerability.first_seen.asc(),Vulnerability.id.asc())).all()
        return {"code":0,"data":[serialize(v) for v in rows],"message":"success"}

@app.post("/api/v1/vulnerabilities/enrich-severity", dependencies=[Depends(auth)])
def enrich_existing_severities():
    """Best-effort enrichment of up to eight historical unknown CVEs per request."""
    from .collector import nvd_severity
    import app.collector as collector
    collector._nvd_requests=0
    updated=0
    with Session(engine) as db:
        rows=db.scalars(select(Vulnerability).where(
            or_(Vulnerability.severity=="未知",Vulnerability.severity==""),
            Vulnerability.cve!=""
        ).order_by(Vulnerability.first_seen.asc()).limit(8)).all()
        for row in rows:
            level=nvd_severity(row.cve)
            if level!="未知":
                row.severity=level
                updated+=1
        db.commit()
    return {"code":0,"data":{"checked":len(rows),"updated":updated},"message":"completed"}

class BulkDeleteInput(BaseModel):
    ids: list[int] = Field(..., min_items=1, max_items=100)

@app.post("/api/v1/vulnerabilities/bulk-delete", dependencies=[Depends(auth)])
def bulk_delete_vulnerabilities(body: BulkDeleteInput):
    from .review import Review
    from .crawler import CrawlerFinding
    ids=set(body.ids)
    with Session(engine) as db:
        from sqlalchemy import delete
        rows=db.scalars(select(Vulnerability).where(Vulnerability.id.in_(ids))).all()
        for row in rows:
            if row.key.startswith("crawler:"):continue
            # Crawler keys are hashes of script id and URL; remove matching raw findings.
            for finding in db.scalars(select(CrawlerFinding)).all():
                import hashlib
                if row.key==hashlib.sha256(("crawler:"+str(finding.script_id)+":"+finding.url).encode()).hexdigest():
                    db.delete(finding)
        db.execute(delete(Review).where(Review.vulnerability_id.in_(ids)))
        result=db.execute(delete(Vulnerability).where(Vulnerability.id.in_(ids)))
        db.commit()
        return {"code":0,"data":{"deleted":result.rowcount},"message":"deleted"}

@app.get("/api/v1/vulnerabilities/{vuln_id}", dependencies=[Depends(auth)])
def get_vulnerability(vuln_id:int):
    with Session(engine) as db:
        v=db.get(Vulnerability,vuln_id)
        if not v: raise HTTPException(404,"Not found")
        return {"code":0,"data":serialize(v),"message":"success"}

@app.post("/api/v1/vulnerabilities/refresh", dependencies=[Depends(auth)])
def refresh():
    from .collector import collect_configured_sources
    return {"code":0,"data":collect_configured_sources(),"message":"completed"}

# Manual collection progress is kept in memory for this single-worker deployment.
import copy
import threading
import uuid
_collection_lock = threading.Lock()
_collection_jobs = {}

@app.post("/api/v1/vulnerabilities/refresh/start", dependencies=[Depends(auth)])
def start_refresh():
    with _collection_lock:
        if any(j["status"] == "running" for j in _collection_jobs.values()):
            raise HTTPException(409, "已有采集任务正在运行")
        job_id = uuid.uuid4().hex
        _collection_jobs.clear()
        _collection_jobs[job_id] = {"status": "running", "summary": {"details": [], "items": 0, "primary": 0, "secondary": 0, "new": 0, "errors": []}}
    def run():
        from .collector import collect_configured_sources
        def update(summary):
            with _collection_lock:
                _collection_jobs[job_id]["summary"] = copy.deepcopy(summary)
        try:
            result = collect_configured_sources(progress=update)
            with _collection_lock:
                _collection_jobs[job_id] = {"status": "done", "summary": result}
        except Exception as exc:
            with _collection_lock:
                _collection_jobs[job_id] = {"status": "error", "summary": _collection_jobs[job_id]["summary"], "error": str(exc)}
    threading.Thread(target=run, daemon=True).start()
    return {"code": 0, "data": {"job_id": job_id}}

@app.get("/api/v1/vulnerabilities/refresh/status/{job_id}", dependencies=[Depends(auth)])
def refresh_status(job_id: str):
    with _collection_lock:
        job = copy.deepcopy(_collection_jobs.get(job_id))
    if job is None:
        raise HTTPException(404, "采集任务不存在")
    return {"code": 0, "data": job}

# Editable intelligence source settings
from .settings import router as sources_router
app.include_router(sources_router)

from .credentials import router as credentials_router
app.include_router(credentials_router)

from .collection_config import router as collection_config_router
app.include_router(collection_config_router)

from .source_check import router as source_check_router
app.include_router(source_check_router)

from .review import router as review_router
app.include_router(review_router)

from .crawler import router as crawler_router
app.include_router(crawler_router)

from .push_config import router as push_config_router
app.include_router(push_config_router)

from .ai_config import router as ai_router
app.include_router(ai_router)

from .dashboard import router as dashboard_router
app.include_router(dashboard_router)

from .scheduler import lifespan
app.router.lifespan_context = lifespan

# Serve compiled Vue UI on the same port as the API.
UI_DIR = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if UI_DIR.is_dir() and (UI_DIR / "index.html").is_file():
    if (UI_DIR / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=str(UI_DIR / "assets")), name="ui-assets")

    @app.get("/", include_in_schema=False)
    @app.get("/{full_path:path}", include_in_schema=False)
    def frontend_index(full_path: str = ""):
        # Do not turn invalid API requests into HTML pages.
        if full_path.startswith(("api/", "docs", "redoc", "openapi.json")):
            raise HTTPException(404, "Not Found")
        requested = (UI_DIR / full_path).resolve()
        if requested.is_relative_to(UI_DIR.resolve()) and requested.is_file():
            return FileResponse(requested)
        return FileResponse(UI_DIR / "index.html")
