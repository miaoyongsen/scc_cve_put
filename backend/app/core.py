"""Python CVE API and persistence. Provider adapters are intentionally pending parity verification."""
import os
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Text, Boolean, DateTime, Integer, select, func, or_
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cve.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
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
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
Base.metadata.create_all(engine)
app = FastAPI(title="SCC CVE Push", version="0.1.0")

def auth(authorization: Optional[str] = Header(None)):
    expected = os.getenv("API_TOKEN")
    if not expected or authorization != "Bearer " + expected:
        raise HTTPException(401, "Unauthorized")

def serialize(v):
    import json
    return {**{k: getattr(v, k) for k in ("id","key","title","description","severity","cve","disclosure","solutions","pushed","first_seen","last_seen")}, "from":v.source, **{k:json.loads(getattr(v,k) or "[]") for k in ("references","tags","github_search","reason")}}

@app.get("/api/v1/vulnerabilities", dependencies=[Depends(auth)])
def list_vulnerabilities(page:int=1,size:int=20,severity:str="",source:str="",q:str=""):
    page=max(page,1);size=min(max(size,1),100)
    with Session(engine) as db:
        stmt=select(Vulnerability)
        if severity: stmt=stmt.where(Vulnerability.severity==severity)
        if source: stmt=stmt.where(Vulnerability.source==source)
        if q:
            like=f"%{q}%"
            stmt=stmt.where(or_(Vulnerability.title.like(like),Vulnerability.cve.like(like),Vulnerability.key.like(like)))
        total=db.scalar(select(func.count()).select_from(stmt.subquery()))
        rows=db.scalars(stmt.order_by(Vulnerability.last_seen.desc()).offset((page-1)*size).limit(size)).all()
        return {"code":0,"data":{"list":[serialize(x) for x in rows],"total":total,"page":page,"size":size},"message":"success"}

class BulkDeleteInput(BaseModel):
    ids: list[int] = Field(..., min_items=1, max_items=100)

@app.post("/api/v1/vulnerabilities/bulk-delete", dependencies=[Depends(auth)])
def bulk_delete_vulnerabilities(body: BulkDeleteInput):
    from .review import Review
    ids=set(body.ids)
    with Session(engine) as db:
        from sqlalchemy import delete
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
