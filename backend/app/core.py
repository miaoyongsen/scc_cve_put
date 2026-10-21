"""Python CVE API and persistence. Provider adapters are intentionally pending parity verification."""
import os
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Depends
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

@app.get("/api/v1/vulnerabilities/{vuln_id}", dependencies=[Depends(auth)])
def get_vulnerability(vuln_id:int):
    with Session(engine) as db:
        v=db.get(Vulnerability,vuln_id)
        if not v: raise HTTPException(404,"Not found")
        return {"code":0,"data":serialize(v),"message":"success"}

@app.post("/api/v1/vulnerabilities/refresh", dependencies=[Depends(auth)])
def refresh():
    raise HTTPException(503,"WatchVuln Python provider adapters not yet implemented; collection disabled to avoid inaccurate results.")

# Editable intelligence source settings
from .settings import router as sources_router
app.include_router(sources_router)
