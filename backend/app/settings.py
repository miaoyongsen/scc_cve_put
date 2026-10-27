"""Editable source settings persisted in SQLite. No fixed source list in backend."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import String, Boolean, Integer, select, inspect, text
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth

class IntelSource(Base):
    __tablename__="intel_sources"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    name: Mapped[str]=mapped_column(String(100),unique=True)
    enabled: Mapped[bool]=mapped_column(Boolean,default=False)
    ai_enabled: Mapped[bool]=mapped_column(Boolean,default=False)
    adapter: Mapped[str]=mapped_column(String(100),default="")
    notes: Mapped[str]=mapped_column(String(500),default="")

Base.metadata.create_all(engine)
if "ai_enabled" not in {c["name"] for c in inspect(engine).get_columns("intel_sources")}:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE intel_sources ADD COLUMN ai_enabled BOOLEAN NOT NULL DEFAULT 0"))
router=APIRouter(prefix="/api/v1/settings/sources",dependencies=[Depends(auth)])

class SourceInput(BaseModel):
    name: str=Field(min_length=1,max_length=100)
    enabled: bool=False
    ai_enabled: bool=False
    adapter: str=Field(default="",max_length=100)
    notes: str=Field(default="",max_length=500)

def dto(s):
    return {"id":s.id,"name":s.name,"enabled":s.enabled,"ai_enabled":s.ai_enabled,"adapter":s.adapter,"notes":s.notes}

@router.get("")
def get_sources():
    with Session(engine) as db:
        return {"code":0,"data":[dto(s) for s in db.scalars(select(IntelSource).order_by(IntelSource.id)).all()],"message":"success"}

@router.post("")
def add_source(body:SourceInput):
    with Session(engine) as db:
        if db.scalar(select(IntelSource).where(IntelSource.name==body.name)):
            raise HTTPException(409,"Source name already exists")
        s=IntelSource(**body.model_dump())
        db.add(s);db.commit();db.refresh(s)
        return {"code":0,"data":dto(s),"message":"success"}

@router.put("/{source_id}")
def edit_source(source_id:int,body:SourceInput):
    with Session(engine) as db:
        s=db.get(IntelSource,source_id)
        if not s:raise HTTPException(404,"Source not found")
        for k,v in body.model_dump().items():setattr(s,k,v)
        db.commit();db.refresh(s)
        return {"code":0,"data":dto(s),"message":"success"}

@router.delete("/{source_id}")
def remove_source(source_id:int):
    with Session(engine) as db:
        s=db.get(IntelSource,source_id)
        if not s:raise HTTPException(404,"Source not found")
        db.delete(s);db.commit()
        return {"code":0,"message":"success"}
