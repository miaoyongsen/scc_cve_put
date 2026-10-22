"""Editable global polling interval, persisted in the existing SQLite database."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth

ALLOWED_INTERVALS=(15,30,60,180,360,720,1440)
class CollectionConfig(Base):
    __tablename__="collection_config"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    interval_minutes: Mapped[int]=mapped_column(Integer,default=60,nullable=False)
    lookback_hours: Mapped[int]=mapped_column(Integer,default=24,nullable=False)
    whitelist: Mapped[str]=mapped_column(String(2000),default='',nullable=False)
Base.metadata.create_all(engine)
# Add column to existing SQLite installations without deleting settings.
from sqlalchemy import inspect, text
if 'whitelist' not in {x['name'] for x in inspect(engine).get_columns('collection_config')}:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE collection_config ADD COLUMN whitelist VARCHAR(2000) NOT NULL DEFAULT ''"))

if 'lookback_hours' not in {x['name'] for x in inspect(engine).get_columns('collection_config')}:
    with engine.begin() as conn:
        conn.execute(text('ALTER TABLE collection_config ADD COLUMN lookback_hours INTEGER NOT NULL DEFAULT 24'))

def lookback_hours():
    with Session(engine) as db:
        row=db.get(CollectionConfig,1)
        return row.lookback_hours if row else 24

def whitelist_keywords():
    with Session(engine) as db:
        row=db.get(CollectionConfig,1)
        return [x.strip() for x in (row.whitelist if row else '').split(',') if x.strip()]

def interval_minutes():
    with Session(engine) as db:
        row=db.get(CollectionConfig,1)
        return row.interval_minutes if row and row.interval_minutes in ALLOWED_INTERVALS else 60

router=APIRouter(prefix="/api/v1/settings/collection",dependencies=[Depends(auth)])
class CollectionInput(BaseModel):
    interval_minutes: int=Field(default=60)
    whitelist: str=Field(default='',max_length=2000)
    lookback_hours: int=Field(default=24)

@router.get("")
def get_collection():
    with Session(engine) as db:
        return {"code":0,"data":{"interval_minutes":interval_minutes(),"options":list(ALLOWED_INTERVALS),"whitelist":(db.get(CollectionConfig,1).whitelist if db.get(CollectionConfig,1) else ""),"lookback_hours":lookback_hours()},"message":"success"}

@router.put("")
def set_collection(body:CollectionInput):
    from fastapi import HTTPException
    if body.lookback_hours not in (0,24,72,168,720):
        raise HTTPException(422,'Unsupported time range')
    if body.interval_minutes not in ALLOWED_INTERVALS:
        raise HTTPException(422,"Unsupported interval")
    with Session(engine) as db:
        row=db.get(CollectionConfig,1)
        if row is None:
            row=CollectionConfig(id=1)
            db.add(row)
        row.interval_minutes=body.interval_minutes
        row.whitelist=body.whitelist
        row.lookback_hours=body.lookback_hours
        db.commit()
    from .scheduler import wakeup
    wakeup()
    return {"code":0,"data":{"interval_minutes":body.interval_minutes},"message":"success"}
