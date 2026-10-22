"""Editable global polling interval, persisted in the existing SQLite database."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import Integer
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth

ALLOWED_INTERVALS=(15,30,60,180,360,720,1440)
class CollectionConfig(Base):
    __tablename__="collection_config"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    interval_minutes: Mapped[int]=mapped_column(Integer,default=60,nullable=False)
Base.metadata.create_all(engine)

def interval_minutes():
    with Session(engine) as db:
        row=db.get(CollectionConfig,1)
        return row.interval_minutes if row and row.interval_minutes in ALLOWED_INTERVALS else 60

router=APIRouter(prefix="/api/v1/settings/collection",dependencies=[Depends(auth)])
class CollectionInput(BaseModel):
    interval_minutes: int=Field(default=60)

@router.get("")
def get_collection():
    return {"code":0,"data":{"interval_minutes":interval_minutes(),"options":list(ALLOWED_INTERVALS)},"message":"success"}

@router.put("")
def set_collection(body:CollectionInput):
    from fastapi import HTTPException
    if body.interval_minutes not in ALLOWED_INTERVALS:
        raise HTTPException(422,"Unsupported interval")
    with Session(engine) as db:
        row=db.get(CollectionConfig,1)
        if row is None:
            row=CollectionConfig(id=1)
            db.add(row)
        row.interval_minutes=body.interval_minutes
        db.commit()
    from .scheduler import wakeup
    wakeup()
    return {"code":0,"data":{"interval_minutes":body.interval_minutes},"message":"success"}
