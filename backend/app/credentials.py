"""Source credentials: write-only via API, stored in SQLite; never sent to UI."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth
from .settings import IntelSource

class SourceCredential(Base):
    __tablename__="source_credentials"
    source_id: Mapped[int]=mapped_column(Integer,primary_key=True)
    api_key: Mapped[str]=mapped_column(String(2048),default="")
    header_name: Mapped[str]=mapped_column(String(100),default="Authorization")
Base.metadata.create_all(engine)
router=APIRouter(prefix="/api/v1/settings/sources",dependencies=[Depends(auth)])
class CredentialInput(BaseModel):
    api_key: str=Field(max_length=2048)
    header_name: str=Field(default="Authorization",pattern=r"^[A-Za-z0-9-]{1,100}$")

@router.put("/{source_id}/credential")
def put_credential(source_id:int,body:CredentialInput):
    with Session(engine) as db:
        if not db.get(IntelSource,source_id): raise HTTPException(404,"Source not found")
        row=db.get(SourceCredential,source_id)
        if row is None:
            row=SourceCredential(source_id=source_id)
            db.add(row)
        row.api_key=body.api_key
        row.header_name=body.header_name
        db.commit()
    return {"code":0,"data":{"configured":bool(body.api_key)},"message":"success"}

@router.get("/{source_id}/credential")
def get_credential_status(source_id:int):
    with Session(engine) as db:
        if not db.get(IntelSource,source_id): raise HTTPException(404,"Source not found")
        row=db.get(SourceCredential,source_id)
        return {"code":0,"data":{"configured":bool(row and row.api_key),"header_name":row.header_name if row else "Authorization"},"message":"success"}
