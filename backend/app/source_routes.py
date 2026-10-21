"""Administrative API for source settings; never fetches arbitrary endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from .core import auth
from .source_config import SourceUpdate, list_sources, save_source
router=APIRouter(prefix="/api/v1/sources",dependencies=[Depends(auth)])

@router.get("")
def sources(): return {"code":0,"data":list_sources(),"message":"success"}

@router.put("/{source_id}")
def update_source(source_id:str, data:SourceUpdate):
    if not source_id.replace("-","").replace("_","").isalnum() or len(source_id)>80:
        raise HTTPException(400,"Invalid source identifier")
    return {"code":0,"data":save_source(source_id,data),"message":"success"}
