"""Operational dashboard aggregated from existing SQLite collection history."""
import json
from datetime import datetime,timedelta,timezone
from collections import defaultdict
from fastapi import APIRouter,Depends,Query
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from .core import auth,engine,CollectionRun,RunRecord,Vulnerability

router=APIRouter(prefix="/api/v1/dashboard",dependencies=[Depends(auth)])

def ratio(a,b):
    return round(a*100/b,2) if b else None

@router.get("")
def dashboard(days:int=Query(7,ge=1,le=90)):
    since=datetime.now(timezone.utc)-timedelta(days=days)
    totals=dict(runs=0,failed=0,partial=0,items=0,new=0,duplicates=0,push_success=0,push_failed=0,push_skipped=0,vulnerabilities=0)
    trend=defaultdict(lambda:dict(runs=0,failed=0,items=0,duplicates=0))
    sources=defaultdict(lambda:dict(runs=0,failed=0,items=0,duplicates=0))
    recent=[]
    with Session(engine) as db:
        totals["vulnerabilities"]=db.scalar(select(func.count()).select_from(Vulnerability)) or 0
        runs=db.scalars(select(CollectionRun).where(CollectionRun.started_at>=since).order_by(CollectionRun.id.desc())).all()
        for run in runs:
            try:s=json.loads(run.summary or "{}")
            except (ValueError,TypeError):s={}
            day=str(run.started_at)[:10]
            t=trend[day]
            totals["runs"]+=1;t["runs"]+=1
            if run.status=="失败":totals["failed"]+=1;t["failed"]+=1
            if run.status=="部分失败":totals["partial"]+=1;t["failed"]+=1
            for key in ("items","new"):totals[key]+=int(s.get(key) or 0)
            t["items"]+=int(s.get("items") or 0)
            for detail in s.get("details") or []:
                if not isinstance(detail,dict):continue
                name=str(detail.get("name") or detail.get("id") or "未知")
                row=sources[name];row["runs"]+=1;row["items"]+=int(detail.get("items") or 0)
                if detail.get("status") in ("error","partial"):row["failed"]+=1
                duplicates=len(detail.get("duplicates") or [])
                row["duplicates"]+=duplicates;totals["duplicates"]+=duplicates;t["duplicates"]+=duplicates
            if len(recent)<10:recent.append(dict(id=run.id,date=str(run.started_at),mode=run.mode,status=run.status,errors=(s.get("errors") or [])[:2]))
        for status,count in db.execute(select(RunRecord.status,func.count()).where(RunRecord.created_at>=since).group_by(RunRecord.status)):
            if status=="推送成功":totals["push_success"]+=count
            elif status=="推送失败":totals["push_failed"]+=count
            elif status=="推送未成功":totals["push_skipped"]+=count
    return {"code":0,"data":{"days":days,"totals":totals,
        "rates":{"failure_rate":ratio(totals["failed"]+totals["partial"],totals["runs"]),
                 "duplicate_rate":ratio(totals["duplicates"],totals["items"]),
                 "push_success_rate":ratio(totals["push_success"],totals["push_success"]+totals["push_failed"])},
        "trend":[dict(date=k,**v) for k,v in sorted(trend.items())],
        "sources":[dict(name=k,**v) for k,v in sorted(sources.items(),key=lambda x:-x[1]["failed"])[:20]],
        "recent":recent,
        "notes":"推送成功率仅统计成功和失败，不含过滤或未配置渠道；归档日志不参与统计。"}} 
