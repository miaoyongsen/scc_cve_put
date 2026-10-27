"""Persisted notification settings. Webhook secrets are write-only in API responses."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import Integer, String, Boolean, select
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth

class PushConfig(Base):
    __tablename__="push_config"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    wecom_enabled:Mapped[bool]=mapped_column(Boolean,default=False)
    wecom_webhook:Mapped[str]=mapped_column(String(1000),default="")
    severity_filter:Mapped[str]=mapped_column(String(200),default="")
    source_filter:Mapped[str]=mapped_column(String(2000),default="")
    quiet_start:Mapped[str]=mapped_column(String(5),default="")
    quiet_end:Mapped[str]=mapped_column(String(5),default="")
    dedup_hours:Mapped[int]=mapped_column(Integer,default=0)
    message_template:Mapped[str]=mapped_column(String(8000),default="## WatchVuln 漏洞情报\\n> **标题**：{title}\\n> **CVE**：{cve}\\n> **等级**：{severity}\\n> **来源**：{source}\\n> **披露日期**：{disclosure}\\n> **原始数据**：[查看原文]({url})")
Base.metadata.create_all(engine)
from sqlalchemy import inspect, text
if "message_template" not in {c["name"] for c in inspect(engine).get_columns("push_config")}:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE push_config ADD COLUMN message_template VARCHAR(8000)"))
router=APIRouter(prefix="/api/v1/settings/push",dependencies=[Depends(auth)])
class PushInput(BaseModel):
    wecom_enabled:bool=False
    wecom_webhook:str=""
    severity_filter:list[str]=[]
    source_filter:str=""
    quiet_start:str=""
    quiet_end:str=""
    dedup_hours:int=0
    message_template:str="## WatchVuln 漏洞情报\\n> **标题**：{title}\\n> **CVE**：{cve}\\n> **等级**：{severity}\\n> **来源**：{source}\\n> **披露日期**：{disclosure}\\n> **原始数据**：[查看原文]({url})"

DEFAULT_TEMPLATE="## WatchVuln 漏洞情报\\n> **标题**：{title}\\n> **CVE**：{cve}\\n> **等级**：{severity}\\n> **来源**：{source}\\n> **披露日期**：{disclosure}\\n> **原始数据**：[查看原文]({url})"

def current():
    with Session(engine) as db:
        row=db.get(PushConfig,1)
        return dict(wecom_enabled=row.wecom_enabled if row else False,wecom_webhook=row.wecom_webhook if row else "",severity_filter=(row.severity_filter.split(",") if row and row.severity_filter else []),source_filter=row.source_filter if row else "",quiet_start=row.quiet_start if row else "",quiet_end=row.quiet_end if row else "",dedup_hours=row.dedup_hours if row else 0,message_template=(row.message_template if row and row.message_template else DEFAULT_TEMPLATE))

@router.get("")
def get_config():
    c=current()
    c["has_webhook"]=bool(c.pop("wecom_webhook"))
    return {"code":0,"data":c}

@router.put("")
def save_config(body:PushInput):
    from urllib.parse import urlparse
    import re
    if body.wecom_webhook and not (body.wecom_webhook.startswith("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?") and urlparse(body.wecom_webhook).hostname=="qyapi.weixin.qq.com"):
        raise HTTPException(422,"仅允许企业微信官方机器人 Webhook")
    if any(s not in ("严重","高危","中危","低危","未知") for s in body.severity_filter):
        raise HTTPException(422,"非法等级")
    if body.dedup_hours not in (0,1,6,12,24,72):
        raise HTTPException(422,"去重时长不支持")
    if any(x and not re.fullmatch(r"(?:[01]\\d|2[0-3]):[0-5]\\d",x) for x in (body.quiet_start,body.quiet_end)):
        raise HTTPException(422,"静默时间应为 HH:MM")
    with Session(engine) as db:
        row=db.get(PushConfig,1)
        if row is None:row=PushConfig(id=1);db.add(row)
        row.wecom_enabled=body.wecom_enabled
        if body.wecom_webhook:row.wecom_webhook=body.wecom_webhook
        row.severity_filter=",".join(body.severity_filter)
        row.source_filter=body.source_filter[:2000]
        row.quiet_start=body.quiet_start
        row.quiet_end=body.quiet_end
        row.dedup_hours=body.dedup_hours
        if len(body.message_template)>8000:raise HTTPException(422,"模板过长")
        row.message_template=body.message_template
        db.commit()
    return {"code":0,"message":"saved"}

@router.post("/test")
def test_push():
    from .notifications import send_wecom_markdown
    c=current()
    if not c["wecom_enabled"] or not c["wecom_webhook"]:
        raise HTTPException(422,"请先启用并保存企业微信 Webhook")
    try:
        from .legacy_notify import format_wecom
        ok=send_wecom_markdown(format_wecom({"title":"推送模板测试","cve":"CVE-2026-12345","severity":"高危","from":"测试来源","disclosure":"2026-10-26","description":"这是一条模板预览测试消息","solutions":"请按官方公告修复","url":"https://example.com"}),url=c["wecom_webhook"])
    except Exception as exc:
        raise HTTPException(502,str(exc)[:200])
    return {"code":0,"data":{"success":ok}}
