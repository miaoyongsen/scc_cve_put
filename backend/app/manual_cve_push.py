"""Manually look up a CVE and send now or include it in the next digest."""
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, Text, DateTime, select, func
from sqlalchemy.orm import Mapped, mapped_column, Session

from .core import Base, engine, auth, Vulnerability, log_run
from .push_config import current

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/manual-cve", dependencies=[Depends(auth)])
CVE_FORMAT = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
KNOWN_LEVELS = ("严重", "高危", "中危", "低危")
LEVEL_PRIORITY = {"严重": 4, "高危": 3, "中危": 2, "低危": 1, "未知": 0}

# Keep a successful lookup briefly so pressing a push button does not require
# a second NVD HTTP request or unexpectedly change the previewed metadata.
_lookup_lock=threading.Lock()
_lookup_cache={}
LOOKUP_TTL_SECONDS=900


class ManualCVEQueue(Base):
    __tablename__ = "manual_cve_push_queue"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve: Mapped[str] = mapped_column(String(40), unique=True, nullable=False, index=True)
    item_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


Base.metadata.create_all(engine)


class CVEActionInput(BaseModel):
    cve: str = Field(min_length=1, max_length=40)


def _validate_cve(value):
    cve=(value or "").strip().upper()
    if not CVE_FORMAT.fullmatch(cve):
        raise HTTPException(422, "CVE 编号格式错误，应为 CVE-2026-12345")
    return cve


def _db_item(cve):
    with Session(engine) as db:
        records=db.scalars(select(Vulnerability).where(
            func.upper(Vulnerability.cve)==cve
        ).order_by(Vulnerability.id.desc())).all()
        records.sort(key=lambda row: (
            LEVEL_PRIORITY.get(row.severity, 0),
            bool(row.title),
            bool(row.description),
        ),reverse=True)
        if not records:
            return None
        from .core import serialize
        item=serialize(records[0])
        item["source"]="本地漏洞库"
        item["from"]="本地漏洞库"
        item["url"]=(item.get("references") or [""])[0]
        return item


def _nvd_item(cve):
    headers={"User-Agent":"SCC-CVE/1.0 manual CVE lookup","Accept":"application/json"}
    api_key=os.getenv("NVD_API_KEY","").strip()
    if api_key:
        headers["apiKey"]=api_key
    try:
        response=httpx.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId":cve},headers=headers,timeout=12,
            follow_redirects=False,trust_env=False)
        if response.status_code in (403,429,503):
            raise HTTPException(503, "NVD 当前不可用或请求受限，请稍后重试")
        response.raise_for_status()
        matches=response.json().get("vulnerabilities") or []
    except HTTPException:
        raise
    except (httpx.HTTPError,ValueError) as exc:
        log.warning("Manual NVD CVE lookup failed for %s: %s",cve,exc)
        raise HTTPException(503, "NVD 查询失败，请检查网络连接")
    record=next((entry.get("cve") or {} for entry in matches
                 if (entry.get("cve") or {}).get("id","").upper()==cve),None)
    if record is None:
        raise HTTPException(404, "未查询到该 CVE，请检查编号或等待 NVD 收录")
    descriptions=record.get("descriptions") or []
    description=next((row.get("value","") for row in descriptions
                      if row.get("lang")=="en" and row.get("value")), "")
    if not description:
        description=next((row.get("value","") for row in descriptions
                          if row.get("value")), "")
    # NVD supplies prose rather than a dedicated vulnerability title.
    title=description.strip().split("\n",1)[0][:180].strip()
    if len(title)>110:
        title=title[:107].rstrip()+"..."
    metrics=record.get("metrics") or {}
    severity="未知"
    for field in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
        for metric in metrics.get(field) or []:
            cvss=metric.get("cvssData") or {}
            score=cvss.get("baseScore")
            if score is not None:
                try:
                    score=float(score)
                except (TypeError,ValueError):
                    continue
                severity=("严重" if score>=9 else "高危" if score>=7
                          else "中危" if score>=4 else "低危")
                break
        if severity!="未知":
            break
    refs=[row.get("url") for row in record.get("references") or [] if row.get("url")]
    url="https://nvd.nist.gov/vuln/detail/"+cve
    published=record.get("published") or ""
    return {"key":"manual-cve:"+cve,"title":title,"description":description,
        "cve":cve,"severity":severity,"disclosure":published,"solutions":"",
        "references":[url]+[r for r in refs if r!=url][:5],
        "url":url,"from":"NVD","source":"NVD","content_type":"vulnerability"}


def resolve_cve(cve):
    """Use local records when complete; fall back to NVD for incomplete/missing CVEs."""
    with _lookup_lock:
        cached=_lookup_cache.get(cve)
        if cached and cached[0]>time.monotonic():
            return dict(cached[1])
    local=_db_item(cve)
    if local and local.get("title") and local.get("severity") in KNOWN_LEVELS:
        result=local
    else:
        result=None
    if result is not None:
        with _lookup_lock:
            _lookup_cache[cve]=(time.monotonic()+LOOKUP_TTL_SECONDS,dict(result))
        return result
    try:
        official=_nvd_item(cve)
    except HTTPException:
        if local:
            return local
        raise
    if local:
        if not official.get("title"):
            official["title"]=local.get("title") or ""
        if official.get("severity")=="未知":
            official["severity"]=local.get("severity") or "未知"
    with _lookup_lock:
        _lookup_cache[cve]=(time.monotonic()+LOOKUP_TTL_SECONDS,dict(official))
    return official


def _ready(item):
    return bool(item.get("title") and item.get("severity") in KNOWN_LEVELS)


def _prepared_item(cve):
    item=resolve_cve(cve)
    if not _ready(item):
        raise HTTPException(422, "已查询到 CVE，但标题或危害等级不完整，暂时不能推送")
    # Never mark a source vulnerability as sent by a manual override.
    # Use a separate tracking key, leaving collection and audit states untouched.
    item=dict(item)
    item["key"]="manual-cve:"+cve
    item["cve"]=cve
    item["content_type"]="vulnerability"
    return item


def _persist_manual_vulnerability(db, item):
    """Upsert one user-requested CVE in the visible vulnerability monitor.

    This is independent of the review workflow: queued manual CVEs must be
    visible immediately, with wecom_sent=False until delivery succeeds.
    """
    cve=item["cve"]
    key="manual-cve:"+cve
    row=db.scalar(select(Vulnerability).where(Vulnerability.key==key))
    if row is None:
        row=Vulnerability(key=key)
        db.add(row)
    row.cve=cve
    row.title=str(item.get("title") or "")[:500]
    row.description=str(item.get("description") or "")
    row.severity=item["severity"]
    # SQLite disclosure column is 20 characters; retain a valid ISO second value.
    row.disclosure=str(item.get("disclosure") or "")[:19]
    row.solutions=str(item.get("solutions") or "")
    references=item.get("references") or ([item["url"]] if item.get("url") else [])
    row.references=json.dumps(references,ensure_ascii=False)
    row.source="手动查询"
    row.content_type="vulnerability"
    if not row.wecom_sent:
        row.wecom_sent=False
        row.wecom_sent_at=None
        row.pushed=False
    row.last_seen=datetime.now(timezone.utc)
    db.flush()
    return row


@router.get("/lookup")
def lookup_manual_cve(cve: str):
    code=_validate_cve(cve)
    item=resolve_cve(code)
    return {"code":0,"data":{"cve":code,"title":item.get("title") or "",
        "severity":item.get("severity") or "未知",
        "source":item.get("from") or "未知",
        "ready":_ready(item)}}


@router.post("/queue")
def queue_manual_cve(body: CVEActionInput):
    cve=_validate_cve(body.cve)
    item=_prepared_item(cve)
    config=current()
    if not ((config["wecom_enabled"] and config["wecom_webhook"]) or
            os.getenv("WECHAT_WEBHOOK_URL","").strip()):
        raise HTTPException(422, "未配置有效的企业微信机器人")
    with Session(engine) as db:
        row=db.scalar(select(ManualCVEQueue).where(ManualCVEQueue.cve==cve))
        if row and row.status=="queued":
            raise HTTPException(409, "该 CVE 已在等待合并推送队列中")
        _persist_manual_vulnerability(db,item)
        if row is None:
            row=ManualCVEQueue(cve=cve,item_json=json.dumps(item,ensure_ascii=False,default=str))
            db.add(row)
        else:
            row.item_json=json.dumps(item,ensure_ascii=False,default=str)
            row.status="queued"
            row.queued_at=datetime.now(timezone.utc)
            row.sent_at=None
        db.commit()
    log_run(item,"manual","等待合并推送","手动查询 CVE，已加入下次正常采集队列")
    return {"code":0,"data":{"cve":cve,"status":"queued"}}


def pending_manual_entries():
    """Return queued items for the normal digest; no AI work on confirmation."""
    from .legacy_notify import format_wecom_with_ai
    with Session(engine) as db:
        rows=db.scalars(select(ManualCVEQueue).where(
            ManualCVEQueue.status=="queued"
        ).order_by(ManualCVEQueue.id.asc())).all()
        return [(json.loads(row.item_json),
                 format_wecom_with_ai(json.loads(row.item_json))) for row in rows]


def confirm_manual_delivery(items):
    keys={str(item.get("key") or "") for item in items}
    cves={key.removeprefix("manual-cve:") for key in keys
          if key.startswith("manual-cve:")}
    if not cves:
        return 0
    with Session(engine) as db:
        rows=db.scalars(select(ManualCVEQueue).where(
            ManualCVEQueue.cve.in_(cves),ManualCVEQueue.status=="queued")).all()
        for row in rows:
            row.status="sent"
            row.sent_at=datetime.now(timezone.utc)
        db.commit()
        return len(rows)


@router.post("/send")
def send_manual_cve(body: CVEActionInput):
    from .notifications import cve_delivery_guard
    with cve_delivery_guard():
        return _send_manual_cve_locked(body)


def _send_manual_cve_locked(body: CVEActionInput):
    cve=_validate_cve(body.cve)
    item=_prepared_item(cve)
    config=current()
    webhook=(config["wecom_webhook"] if config["wecom_enabled"] else "") or os.getenv("WECHAT_WEBHOOK_URL","").strip()
    if not webhook:
        raise HTTPException(422,"未配置有效的企业微信机器人")
    from .notifications import already_delivered
    with Session(engine) as db:
        if already_delivered(db,cve):
            raise HTTPException(409,"重复 CVE，历史已推送")
    # Persist at the moment the user confirms, not after network delivery.
    # A failed WeCom attempt stays visible with its unsent state.
    with Session(engine) as db:
        _persist_manual_vulnerability(db,item)
        db.commit()
    from .legacy_notify import format_wecom_with_ai
    from .notifications import send_wecom_markdown, mark_wecom_delivered
    message=format_wecom_with_ai(item)
    try:
        success=send_wecom_markdown(message,url=webhook)
    except Exception as exc:
        log_run(item,"manual","推送失败",str(exc)[:500])
        raise HTTPException(502,"企业微信发送失败："+str(exc)[:200])
    if not success:
        log_run(item,"manual","推送失败","企业微信未确认发送成功")
        raise HTTPException(502,"企业微信未确认发送成功")
    mark_wecom_delivered([item])
    # If the same CVE was previously queued, suppress its next automatic resend.
    confirm_manual_delivery([item])
    log_run(item,"manual","推送成功","手动 CVE 立即推送")
    return {"code":0,"data":{"cve":cve,"status":"sent"}}
