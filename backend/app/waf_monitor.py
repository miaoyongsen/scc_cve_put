"""Independent WAF receipt polling and WeCom outcome notifications.

Only terminal Done/Failed response statuses trigger notifications. Every request
has one persisted notification attempt; failed deliveries are recorded but never
automatically retried, avoiding duplicates after an uncertain webhook timeout.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, Text, Boolean, DateTime, select, func
from sqlalchemy.orm import Mapped, mapped_column, Session

from .core import Base, engine, auth
from .waf_block import WafBlockRequest, query_request

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/waf/monitor", dependencies=[Depends(auth)])

ALLOWED_INTERVALS = (1, 3, 5, 10, 15, 30, 60)
TERMINAL_SUCCESS = ("done",)
TERMINAL_FAILURE = ("failed",)
WAITING_STATUSES = ("已提交，待回执", "pending", "Processing", "processing")
_stop = threading.Event()
_wake = threading.Event()
_work_lock = threading.Lock()
_worker = None
_state_lock = threading.Lock()
_state = {"running": False, "last_run": None, "last_error": None,
          "last_queried": 0, "last_found": 0, "last_notified": 0}


class WafMonitorConfig(Base):
    __tablename__ = "waf_monitor_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=3)
    success_webhook: Mapped[str] = mapped_column(Text, default="")
    failure_webhook: Mapped[str] = mapped_column(Text, default="")


class WafNotification(Base):
    __tablename__ = "waf_notification_records"
    request_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    outcome: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(24), default="claimed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")


Base.metadata.create_all(engine)


class ConfigInput(BaseModel):
    enabled: bool = False
    interval_minutes: int = Field(default=3)
    success_webhook: str = Field(default="", max_length=2000)
    failure_webhook: str = Field(default="", max_length=2000)
    clear_success_webhook: bool = False
    clear_failure_webhook: bool = False


def get_config(db):
    row = db.get(WafMonitorConfig, 1)
    if row is None:
        row = WafMonitorConfig(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def validate_webhook(value: str) -> str:
    url = value.strip()
    if not url:
        return ""
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != "qyapi.weixin.qq.com"
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.path != "/cgi-bin/webhook/send" or not parsed.query
            or parsed.fragment):
        raise HTTPException(422, "仅支持企业微信机器人 HTTPS Webhook 地址")
    return url


def config_dto(config):
    return {"enabled":bool(config.enabled), "interval_minutes":config.interval_minutes,
            "has_success_webhook":bool(config.success_webhook),
            "has_failure_webhook":bool(config.failure_webhook)}


@router.get("/config")
def read_config():
    with Session(engine) as db:
        return {"code":0,"data":config_dto(get_config(db))}


@router.put("/config")
def update_config(body: ConfigInput):
    if body.interval_minutes not in ALLOWED_INTERVALS:
        raise HTTPException(422, "查询间隔只能选择 1、3、5、10、15、30、60 分钟")
    with Session(engine) as db:
        c=get_config(db)
        c.enabled=body.enabled
        c.interval_minutes=body.interval_minutes
        if body.clear_success_webhook:
            c.success_webhook=""
        elif body.success_webhook.strip():
            c.success_webhook=validate_webhook(body.success_webhook)
        if body.clear_failure_webhook:
            c.failure_webhook=""
        elif body.failure_webhook.strip():
            c.failure_webhook=validate_webhook(body.failure_webhook)
        db.commit()
        result=config_dto(c)
    _wake.set()
    return {"code":0,"data":result}


def send_wecom(url, row, outcome):
    label="封禁成功" if outcome=="success" else "封禁失败"
    text = ("【SCC WAF " + label + "】\n"
            + "请求编号：" + row.client_request_id + "\n"
            + "工单编号：" + (row.service_request_id or "—") + "\n"
            + "封禁IP：" + row.block_ip + "\n"
            + "处理状态：" + row.status + "\n"
            + "提交时间：" + str(row.created_at or "—"))
    # WeCom text length limit is 2048 bytes; truncate IP list if needed.
    if len(text.encode("utf-8")) > 1900:
        text = text[:550] + "\n（IP 列表过长，已截断，请在 SCC 查看完整记录）"
    result = httpx.post(url, json={"msgtype":"text","text":{"content":text}},
                        timeout=15, follow_redirects=False, trust_env=False)
    result.raise_for_status()
    response=result.json()
    if response.get("errcode") != 0:
        raise RuntimeError("WeCom webhook rejected message (errcode=" + str(response.get("errcode")) + ")")


def notify_terminal():
    notified=0
    # 'claimed' persisted before sending: even a crash or timeout cannot cause a
    # duplicate auto-notification. History remains for troubleshooting.
    with Session(engine) as db:
        config=get_config(db)
        candidates=db.scalars(
            select(WafBlockRequest).where(
                func.lower(WafBlockRequest.status).in_(TERMINAL_SUCCESS + TERMINAL_FAILURE),
                WafBlockRequest.client_request_id.not_in(select(WafNotification.request_id))
            ).order_by(WafBlockRequest.id).limit(500)
        ).all()
        for row in candidates:
            outcome="success" if row.status.lower() in TERMINAL_SUCCESS else "failure"
            url=config.success_webhook if outcome=="success" else config.failure_webhook
            if not url or db.get(WafNotification,row.client_request_id):
                continue
            claim=WafNotification(request_id=row.client_request_id,outcome=outcome,state="claimed")
            db.add(claim)
            db.commit()
            try:
                send_wecom(url,row,outcome)
            except Exception as exc:
                claim.state="failed"
                claim.error=(type(exc).__name__ + ": " + str(exc))[:1000]
                log.warning("WAF notification failed for %s: %s",row.client_request_id,type(exc).__name__)
            else:
                claim.state="sent"
                claim.sent_at=datetime.now(timezone.utc)
                notified+=1
            db.commit()
    return notified


def run_poll():
    if not _work_lock.acquire(blocking=False):
        raise HTTPException(409,"WAF 回执查询任务正在运行")
    with _state_lock:_state["running"]=True
    queried=found=notified=0
    errors=[]
    try:
        with Session(engine) as db:
            pending=db.scalars(
                select(WafBlockRequest.client_request_id)
                .where(WafBlockRequest.status.in_(WAITING_STATUSES))
                .order_by(WafBlockRequest.id).limit(500)
            ).all()
        for request_id in pending:
            queried+=1
            try:
                result=query_request(request_id)
                if result.get("data",{}).get("found"):
                    found+=1
            except Exception as exc:
                errors.append(request_id + ": " + type(exc).__name__)
                log.exception("WAF receipt poll failed for %s",request_id)
        try:
            notified=notify_terminal()
        except Exception as exc:
            errors.append("通知阶段：" + type(exc).__name__)
            log.exception("WAF notification phase failed")
        with _state_lock:
            _state.update(last_run=datetime.now(timezone.utc).isoformat(),
                          last_error="; ".join(errors[:5]) or None,
                          last_queried=queried,last_found=found,last_notified=notified)
        return {"queried":queried,"found":found,"notified":notified,
                "errors":errors[:5]}
    finally:
        with _state_lock:_state["running"]=False
        _work_lock.release()


def monitor_loop():
    while not _stop.is_set():
        with Session(engine) as db:
            config=get_config(db)
            enabled=bool(config.enabled)
            interval=config.interval_minutes
        # Wakeup on settings change, re-evaluate without running a stale timer.
        if _wake.wait(timeout=interval*60 if enabled else 60):
            _wake.clear()
            continue
        if _stop.is_set():break
        if enabled:
            try:run_poll()
            except Exception:log.exception("Scheduled WAF polling failed")


def start_monitor():
    global _worker
    _stop.clear()
    _wake.clear()
    _worker=threading.Thread(target=monitor_loop,name="waf-response-monitor",daemon=True)
    _worker.start()


def stop_monitor():
    _stop.set()
    _wake.set()
    if _worker:_worker.join(timeout=5)


@router.get("/status")
def status():
    with Session(engine) as db:
        config=get_config(db)
        waiting=db.scalar(select(func.count()).select_from(WafBlockRequest).where(
            WafBlockRequest.status.in_(WAITING_STATUSES))) or 0
        sent=db.scalar(select(func.count()).select_from(WafNotification).where(WafNotification.state=="sent")) or 0
        failed=db.scalar(select(func.count()).select_from(WafNotification).where(WafNotification.state=="failed")) or 0
    with _state_lock:runtime=dict(_state)
    return {"code":0,"data":{**runtime,"enabled":bool(config.enabled),
           "worker_alive":bool(_worker and _worker.is_alive()),
           "waiting_requests":waiting,"notifications_sent":sent,"notifications_failed":failed}}


@router.post("/poll")
def poll_now():
    return {"code":0,"data":run_poll()}
