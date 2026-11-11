"""Independent MSOC SQLite monitor and WeCom notifier.
Reads SCC_TT monthly tables read-only. Settings and cursors live in SCC_CVE's DB.
"""
import json
import logging
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, Session, mapped_column

from .core import Base, engine, auth

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/msoc", dependencies=[Depends(auth)])
DEFAULT_DB_PATH = "/home/msocadmin/SCC_TT/data/webhook.db"
ALLOWED_INTERVALS = (1, 3, 5, 10, 15, 30)
MAX_BATCH_ROWS = 100
MAX_MESSAGE_BYTES = 3800
_send_lock = threading.Lock()
_last_send_started = 0.0
_poll_lock = threading.Lock()


class MSOCConfig(Base):
    __tablename__ = "msoc_monitor_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    db_path: Mapped[str] = mapped_column(String(1000), default=DEFAULT_DB_PATH)
    poll_interval: Mapped[int] = mapped_column(Integer, default=3)
    wecom_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    wecom_webhook: Mapped[str] = mapped_column(String(1000), default="")
    error_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    error_webhook: Mapped[str] = mapped_column(String(1000), default="")
    cursor_month: Mapped[str] = mapped_column(String(6), default="")
    cursor_id: Mapped[int] = mapped_column(Integer, default=0)
    initialized: Mapped[bool] = mapped_column(Boolean, default=False)
    last_query: Mapped[str] = mapped_column(String(40), default="")
    last_push: Mapped[str] = mapped_column(String(40), default="")
    total_pushed: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(Text, default="")


Base.metadata.create_all(engine)
_stop = threading.Event()
_wakeup = threading.Event()
_thread = None
_state_lock = threading.Lock()
_state = {"running": False, "last_query": None, "last_push": None,
          "last_error": None, "last_query_count": 0, "total_pushed": 0}
_error_signature = ""
_error_notified_at = 0.0


def _now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _config():
    with Session(engine) as db:
        row = db.get(MSOCConfig, 1)
        if row is None:
            row = MSOCConfig(id=1, db_path=DEFAULT_DB_PATH, poll_interval=3)
            db.add(row)
            db.commit()
            db.refresh(row)
        return row


def _config_data(row):
    return {
        "enabled": bool(row.enabled), "db_path": row.db_path,
        "poll_interval": row.poll_interval, "wecom_enabled": bool(row.wecom_enabled),
        "has_wecom_webhook": bool(row.wecom_webhook), "error_enabled": bool(row.error_enabled),
        "has_error_webhook": bool(row.error_webhook), "cursor_month": row.cursor_month,
        "cursor_id": row.cursor_id, "initialized": bool(row.initialized),
        "last_query": row.last_query, "last_push": row.last_push,
        "total_pushed": row.total_pushed, "last_error": row.last_error,
    }


def _save_status(**values):
    with Session(engine) as db:
        row = db.get(MSOCConfig, 1)
        if row is None:
            row = MSOCConfig(id=1, db_path=DEFAULT_DB_PATH, poll_interval=3)
            db.add(row)
        for key, value in values.items():
            setattr(row, key, value)
        db.commit()
    with _state_lock:
        for key, value in values.items():
            if key in _state:
                _state[key] = value


def _send_markdown(webhook, content):
    global _last_send_started
    if not webhook:
        raise RuntimeError("企业微信 Webhook 未配置")
    if not webhook.startswith("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?"):
        raise ValueError("仅允许企业微信官方机器人 Webhook")
    with _send_lock:
        remaining = 3.0 - (time.monotonic() - _last_send_started)
        if _last_send_started and remaining > 0:
            time.sleep(remaining)
        _last_send_started = time.monotonic()
        with httpx.Client(timeout=20) as client:
            response = client.post(webhook, json={"msgtype": "markdown", "markdown": {"content": content}})
            response.raise_for_status()
            result = response.json()
    if result.get("errcode") != 0:
        raise RuntimeError("企业微信返回错误：" + str(result.get("errmsg", result.get("errcode"))))
    return True


def _notify_error(message):
    global _error_signature, _error_notified_at
    signature = str(message)[:500]
    now = time.monotonic()
    if signature == _error_signature and now - _error_notified_at < 900:
        return
    _error_signature, _error_notified_at = signature, now
    try:
        row = _config()
        if row.error_enabled and row.error_webhook:
            content = "## MSOC 监控异常告警\n> **时间**：" + _now() + "\n> **异常**：\n" + signature[:2500]
            _send_markdown(row.error_webhook, content)
    except Exception:
        log.exception("MSOC error notification failed")


def _readonly_connection(path):
    db_path = Path(path).expanduser().resolve()
    if not db_path.is_file():
        raise FileNotFoundError("找不到 SCC_TT 数据库：" + str(db_path))
    uri = "file:" + quote(str(db_path), safe="/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _month_tables(conn):
    names = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name GLOB 'webhook_[0-9][0-9][0-9][0-9][0-9][0-9]'"
    ).fetchall()
    result = []
    for item in names:
        month = item["name"].replace("webhook_", "", 1)
        if re.fullmatch(r"20\d{4}", month) and 1 <= int(month[4:]) <= 12:
            result.append(month)
    return sorted(result)


def _read_pending(path, cursor_month, cursor_id, limit=MAX_BATCH_ROWS):
    conn = _readonly_connection(path)
    try:
        months = _month_tables(conn)
        result = []
        for month in months:
            if cursor_month and month < cursor_month:
                continue
            table = "webhook_" + month
            columns = {x["name"] for x in conn.execute('PRAGMA table_info("' + table + '")')}
            if not {"id", "content"}.issubset(columns):
                continue
            time_column = "received_at" if "received_at" in columns else ("time" if "time" in columns else "")
            selected_time = '"' + time_column + '"' if time_column else "''"
            after_id = cursor_id if month == cursor_month else 0
            rows = conn.execute(
                'SELECT id, content, ' + selected_time + ' AS received_at FROM "' + table + '" '
                "WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after_id, max(1, limit - len(result))),
            ).fetchall()
            for item in rows:
                result.append({"month": month, "id": int(item["id"]),
                               "content": item["content"], "received_at": item["received_at"] or ""})
            if len(result) >= limit:
                break
        return months, result
    finally:
        conn.close()


def _format_row(row):
    raw = row["content"]
    try:
        raw = json.dumps(json.loads(raw), ensure_ascii=False, indent=2)
    except Exception:
        raw = str(raw)
    raw_bytes = raw.encode("utf-8")
    if len(raw_bytes) > 2200:
        raw = raw_bytes[:2200].decode("utf-8", "ignore") + "\n……（内容过长，完整内容请在 MSOC 日志页面查看）"
    return ("### 日志 #" + str(row["id"]) + " · " + row["month"] + "\n"
            "> **接收时间**：" + (row["received_at"] or "未知") + "\n"
            "JSON 原文：\n" + raw)


def _send_rows(rows, webhook):
    groups, current, current_len = [], [], 0
    for row in rows:
        item = _format_row(row)
        item_bytes = len(item.encode("utf-8"))
        if current and (len(current) >= 4 or current_len + item_bytes > MAX_MESSAGE_BYTES - 200):
            groups.append(current)
            current, current_len = [], 0
        current.append((row, item))
        current_len += item_bytes
    if current:
        groups.append(current)
    sent = 0
    for group in groups:
        body = "## MSOC 新增日志（" + str(len(group)) + " 条）\n\n"
        body += "\n\n".join(item for _, item in group)
        _send_markdown(webhook, body)
        last = group[-1][0]
        with Session(engine) as db:
            config = db.get(MSOCConfig, 1)
            config.cursor_month = last["month"]
            config.cursor_id = last["id"]
            config.last_push = _now()
            config.total_pushed = (config.total_pushed or 0) + len(group)
            config.last_error = ""
            db.commit()
        sent += len(group)
    return sent


def _poll_once_impl():
    row = _config()
    if not row.enabled:
        return {"skipped": True, "reason": "MSOC 监控未启用", "count": 0}
    if not row.wecom_enabled or not row.wecom_webhook:
        raise RuntimeError("请先启用并配置 MSOC 正常推送机器人")
    months, pending = _read_pending(row.db_path, row.cursor_month, row.cursor_id)
    now = _now()
    if not row.initialized:
        if months:
            latest = months[-1]
            conn = _readonly_connection(row.db_path)
            try:
                maximum = conn.execute('SELECT COALESCE(MAX(id),0) FROM "webhook_' + latest + '"').fetchone()[0]
            finally:
                conn.close()
            _save_status(cursor_month=latest, cursor_id=int(maximum or 0),
                         initialized=True, last_query=now, last_error="")
            return {"initialized": True, "baseline_month": latest,
                    "baseline_id": int(maximum or 0), "count": 0}
        _save_status(initialized=True, last_query=now, last_error="")
        return {"initialized": True, "count": 0}
    _save_status(last_query=now, last_error="")
    found = sent = 0
    while pending:
        found += len(pending)
        sent += _send_rows(pending, row.wecom_webhook)
        cursor = _config()
        _, pending = _read_pending(row.db_path, cursor.cursor_month, cursor.cursor_id)
    with _state_lock:
        _state["last_query_count"] = found
        _state["total_pushed"] = _config().total_pushed
    return {"count": found, "pushed": sent}


def poll_once():
    with _poll_lock:
        return _poll_once_impl()


def _monitor_loop():
    global _error_signature
    log.info("MSOC monitor worker started")
    while not _stop.is_set():
        try:
            row = _config()
            if not row.enabled:
                _wakeup.wait(5)
                _wakeup.clear()
                continue
            with _state_lock:
                _state["running"] = True
            try:
                result = poll_once()
                log.info("MSOC polling completed: %s", result)
                _error_signature = ""
                with _state_lock:
                    _state["last_error"] = None
                    _state["last_query_count"] = result.get("count", 0)
            except Exception as exc:
                message = str(exc)[:2500]
                log.exception("MSOC polling failed")
                _save_status(last_error=message)
                with _state_lock:
                    _state["last_error"] = message
                _notify_error(message)
            finally:
                with _state_lock:
                    _state["running"] = False
            _wakeup.wait(max(1, row.poll_interval * 60))
            _wakeup.clear()
        except Exception:
            log.exception("MSOC monitor loop crashed")
            _wakeup.wait(10)
            _wakeup.clear()
    log.info("MSOC monitor worker stopped")


def start_monitor():
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _wakeup.set()
    _thread = threading.Thread(target=_monitor_loop, name="msoc-db-monitor", daemon=True)
    _thread.start()


def stop_monitor():
    _stop.set()
    _wakeup.set()
    if _thread:
        _thread.join(timeout=10)


def wake_monitor():
    _wakeup.set()


class MSOCConfigInput(BaseModel):
    enabled: bool = False
    db_path: str = Field(default=DEFAULT_DB_PATH, min_length=1, max_length=1000)
    poll_interval: int = 3
    wecom_enabled: bool = False
    wecom_webhook: str = ""
    error_enabled: bool = False
    error_webhook: str = ""


def _validate_webhook(value, label):
    if value and not value.startswith("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?"):
        raise HTTPException(422, label + "仅允许企业微信官方机器人 Webhook")


@router.get("/config")
def get_config():
    return {"code": 0, "data": _config_data(_config())}


@router.put("/config")
def put_config(body: MSOCConfigInput):
    if body.poll_interval not in ALLOWED_INTERVALS:
        raise HTTPException(422, "查询间隔仅支持 1、3、5、10、15、30 分钟")
    _validate_webhook(body.wecom_webhook, "正常推送：")
    _validate_webhook(body.error_webhook, "异常告警：")
    with Session(engine) as db:
        row = db.get(MSOCConfig, 1)
        if row is None:
            row = MSOCConfig(id=1, db_path=DEFAULT_DB_PATH, poll_interval=3)
            db.add(row)
        if body.db_path != row.db_path:
            row.cursor_month, row.cursor_id, row.initialized = "", 0, False
        row.enabled = body.enabled
        row.db_path = body.db_path
        row.poll_interval = body.poll_interval
        row.wecom_enabled = body.wecom_enabled
        row.error_enabled = body.error_enabled
        if body.wecom_webhook:
            row.wecom_webhook = body.wecom_webhook
        if body.error_webhook:
            row.error_webhook = body.error_webhook
        db.commit()
    wake_monitor()
    return {"code": 0, "message": "配置已保存"}


@router.get("/status")
def get_status():
    row = _config()
    with _state_lock:
        state = dict(_state)
    return {"code": 0, "data": {**state, **_config_data(row),
                                 "worker_alive": bool(_thread and _thread.is_alive())}}


@router.post("/test")
def test_normal_push():
    row = _config()
    if not row.wecom_webhook:
        raise HTTPException(422, "请先保存正常推送 Webhook")
    try:
        _send_markdown(row.wecom_webhook, "## MSOC 正常推送测试\n> **状态**：连接成功\n> **时间**：" + _now())
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])
    return {"code": 0, "data": {"success": True}}


@router.post("/test-error")
def test_error_push():
    row = _config()
    if not row.error_webhook:
        raise HTTPException(422, "请先保存异常告警 Webhook")
    try:
        _send_markdown(row.error_webhook, "## MSOC 异常告警测试\n> **状态**：连接成功\n> **时间**：" + _now())
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])
    return {"code": 0, "data": {"success": True}}


@router.post("/poll")
def manual_poll():
    try:
        result = poll_once()
    except Exception as exc:
        _save_status(last_error=str(exc)[:2500])
        _notify_error(str(exc))
        raise HTTPException(502, str(exc)[:500])
    return {"code": 0, "data": result}


@router.post("/test-db")
def test_database_connection():
    row = _config()
    try:
        conn = _readonly_connection(row.db_path)
        try:
            months = _month_tables(conn)
            total = 0
            for month in months:
                total += conn.execute('SELECT COUNT(*) FROM "webhook_' + month + '"').fetchone()[0]
        finally:
            conn.close()
        return {"code": 0, "data": {"success": True, "db_path": row.db_path,
                                    "months": months, "total": total}}
    except Exception as exc:
        raise HTTPException(503, str(exc)[:500])


@router.get("/months")
def list_months():
    row = _config()
    try:
        conn = _readonly_connection(row.db_path)
        try:
            months = _month_tables(conn)
        finally:
            conn.close()
        return {"code": 0, "data": months}
    except Exception as exc:
        raise HTTPException(503, str(exc)[:500])


@router.get("/logs")
def list_logs(month: str = Query(default=""), page: int = Query(default=1, ge=1),
              size: int = Query(default=30, ge=1, le=100),
              q: str = Query(default="", max_length=500)):
    if month and not re.fullmatch(r"20\d{4}", month):
        raise HTTPException(422, "月份格式应为 YYYYMM")
    row = _config()
    try:
        conn = _readonly_connection(row.db_path)
        try:
            months = _month_tables(conn)
            if not month:
                month = months[-1] if months else ""
            if month not in months:
                return {"code": 0, "data": {"month": month, "months": months, "total": 0, "list": []}}
            table = "webhook_" + month
            where, args = "", []
            if q:
                where, args = " WHERE content LIKE ?", ["%" + q + "%"]
            total = conn.execute('SELECT COUNT(*) FROM "' + table + '"' + where, args).fetchone()[0]
            columns = {x["name"] for x in conn.execute('PRAGMA table_info("' + table + '")')}
            time_col = "received_at" if "received_at" in columns else ("time" if "time" in columns else "")
            selected_time = '"' + time_col + '"' if time_col else "''"
            rows = conn.execute(
                'SELECT id, content, ' + selected_time + ' AS received_at FROM "' + table + '"' + where +
                " ORDER BY id DESC LIMIT ? OFFSET ?",
                args + [size, (page - 1) * size],
            ).fetchall()
            data = [{"id": int(x["id"]), "content": x["content"],
                     "received_at": x["received_at"] or "", "month": month} for x in rows]
            return {"code": 0, "data": {"month": month, "months": months, "total": total,
                                        "page": page, "size": size, "list": data}}
        finally:
            conn.close()
    except Exception as exc:
        raise HTTPException(503, str(exc)[:500])


@router.get("/logs/{month}/{record_id}")
def get_log_detail(month: str, record_id: int):
    if not re.fullmatch(r"20\d{4}", month):
        raise HTTPException(422, "月份格式应为 YYYYMM")
    row = _config()
    try:
        conn = _readonly_connection(row.db_path)
        try:
            if month not in _month_tables(conn):
                raise HTTPException(404, "月份数据表不存在")
            table = "webhook_" + month
            record = conn.execute('SELECT * FROM "' + table + '" WHERE id=?', (record_id,)).fetchone()
            if not record:
                raise HTTPException(404, "日志不存在")
            return {"code": 0, "data": {key: record[key] for key in record.keys()}}
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, str(exc)[:500])
