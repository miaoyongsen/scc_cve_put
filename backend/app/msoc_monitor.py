"""Independent MSOC monitor.

SCC_TT is a read-only source. MSOC delivery state and the log list are stored
in SCC_CVE's own database. Each poll only reads the configured recent window;
there is no historical catch-up after downtime.
"""
import json
import logging
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Integer, String, Text, UniqueConstraint, Index, select, func
from sqlalchemy.orm import Mapped, Session, mapped_column

from .core import Base, engine, auth

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/msoc", dependencies=[Depends(auth)])
DEFAULT_DB_PATH = "/home/msocadmin/SCC_TT/data/webhook.db"
ALLOWED_INTERVALS = (1, 3, 5, 10, 15, 30)
MAX_MESSAGE_BYTES = 3800
SHANGHAI = ZoneInfo("Asia/Shanghai")

_send_lock = threading.Lock()
_last_send_started = 0.0
_poll_lock = threading.Lock()
_stop = threading.Event()
_wakeup = threading.Event()
_thread = None
_state_lock = threading.Lock()
_state = {
    "running": False,
    "last_query_count": 0,
    "last_captured_count": 0,
    "last_error": None,
}
_error_signature = ""
_error_notified_at = 0.0


class MSOCConfig(Base):
    __tablename__ = "msoc_monitor_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    db_path: Mapped[str] = mapped_column(String(1000), default=DEFAULT_DB_PATH)
    # This is both the polling cadence and the look-back window.
    poll_interval: Mapped[int] = mapped_column(Integer, default=3)
    wecom_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    wecom_webhook: Mapped[str] = mapped_column(String(1000), default="")
    error_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    error_webhook: Mapped[str] = mapped_column(String(1000), default="")
    # Retained for compatibility with the first version; no longer used as a cursor.
    cursor_month: Mapped[str] = mapped_column(String(6), default="")
    cursor_id: Mapped[int] = mapped_column(Integer, default=0)
    initialized: Mapped[bool] = mapped_column(Boolean, default=False)
    last_query: Mapped[str] = mapped_column(String(40), default="")
    last_push: Mapped[str] = mapped_column(String(40), default="")
    total_pushed: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(Text, default="")


class MSOCDelivery(Base):
    """SCC_CVE-owned copy and send state for one SCC_TT source record."""
    __tablename__ = "msoc_delivery_records"
    __table_args__ = (
        UniqueConstraint("source_db", "source_month", "source_id",
                         name="uq_msoc_source_record"),
        Index("idx_msoc_received_at", "source_month", "received_at"),
        Index("idx_msoc_sent", "sent"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_db: Mapped[str] = mapped_column(String(1000), nullable=False)
    source_month: Mapped[str] = mapped_column(String(6), nullable=False)
    source_id: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    received_at: Mapped[str] = mapped_column(String(50), default="")
    sent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str] = mapped_column(Text, default="")
    sent_at: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[str] = mapped_column(String(40), default="")


# Creates the new MSOC delivery table in SCC_CVE's database.
Base.metadata.create_all(engine)


def _now_dt():
    return datetime.now(SHANGHAI)


def _now():
    return _now_dt().isoformat(timespec="seconds")


def _config():
    with Session(engine) as db:
        row = db.get(MSOCConfig, 1)
        if row is None:
            row = MSOCConfig(id=1, db_path=DEFAULT_DB_PATH, poll_interval=3)
            db.add(row)
            db.commit()
            db.refresh(row)
        return row


def _canonical_db_path(path):
    return str(Path(path).expanduser().resolve())


def _config_data(row):
    return {
        "enabled": bool(row.enabled),
        "db_path": row.db_path,
        "poll_interval": row.poll_interval,
        "wecom_enabled": bool(row.wecom_enabled),
        "has_wecom_webhook": bool(row.wecom_webhook),
        "error_enabled": bool(row.error_enabled),
        "has_error_webhook": bool(row.error_webhook),
        "last_query": row.last_query,
        "last_push": row.last_push,
        "last_error": row.last_error,
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


def _delivery_counts(source_db):
    with Session(engine) as db:
        total = db.scalar(
            select(func.count()).select_from(MSOCDelivery).where(MSOCDelivery.source_db == source_db)
        ) or 0
        sent = db.scalar(
            select(func.count()).select_from(MSOCDelivery).where(
                MSOCDelivery.source_db == source_db, MSOCDelivery.sent.is_(True)
            )
        ) or 0
    return {"total_records": int(total), "sent_records": int(sent),
            "unsent_records": int(total - sent)}


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
            response = client.post(
                webhook,
                json={"msgtype": "markdown", "markdown": {"content": content}},
            )
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
            content = (
                "## MSOC 监控异常告警\n"
                "> **时间**：" + _now() + "\n"
                "> **异常**：\n" + signature[:2500]
            )
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


def _month_range(start_dt, end_dt):
    months = []
    year, month = start_dt.year, start_dt.month
    while (year, month) <= (end_dt.year, end_dt.month):
        months.append("%04d%02d" % (year, month))
        month += 1
        if month == 13:
            year, month = year + 1, 1
    return months


def _existing_month_tables(conn):
    names = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name GLOB 'webhook_[0-9][0-9][0-9][0-9][0-9][0-9]'"
    ).fetchall()
    return {
        item["name"].replace("webhook_", "", 1)
        for item in names
        if re.fullmatch(r"20\d{4}", item["name"].replace("webhook_", "", 1))
        and 1 <= int(item["name"][-2:]) <= 12
    }


def _read_recent_source(path, minutes):
    """Read only records whose SCC_TT received_at is in the last N minutes."""
    end_dt = _now_dt()
    start_dt = end_dt - timedelta(minutes=minutes)
    start_text = start_dt.isoformat(timespec="milliseconds")
    end_text = end_dt.isoformat(timespec="milliseconds")
    source_db = _canonical_db_path(path)
    conn = _readonly_connection(source_db)
    records = []
    try:
        existing = _existing_month_tables(conn)
        for month in _month_range(start_dt, end_dt):
            if month not in existing:
                continue
            table = "webhook_" + month
            columns = {item["name"] for item in conn.execute('PRAGMA table_info("' + table + '")')}
            required = {"id", "content", "received_at"}
            if not required.issubset(columns):
                raise RuntimeError(
                    table + " 表结构不符合预期，需要 id、content、received_at 三列"
                )
            cursor = conn.execute(
                'SELECT id, content, received_at FROM "' + table + '" '
                "WHERE received_at >= ? AND received_at <= ? "
                "ORDER BY received_at ASC, id ASC",
                (start_text, end_text),
            )
            while True:
                batch = cursor.fetchmany(500)
                if not batch:
                    break
                for item in batch:
                    records.append({
                        "source_db": source_db,
                        "source_month": month,
                        "source_id": int(item["id"]),
                        "content": item["content"],
                        "received_at": item["received_at"] or "",
                    })
        return source_db, start_text, end_text, records
    finally:
        conn.close()


def _capture_records(source_db, records):
    """Persist all seen source records in SCC_CVE, initially marked unsent."""
    if not records:
        return 0, []
    captured = 0
    unsent = []
    by_month = {}
    for record in records:
        by_month.setdefault(record["source_month"], []).append(record)

    with Session(engine) as db:
        for month, month_records in by_month.items():
            ids = [item["source_id"] for item in month_records]
            existing_ids = set(db.scalars(
                select(MSOCDelivery.source_id).where(
                    MSOCDelivery.source_db == source_db,
                    MSOCDelivery.source_month == month,
                    MSOCDelivery.source_id.in_(ids),
                )
            ).all())
            for item in month_records:
                if item["source_id"] not in existing_ids:
                    db.add(MSOCDelivery(
                        source_db=source_db,
                        source_month=month,
                        source_id=item["source_id"],
                        content=item["content"],
                        received_at=item["received_at"],
                        sent=False,
                        attempt_count=0,
                        last_error="",
                        sent_at="",
                        created_at=_now(),
                    ))
                    captured += 1
            db.flush()
            rows = db.scalars(
                select(MSOCDelivery).where(
                    MSOCDelivery.source_db == source_db,
                    MSOCDelivery.source_month == month,
                    MSOCDelivery.source_id.in_(ids),
                    MSOCDelivery.sent.is_(False),
                ).order_by(MSOCDelivery.received_at.asc(), MSOCDelivery.source_id.asc())
            ).all()
            for row in rows:
                unsent.append({
                    "id": row.id,
                    "source_month": row.source_month,
                    "source_id": row.source_id,
                    "content": row.content,
                    "received_at": row.received_at,
                    "attempt_count": row.attempt_count,
                })
        db.commit()
    unsent.sort(key=lambda item: (item["received_at"], item["source_month"], item["source_id"]))
    return captured, unsent


def _format_delivery(row):
    raw = row["content"]
    try:
        raw = json.dumps(json.loads(raw), ensure_ascii=False, indent=2)
    except Exception:
        raw = str(raw)
    raw_bytes = raw.encode("utf-8")
    if len(raw_bytes) > 2100:
        raw = raw_bytes[:2100].decode("utf-8", "ignore") + "\n……（内容过长，完整内容请在 MSOC 日志页面查看）"
    return (
        "### 日志 #" + str(row["source_id"]) + " · " + row["source_month"] + "\n"
        "> **接收时间**：" + (row["received_at"] or "未知") + "\n"
        "JSON 原文：\n" + raw
    )


def _send_deliveries(deliveries, webhook):
    """Send only unsent records from this poll's current time window."""
    if not deliveries:
        return 0
    groups, current, current_bytes = [], [], 0
    for row in deliveries:
        item = _format_delivery(row)
        item_bytes = len(item.encode("utf-8"))
        if current and (len(current) >= 4 or current_bytes + item_bytes > MAX_MESSAGE_BYTES - 200):
            groups.append(current)
            current, current_bytes = [], 0
        current.append((row, item))
        current_bytes += item_bytes
    if current:
        groups.append(current)

    sent_count = 0
    for group in groups:
        group_rows = [item[0] for item in group]
        with Session(engine) as db:
            for item in group_rows:
                delivery = db.get(MSOCDelivery, item["id"])
                if delivery and not delivery.sent:
                    delivery.attempt_count = (delivery.attempt_count or 0) + 1
            db.commit()

        body = "## MSOC 新增日志（" + str(len(group)) + " 条）\n\n"
        body += "\n\n".join(item[1] for item in group)
        try:
            _send_markdown(webhook, body)
        except Exception as exc:
            error_text = str(exc)[:2000]
            with Session(engine) as db:
                for item in group_rows:
                    delivery = db.get(MSOCDelivery, item["id"])
                    if delivery and not delivery.sent:
                        delivery.last_error = error_text
                db.commit()
            raise

        sent_at = _now()
        with Session(engine) as db:
            for item in group_rows:
                delivery = db.get(MSOCDelivery, item["id"])
                if delivery:
                    delivery.sent = True
                    delivery.sent_at = sent_at
                    delivery.last_error = ""
            db.commit()
        _save_status(last_push=sent_at)
        sent_count += len(group_rows)
    return sent_count


def _poll_once_impl():
    config = _config()
    if not config.enabled:
        return {"skipped": True, "reason": "MSOC 监控未启用", "count": 0, "pushed": 0}

    source_db, start_text, end_text, source_records = _read_recent_source(
        config.db_path, config.poll_interval
    )
    captured, unsent = _capture_records(source_db, source_records)
    _save_status(last_query=_now(), last_error="")

    with _state_lock:
        _state["last_query_count"] = len(source_records)
        _state["last_captured_count"] = captured

    pushed = 0
    if config.wecom_enabled:
        if not config.wecom_webhook:
            raise RuntimeError("正常推送已启用，但尚未配置企业微信 Webhook")
        pushed = _send_deliveries(unsent, config.wecom_webhook)

    counts = _delivery_counts(source_db)
    return {
        "count": len(source_records),
        "captured": captured,
        "pushed": pushed,
        "unsent": counts["unsent_records"],
        "window_start": start_text,
        "window_end": end_text,
        **counts,
    }


def poll_once():
    with _poll_lock:
        return _poll_once_impl()


def _monitor_loop():
    global _error_signature
    log.info("MSOC recent-window monitor worker started")
    while not _stop.is_set():
        try:
            config = _config()
            if not config.enabled:
                _wakeup.wait(5)
                _wakeup.clear()
                continue

            with _state_lock:
                _state["running"] = True
            try:
                result = poll_once()
                log.info("MSOC recent-window poll completed: %s", result)
                _error_signature = ""
                with _state_lock:
                    _state["last_error"] = None
            except Exception as exc:
                message = str(exc)[:2500]
                log.exception("MSOC polling or push failed")
                _save_status(last_error=message)
                with _state_lock:
                    _state["last_error"] = message
                _notify_error(message)
            finally:
                with _state_lock:
                    _state["running"] = False

            _wakeup.wait(max(1, config.poll_interval * 60))
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
    config = _config()
    source_db = _canonical_db_path(config.db_path)
    with _state_lock:
        state = dict(_state)
    counts = _delivery_counts(source_db)
    return {
        "code": 0,
        "data": {
            **_config_data(config),
            **state,
            **counts,
            "worker_alive": bool(_thread and _thread.is_alive()),
        },
    }


@router.post("/test")
def test_normal_push():
    config = _config()
    if not config.wecom_webhook:
        raise HTTPException(422, "请先保存正常推送 Webhook")
    try:
        _send_markdown(
            config.wecom_webhook,
            "## MSOC 正常推送测试\n> **状态**：连接成功\n> **时间**：" + _now(),
        )
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])
    return {"code": 0, "data": {"success": True}}


@router.post("/test-error")
def test_error_push():
    config = _config()
    if not config.error_webhook:
        raise HTTPException(422, "请先保存异常告警 Webhook")
    try:
        _send_markdown(
            config.error_webhook,
            "## MSOC 异常告警测试\n> **状态**：连接成功\n> **时间**：" + _now(),
        )
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])
    return {"code": 0, "data": {"success": True}}


@router.post("/poll")
def manual_poll():
    try:
        result = poll_once()
        return {"code": 0, "data": result}
    except Exception as exc:
        message = str(exc)[:2500]
        _save_status(last_error=message)
        with _state_lock:
            _state["last_error"] = message
        _notify_error(message)
        raise HTTPException(502, message[:500])


@router.post("/test-db")
def test_database_connection():
    config = _config()
    try:
        conn = _readonly_connection(config.db_path)
        try:
            months = sorted(_existing_month_tables(conn))
            total = 0
            for month in months:
                table = "webhook_" + month
                columns = {item["name"] for item in conn.execute('PRAGMA table_info("' + table + '")')}
                if not {"id", "content", "received_at"}.issubset(columns):
                    raise RuntimeError(table + " 表结构不符合预期，需要 id、content、received_at 三列")
                total += conn.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0]
        finally:
            conn.close()
        return {
            "code": 0,
            "data": {
                "success": True,
                "db_path": _canonical_db_path(config.db_path),
                "months": months,
                "total": int(total),
            },
        }
    except Exception as exc:
        raise HTTPException(503, str(exc)[:500])


@router.get("/months")
def list_months():
    config = _config()
    source_db = _canonical_db_path(config.db_path)
    with Session(engine) as db:
        months = db.scalars(
            select(MSOCDelivery.source_month)
            .where(MSOCDelivery.source_db == source_db)
            .distinct()
            .order_by(MSOCDelivery.source_month.desc())
        ).all()
    return {"code": 0, "data": list(months)}


def _delivery_dict(row):
    return {
        "id": row.id,
        "source_id": row.source_id,
        "source_month": row.source_month,
        "content": row.content,
        "received_at": row.received_at,
        "sent": bool(row.sent),
        "sent_at": row.sent_at,
        "attempt_count": row.attempt_count,
        "last_error": row.last_error,
    }


@router.get("/logs")
def list_logs(
    month: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=30, ge=1, le=100),
    q: str = Query(default="", max_length=500),
    sent: str = Query(default="all"),
):
    if month and not re.fullmatch(r"20\d{4}", month):
        raise HTTPException(422, "月份格式应为 YYYYMM")
    if sent not in ("all", "sent", "unsent"):
        raise HTTPException(422, "发送状态仅支持 all、sent、unsent")

    config = _config()
    source_db = _canonical_db_path(config.db_path)
    with Session(engine) as db:
        statement = select(MSOCDelivery).where(MSOCDelivery.source_db == source_db)
        if month:
            statement = statement.where(MSOCDelivery.source_month == month)
        if sent == "sent":
            statement = statement.where(MSOCDelivery.sent.is_(True))
        elif sent == "unsent":
            statement = statement.where(MSOCDelivery.sent.is_(False))
        if q:
            statement = statement.where(MSOCDelivery.content.like("%" + q + "%"))

        total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
        rows = db.scalars(
            statement.order_by(
                MSOCDelivery.received_at.desc(),
                MSOCDelivery.source_month.desc(),
                MSOCDelivery.source_id.desc(),
            ).offset((page - 1) * size).limit(size)
        ).all()
        months = db.scalars(
            select(MSOCDelivery.source_month)
            .where(MSOCDelivery.source_db == source_db)
            .distinct()
            .order_by(MSOCDelivery.source_month.desc())
        ).all()
        data = [_delivery_dict(item) for item in rows]
    return {
        "code": 0,
        "data": {
            "month": month,
            "months": list(months),
            "total": int(total),
            "page": page,
            "size": size,
            "list": data,
        },
    }


@router.get("/logs/{month}/{record_id}")
def get_log_detail(month: str, record_id: int):
    if not re.fullmatch(r"20\d{4}", month):
        raise HTTPException(422, "月份格式应为 YYYYMM")
    config = _config()
    source_db = _canonical_db_path(config.db_path)
    with Session(engine) as db:
        row = db.scalar(
            select(MSOCDelivery).where(
                MSOCDelivery.id == record_id,
                MSOCDelivery.source_db == source_db,
                MSOCDelivery.source_month == month,
            )
        )
        if row is None:
            raise HTTPException(404, "MSOC 日志不存在")
        return {"code": 0, "data": _delivery_dict(row)}
