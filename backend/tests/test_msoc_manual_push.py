"""Manual MSOC re-send is independent of the normal rolling time window."""
import os

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

os.environ.setdefault("API_TOKEN", "test-only")
from app import core, msoc_monitor


def test_manual_push_can_resend_sent_record_without_changing_original_sent_time(monkeypatch):
    local = create_engine("sqlite:///:memory:",
                          connect_args={"check_same_thread": False}, poolclass=StaticPool)
    core.Base.metadata.create_all(local)
    monkeypatch.setattr(msoc_monitor, "engine", local)
    monkeypatch.setattr(msoc_monitor, "_canonical_db_path", lambda value: value)
    config = type("Config", (), {
        "db_path": "source.db",
        "wecom_webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        "message_template": msoc_monitor.DEFAULT_MESSAGE_TEMPLATE,
    })()
    monkeypatch.setattr(msoc_monitor, "_config", lambda: config)
    delivered = []
    monkeypatch.setattr(msoc_monitor, "_send_markdown",
                        lambda webhook, body: delivered.append(body) or True)

    with Session(local) as db:
        db.add(msoc_monitor.MSOCDelivery(
            source_db="source.db", source_month="202611", source_id=99,
            content='{"ticket_identifier":"T-99","priority":"High","disposal":"告警详情：test"}',
            received_at="2026-11-26T09:00:00+08:00",
            sent=True, sent_at="2026-11-26T09:01:00+08:00",
            attempt_count=1,
        ))
        db.commit()
    result = msoc_monitor.manually_push_log("202611", 1)
    assert result["data"]["success"] is True
    assert len(delivered) == 1
    assert "T-99" in delivered[0]
    with Session(local) as db:
        row = db.get(msoc_monitor.MSOCDelivery, 1)
        assert row.sent_at == "2026-11-26T09:01:00+08:00"
        log = db.scalar(select(msoc_monitor.MSOCManualPush))
        assert log.status == "成功"


def test_manual_push_marks_unsent_log_as_sent(monkeypatch):
    local = create_engine("sqlite:///:memory:",
                          connect_args={"check_same_thread": False}, poolclass=StaticPool)
    core.Base.metadata.create_all(local)
    monkeypatch.setattr(msoc_monitor, "engine", local)
    monkeypatch.setattr(msoc_monitor, "_canonical_db_path", lambda value: value)
    config = type("Config", (), {
        "db_path": "source.db",
        "wecom_webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        "message_template": msoc_monitor.DEFAULT_MESSAGE_TEMPLATE,
    })()
    monkeypatch.setattr(msoc_monitor, "_config", lambda: config)
    monkeypatch.setattr(msoc_monitor, "_send_markdown", lambda webhook, body: True)
    with Session(local) as db:
        db.add(msoc_monitor.MSOCDelivery(
            source_db="source.db", source_month="202611", source_id=100,
            content="{}", received_at="2026-11-26T09:00:00+08:00",
            sent=False, attempt_count=0,
        ))
        db.commit()
    msoc_monitor.manually_push_log("202611", 1)
    with Session(local) as db:
        row = db.get(msoc_monitor.MSOCDelivery, 1)
        assert row.sent is True
        assert row.sent_at
