"""MSOC history catch-up must never trigger historic WeCom pushes."""
import os
import sqlite3
from datetime import datetime, timedelta
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

os.environ.setdefault("API_TOKEN", "test-only")
from app import core, msoc_monitor


def test_msoc_backfills_older_records_but_only_pushes_current_window(tmp_path, monkeypatch):
    source=tmp_path / "webhook.db"
    now=msoc_monitor._now_dt()
    month=now.strftime("%Y%m")
    older=(now-timedelta(days=2)).isoformat(timespec="milliseconds")
    recent=(now-timedelta(seconds=10)).isoformat(timespec="milliseconds")
    with sqlite3.connect(source) as db:
        db.execute(f'CREATE TABLE "webhook_{month}" (id INTEGER PRIMARY KEY, content TEXT, received_at TEXT)')
        db.executemany(f'INSERT INTO "webhook_{month}" VALUES (?, ?, ?)',
                       [(1,'{"older":true}',older),(2,'{"recent":true}',recent)])
        db.commit()

    local=create_engine("sqlite:///:memory:",
        connect_args={"check_same_thread":False},poolclass=StaticPool)
    core.Base.metadata.create_all(local)
    monkeypatch.setattr(msoc_monitor,"engine",local)
    monkeypatch.setattr(msoc_monitor,"_config",lambda: type("Config",(),{
        "enabled":True,"db_path":str(source),"poll_interval":1,
        "wecom_enabled":True,"wecom_webhook":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test"
    })())
    monkeypatch.setattr(msoc_monitor,"_save_status",lambda **kwargs:None)
    pushed=[]
    monkeypatch.setattr(msoc_monitor,"_send_markdown",
                        lambda webhook,body:pushed.append(body) or True)
    result=msoc_monitor._poll_once_impl()
    assert result["count"]==1
    assert result["backfilled"]==1
    assert result["captured"]==2
    assert result["pushed"]==1
    assert len(pushed)==1
    assert '"recent":true' in pushed[0]
    assert '"older":true' not in pushed[0]
    with Session(local) as db:
        rows=db.scalars(select(msoc_monitor.MSOCDelivery).order_by(
            msoc_monitor.MSOCDelivery.source_id)).all()
        assert len(rows)==2
        assert rows[0].source_id==1 and rows[0].sent is False
        assert rows[1].source_id==2 and rows[1].sent is True
    # Repeating synchronization is idempotent, and history is never pushed.
    pushed.clear()
    result=msoc_monitor._poll_once_impl()
    assert result["backfilled"]==0
    assert result["captured"]==0
    assert pushed==[]
