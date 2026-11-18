"""Manual CVE lookup and explicit WeCom delivery flow."""
import os

os.environ.setdefault("API_TOKEN", "test-only")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import core, manual_cve_push as manual, notification_digest, notifications, ai_config


@pytest.fixture
def local_db(monkeypatch):
    local=create_engine("sqlite:///:memory:",
        connect_args={"check_same_thread":False},poolclass=StaticPool)
    core.Base.metadata.create_all(local)
    monkeypatch.setattr(manual,"engine",local)
    monkeypatch.setattr(core,"engine",local)
    monkeypatch.setattr(manual,"log_run",lambda *args,**kwargs:None)
    monkeypatch.setattr(notification_digest,"log_run",lambda *args,**kwargs:None)
    monkeypatch.setattr(notifications,"mark_wecom_delivered",lambda items:None)
    monkeypatch.setattr(ai_config,"ai_enabled",lambda:False)
    manual._lookup_cache.clear()
    config={
        "wecom_enabled":True,
        "wecom_webhook":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        "message_template":"## {title}\n> **编号**：{cve}\n> **等级**：{severity}\n> **来源**：{source}",
        "article_template":""
    }
    monkeypatch.setattr(manual,"current",lambda:config)
    monkeypatch.setattr(notification_digest,"current",lambda:config)
    monkeypatch.setattr("app.push_config.current",lambda:config)
    return local


def _mock_nvd(monkeypatch):
    calls=[]
    class Response:
        status_code=200
        def raise_for_status(self):
            return None
        def json(self):
            return {"vulnerabilities":[{"cve":{
                "id":"CVE-2026-12345",
                "descriptions":[{"lang":"en","value":"Example vulnerability in a server application."}],
                "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.4}}]},
                "references":[{"url":"https://vendor.example/advisory"}],
                "published":"2026-11-18T00:00:00.000",
            }}]}
    def request(*args,**kwargs):
        calls.append(kwargs.get("params",{}))
        return Response()
    monkeypatch.setattr(manual.httpx,"get",request)
    return calls


def test_manual_lookup_then_queued_only_delivers_in_next_digest(local_db,monkeypatch):
    calls=_mock_nvd(monkeypatch)
    result=manual.lookup_manual_cve("cve-2026-12345")["data"]
    assert result["title"]=="Example vulnerability in a server application."
    assert result["severity"]=="高危"
    assert result["ready"] is True
    assert len(calls)==1

    sent=[]
    monkeypatch.setattr(notification_digest,"send_wecom_markdown",
        lambda body,url=None:sent.append(body) or True)
    queued=manual.queue_manual_cve(manual.CVEActionInput(cve="CVE-2026-12345"))
    assert queued["data"]["status"]=="queued"
    assert sent==[]
    assert len(calls)==1  # the confirmation reused the previewed metadata
    with pytest.raises(HTTPException) as err:
        manual.queue_manual_cve(manual.CVEActionInput(cve="CVE-2026-12345"))
    assert err.value.status_code==409

    token=notification_digest.begin_digest()
    try:
        outcome=notification_digest.flush_digest()
    finally:
        notification_digest.end_digest(token)
    assert outcome["notifications"]==1
    assert len(sent)==1
    assert "Example vulnerability in a server application" in sent[0]
    assert "CVE-2026-12345" in sent[0]
    with Session(local_db) as db:
        row=db.scalar(select(manual.ManualCVEQueue))
        assert row.status=="sent"
        assert row.sent_at is not None

    sent.clear()
    token=notification_digest.begin_digest()
    try:
        outcome=notification_digest.flush_digest()
    finally:
        notification_digest.end_digest(token)
    assert outcome["notifications"]==0
    assert sent==[]


def test_manual_immediate_send_clears_an_existing_queue(local_db,monkeypatch):
    _mock_nvd(monkeypatch)
    manual.lookup_manual_cve("CVE-2026-12345")
    manual.queue_manual_cve(manual.CVEActionInput(cve="CVE-2026-12345"))
    messages=[]
    monkeypatch.setattr(notifications,"send_wecom_markdown",
        lambda message,url=None:messages.append(message) or True)
    result=manual.send_manual_cve(manual.CVEActionInput(cve="CVE-2026-12345"))
    assert result["data"]["status"]=="sent"
    assert len(messages)==1
    assert "> **编号**：CVE-2026-12345" in messages[0]
    assert manual.pending_manual_entries()==[]


def test_unknown_severity_cannot_be_pushed(local_db,monkeypatch):
    _mock_nvd(monkeypatch)
    item={"key":"x","cve":"CVE-2026-12345","title":"Example","severity":"未知",
          "references":[],"from":"test","content_type":"vulnerability"}
    monkeypatch.setattr(manual,"resolve_cve",lambda _:item)
    assert manual.lookup_manual_cve("CVE-2026-12345")["data"]["ready"] is False
    for fn in (manual.queue_manual_cve,manual.send_manual_cve):
        with pytest.raises(HTTPException) as err:
            fn(manual.CVEActionInput(cve="CVE-2026-12345"))
        assert err.value.status_code==422


def test_invalid_manual_cve_is_rejected(local_db):
    with pytest.raises(HTTPException) as err:
        manual.lookup_manual_cve("CVE-2026-notvalid")
    assert err.value.status_code==422
