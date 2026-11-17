import os
os.environ.setdefault("API_TOKEN", "test-only")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import core, review, ai_config
from app.worker import upsert


@pytest.fixture
def isolated_db(monkeypatch):
    local_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    core.Base.metadata.create_all(local_engine)
    monkeypatch.setattr(core, "engine", local_engine)
    monkeypatch.setattr(review, "engine", local_engine)
    monkeypatch.setattr(review, "log_run", lambda *args, **kwargs: None)
    return local_engine


def test_review_edit_duplicate_gate_and_visibility(isolated_db, monkeypatch):
    with Session(isolated_db) as db:
        pending = core.Vulnerability(
            key="pending-one", title="Apache pending", cve="", severity="未知",
            source="test", content_type="vulnerability"
        )
        existing = core.Vulnerability(
            key="existing-one", title="Already published", cve="CVE-2026-12345",
            severity="高危", source="test", content_type="vulnerability"
        )
        db.add_all([pending, existing])
        db.flush()
        pending_id = pending.id
        db.add(review.Review(vulnerability_id=pending_id, status="pending", matched_keyword="缺少CVE"))
        db.commit()

    def visible_ids():
        data = core.list_vulnerabilities(sort_by="first_seen")["data"]["list"]
        return {item["id"] for item in data}

    assert pending_id not in visible_ids()

    with pytest.raises(HTTPException) as error:
        review.approve(pending_id)
    assert error.value.status_code == 422

    with pytest.raises(HTTPException) as error:
        review.edit_pending(pending_id, review.ReviewEditInput(
            cve="cve-2026-12345", severity="高危"
        ))
    assert error.value.status_code == 409

    result = review.edit_pending(pending_id, review.ReviewEditInput(
        cve="CVE-2026-23456", severity="高危"
    ))
    assert result["data"]["ready"] is True
    assert pending_id not in visible_ids()

    # Source refresh must not erase values filled out manually.
    with Session(isolated_db) as db:
        upsert(db, {
            "key": "pending-one", "title": "Apache pending", "severity": "未知",
            "cve": "", "description": "", "references": [], "tags": [],
            "content_type": "vulnerability",
        }, True)
        refreshed = db.get(core.Vulnerability, pending_id)
        assert refreshed.cve == "CVE-2026-23456"
        assert refreshed.severity == "高危"

    from app import notification_digest, notifications
    monkeypatch.setattr(notification_digest, "engine", isolated_db)
    monkeypatch.setattr(notifications, "engine", isolated_db, raising=False)
    monkeypatch.setattr("app.push_config.current", lambda: {
        "wecom_enabled": True, "wecom_webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        "message_template": "## {title}\\n> {cve} {severity}",
        "article_template": "",
    })
    sent=[]
    monkeypatch.setattr(notification_digest, "send_wecom_markdown",
                        lambda content, url=None: sent.append(content) or True)
    monkeypatch.setattr(notifications, "mark_wecom_delivered",
                        lambda items: None)
    monkeypatch.setattr(notification_digest, "log_run", lambda *args, **kwargs: None)
    # Manual confirmation only queues, without contacting WeCom.
    queued=review.approve(pending_id)
    assert queued["data"]["status"]=="queued"
    assert sent==[]
    assert pending_id not in visible_ids()
    with Session(isolated_db) as db:
        assert db.scalar(select(review.Review.status).where(
            review.Review.vulnerability_id == pending_id
        )) == "queued"
        assert db.scalar(select(review.Review.manual_fields).where(
            review.Review.vulnerability_id == pending_id
        )) is True
    # The next collection digest delivers even when it has no new RSS items.
    token=notification_digest.begin_digest()
    try:
        delivery=notification_digest.flush_digest()
        assert delivery["notifications"]==1
    finally:
        notification_digest.end_digest(token)
    assert len(sent)==1
    assert pending_id in visible_ids()
    with Session(isolated_db) as db:
        assert db.scalar(select(review.Review.status).where(
            review.Review.vulnerability_id == pending_id
        )) == "approved"


def test_unknown_severity_not_approvable(isolated_db):
    with Session(isolated_db) as db:
        pending = core.Vulnerability(
            key="missing-grade", title="Incomplete", cve="CVE-2026-98765",
            severity="未知", source="test"
        )
        db.add(pending)
        db.flush()
        pending_id = pending.id
        db.add(review.Review(vulnerability_id=pending_id, status="pending", matched_keyword="等级未知"))
        db.commit()

    with pytest.raises(HTTPException) as error:
        review.approve(pending_id)
    assert error.value.status_code == 422


def test_failed_next_digest_keeps_review_queued(isolated_db, monkeypatch):
    from app import notification_digest
    with Session(isolated_db) as db:
        vuln=core.Vulnerability(key="retry-item",title="Test retry",cve="CVE-2026-88888",
                                severity="高危",source="test")
        db.add(vuln)
        db.flush()
        vuln_id=vuln.id
        db.add(review.Review(vulnerability_id=vuln_id,status="pending"))
        db.commit()
    review.approve(vuln_id)
    monkeypatch.setattr("app.push_config.current", lambda: {
        "wecom_enabled": True,"wecom_webhook":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        "message_template":"## {title}\\n> {cve} {severity}\\n\\n",
        "article_template":"",
    })
    monkeypatch.setattr(notification_digest, "log_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(notification_digest, "send_wecom_markdown",
                        lambda content,url=None: False)
    token=notification_digest.begin_digest()
    try:
        result=notification_digest.flush_digest()
    finally:
        notification_digest.end_digest(token)
    assert result["notifications"]==0
    assert result["errors"]
    with Session(isolated_db) as db:
        assert db.scalar(select(review.Review.status).where(
            review.Review.vulnerability_id==vuln_id
        ))=="queued"


def test_save_review_with_only_known_severity(isolated_db):
    with Session(isolated_db) as db:
        vuln=core.Vulnerability(key="severity-only",title="Apache no CVE",cve="",severity="未知")
        db.add(vuln)
        db.flush()
        vid=vuln.id
        db.add(review.Review(vulnerability_id=vid,status="pending"))
        db.commit()
    updated=review.edit_pending(vid,review.ReviewEditInput(cve="",severity="中危"))
    assert updated["data"]["severity"]=="中危"
    assert updated["data"]["ready"] is False
    with Session(isolated_db) as db:
        assert db.get(core.Vulnerability,vid).cve==""
    with pytest.raises(HTTPException) as error:
        review.approve(vid)
    assert error.value.status_code==422


def test_save_review_with_only_cve(isolated_db):
    with Session(isolated_db) as db:
        vuln=core.Vulnerability(key="cve-only",title="Apache unknown",cve="",severity="未知")
        db.add(vuln)
        db.flush()
        vid=vuln.id
        db.add(review.Review(vulnerability_id=vid,status="pending"))
        db.commit()
    updated=review.edit_pending(vid,review.ReviewEditInput(cve="cve-2026-54321",severity="未知"))
    assert updated["data"]["cve"]=="CVE-2026-54321"
    assert updated["data"]["ready"] is False


def test_edit_unchanged_cve_allows_severity_even_if_other_source_has_cve(isolated_db):
    with Session(isolated_db) as db:
        first=core.Vulnerability(key="first-src",title="Apache source one",
                                 cve="CVE-2026-77777",severity="未知")
        second=core.Vulnerability(key="second-src",title="Apache source two",
                                  cve="CVE-2026-77777",severity="高危")
        db.add_all([first,second])
        db.flush()
        vid=first.id
        db.add(review.Review(vulnerability_id=vid,status="pending"))
        db.commit()
    result=review.edit_pending(vid,review.ReviewEditInput(cve="CVE-2026-77777",severity="高危"))
    assert result["data"]["ready"] is True


def test_reject_review_edit_without_cve_and_known_severity(isolated_db):
    with Session(isolated_db) as db:
        vuln=core.Vulnerability(key="no-info",title="Apache missing fields",
                                cve="",severity="未知")
        db.add(vuln)
        db.flush()
        vid=vuln.id
        db.add(review.Review(vulnerability_id=vid,status="pending"))
        db.commit()
    with pytest.raises(HTTPException) as error:
        review.edit_pending(vid,review.ReviewEditInput(cve="",severity="未知"))
    assert error.value.status_code==422


def test_review_ai_runs_during_next_digest_not_during_confirmation(isolated_db, monkeypatch):
    from app import notification_digest, notifications, ai_config
    with Session(isolated_db) as db:
        vuln=core.Vulnerability(key="ai-reviewed",title="Apache reviewed vulnerability",
            cve="CVE-2026-65432",severity="高危",source="test")
        db.add(vuln)
        db.flush()
        vid=vuln.id
        db.add(review.Review(vulnerability_id=vid,status="pending"))
        db.commit()

    calls=[]
    monkeypatch.setattr("app.push_config.current",lambda:{
        "wecom_enabled":True,"wecom_webhook":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        "message_template":"## {title}\\n> {cve} {severity}",
        "article_template":"",
    })
    monkeypatch.setattr(ai_config,"ai_enabled",lambda: True)
    monkeypatch.setattr(ai_config,"analyze_intelligence",
        lambda item: calls.append(item["cve"]) or "模拟 AI 研判结果")
    monkeypatch.setattr(notification_digest,"log_run",lambda *args,**kwargs:None)
    monkeypatch.setattr(notifications,"mark_wecom_delivered",lambda *args,**kwargs:None)
    sent=[]
    monkeypatch.setattr(notification_digest,"send_wecom_markdown",
        lambda content,url=None: sent.append(content) or True)

    assert review.approve(vid)["data"]["status"]=="queued"
    assert calls==[]
    assert sent==[]
    token=notification_digest.begin_digest()
    try:
        result=notification_digest.flush_digest()
    finally:
        notification_digest.end_digest(token)
    assert result["notifications"]==1
    assert calls==["CVE-2026-65432"]
    assert len(sent)==1
    assert "> **AI研判：** 模拟 AI 研判结果" in sent[0]
    assert "> CVE-2026-65432 🟠 <font color=\"warning\">高危</font>\n> **AI研判：**" in sent[0]
    assert "\n\n> **AI研判：**" not in sent[0]
    assert "模拟 AI 研判结果" in sent[0]
    with Session(isolated_db) as db:
        assert db.scalar(select(review.Review.status).where(
            review.Review.vulnerability_id==vid))=="approved"
        saved=db.query(ai_config.AIAnalysis).filter_by(vuln_key="CVE-2026-65432").first()
        assert saved and saved.result=="模拟 AI 研判结果"


def test_ignored_review_remains_in_audit_list(isolated_db):
    with Session(isolated_db) as db:
        vuln=core.Vulnerability(key="ignored-for-audit",title="Apache ignored finding",
                                cve="CVE-2026-87654",severity="未知",source="test")
        db.add(vuln)
        db.flush()
        vid=vuln.id
        db.add(review.Review(vulnerability_id=vid,status="pending",matched_keyword="等级未知"))
        db.commit()

    result=review.reject(vid)
    assert result["message"]=="rejected"
    entries=review.pending_reviews()["data"]
    record=next(row for row in entries if row["id"]==vid)
    assert record["review_status"]=="rejected"
    assert record["reviewed_at"] is not None
    assert record["cve"]=="CVE-2026-87654"
    with Session(isolated_db) as db:
        assert db.get(core.Vulnerability,vid) is not None
    # Ignoring must never make the record reappear in regular monitoring.
    assert vid not in {row["id"] for row in core.list_vulnerabilities()["data"]["list"]}
    with pytest.raises(HTTPException) as error:
        review.approve(vid)
    assert error.value.status_code==409
