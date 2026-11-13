import os
os.environ.setdefault("API_TOKEN", "test-only")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import core, review
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

    monkeypatch.setattr(review, "send_vulnerability", lambda *args, **kwargs: {"wechat": True})
    review.approve(pending_id)
    assert pending_id in visible_ids()
    with Session(isolated_db) as db:
        assert db.scalar(select(review.Review.manual_fields).where(
            review.Review.vulnerability_id == pending_id
        )) is True


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
