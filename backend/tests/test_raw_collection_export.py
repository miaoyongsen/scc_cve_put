"""Raw collection audit snapshots: XLSX includes filtered items and extra CVEs."""
import os
os.environ.setdefault("API_TOKEN","test-only")

from io import BytesIO
from zipfile import ZipFile
from xml.etree import ElementTree as ET

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import core
from app.raw_export import build_raw_collection_xlsx


@pytest.fixture
def audit_db(monkeypatch):
    db=create_engine("sqlite:///:memory:",
        connect_args={"check_same_thread":False},poolclass=StaticPool)
    core.Base.metadata.create_all(db)
    monkeypatch.setattr(core,"engine",db)
    return db


def test_raw_collection_excel_includes_filtered_duplicates_and_additional_cves(audit_db):
    run_id=core.begin_run("测试采集")
    token=core._active_run.set(run_id)
    try:
        first=core.record_raw_item({
            "source":"Red Hat","title":"CVE-2026-12345 and CVE-2026-67890",
            "description":"Both CVEs affect this component.","cve":"CVE-2026-12345",
            "severity":"中危","disclosure":"2026-11-18",
            "url":"https://example.org/a"
        },source_type="Python")
        second=core.record_raw_item({
            "from":"RSS feed","title":"New finding","description":"CVE-2026-10001",
            "cve":"","severity":"未知","references":["https://example.org/b"]
        },source_type="RSS")
        core.update_raw_item(first,outcome="过滤：severity",reason="中危不推送")
        core.update_raw_item(second,outcome="重复",reason="已采集")
    finally:
        core._active_run.reset(token)
    with Session(audit_db) as db:
        rows=db.scalars(select(core.RawCollectionItem).where(
            core.RawCollectionItem.run_id==run_id).order_by(core.RawCollectionItem.id)).all()
        assert len(rows)==2
        result=build_raw_collection_xlsx(rows,run_id,"测试采集")
    with ZipFile(BytesIO(result)) as xlsx:
        assert xlsx.testzip() is None
        xml=xlsx.read("xl/worksheets/sheet1.xml")
        ET.fromstring(xml)
        text=xml.decode("utf-8")
        assert "CVE-2026-12345" in text
        assert "CVE-2026-67890" in text
        assert "CVE-2026-10001" in text
        assert "需检查：" in text
        assert "过滤：severity" in text
        assert "重复" in text
        assert "RSS feed" in text
        assert "原始JSON" in text
        assert xlsx.read("xl/worksheets/sheet2.xml").find(b"数据口径")>=0


def test_raw_excel_download_works_only_with_snapshot(audit_db):
    run_id=core.begin_run("测试采集")
    with pytest.raises(HTTPException) as error:
        core.download_collection_raw_xlsx(run_id)
    assert error.value.status_code==404
    token=core._active_run.set(run_id)
    try:
        core.record_raw_item({"from":"Github","title":"A","cve":"CVE-2026-87654",
                              "severity":"严重"},source_type="RSS")
    finally:
        core._active_run.reset(token)
    response=core.download_collection_raw_xlsx(run_id)
    assert response.media_type=="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    with Session(audit_db) as db:
        assert db.scalar(select(core.RawCollectionItem.run_id))==run_id


def test_raw_snapshot_follows_python_crawler_retention(audit_db,monkeypatch):
    monkeypatch.setattr(core,"CRAWLER_RUN_HISTORY_LIMIT",1)
    ids=[]
    for n in range(3):
        rid=core.begin_run("Python 爬虫")
        ids.append(rid)
        token=core._active_run.set(rid)
        try:
            core.record_raw_item({"title":"old"+str(n),"cve":"CVE-2026-12345"},
                                  source_type="Python")
        finally:
            core._active_run.reset(token)
        core.finish_run(rid,"完成",{})
    # prune explicitly with configured cap; no dangling raw snapshot rows.
    core.prune_collection_run_history(keep=1)
    with Session(audit_db) as db:
        saved=db.scalars(select(core.RawCollectionItem.run_id)).all()
        assert saved==[ids[-1]]
