"""Collection history retention must not affect intelligence data."""
import os
os.environ.setdefault("API_TOKEN", "test-only")

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from datetime import datetime, timezone
from app import core


def test_keep_latest_twenty_completed_runs_and_preserve_live_tasks(monkeypatch):
    engine=create_engine("sqlite:///:memory:",connect_args={"check_same_thread":False},poolclass=StaticPool)
    core.Base.metadata.create_all(engine)
    monkeypatch.setattr(core,"engine",engine)
    with Session(engine) as db:
        db.add(core.Vulnerability(key="safe-entry",title="Unrelated CVE",cve="CVE-2026-99999"))
        for i in range(25):
            row=core.CollectionRun(mode="Python 爬虫",status="完成",
                ended_at=datetime.now(timezone.utc),summary="{}")
            db.add(row)
            db.flush()
            db.add(core.RunRecord(run_id=row.id,title="record-"+str(i)))
        running=core.CollectionRun(mode="统一采集",status="running")
        db.add(running)
        db.commit()
        running_id=running.id

    assert core.prune_collection_run_history()==5
    assert core.prune_collection_run_history()==0
    with Session(engine) as db:
        finished=db.scalars(select(core.CollectionRun).where(core.CollectionRun.status=="完成")).all()
        assert len(finished)==20
        assert db.get(core.CollectionRun,running_id) is not None
        retained_ids={r.id for r in finished}
        associated=db.scalars(select(core.RunRecord)).all()
        assert len(associated)==20
        assert all(r.run_id in retained_ids for r in associated)
        assert db.scalar(select(func.count()).select_from(core.Vulnerability))==1
