"""Manual review only for unknown-severity CVE intelligence."""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, DateTime, ForeignKey, select, delete, or_
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth, Vulnerability, RunRecord, serialize, log_run
from .legacy_notify import send_vulnerability

class Review(Base):
    __tablename__="vulnerability_reviews"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    vulnerability_id: Mapped[int]=mapped_column(Integer,ForeignKey("vulnerabilities.id"),unique=True,index=True)
    status: Mapped[str]=mapped_column(String(20),default="pending",nullable=False)
    matched_keyword: Mapped[str]=mapped_column(String(200),default="")
    reviewed_at: Mapped[Optional[datetime]]=mapped_column(DateTime(timezone=True),nullable=True)

Base.metadata.create_all(engine)

def has_unknown_pending_review(db, cve):
    """Whether this CVE is awaiting review solely because its severity was unknown."""
    if not cve:
        return False
    return db.scalar(
        select(Review.id).join(Vulnerability, Review.vulnerability_id == Vulnerability.id)
        .where(Vulnerability.cve == cve, Review.status == "pending",
               Review.matched_keyword == "等级未知")
    ) is not None

def resolve_unknown_reviews(cve):
    """Close unknown-severity reviews only after a confirmed high/critical delivery."""
    if not cve:
        return 0
    with Session(engine) as db:
        rows = db.scalars(
            select(Review).join(Vulnerability, Review.vulnerability_id == Vulnerability.id)
            .where(Vulnerability.cve == cve, Review.status == "pending",
                   Review.matched_keyword == "等级未知")
        ).all()
        for row in rows:
            row.status = "approved"
            row.reviewed_at = datetime.now(timezone.utc)
            vuln = db.get(Vulnerability, row.vulnerability_id)
            if vuln:
                vuln.pushed = True
        db.commit()
        return len(rows)
router=APIRouter(prefix="/api/v1/reviews",dependencies=[Depends(auth)])

@router.get("")
def pending_reviews():
    with Session(engine) as db:
        records=db.scalars(select(Review).where(Review.status=="pending").order_by(Review.id.desc())).all()
        return {"code":0,"data":[{**serialize(db.get(Vulnerability,r.vulnerability_id)),"matched_keyword":r.matched_keyword,"review_status":r.status} for r in records],"message":"success"}

class PendingDeleteInput(BaseModel):
    ids: list[int] = Field(..., min_items=1, max_items=500)


def _delete_pending_records(ids: list[int]):
    """Permanently delete selected pending items and every source of each selected CVE.

    The operation is transactional. An item without CVE deletes only its own
    vulnerability. Collection-run summary history is intentionally preserved.
    """
    from .crawler import CrawlerFinding
    from .ai_config import AIAnalysis
    import hashlib
    unique_ids=set(ids)
    with Session(engine) as db:
        selected=db.scalars(
            select(Vulnerability).join(Review,Review.vulnerability_id==Vulnerability.id)
            .where(Vulnerability.id.in_(unique_ids),Review.status=="pending")
        ).all()
        if len(selected)!=len(unique_ids):
            raise HTTPException(409,"所选记录含已处理或不存在的待审核项目，请刷新后重试")
        cves={row.cve.strip().upper() for row in selected if row.cve and row.cve.strip()}
        conditions=[Vulnerability.id.in_(unique_ids)]
        if cves:
            conditions.append(Vulnerability.cve.in_(cves))
        affected=db.scalars(select(Vulnerability).where(or_(*conditions))).all()
        affected_ids=[row.id for row in affected]
        affected_keys={row.key for row in affected}
        affected_urls=set()
        for row in affected:
            try:
                import json
                affected_urls.update(str(u) for u in json.loads(row.references or "[]") if u)
            except (TypeError,ValueError):
                pass

        # Delete raw crawler findings by both CVE and exact source-key matching;
        # without a CVE, do not broaden the deletion to unrelated records.
        raw_ids=[]
        for finding in db.scalars(select(CrawlerFinding)).all():
            fingerprint=hashlib.sha256(
                ("crawler:"+str(finding.script_id)+":"+finding.url).encode()
            ).hexdigest()
            if (finding.cve and finding.cve.strip().upper() in cves) or fingerprint in affected_keys:
                raw_ids.append(finding.id)
        if raw_ids:
            db.execute(delete(CrawlerFinding).where(CrawlerFinding.id.in_(raw_ids)))

        # Clear associated AI results and review records before the vulnerable rows.
        db.execute(delete(AIAnalysis).where(AIAnalysis.vuln_key.in_(affected_keys)))
        deleted_reviews=db.execute(delete(Review).where(Review.vulnerability_id.in_(affected_ids))).rowcount
        # Keep run/collection audit history unchanged; these events describe past work.
        deleted_vulnerabilities=db.execute(
            delete(Vulnerability).where(Vulnerability.id.in_(affected_ids))
        ).rowcount
        db.commit()
        return {
            "selected":len(selected),
            "deleted_reviews":deleted_reviews,
            "deleted_vulnerabilities":deleted_vulnerabilities,
            "deleted_crawler_findings":len(raw_ids),
            "cves":sorted(cves),
        }


@router.post("/bulk-delete")
def bulk_delete_pending(body: PendingDeleteInput):
    return {"code":0,"data":_delete_pending_records(body.ids),"message":"deleted"}


@router.delete("/{vulnerability_id}")
def delete_pending(vulnerability_id:int):
    return {"code":0,"data":_delete_pending_records([vulnerability_id]),"message":"deleted"}


@router.post("/{vulnerability_id}/approve")
def approve(vulnerability_id:int):
    with Session(engine) as db:
        review=db.scalar(select(Review).where(Review.vulnerability_id==vulnerability_id))
        if not review or review.status!="pending":raise HTTPException(409,"Not pending approval")
        vuln=db.get(Vulnerability,vulnerability_id)
        if not vuln:raise HTTPException(404,"Vulnerability not found")
        item=serialize(vuln)
        # Mark processing first: prevents repeat approval and automatic requeue.
        review.status="sending"
        db.commit()
    try:
        results=send_vulnerability(item,ai_enabled=False)
        if not results or not all(results.values()):
            raise RuntimeError("No notification channel succeeded")
    except Exception as exc:
        with Session(engine) as db:
            review=db.scalar(select(Review).where(Review.vulnerability_id==vulnerability_id))
            review.status="pending"
            db.commit()
        log_run(item,"review","推送失败",str(exc))
        raise HTTPException(502,"Notification failed: "+str(exc)[:150])
    with Session(engine) as db:
        review=db.scalar(select(Review).where(Review.vulnerability_id==vulnerability_id))
        review.status="approved"
        review.reviewed_at=datetime.now(timezone.utc)
        vuln=db.get(Vulnerability,vulnerability_id)
        vuln.pushed=True
        db.commit()
    log_run(item,"review","推送成功","人工审核通过")
    return {"code":0,"message":"approved and sent"}

@router.post("/{vulnerability_id}/reject")
def reject(vulnerability_id:int):
    with Session(engine) as db:
        review=db.scalar(select(Review).where(Review.vulnerability_id==vulnerability_id))
        if not review or review.status!="pending":raise HTTPException(409,"Not pending approval")
        review.status="rejected"
        review.reviewed_at=datetime.now(timezone.utc)
        db.commit()
    return {"code":0,"message":"rejected"}
