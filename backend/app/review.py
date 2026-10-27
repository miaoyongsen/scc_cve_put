"""Persistent manual approval workflow for second-tier CVE intelligence."""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Integer, String, DateTime, ForeignKey, select
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth, Vulnerability, serialize
from .legacy_notify import send_vulnerability

class Review(Base):
    __tablename__="vulnerability_reviews"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    vulnerability_id: Mapped[int]=mapped_column(Integer,ForeignKey("vulnerabilities.id"),unique=True,index=True)
    status: Mapped[str]=mapped_column(String(20),default="pending",nullable=False)
    matched_keyword: Mapped[str]=mapped_column(String(200),default="")
    reviewed_at: Mapped[Optional[datetime]]=mapped_column(DateTime(timezone=True),nullable=True)

Base.metadata.create_all(engine)
router=APIRouter(prefix="/api/v1/reviews",dependencies=[Depends(auth)])

@router.get("")
def pending_reviews():
    with Session(engine) as db:
        records=db.scalars(select(Review).where(Review.status=="pending").order_by(Review.id.desc())).all()
        return {"code":0,"data":[{**serialize(db.get(Vulnerability,r.vulnerability_id)),"matched_keyword":r.matched_keyword,"review_status":r.status} for r in records],"message":"success"}

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
        raise HTTPException(502,"Notification failed: "+str(exc)[:150])
    with Session(engine) as db:
        review=db.scalar(select(Review).where(Review.vulnerability_id==vulnerability_id))
        review.status="approved"
        review.reviewed_at=datetime.now(timezone.utc)
        vuln=db.get(Vulnerability,vulnerability_id)
        vuln.pushed=True
        db.commit()
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
