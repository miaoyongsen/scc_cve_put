"""Collection orchestration with injectable source adapters.

IMPORTANT: Original WatchVuln crawler implementations remain to be ported.
No provider is silently replaced by an unrelated feed.
"""
import json
import logging
import os
import threading
from datetime import datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .core import engine, Vulnerability

log = logging.getLogger(__name__)

_lock = threading.Lock()

def matches(item, valuable, black_keywords=(), white_keywords=()):
    """Exact high-level Go watchVulnMatches behavior; valuable is provider's IsValuable."""
    if not item or not item.get("key") or not valuable:
        return False
    title = item.get("title") or ""
    desc = item.get("description") or ""
    if any(w and w.lower() in title.lower() for w in black_keywords):
        return False
    if white_keywords and not any(w and (w.lower() in title.lower() or w.lower() in desc.lower()) for w in white_keywords):
        return False
    return True

def same_strings(a, b):
    """Preserves Go behavior, including its set-based comparison semantics."""
    return len(a) == len(b) and all(x in set(a) for x in b)

def upsert(db: Session, item: dict, enable_cve_filter: bool):
    """Mirrors Go watchvuln.go upsert notification decision (not delivery)."""
    key = item["key"]
    existing = db.scalar(select(Vulnerability).where(Vulnerability.key == key))
    cve = item.get("cve") or ""
    tags = item.get("tags") or []
    matched_keywords = item.get("matched_keywords") or []
    severity = item.get("severity") or ""
    content_type = "article" if item.get("content_type") in ("article", "article_review") else "vulnerability"
    if existing is None:
        duplicate = bool(enable_cve_filter and cve and db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.cve == cve)))
        row = Vulnerability(key=key, title=item.get("title") or "", description=item.get("description") or "",
            severity=severity,cve=cve,disclosure=item.get("disclosure") or "",solutions=item.get("solutions") or "",
            references=json.dumps(item.get("references") or [],ensure_ascii=False),
            tags=json.dumps(tags,ensure_ascii=False),matched_keywords=json.dumps(matched_keywords,ensure_ascii=False),github_search=json.dumps(item.get("github_search") or [],ensure_ascii=False),
            source=item.get("from") or "",content_type=content_type,reason=json.dumps(item.get("reason") or [],ensure_ascii=False),pushed=duplicate)
        db.add(row)
        db.commit()
        return not duplicate
    # Values manually completed by a reviewer must survive subsequent source refreshes.
    # The manual_fields marker is stored on the existing Review record.
    from .review import Review
    manually_completed = db.scalar(select(Review.id).where(
        Review.vulnerability_id == existing.id,
        Review.manual_fields.is_(True)
    ).limit(1)) is not None
    if manually_completed:
        cve = existing.cve
        severity = existing.severity
    old_tags = json.loads(existing.tags or "[]")
    changed = existing.severity != severity or not same_strings(old_tags, tags)
    should_notify = changed
    if should_notify and enable_cve_filter and cve:
        other = db.scalar(select(func.count()).select_from(Vulnerability).where(
            Vulnerability.cve == cve,Vulnerability.key != key,Vulnerability.pushed.is_(True)))
        should_notify = not bool(other)
    for attr, val in {"title":item.get("title") or "","description":item.get("description") or "",
        "severity":severity,"content_type":content_type,"cve":cve,"disclosure":item.get("disclosure") or "",
        "solutions":item.get("solutions") or "","references":json.dumps(item.get("references") or [],ensure_ascii=False),
        "tags":json.dumps(tags,ensure_ascii=False),"matched_keywords":json.dumps(matched_keywords,ensure_ascii=False),"github_search":json.dumps(item.get("github_search") or [],ensure_ascii=False),
        "source":item.get("from") or "","reason":json.dumps(item.get("reason") or [],ensure_ascii=False),
        "last_seen":datetime.now(timezone.utc)}.items():
        setattr(existing,attr,val)
    if changed and not should_notify: existing.pushed=True
    db.commit()
    return should_notify

def collect_once(adapters, config, notify):
    """Each adapter must implement get_update(1) and is_valuable(item)."""
    if not _lock.acquire(blocking=False):
        raise RuntimeError("collection already running")
    try:
        for source in config.get("sources", []):
            adapter=adapters.get(source)
            if adapter is None:
                log.warning("Source %s not implemented; refusing to substitute a different feed",source)
                continue
            try:
                for item in adapter.get_update(1):
                    if not matches(item,adapter.is_valuable(item),config.get("black_keywords",[]),config.get("white_keywords",[])):
                        continue
                    with Session(engine) as db:
                        should_notify=upsert(db,item,config.get("enable_cve_filter",False))
                    if should_notify: notify(item)
            except Exception:
                log.exception("Source %s failed",source)
    finally:
        _lock.release()
