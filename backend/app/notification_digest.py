"""Per-collection notification digest. Does not affect manual approval pushes."""
from contextvars import ContextVar
from datetime import datetime
import os
import time
from .notifications import send_wecom_markdown
from .push_config import current
from .core import log_run

_active_digest=ContextVar("active_notification_digest",default=None)
MAX_MARKDOWN=3500  # Includes the digest header; safely below sender's 3720-byte limit.
# Reserve room for the "第 N/M 部分" header inserted after grouping.
DIGEST_PART_LABEL_BYTES=120

def _bytes(value):
    return len(value.encode("utf-8"))

def build_digest_chunks(header, entries, lines):
    """Pack complete vulnerability entries, never split between their fields.

    Each resulting message must fit in one call of send_wecom_markdown.
    Exception: an individual entry larger than the budget is emitted alone,
    and the shared sender handles that inherently oversized entry.
    """
    chunks=[]
    part=header
    part_entries=[]
    budget=MAX_MARKDOWN-DIGEST_PART_LABEL_BYTES
    for (item,_),line in zip(entries,lines):
        if part_entries and _bytes(part+line)>budget:
            chunks.append((part,list(part_entries)))
            part=header
            part_entries=[]
        part+=line
        part_entries.append(item)
        if _bytes(part)>budget:
            # This one entry cannot fit; keep it separate from other entries.
            chunks.append((part,list(part_entries)))
            part=header
            part_entries=[]
    if part_entries:
        chunks.append((part,part_entries))
    return chunks


def begin_digest():
    return _active_digest.set({"vulnerability":[],"article":[],"nvd_deadline":time.monotonic()+180})

def end_digest(token):
    _active_digest.reset(token)

def queue_message(item,message):
    digest=_active_digest.get()
    if digest is None:return False
    kind="article" if item.get("content_type") in ("article","article_review") else "vulnerability"
    if kind=="vulnerability" and item.get("cve"):
        if any(old.get("cve")==item["cve"] for old,_ in digest[kind]):
            return True
    digest[kind].append((dict(item),message))
    return True

def add_approved_reviews_to_digest(digest):
    """Include durable review approvals in the next collection's digest.

    Put manually reviewed entries first, replacing any automatic entry with
    the same CVE, so the reviewed record's delivery is tracked accurately.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import Session
    from .core import engine, Vulnerability, serialize
    from .review import Review
    from .legacy_notify import format_wecom

    with Session(engine) as db:
        rows=db.execute(
            select(Vulnerability)
            .join(Review,Review.vulnerability_id==Vulnerability.id)
            .where(Review.status=="queued")
            .order_by(Review.id.asc())
        ).scalars().all()
        entries=[]
        reviewed_cves=set()
        for vuln in rows:
            item=serialize(vuln)
            cve=(item.get("cve") or "").upper()
            # Normal review save already enforces a unique CVE.
            if cve in reviewed_cves:
                continue
            reviewed_cves.add(cve)
            entries.append((item,format_wecom(item)))
    if not entries:
        return 0
    remaining=[
        (item,msg) for item,msg in digest["vulnerability"]
        if (item.get("cve") or "").upper() not in reviewed_cves
    ]
    digest["vulnerability"]=entries+remaining
    return len(entries)


def flush_digest():
    digest=_active_digest.get()
    if digest is None:return {"notifications":0,"errors":[],"pushed":[]}
    add_approved_reviews_to_digest(digest)
    config=current()
    # Match manual push behavior: DB-configured webhook first, then .env fallback.
    webhook=(config["wecom_webhook"] if config["wecom_enabled"] else "") or os.getenv("WECHAT_WEBHOOK_URL", "").strip()
    result={"notifications":0,"errors":[],"pushed":[]}
    for kind,label in (("vulnerability","漏洞情报"),("article","安全文章")):
        entries=digest[kind]
        if not entries:continue
        if not webhook:
            result["errors"].append(label+": 未启用或未配置企业微信机器人")
            for item,_ in entries:log_run(item,"article" if kind=="article" else "direct","推送未成功","无有效企业微信渠道")
            continue
        header="## SCC CVE "+label+"汇总\n> 采集时间："+datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")+"\n> 共 "+str(len(entries))+" 条\n"
        # Build readable summary entries, then split by UTF-8 bytes.  The
        # shared WeCom sender will further segment any single oversize entry.
        # Never truncate an entry just to fit a message limit.
        lines=[]
        for i,(item,message) in enumerate(entries,1):
            link=(item.get("references") or [item.get("url") or ""])[0]
            title=str(item.get("title") or "未命名").replace("\n"," ").strip()
            source=str(item.get("from") or item.get("source") or "未知来源")
            cve=str(item.get("cve") or "")
            severity=str(item.get("severity") or "")
            badges={"严重":"🔴","高危":"🟠","中危":"🟡","低危":"🟢","未知":"⚪"}
            severity_label=badges.get(severity,"⚪")+" "+severity
            if severity in ("严重","高危"):
                severity_label=badges[severity]+' <font color="warning">'+severity+"</font>"
            line=f"\n> **{i}. {title}**\n> {severity_label} {cve} · {source}\n"
            ai=message.partition("AI 研判（仅供参考）")[2].strip() if "AI 研判（仅供参考）" in message else ""
            if ai:line+="> AI 研判："+" ".join(ai.split())+"\n"
            if link:line+="> [查看原文]("+str(link)+")\n"
            lines.append(line)

        # One UTF-8 budget at the digest layer avoids unintended double-splits.
        chunks=build_digest_chunks(header,entries,lines)

        for idx,(part,part_entries) in enumerate(chunks,1):
            payload=part if len(chunks)==1 else part.replace(
                header,header+f"> 第 {idx}/{len(chunks)} 部分\n",1
            )
            try:
                # Normal groups MUST fit exactly one WeCom message.
                # Standalone oversized entries may require multiple messages.
                if len(part_entries)>1 and _bytes(payload)>3720:
                    raise RuntimeError("分组消息超过单条安全上限，请检查分组逻辑")
                if not send_wecom_markdown(payload,url=webhook):
                    raise RuntimeError("机器人未确认发送成功")
                from .notifications import mark_wecom_delivered
                mark_wecom_delivered(part_entries)
                if kind=="vulnerability":
                    from .review import confirm_queued_delivery
                    confirm_queued_delivery(part_entries)
                result["notifications"]+=len(part_entries)
                result["pushed"].extend(
                    {"title":item.get("title"),"cve":item.get("cve"),
                     "from":item.get("from") or item.get("source")}
                    for item in part_entries
                )
                for item in part_entries:
                    log_run(item,"article" if kind=="article" else "direct","推送成功","合并推送")
                    if kind=="vulnerability" and item.get("severity") in ("高危","严重"):
                        from .review import resolve_unknown_reviews
                        resolve_unknown_reviews(item.get("cve"))
            except Exception as exc:
                result["errors"].append(label+f"（第 {idx}/{len(chunks)} 组）: "+str(exc)[:300])
                for item in part_entries:
                    log_run(item,"article" if kind=="article" else "direct","推送失败",str(exc)[:500])
    return result
