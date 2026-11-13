"""Per-collection notification digest. Does not affect manual approval pushes."""
from contextvars import ContextVar
from datetime import datetime
import os
import time
from .notifications import send_wecom_markdown
from .push_config import current
from .core import log_run

_active_digest=ContextVar("active_notification_digest",default=None)
MAX_MARKDOWN=3800

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

def flush_digest():
    digest=_active_digest.get()
    if digest is None:return {"notifications":0,"errors":[],"pushed":[]}
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

        chunks=[]
        chunk=header
        chunk_entries=[]
        for (item,_),line in zip(entries,lines):
            if chunk_entries and len((chunk+line).encode("utf-8"))>MAX_MARKDOWN:
                chunks.append((chunk,list(chunk_entries)))
                chunk=header
                chunk_entries=[]
            chunk+=line
            chunk_entries.append(item)
        if chunk_entries:
            chunks.append((chunk,chunk_entries))

        for idx,(part,part_entries) in enumerate(chunks,1):
            payload=part if len(chunks)==1 else part.replace(
                header,header+f"> 第 {idx}/{len(chunks)} 部分\n",1
            )
            try:
                # This helper enforces the 4096-byte limit on every HTTP request.
                if not send_wecom_markdown(payload,url=webhook):
                    raise RuntimeError("机器人未确认发送成功")
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
