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
            for item,_ in entries:log_run(item,"article" if kind=="article" else "primary","推送未成功","无有效企业微信渠道")
            continue
        header="## SCC CVE "+label+"汇总\n> 采集时间："+datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")+"\n> 共 "+str(len(entries))+" 条\n"
        # WeCom markdown content is limited; keep one message per category when possible.
        # If too many items, send bounded parts rather than silently truncating.
        chunks=[]
        chunk=header
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
            line=f"\n> **{i}. {title[:100]}**\n> {severity_label} {cve} · {source[:50]}\n"
            ai=message.partition("AI 研判（仅供参考）")[2].strip() if "AI 研判（仅供参考）" in message else ""
            if ai:line+="> AI 研判："+(" ".join(ai.split())[:130])+"\n"
            if link:line+="> [查看原文]("+str(link)+")\n"
            if len(chunk)+len(line)>MAX_MARKDOWN and chunk!=header:
                chunks.append(chunk);chunk=header
            chunk+=line[:MAX_MARKDOWN-len(header)]
        if chunk!=header:chunks.append(chunk)
        try:
            for idx,part in enumerate(chunks,1):
                payload=part if len(chunks)==1 else part.replace(header,header+f"> 第 {idx}/{len(chunks)} 部分\n",1)
                if not send_wecom_markdown(payload,url=webhook):
                    raise RuntimeError("机器人未确认发送成功")
            result["notifications"]+=len(entries)
            result["pushed"].extend({"title":item.get("title"),"cve":item.get("cve"),"from":item.get("from") or item.get("source")} for item,_ in entries)
            for item,_ in entries:
                log_run(item,"article" if kind=="article" else "primary","推送成功","合并推送")
                if kind=="vulnerability" and item.get("severity") in ("高危","严重"):
                    from .review import resolve_unknown_reviews
                    resolve_unknown_reviews(item.get("cve"))
        except Exception as exc:
            result["errors"].append(label+": "+str(exc)[:300])
            for item,_ in entries:log_run(item,"article" if kind=="article" else "primary","推送失败",str(exc)[:500])
    return result
