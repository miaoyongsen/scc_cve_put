"""CVE feed collection with frontend-managed source configuration.

Supported adapter: RSS/Atom (explicit opt-in). This is NOT a replacement for
the original WatchVuln provider-specific IsValuable logic.
"""
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import socket
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

import httpx
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from .credentials import SourceCredential
from .core import engine
from .settings import IntelSource
from .worker import matches, upsert
from .legacy_notify import send_vulnerability
from .core import log_run

log = logging.getLogger(__name__)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

HTML_TAG = re.compile(r"<[^>]+>")
SPACE = re.compile(r"\s+")
CVSS_SCORE = re.compile(r"(?i)\bCVSS(?:\s*v?[234](?:\.\d)?)?(?:\s*(?:base\s*)?score)?\s*[:=]?\s*(10(?:\.0+)?|[0-9](?:\.\d+)?)\b")
LEVEL_WORDS = [
    ("严重", re.compile(r"(?i)\bcritical\b|严重|超危")),
    ("高危", re.compile(r"(?i)\bhigh\b|高危")),
    ("中危", re.compile(r"(?i)\bmedium\b|\bmoderate\b|中危")),
    ("低危", re.compile(r"(?i)\blow\b|低危")),
]
def clean_text(value):
    value=html.unescape(value or "")
    value=HTML_TAG.sub(" ",value)
    return SPACE.sub(" ",value).strip()

def severity_from_score(score):
    try:
        n=float(score)
        if 0 <= n <= 10:
            return "严重" if n>=9 else "高危" if n>=7 else "中危" if n>=4 else "低危"
    except (ValueError,TypeError):
        pass
    return "未知"

def extract_severity(title, description, entry):
    # Prefer structured metadata over free-form description.
    metadata=" ".join(clean_text(e.text) for e in entry.iter()
                      if e.tag.rsplit("}",1)[-1].lower() in ("category","severity","cvss_score","cvss","cvssscore","base_score"))
    for part in (metadata,title,description[:1000]):
        score=CVSS_SCORE.search(part)
        if score:
            result=severity_from_score(score.group(1))
            if result!="未知":return result
        for level,pattern in LEVEL_WORDS:
            if pattern.search(part):return level
    return "未知"

# Shared NVD limiter and short-lived cache; preserve official API quotas.
import threading
import time
_nvd_lock=threading.Lock()
_nvd_cache={}
_nvd_next=0.0
def nvd_severity(cve):
    global _nvd_next
    cve=(cve or "").strip().upper()
    if not CVE_PATTERN.fullmatch(cve):return "未知"
    now=time.monotonic()
    with _nvd_lock:
        cached=_nvd_cache.get(cve)
        if cached and cached[1]>now:return cached[0]
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE IF NOT EXISTS nvd_cache (cve TEXT PRIMARY KEY, severity TEXT NOT NULL)"))
            saved=conn.execute(text("SELECT severity FROM nvd_cache WHERE cve=:cve"),{"cve":cve}).scalar()
        if saved:
            _nvd_cache[cve]=(saved,float("inf"))
            return saved
        api_key=os.getenv("NVD_API_KEY","").strip()
        interval=0.8 if api_key else 7.5
        delay=max(0,_nvd_next-time.monotonic())
        from .notification_digest import _active_digest
        batch=_active_digest.get()
        deadline=batch.get("nvd_deadline") if batch else None
        if deadline and time.monotonic()+delay+8>deadline:return "未知"
        if delay:time.sleep(delay)
        _nvd_next=time.monotonic()+interval
        headers={"User-Agent":"SCC-CVE/1.0 (NVD vulnerability enrichment)","Accept":"application/json"}
        if api_key:headers["apiKey"]=api_key
        try:
            response=httpx.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                               params={"cveId":cve},headers=headers,timeout=8,
                               follow_redirects=False,trust_env=False)
            if response.status_code in (429,403,503):
                _nvd_next=time.monotonic()+30
                log.warning("NVD rate limit or unavailable: HTTP %s",response.status_code)
                return "未知"
            response.raise_for_status()
            data=response.json().get("vulnerabilities",[])
            metrics=data[0]["cve"].get("metrics",{}) if data else {}
            for field in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                for metric in metrics.get(field,[]):
                    score=metric.get("cvssData",{}).get("baseScore")
                    if score is not None:
                        level=severity_from_score(score)
                        with engine.begin() as conn:
                            conn.execute(text("INSERT OR REPLACE INTO nvd_cache(cve,severity) VALUES (:cve,:severity)"),{"cve":cve,"severity":level})
                        _nvd_cache[cve]=(level,float("inf"))
                        return level
            with engine.begin() as conn:
                conn.execute(text("INSERT OR IGNORE INTO nvd_cache(cve,severity) VALUES (:cve,:severity)"),{"cve":cve,"severity":"未知"})
            _nvd_cache[cve]=("未知",float("inf"))
        except (httpx.HTTPError,ValueError,KeyError,IndexError) as exc:
            log.warning("NVD lookup failed for %s: %s",cve,exc)
        return "未知"

def validate_url(url):
    p=urlparse(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.port not in (None,443):
        raise ValueError("Only public HTTPS URLs on port 443 are allowed")
    if p.hostname.lower() in ("localhost",) or p.hostname.lower().endswith((".local",".internal")):
        raise ValueError("Private hosts are not allowed")
    for info in socket.getaddrinfo(p.hostname,443,type=socket.SOCK_STREAM):
        ip=ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValueError("Private or reserved IP address not allowed")
    return url

def read_feed(url, api_key="", header_name="Authorization", on_status=None):
    validate_url(url)
    # Redirects disabled; source URL is validated before any request.
    # For public exposure, enforce egress firewall rules as well.
    max_feed_bytes=30_000_000  # 30 MB; annual feeds such as Microsoft MSRC can be large.
    with httpx.Client(timeout=httpx.Timeout(60.0,connect=15.0),follow_redirects=False,trust_env=False) as client:
        headers={"User-Agent":"SCC-CVE/0.1","Accept":"application/rss+xml, application/atom+xml, application/xml"}
        if api_key: headers[header_name]=api_key
        chunks=[]
        received=0
        with client.stream("GET",url,headers=headers) as response:
            if on_status:on_status(response.status_code)
            response.raise_for_status()
            for chunk in response.iter_bytes():
                received+=len(chunk)
                if received>max_feed_bytes:
                    raise ValueError("Feed too large (30 MB limit)")
                chunks.append(chunk)
    root=ET.fromstring(b"".join(chunks))
    if root.tag.lower().endswith("rss") or root.tag.lower()=="rss":
        entries=root.findall("./channel/item")
    elif root.tag=="{http://www.w3.org/2005/Atom}feed":
        entries=root.findall("{http://www.w3.org/2005/Atom}entry")
    else:
        raise ValueError("Only RSS and Atom XML feeds are supported")
    def get_text(e,*paths):
        for path in paths:
            x=e.find(path)
            if x is not None:
                value=" ".join(x.itertext()).strip()
                if value:return value
        return ""
    def get_link(e):
        for x in e.iter():
            if x.tag.rsplit("}",1)[-1]!="link":continue
            href=x.get("href","").strip()
            if href and x.get("rel","alternate")=="alternate":return href
            if x.text and x.text.strip():return x.text.strip()
        return ""
    for e in entries[:2000]:
        title=clean_text(get_text(e,"title","{http://www.w3.org/2005/Atom}title"))
        description=clean_text(get_text(e,"description","{http://www.w3.org/2005/Atom}summary","{http://www.w3.org/2005/Atom}content","{http://purl.org/rss/1.0/modules/content/}encoded"))
        guid=get_link(e) or get_text(e,"guid","{http://www.w3.org/2005/Atom}id")
        disclosure=get_text(e,"pubDate","{http://purl.org/dc/elements/1.1/}date","{http://www.w3.org/2005/Atom}published","{http://www.w3.org/2005/Atom}updated")
        cve=CVE_PATTERN.search(title+" "+description)
        if not title:continue
        yield {"key":hashlib.sha256((url+"|"+(guid or title)).encode()).hexdigest(),
               "title":title,"description":description,"severity":extract_severity(title,description,e),
               "cve":cve.group(0).upper() if cve else "",
               "disclosure":disclosure,"tags":[],"references":[guid] if guid else [],
               "solutions":"","reason":[]}

def _collect_configured_sources(progress=None):
    from .eligibility import evaluate
    from .review import Review, has_unknown_pending_review, resolve_unknown_reviews
    from .core import Vulnerability
    from sqlalchemy import select
    summary={"sources":0,"items":0,"eligible":0,"notifications":0,"errors":[],"primary":0,"secondary":0,"new":0,"details":[]}
    with Session(engine) as db:
        sources=[(s.id,s.name,s.adapter,s.notes,s.ai_enabled) for s in db.scalars(select(IntelSource).where(IntelSource.enabled.is_(True))).all()]
    for source_id,name,adapter,notes,ai_enabled in sources:
        summary["sources"]+=1
        detail={"name":name,"adapter":adapter,"http_status":None,"duplicates":[],"pushed":[],"pending":[],"items":0,"primary":0,"secondary":0,"new":0,"status":"running","filtered_severity":0,"filtered_date":0,"filtered_keyword":0,"filtered_rule":0,"missing_date":0}
        summary["details"].append(detail)
        if progress:progress(summary)
        if adapter != "rss":
            detail["error"]=f"不支持的适配器: {adapter!r}"
            summary["errors"].append(f"{name}: {detail['error']}")
            detail["status"]="error"
            if progress:progress(summary)
            continue
        try:
            # notes holds feed URL for RSS adapters.
            with Session(engine) as db:
                credential=db.get(SourceCredential,source_id)
                key=credential.api_key if credential else ""
                header=credential.header_name if credential else "Authorization"
            for item in read_feed(notes,key,header,on_status=lambda code:detail.update(http_status=code)):
                summary["items"]+=1
                detail["items"]+=1
                item["from"]=name
                if item.get("severity")=="未知" and item.get("cve"):
                    from .core import Vulnerability
                    with Session(engine) as check_db:
                        known=check_db.scalar(select(Vulnerability.id).where(Vulnerability.cve==item["cve"]))
                    if not known:item["severity"]=nvd_severity(item["cve"])
                tier,matched,rejected=evaluate(item)
                if rejected:
                    field={"severity":"filtered_severity","date":"filtered_date",
                           "missing_date":"missing_date","keyword":"filtered_keyword"}[rejected]
                    detail[field]+=1
                    continue
                direct=matched if tier=="primary" else None
                manual=matched if tier=="secondary" else None
                if not matches(item, True):
                    detail["filtered_rule"]+=1
                    continue
                summary["eligible"]+=1
                if direct:
                    summary["primary"]+=1
                    detail["primary"]+=1
                elif manual:
                    summary["secondary"]+=1
                    detail["secondary"]+=1
                with Session(engine) as db:
                    existing=db.scalar(select(Vulnerability.id).where(Vulnerability.key==item["key"]))
                    new_cve=bool(item.get("cve")) and not bool(db.scalar(select(Vulnerability.id).where(Vulnerability.cve==item["cve"])))
                    pending_upgrade = (tier=="primary" and item.get("severity") in ("高危","严重") and has_unknown_pending_review(db,item.get("cve")))
                    notify=upsert(db,item,True)
                    if pending_upgrade:
                        notify=True
                    if existing is None:
                        summary["new"]+=1
                        detail["new"]+=1
                    vuln=db.scalar(select(Vulnerability).where(Vulnerability.key==item["key"]))
                    review=db.scalar(select(Review).where(Review.vulnerability_id==vuln.id))
                    if review and not (pending_upgrade and review.status=="pending" and review.matched_keyword=="等级未知"):
                        notify=False
                    elif manual and not direct:
                        db.add(Review(vulnerability_id=vuln.id,status="pending",matched_keyword=manual))
                        db.commit()
                        notify=False
                if existing is not None or (item.get("cve") and not new_cve):
                    detail["duplicates"].append({"title":item.get("title"),"cve":item.get("cve"),"reason":"已有记录或重复 CVE"})
                if tier=="secondary":detail["pending"].append({"title":item.get("title"),"cve":item.get("cve")})
                log_run(item,tier,"待推送" if notify else ("待审核" if tier=="secondary" else "未推送"),matched or "")
                if notify:
                    try:
                        result=send_vulnerability(item,ai_enabled=new_cve)
                        if result and result.get("queued"):
                            log_run(item,tier,"待合并推送")
                        elif result and any(result.values()):
                            summary["notifications"]+=1
                            log_run(item,tier,"推送成功")
                            detail["pushed"].append({"title":item.get("title"),"cve":item.get("cve")})
                            if tier=="primary" and item.get("severity") in ("高危","严重"):
                                resolve_unknown_reviews(item.get("cve"))
                        else:
                            log_run(item,tier,"推送未成功","无有效通知渠道或被推送规则过滤")
                    except Exception as exc:
                        log_run(item,tier,"推送失败",str(exc))
                        log.exception("Notification failed for %s",item["key"])
                        detail["status"]="partial"
                        detail.setdefault("notification_errors",[]).append(str(exc)[:500])
                        summary["errors"].append(f"{name}: 推送失败: {str(exc)[:300]}")
            if detail["status"]=="running":detail["status"]="done"
        except Exception as exc:
            detail["status"]="error"
            log.exception("Source %s failed",name)
            detail["error"]=f"{type(exc).__name__}: {str(exc)[:500]}"
            summary["errors"].append(f"{name}: {detail['error']}")
        finally:
            if progress:progress(summary)
    return summary

# One collection session covers RSS and configured Python scripts.
import threading
_collection_mutex=threading.Lock()

def collect_configured_sources(progress=None, mode="all"):
    from .core import _active_run, begin_run, finish_run
    from .crawler import CrawlerScript, _collect_script
    if not _collection_mutex.acquire(blocking=False):
        raise RuntimeError("已有统一采集任务正在运行")
    run_id=None
    token=None
    digest_token=None
    from .notification_digest import begin_digest,end_digest,flush_digest
    try:
        digest_token=begin_digest()
        run_id=begin_run({"all":"统一采集（RSS + Python）","vulnerability":"漏洞情报定时采集","article":"安全文章定时采集"}.get(mode,"统一采集"))
        token=_active_run.set(run_id)
        summary={"sources":0,"items":0,"eligible":0,"notifications":0,
                 "errors":[],"primary":0,"secondary":0,"new":0,"details":[]}
        try:
            if mode!="article":
                rss=_collect_configured_sources(progress)
                summary.update(rss)
        except Exception as exc:
            log.exception("RSS collection failed")
            summary["errors"].append("RSS: "+str(exc)[:200])
        if progress:progress(summary)
        with Session(engine) as db:
            scripts=[(x.id,x.name) for x in db.scalars(select(CrawlerScript).order_by(CrawlerScript.id)).all()
                     if mode=="all" or (mode=="article" and x.content_type in ("article","article_review"))
                     or (mode=="vulnerability" and x.content_type=="vulnerability")]
        for script_id,name in scripts:
            detail={"id":script_id,"name":name,"adapter":"python","http_status":None,
                    "status":"running","items":0,"new":0,"primary":0,"secondary":0,
                    "notifications":0,"duplicates":[],"pushed":[],"pending":[]}
            summary["sources"]+=1
            summary["details"].append(detail)
            if progress:progress(summary)
            try:
                data=_collect_script(script_id)["data"]
                detail.update(data)
                detail["items"]=data.get("count",0)
                detail["new"]=data.get("inserted",0)
                detail["status"]="done" if not data.get("notification_errors") else "partial"
                summary["items"]+=detail["items"]
                summary["new"]+=detail["new"]
                summary["primary"]+=data.get("primary",0)
                summary["secondary"]+=data.get("secondary",0)
                summary["notifications"]+=data.get("notifications",0)
                summary["eligible"]+=detail["items"]-data.get("filtered",0)
                if data.get("notification_errors"):
                    summary["errors"].extend(name+": "+e for e in data["notification_errors"])
            except Exception as exc:
                detail["status"]="error"
                detail["error"]=str(exc)[:500]
                summary["errors"].append(name+": "+str(exc)[:200])
                log.exception("Python crawler %s failed",name)
            finally:
                if progress:progress(summary)
        delivery=flush_digest()
        summary["notifications"]+=delivery["notifications"]
        summary["errors"].extend(delivery["errors"])
        if delivery["pushed"]:
            for pushed in delivery["pushed"]:
                for d in summary["details"]:
                    if d.get("name")==pushed.get("from"):
                        d.setdefault("pushed",[]).append({"title":pushed["title"],"cve":pushed["cve"]})
                        d["notifications"]=d.get("notifications",0)+1
                        break
        if delivery["errors"]:
            summary["details"].append({"name":"企业微信合并推送","adapter":"notification","status":"error","error":"；".join(delivery["errors"]),"items":0})
        failed=sum(d.get("status")=="error" for d in summary["details"])
        state="失败" if summary["details"] and failed==len(summary["details"]) else ("部分失败" if summary["errors"] else "完成")
        finish_run(run_id,state,summary)
        return summary
    except Exception as exc:
        if run_id is not None:finish_run(run_id,"失败",{"error":str(exc)})
        raise
    finally:
        if digest_token is not None:end_digest(digest_token)
        if token is not None:_active_run.reset(token)
        _collection_mutex.release()
