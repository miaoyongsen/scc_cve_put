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
from sqlalchemy import select
from sqlalchemy.orm import Session
from .credentials import SourceCredential
from .core import engine
from .settings import IntelSource
from .worker import matches, upsert
from .legacy_notify import send_vulnerability

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

# NVD lookup is best-effort and cached, not required for feed collection.
_nvd_cache={}
_nvd_requests=0
def nvd_severity(cve):
    global _nvd_requests
    if not cve:return "未知"
    if cve in _nvd_cache:return _nvd_cache[cve]
    # Keep each collection run bounded; the public NVD API is rate-limited.
    if _nvd_requests>=8:return "未知"
    _nvd_requests+=1
    try:
        response=httpx.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                           params={"cveId":cve},timeout=4,follow_redirects=False,trust_env=False)
        response.raise_for_status()
        data=response.json().get("vulnerabilities",[])
        metrics=data[0]["cve"].get("metrics",{}) if data else {}
        for field in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            for metric in metrics.get(field,[]):
                score=metric.get("cvssData",{}).get("baseScore")
                if score is not None:
                    result=severity_from_score(score)
                    _nvd_cache[cve]=result
                    return result
    except (httpx.HTTPError,ValueError,KeyError,IndexError) as exc:
        log.debug("NVD lookup unavailable for %s: %s",cve,exc)
    _nvd_cache[cve]="未知"
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

def read_feed(url, api_key="", header_name="Authorization"):
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

def collect_configured_sources(progress=None):
    from .eligibility import evaluate
    from .review import Review
    from .core import Vulnerability
    from sqlalchemy import select
    global _nvd_requests
    _nvd_requests=0
    summary={"sources":0,"items":0,"eligible":0,"notifications":0,"errors":[],"primary":0,"secondary":0,"new":0,"details":[]}
    with Session(engine) as db:
        sources=[(s.id,s.name,s.adapter,s.notes,s.ai_enabled) for s in db.scalars(select(IntelSource).where(IntelSource.enabled.is_(True))).all()]
    for source_id,name,adapter,notes,ai_enabled in sources:
        summary["sources"]+=1
        detail={"name":name,"items":0,"primary":0,"secondary":0,"new":0,"status":"running","filtered_severity":0,"filtered_date":0,"filtered_keyword":0,"filtered_rule":0,"missing_date":0}
        summary["details"].append(detail)
        if progress:progress(summary)
        if adapter != "rss":
            summary["errors"].append(f"{name}: unsupported adapter {adapter!r}")
            detail["status"]="error"
            if progress:progress(summary)
            continue
        try:
            # notes holds feed URL for RSS adapters.
            with Session(engine) as db:
                credential=db.get(SourceCredential,source_id)
                key=credential.api_key if credential else ""
                header=credential.header_name if credential else "Authorization"
            for item in read_feed(notes,key,header):
                summary["items"]+=1
                detail["items"]+=1
                item["from"]=name
                if item.get("severity")=="未知" and item.get("cve"):
                    item["severity"]=nvd_severity(item["cve"])
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
                    notify=upsert(db,item,True)
                    if existing is None:
                        summary["new"]+=1
                        detail["new"]+=1
                    vuln=db.scalar(select(Vulnerability).where(Vulnerability.key==item["key"]))
                    review=db.scalar(select(Review).where(Review.vulnerability_id==vuln.id))
                    if review:
                        notify=False
                    elif manual and not direct:
                        db.add(Review(vulnerability_id=vuln.id,status="pending",matched_keyword=manual))
                        db.commit()
                        notify=False
                if notify:
                    try:
                        result=send_vulnerability(item,ai_enabled=ai_enabled)
                        if result and any(result.values()):
                            summary["notifications"]+=1
                    except Exception:
                        log.exception("Notification failed for %s",item["key"])
                        summary["errors"].append(f"{name}: notification failed")
            detail["status"]="done"
        except Exception as exc:
            detail["status"]="error"
            log.exception("Source %s failed",name)
            summary["errors"].append(f"{name}: {type(exc).__name__}")
        finally:
            if progress:progress(summary)
    return summary
