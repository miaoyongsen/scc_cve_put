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
SPACE = re.compile(r"\\s+")
SEVERITY_PATTERNS = (
    ("严重", re.compile(r"(?i)(?:\\bcritical\\b|\\bCRITICAL\\b|严重|超危|CVSS(?:\\s*v[234](?:\\.\\d)?)?\\s*[:=]?\\s*(?:9(?:\\.\\d+)?|10(?:\\.0+)?)(?!\\d))")),
    ("高危", re.compile(r"(?i)(?:\\bhigh\\b|高危|CVSS(?:\\s*v[234](?:\\.\\d)?)?\\s*[:=]?\\s*[78](?:\\.\\d+)?(?!\\d))")),
    ("中危", re.compile(r"(?i)(?:\\bmedium\\b|\\bmoderate\\b|中危|CVSS(?:\\s*v[234](?:\\.\\d)?)?\\s*[:=]?\\s*[456](?:\\.\\d+)?(?!\\d))")),
    ("低危", re.compile(r"(?i)(?:\\blow\\b|低危|CVSS(?:\\s*v[234](?:\\.\\d)?)?\\s*[:=]?\\s*[0-3](?:\\.\\d+)?(?!\\d))")),
)
def clean_text(value):
    value=html.unescape(value or "")
    value=HTML_TAG.sub(" ",value)
    return SPACE.sub(" ",value).strip()

def extract_severity(title, description, entry):
    # Prefer explicit RSS category/severity metadata; descriptions may mention
    # unrelated vulnerabilities with different severity levels.
    metadata=" ".join(clean_text(e.text) for e in entry.iter()
                      if e.tag.rsplit("}",1)[-1].lower() in ("category","severity","cvss_score","cvss"))
    for part in (metadata, title, description[:500]):
        for level,pattern in SEVERITY_PATTERNS:
            if pattern.search(part):return level
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
    with httpx.Client(timeout=15,follow_redirects=False,trust_env=False) as client:
        headers={"User-Agent":"SCC-CVE/0.1","Accept":"application/rss+xml, application/atom+xml, application/xml"}
        if api_key: headers[header_name]=api_key
        response=client.get(url,headers=headers)
        response.raise_for_status()
        if len(response.content)>2_000_000: raise ValueError("Feed too large")
    root=ET.fromstring(response.content)
    if root.tag.lower().endswith("rss") or root.tag.lower()=="rss":
        entries=root.findall("./channel/item")
    elif root.tag=="{http://www.w3.org/2005/Atom}feed":
        entries=root.findall("{http://www.w3.org/2005/Atom}entry")
    else:
        raise ValueError("Only RSS and Atom XML feeds are supported")
    def get_text(e,*paths):
        for path in paths:
            x=e.find(path)
            if x is not None and x.text:return x.text.strip()
        return ""
    for e in entries[:100]:
        title=clean_text(get_text(e,"title","{http://www.w3.org/2005/Atom}title"))
        description=clean_text(get_text(e,"description","{http://www.w3.org/2005/Atom}summary","{http://www.w3.org/2005/Atom}content"))
        guid=get_text(e,"guid","link","{http://www.w3.org/2005/Atom}id")
        disclosure=get_text(e,"pubDate","{http://www.w3.org/2005/Atom}published","{http://www.w3.org/2005/Atom}updated")
        cve=CVE_PATTERN.search(title+" "+description)
        if not title:continue
        yield {"key":hashlib.sha256((url+"|"+(guid or title)).encode()).hexdigest(),
               "title":title,"description":description,"severity":extract_severity(title,description,e),
               "cve":cve.group(0).upper() if cve else "",
               "disclosure":disclosure,"tags":[],"references":[guid] if guid else [],
               "solutions":"","reason":[]}

def collect_configured_sources():
    from .collection_config import whitelist_keywords, review_keywords, lookback_hours
    from .review import Review
    from .core import Vulnerability
    from sqlalchemy import select
    hours=lookback_hours()
    cutoff=datetime.now(timezone.utc)-timedelta(hours=hours) if hours else None
    keywords=[x.casefold() for x in whitelist_keywords()]
    secondary=[x.casefold() for x in review_keywords()]
    summary={"sources":0,"items":0,"eligible":0,"notifications":0,"errors":[]}
    with Session(engine) as db:
        sources=[(s.id,s.name,s.adapter,s.notes) for s in db.scalars(select(IntelSource).where(IntelSource.enabled.is_(True))).all()]
    for source_id,name,adapter,notes in sources:
        summary["sources"]+=1
        if adapter != "rss":
            summary["errors"].append(f"{name}: unsupported adapter {adapter!r}")
            continue
        try:
            # notes holds feed URL for RSS adapters.
            with Session(engine) as db:
                credential=db.get(SourceCredential,source_id)
                key=credential.api_key if credential else ""
                header=credential.header_name if credential else "Authorization"
            for item in read_feed(notes,key,header):
                summary["items"]+=1
                item["from"]=name
                if cutoff:
                    try:
                        published=parsedate_to_datetime(item["disclosure"])
                        if published.tzinfo is None: published=published.replace(tzinfo=timezone.utc)
                    except (ValueError,TypeError,IndexError):
                        try:
                            published=datetime.fromisoformat(item["disclosure"].replace("Z","+00:00"))
                            if published.tzinfo is None:published=published.replace(tzinfo=timezone.utc)
                        except (ValueError,TypeError):
                            continue
                    if published.astimezone(timezone.utc)<cutoff:continue
                # RSS has no WatchVuln IsValuable equivalent. Do not pretend it does.
                title=item["title"].casefold()
                direct=next((word for word in keywords if word in title),None)
                manual=next((word for word in secondary if word in title),None)
                if not direct and not manual and (keywords or secondary):continue
                if not matches(item, True):
                    continue
                summary["eligible"]+=1
                with Session(engine) as db:
                    notify=upsert(db,item,True)
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
                        result=send_vulnerability(item)
                        if result and any(result.values()):
                            summary["notifications"]+=1
                    except Exception:
                        log.exception("Notification failed for %s",item["key"])
                        summary["errors"].append(f"{name}: notification failed")
        except Exception as exc:
            log.exception("Source %s failed",name)
            summary["errors"].append(f"{name}: {type(exc).__name__}")
    return summary
