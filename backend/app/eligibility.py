"""Shared eligibility rules for RSS and Python crawler findings."""
import re
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from .collection_config import whitelist_keywords, review_keywords, lookback_hours, allowed_severities

def keyword_matches(title, word):
    """*phrase* matches complete words in order, allowing whitespace between them."""
    if word.startswith("*") and word.endswith("*") and len(word)>2:
        parts=word[1:-1].split()
        if not parts:
            return False
        phrase=r"\s+".join(re.escape(part) for part in parts)
        return re.search(r"(?<![A-Za-z0-9_])"+phrase+r"(?![A-Za-z0-9_])",title,re.IGNORECASE) is not None
    return word in title

def evaluate(item, config=None):
    """Return (tier, matched_keyword, rejection_reason). Tier is primary/secondary/none."""
    if config is None:
        config={
            "severities":set(allowed_severities()),
            "hours":lookback_hours(),
            "primary":[x.casefold() for x in whitelist_keywords()],
            "secondary":[x.casefold() for x in review_keywords()],
        }
    if (item.get("severity") or "未知") not in config["severities"]:
        return None,None,"severity"
    if config["hours"]:
        raw=item.get("disclosure") or ""
        try:
            try:
                published=parsedate_to_datetime(raw)
            except (ValueError,TypeError,IndexError):
                published=datetime.fromisoformat(raw.replace("Z","+00:00"))
            if published.tzinfo is None:
                published=published.replace(tzinfo=timezone.utc)
        except (ValueError,TypeError,IndexError,OverflowError):
            return None,None,"missing_date"
        if published.astimezone(timezone.utc)<datetime.now(timezone.utc)-timedelta(hours=config["hours"]):
            return None,None,"date"
    title=(item.get("title") or "").casefold()
    direct=next((word for word in config["primary"] if keyword_matches(title,word)),None)
    manual=next((word for word in config["secondary"] if keyword_matches(title,word)),None)
    if item.get("severity", "未知") in ("中危", "低危", "未知"):
        return "secondary", manual or direct or "等级审核", None
    if direct:return "primary",direct,None
    if manual:return "secondary",manual,None
    if config["primary"] or config["secondary"]:
        return None,None,"keyword"
    return "primary",None,None
