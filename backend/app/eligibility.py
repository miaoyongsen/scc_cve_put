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
        return re.search(r"(?<![A-Za-z0-9_.])"+phrase+r"(?![A-Za-z0-9_])",title,re.IGNORECASE) is not None
    if word.casefold() == "php":
        # Do not treat .php file extensions as PHP technology mentions.
        return re.search(r"(?<![A-Za-z0-9_.])php(?![A-Za-z0-9_])", title, re.IGNORECASE) is not None
    return word in title

def allow_unknown_review_upgrade(item, tier, matched, rejected, has_pending_unknown_review):
    """Promote a known high/critical CVE when an earlier unknown-severity review is pending.

    This exception is deliberately limited to keyword rejection / ordinary eligibility.
    Date-window and configured severity rejections remain authoritative.
    """
    severity = item.get("severity") or "未知"
    if (has_pending_unknown_review
            and severity in ("高危", "严重")
            and rejected in (None, "keyword")):
        return "primary", "等级未知升级", None
    return tier, matched, rejected


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
    severity=item.get("severity") or "未知"
    if severity in ("中危", "低危"):
        return None,None,"severity"
    if severity == "未知":
        if direct:
            return "secondary","等级未知",None
        return None,None,"keyword"
    if direct:return "primary",direct,None
    if manual:return "secondary",manual,None
    if config["primary"] or config["secondary"]:
        return None,None,"keyword"
    return "primary",None,None
