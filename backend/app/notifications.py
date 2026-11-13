"""WeCom markdown webhook sender with a global three-second pacing limit."""
import os
import threading
import time
import httpx

_SEND_INTERVAL_SECONDS = 3.0
_send_lock = threading.Lock()
_last_send_started = None

# WeCom's markdown.content limit is 4096 UTF-8 bytes, not Unicode characters.
# Leave headroom for continuation labels and future formatting.
_MARKDOWN_PART_BYTES = 3800


def split_wecom_markdown(content: str, limit: int = _MARKDOWN_PART_BYTES):
    """Split a long markdown message without losing characters or breaking UTF-8.

    Prefer newline boundaries. An individual line longer than the limit is
    split by Unicode codepoint (never through a UTF-8 byte sequence).
    """
    if limit < 32:
        raise ValueError("Markdown part limit is too small")
    if not content:
        return [""]
    parts = []
    current = ""
    for line in content.splitlines(keepends=True):
        while line:
            remaining = limit - len(current.encode("utf-8"))
            if remaining == 0:
                parts.append(current)
                current = ""
                continue
            if len(line.encode("utf-8")) <= remaining:
                current += line
                break
            # Find the largest codepoint-safe prefix that fits.
            used = 0
            cutoff = 0
            for pos, char in enumerate(line):
                size = len(char.encode("utf-8"))
                if used + size > remaining:
                    break
                used += size
                cutoff = pos + 1
            if cutoff == 0:
                parts.append(current)
                current = ""
                continue
            fragment = line[:cutoff]
            # Keep markdown readable where possible.
            if current and "\n" in fragment:
                newline_pos = fragment.rfind("\n") + 1
                if newline_pos:
                    cutoff = newline_pos
                    fragment = line[:cutoff]
            current += fragment
            line = line[cutoff:]
            parts.append(current)
            current = ""
    if current:
        parts.append(current)
    return _balance_short_tail(parts,limit)


def _balance_short_tail(parts, limit):
    """Avoid tiny final continuation messages for inherently oversized items."""
    if len(parts)<2 or len(parts[-1].encode("utf-8"))>=limit//4:
        return parts
    combined=parts[-2]+parts[-1]
    total=len(combined.encode("utf-8"))
    # Rebalance the last two messages only when both can safely fit.
    if total>2*limit:
        return parts
    target=total//2
    used=0
    cut=0
    for idx,char in enumerate(combined):
        used+=len(char.encode("utf-8"))
        if used>target:
            break
        cut=idx+1
    if cut==0 or cut==len(combined):
        return parts
    # Prefer a paragraph/line boundary near the middle, when available.
    near=combined.rfind("\n",0,cut+1)
    if near>0:
        near+=1
        left_bytes=len(combined[:near].encode("utf-8"))
        if total//3<=left_bytes<=limit and total-left_bytes<=limit:
            cut=near
    before,after=combined[:cut],combined[cut:]
    if len(before.encode("utf-8"))>limit or len(after.encode("utf-8"))>limit:
        return parts
    return parts[:-2]+[before,after]


def mark_wecom_delivered(items):
    """Persist confirmed WeCom deliveries; never infer success from dedup flags."""
    from sqlalchemy import update
    from sqlalchemy.orm import Session
    from datetime import datetime, timezone
    from .core import engine, Vulnerability
    keys = {str(item.get("key") or "") for item in items if item.get("key")}
    if not keys:
        return
    sent_at=datetime.now(timezone.utc)
    with Session(engine) as db:
        for key in keys:
            db.execute(update(Vulnerability).where(Vulnerability.key == key).values(wecom_sent=True,wecom_sent_at=sent_at))
        db.commit()


def send_wecom_markdown(text: str, url=None):
    content = str(text)
    # Reserve 80 bytes for part numbering, including two-digit counts.
    parts = split_wecom_markdown(content, _MARKDOWN_PART_BYTES - 80)
    total = len(parts)
    for idx, part in enumerate(parts, 1):
        heading = f"> 消息分段 {idx}/{total}\n" if total > 1 else ""
        payload_content = heading + part
        if len(payload_content.encode("utf-8")) > 4096:
            raise ValueError("WeCom markdown part exceeds the 4096-byte limit")
        if not _send_wecom({"msgtype":"markdown","markdown":{"content":payload_content}},url):
            return False
    return True

def send_wecom_text(text: str, url=None):
    """Split operational text alerts within the 2048-byte WeCom text limit."""
    parts = split_wecom_markdown(str(text), 1850)
    for part in parts:
        if not _send_wecom({"msgtype":"text","text":{"content":part}},url):
            return False
    return True

def _send_wecom(payload, url=None):
    global _last_send_started
    url = url or os.getenv("WECHAT_WEBHOOK_URL", "")
    if not url:
        return False
    if not url.startswith("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?"):
        raise ValueError("WECHAT_WEBHOOK_URL must be an official WeCom webhook URL")
    # Serialize all webhook calls in this backend process, including test pushes.
    # The interval is measured between request start times, not after completion.
    with _send_lock:
        if _last_send_started is not None:
            remaining=_SEND_INTERVAL_SECONDS-(time.monotonic()-_last_send_started)
            if remaining>0:
                time.sleep(remaining)
        _last_send_started=time.monotonic()
        with httpx.Client(timeout=15) as client:
            response=client.post(url,json=payload)
            response.raise_for_status()
            data=response.json()
            if data.get("errcode") != 0:
                raise RuntimeError(f"WeCom rejected notification: {data.get('errmsg','unknown error')}")
    return True
