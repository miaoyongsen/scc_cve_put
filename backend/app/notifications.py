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
    return parts


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
    """Independent plain-text transport for operational alerts."""
    return _send_wecom({"msgtype":"text","text":{"content":text}},url)

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
