"""WeCom markdown webhook sender with a global three-second pacing limit."""
import os
import threading
import time
import httpx

_SEND_INTERVAL_SECONDS = 3.0
_send_lock = threading.Lock()
_last_send_started = None

def send_wecom_markdown(text: str, url=None):
    return _send_wecom({"msgtype":"markdown","markdown":{"content":text}},url)

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
