"""WeCom markdown webhook sender; only invoked for actual collected items."""
import os
import httpx

def send_wecom_markdown(text: str, url=None):
    url = url or os.getenv("WECHAT_WEBHOOK_URL", "")
    if not url:
        return False
    if not url.startswith("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?"):
        raise ValueError("WECHAT_WEBHOOK_URL must be an official WeCom webhook URL")
    with httpx.Client(timeout=15) as client:
        response=client.post(url,json={"msgtype":"markdown","markdown":{"content":text}})
        response.raise_for_status()
        data=response.json()
        if data.get("errcode") != 0:
            raise RuntimeError(f"WeCom rejected notification: {data.get('errmsg','unknown error')}")
    return True
