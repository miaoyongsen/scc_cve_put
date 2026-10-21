"""Exact original Go WatchVuln markdown message layout."""
import html
import smtplib
import os
from email.message import EmailMessage
from .notifications import send_wecom_markdown

def dash(value):
    return str(value) if value else "-"

def format_wecom(item):
    return (
        "## WatchVuln 漏洞情报\n"
        f"> **标题**：{dash(item.get('title'))}\n"
        f"> **CVE**：{dash(item.get('cve'))}\n"
        f"> **等级**：{dash(item.get('severity'))}\n"
        f"> **来源**：{dash(item.get('from'))}\n"
        f"> **披露日期**：{dash(item.get('disclosure'))}\n"
        "> 请前往 IP Sentinel 漏洞监控查看详情"
    )

def send_smtp(item):
    host=os.getenv("SMTP_HOST","")
    recipients=[x.strip() for x in os.getenv("SMTP_TO","").split(",") if x.strip()]
    if not host or not recipients: return False
    port=int(os.getenv("SMTP_PORT","465"))
    user=os.getenv("SMTP_USERNAME","")
    password=os.getenv("SMTP_PASSWORD","")
    sender=os.getenv("SMTP_FROM",user)
    msg=EmailMessage()
    msg["From"]=sender
    msg["To"]=", ".join(recipients)
    msg["Subject"]=f"[WatchVuln {dash(item.get('severity'))}] {dash(item.get('title'))}"
    body="<h2>WatchVuln 漏洞情报</h2>"+ "".join(
        f"<p><b>{label}：</b>{html.escape(dash(item.get(field)))}</p>"
        for label,field in (("标题","title"),("CVE","cve"),("等级","severity"),("来源","from"),("披露日期","disclosure"))
    )+f"<p>{html.escape(item.get('description') or '')}</p>"
    msg.set_content(body,subtype="html")
    if port==465:
        with smtplib.SMTP_SSL(host,port,timeout=15) as server:
            if user:server.login(user,password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host,port,timeout=15) as server:
            server.starttls()
            if user:server.login(user,password)
            server.send_message(msg)
    return True

def send_vulnerability(item):
    """Returns individual channel results; errors are raised for callers to log."""
    result={}
    if os.getenv("WECHAT_WEBHOOK_URL"):
        result["wechat"]=send_wecom_markdown(format_wecom(item))
    if os.getenv("SMTP_HOST") and os.getenv("SMTP_TO"):
        result["email"]=send_smtp(item)
    return result
