"""Exact original Go WatchVuln markdown message layout."""
import html
import smtplib
import os
from email.message import EmailMessage
from .notifications import send_wecom_markdown

def dash(value):
    return str(value) if value else "-"

def format_wecom(item):
    """Render the UI-managed template with a fixed, safe placeholder set."""
    import re
    from .push_config import current
    template=current()["message_template"]
    fields={
        "title":item.get("title"),"cve":item.get("cve"),
        "severity":item.get("severity"),"source":item.get("from") or item.get("source"),
        "disclosure":item.get("disclosure"),"description":item.get("description"),
        "solutions":item.get("solutions"),"url":item.get("url"),
    }
    refs=item.get("references")
    if not fields["url"] and isinstance(refs,list) and refs:fields["url"]=refs[0]
    # Normalize templates saved by older versions that stored literal backslash-n.
    template=template.replace(chr(92)+"n", "\n")
    for key,value in fields.items():
        template=template.replace("{"+key+"}",dash(value))
    return template


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

def send_vulnerability(item, ai_enabled=None):
    """Returns individual channel results; errors are raised for callers to log."""
    from .push_config import current
    c=current()
    if c["severity_filter"] and item.get("severity") not in c["severity_filter"]:return {}
    sources=[x.strip().casefold() for x in c["source_filter"].split(",") if x.strip()]
    if sources and (item.get("from") or "").casefold() not in sources:return {}
    from datetime import datetime
    if c["quiet_start"] and c["quiet_end"]:
        now=datetime.now().strftime("%H:%M")
        start,end=c["quiet_start"],c["quiet_end"]
        if (start<=now<end if start<end else now>=start or now<end):return {}
    # One global switch. AI only runs for newly inserted CVE IDs.
    # The caller must explicitly pass ai_enabled=True for a newly observed CVE.
    ai_text=""
    from .ai_config import ai_enabled as global_ai_enabled, AIAnalysis
    if ai_enabled is True and global_ai_enabled() and item.get("cve"):
        from .core import engine
        from sqlalchemy.orm import Session
        cve=item["cve"].upper()
        with Session(engine) as db:
            previous=db.query(AIAnalysis).filter_by(vuln_key=cve).first()
            if previous:
                ai_text=previous.result
        if not ai_text:
            try:
                from .ai_config import analyze_intelligence
                ai_text=analyze_intelligence(item)
            except Exception:
                import logging
                logging.getLogger(__name__).exception("DeepSeek analysis failed; sending original intelligence")
    result={}
    webhook=c["wecom_webhook"] if c["wecom_enabled"] else ""
    if webhook or os.getenv("WECHAT_WEBHOOK_URL"):
        result["wechat"]=send_wecom_markdown(format_wecom(item)+("\n\n## AI 分析（仅供参考）\n"+ai_text[:3000] if ai_text else ""),url=webhook or None)
    if os.getenv("SMTP_HOST") and os.getenv("SMTP_TO"):
        result["email"]=send_smtp(item)
    return result
