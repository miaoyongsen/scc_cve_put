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
    config=current()
    is_article=item.get("content_type") in ("article","article_review")
    template=config["article_template"] if is_article else config["message_template"]
    fields={
        "title":item.get("title"),"cve":item.get("cve"),
        "severity":item.get("severity"),"source":item.get("from") or item.get("source"),
        "disclosure":item.get("disclosure"),"description":item.get("description"),
        "solutions":item.get("solutions"),"url":item.get("url"),
    }
    refs=item.get("references")
    if not fields["url"] and isinstance(refs,list) and refs:fields["url"]=refs[0]
    # Convert literal \n (including double-escaped forms) into real line breaks.
    template=re.sub(r"(?:\\)+n", "\n", template)
    severity=dash(fields["severity"])
    if is_article:
        fields["cve"]=item.get("cve") or ""
        fields["severity"]=item.get("severity") or ""
    # WeCom robot markdown supports warning/info/comment, not arbitrary hex colors.
    # Emoji distinguishes critical red from high orange on all clients.
    severity_badges={"严重":"🔴","高危":"🟠","中危":"🟡","低危":"🟢","未知":"⚪"}
    badge=severity_badges.get(severity,"⚪")
    if not is_article and severity in ("严重","高危"):
        fields["severity"]=badge+' <font color="warning">'+severity+'</font>'
    elif not is_article:
        fields["severity"]=badge+" "+severity
    for key,value in fields.items():
        template=template.replace("{"+key+"}",dash(value))
    if "{url}" not in (config["article_template"] if is_article else config["message_template"]) and fields["url"]:
        template+="\n> **原始数据**：[查看原文]("+str(fields["url"])+")"
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
    is_article=item.get("content_type") in ("article","article_review")
    # Security articles bypass vulnerability-only severity, source and quiet-hour filters.
    if not is_article:
        if c["severity_filter"] and item.get("severity") not in c["severity_filter"]:return {}
        sources=[x.strip().casefold() for x in c["source_filter"].split(",") if x.strip()]
        if sources and (item.get("from") or "").casefold() not in sources:return {}
        from datetime import datetime
        if c["quiet_start"] and c["quiet_end"]:
            now=datetime.now().strftime("%H:%M")
            start,end=c["quiet_start"],c["quiet_end"]
            if (start<=now<end if start<end else now>=start or now<end):return {}
    # Single-threaded delivery: analyze first, then send one combined message.
    # AI is limited to vulnerability intelligence with a valid CVE and global switch.
    import logging
    import re
    ai_text=""
    cve=(item.get("cve") or "").strip().upper()
    if (item.get("content_type","vulnerability")=="vulnerability"
            and re.fullmatch(r"CVE-\d{4}-\d{4,}",cve)):
        try:
            from .ai_config import ai_enabled as global_ai_enabled, AIAnalysis, analyze_intelligence
            if global_ai_enabled():
                from .core import engine
                from sqlalchemy.orm import Session
                with Session(engine) as db:
                    previous=db.query(AIAnalysis).filter_by(vuln_key=cve).first()
                    if previous and previous.status=="success":
                        ai_text=previous.result
                if not ai_text:
                    ai_text=analyze_intelligence(item)
                    with Session(engine) as db:
                        row=db.query(AIAnalysis).filter_by(vuln_key=cve).first()
                        if row is None:
                            row=AIAnalysis(vuln_key=cve)
                            db.add(row)
                        row.source=item.get("from") or ""
                        row.model="deepseek"
                        row.result=ai_text
                        row.status="success"
                        row.error=""
                        db.commit()
        except Exception:
            logging.getLogger(__name__).exception("AI analysis failed for %s; sending original intelligence",cve)
    message=format_wecom(item)
    if ai_text:
        message+="\n\n## AI 研判（仅供参考）\n"+ai_text[:3000]
    from .notification_digest import queue_message
    if queue_message(item,message):
        if os.getenv("SMTP_HOST") and os.getenv("SMTP_TO"):
            send_smtp(item)
        return {"queued":True}
    result={}
    webhook=c["wecom_webhook"] if c["wecom_enabled"] else ""
    if webhook or os.getenv("WECHAT_WEBHOOK_URL"):
        result["wechat"]=send_wecom_markdown(message,url=webhook or None)
    if os.getenv("SMTP_HOST") and os.getenv("SMTP_TO"):
        result["email"]=send_smtp(item)
    return result
