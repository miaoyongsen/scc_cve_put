import smtplib
import ssl
import re
import socket
from email.message import EmailMessage
from email import policy
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, Text, DateTime, select, func
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth

router=APIRouter(prefix="/api/v1/settings/email",dependencies=[Depends(auth)])

class SMTPSettings(Base):
    __tablename__="smtp_settings"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    host: Mapped[str]=mapped_column(String(255),default="")
    port: Mapped[int]=mapped_column(Integer,default=465)
    security: Mapped[str]=mapped_column(String(20),default="ssl")
    username: Mapped[str]=mapped_column(String(255),default="")
    password: Mapped[str]=mapped_column(Text,default="")
    flow_recipient: Mapped[str]=mapped_column(String(255),default="")

class EmailSendLog(Base):
    __tablename__="email_send_logs"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    task_id: Mapped[str]=mapped_column(String(100),default="")
    sender: Mapped[str]=mapped_column(String(255))
    recipient: Mapped[str]=mapped_column(String(255))
    subject: Mapped[str]=mapped_column(Text)
    body: Mapped[str]=mapped_column(Text)
    status: Mapped[str]=mapped_column(String(30),default="发送中")
    error: Mapped[str]=mapped_column(Text,default="")
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))

class TeamsMailSettings(Base):
    __tablename__='teams_mail_settings'
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    webhook_url: Mapped[str]=mapped_column(Text,default='')

Base.metadata.create_all(engine)

class SMTPInput(BaseModel):
    host: str=Field(min_length=1,max_length=255)
    port: int=Field(ge=1,le=65535)
    security: str="ssl"
    username: str=Field(min_length=1,max_length=255)
    password: str=""
    flow_recipient: str=""

def valid_email(s):
    return bool(re.fullmatch(r"[^@\s<>;,]+@[^@\s<>;,]+\.[^@\s<>;,]+",s or ""))

def public_settings(row):
    return {"host":row.host if row else "", "port":row.port if row else 465,
        "security":row.security if row else "ssl","username":row.username if row else "",
        "has_password":bool(row and row.password),"flow_recipient":row.flow_recipient if row else ""}

def validate_settings(body):
    if not re.fullmatch(r"[A-Za-z0-9.-]+",body.host.strip()):
        raise HTTPException(422,"SMTP服务器填写域名或IPv4地址，不包含协议")
    if body.security not in ("ssl","starttls"):
        raise HTTPException(422,"仅支持 SSL/TLS 或 STARTTLS 加密")
    if not valid_email(body.username.strip()):
        raise HTTPException(422,"请输入完整的邮箱账号")
    if body.flow_recipient.strip() and not valid_email(body.flow_recipient.strip()):
        raise HTTPException(422,"微软流接收邮箱格式无效")

def config_snapshot(require_recipient=False):
    with Session(engine) as db:
        row=db.get(SMTPSettings,1)
        if not row or not all((row.host,row.username,row.password)):
            raise HTTPException(422,"请先在公共配置 → 邮箱配置中保存 SMTP 设置")
        if require_recipient and not valid_email(row.flow_recipient):
            raise HTTPException(422,"请先配置微软流接收邮箱")
        return {**public_settings(row),"password":row.password}

def open_smtp(cfg):
    ctx=ssl.create_default_context()
    if cfg["security"]=="ssl":
        smtp=smtplib.SMTP_SSL(cfg["host"],cfg["port"],timeout=20,context=ctx)
    else:
        smtp=smtplib.SMTP(cfg["host"],cfg["port"],timeout=20)
    try:
        smtp.ehlo()
        if cfg["security"]=="starttls":
            smtp.starttls(context=ctx)
            smtp.ehlo()
        smtp.login(cfg["username"],cfg["password"])
        return smtp
    except Exception:
        smtp.close()
        raise

def error_label(exc):
    if isinstance(exc,smtplib.SMTPAuthenticationError):
        return "SMTP认证失败（"+str(exc.smtp_code)+"），请检查账号、授权码及SMTP权限"
    if isinstance(exc,ssl.SSLError):return "TLS证书或加密握手失败"
    if isinstance(exc,(TimeoutError,socket.timeout)):return "SMTP连接或响应超时，请检查服务器出网及端口"
    if isinstance(exc,smtplib.SMTPResponseException):return "SMTP拒绝请求（"+str(exc.smtp_code)+"）"
    if isinstance(exc,smtplib.SMTPRecipientsRefused):return "SMTP拒绝收件人"
    return "SMTP错误："+type(exc).__name__

@router.get("")
def get_settings():
    with Session(engine) as db:
        return {"code":0,"data":public_settings(db.get(SMTPSettings,1))}

@router.put("")
def save_settings(body:SMTPInput):
    validate_settings(body)
    with Session(engine) as db:
        row=db.get(SMTPSettings,1)
        if row is None:
            row=SMTPSettings(id=1)
            db.add(row)
        for key in ("host","security","username","flow_recipient"):
            setattr(row,key,getattr(body,key).strip())
        row.port=body.port
        if body.password:row.password=body.password
        if not row.password:raise HTTPException(422,"首次配置请输入邮箱密码或SMTP授权码")
        db.commit();db.refresh(row)
        return {"code":0,"data":public_settings(row)}

def diagnostic_text(value, cfg):
    import base64
    value = str(value)
    for secret in (cfg.get("password"), cfg.get("username")):
        if secret:
            value = re.sub(re.escape(secret), "[已脱敏]", value, flags=re.I)
            value = value.replace(base64.b64encode(secret.encode()).decode(), "[已脱敏]")
    return value[:2000]


@router.post("/test")
def test_connection(body: SMTPInput = None):
    import time
    if body is None:
        cfg = config_snapshot()
    else:
        validate_settings(body)
        cfg = {"host": body.host.strip(), "port": body.port,
               "security": body.security, "username": body.username.strip(),
               "password": body.password}
        if not cfg["password"]:
            with Session(engine) as db:
                row = db.get(SMTPSettings, 1)
                if row and row.username == cfg["username"] and row.host == cfg["host"]:
                    cfg["password"] = row.password
        if not cfg["password"]:
            raise HTTPException(422, "请输入 SMTP 授权码")
    names = ["DNS 域名解析", "TCP 端口连接", "SSL/TLS 握手",
             "SMTP 服务响应", "SMTP 账号认证"]
    steps = {name: {"name": name, "status": "未执行", "elapsed_ms": None, "detail": ""} for name in names}
    smtp = None
    sock = None
    active = ""
    started = time.monotonic()
    def run(name, fn):
        nonlocal active, started
        active = name
        started = time.monotonic()
        result = fn()
        steps[name].update(status="成功", elapsed_ms=round((time.monotonic()-started)*1000))
        if isinstance(result, str):
            steps[name]["detail"] = diagnostic_text(result, cfg)
        return result
    def check_reply(pair, expected):
        code, reply = pair
        if code != expected:
            raise smtplib.SMTPResponseException(code, reply)
        return str(code) + " " + reply.decode("utf-8", errors="replace")
    def connect_tcp():
        last = None
        deadline = time.monotonic() + 10
        for family, kind, proto, _, address in addresses:
            s = socket.socket(family, kind, proto)
            try:
                s.settimeout(max(0.1, deadline-time.monotonic()))
                s.connect(address)
                s.settimeout(10)
                return s
            except OSError as exc:
                last = exc
                s.close()
            if time.monotonic() >= deadline:
                break
        raise last or OSError("No reachable address")
    try:
        addresses = run(names[0], lambda: socket.getaddrinfo(cfg["host"], cfg["port"], type=socket.SOCK_STREAM))
        steps[names[0]]["detail"] = ", ".join(dict.fromkeys(a[4][0] for a in addresses))
        sock = run(names[1], connect_tcp)
        steps[names[1]]["detail"] = str(sock.getpeername())
        smtp = smtplib.SMTP(timeout=10)
        smtp._host = cfg["host"]
        if cfg["security"] == "ssl":
            sock = run(names[2], lambda: ssl.create_default_context().wrap_socket(sock, server_hostname=cfg["host"]))
            steps[names[2]]["detail"] = str(sock.version())
        smtp.sock = sock
        def greeting():
            check_reply(smtp.getreply(), 220)
            return check_reply(smtp.ehlo(), 250)
        run(names[3], greeting)
        if cfg["security"] == "starttls":
            def upgrade():
                check_reply(smtp.starttls(context=ssl.create_default_context()), 220)
                return str(smtp.sock.version())
            run(names[2], upgrade)
            run(names[3], lambda: check_reply(smtp.ehlo(), 250))
        def login():
            code, reply = smtp.login(cfg["username"], cfg["password"])
            return str(code) + " " + reply.decode("utf-8", errors="replace")
        run(names[4], login)
        success, message = True, "SMTP TLS连接及账号认证成功（未发送邮件）"
    except Exception as exc:
        detail = diagnostic_text(type(exc).__name__ + ": " + str(exc), cfg)
        if active:
            steps[active].update(status="失败", elapsed_ms=round((time.monotonic()-started)*1000), detail=detail)
        success, message = False, active + "失败：" + error_label(exc)
    finally:
        if smtp is not None:
            smtp.close()
        if sock is not None:
            sock.close()
    ordered = names if cfg["security"] == "ssl" else [names[0],names[1],names[3],names[2],names[4]]
    return {"code":0,"data":{"success":success,"message":message,
        "steps":[steps[n] for n in ordered],
        "server":cfg["host"]+":"+str(cfg["port"]), "security":cfg["security"]}}


def send_logged(cfg,recipient,subject,body,task_id=""):
    """Log each actual SMTP attempt; success means SMTP acceptance, not Flow delivery."""
    if not valid_email(recipient):
        raise HTTPException(422,"收件人格式无效")
    message=EmailMessage(policy=policy.SMTP)
    message["From"]=cfg["username"]
    message["To"]=recipient
    message["Subject"]=subject
    message.set_content(body,subtype="plain",charset="utf-8")
    with Session(engine) as db:
        row=EmailSendLog(task_id=task_id,sender=cfg["username"],recipient=recipient,
            subject=subject,body=body,status="发送中")
        db.add(row);db.commit();db.refresh(row);log_id=row.id
    smtp=None
    transmitting=False
    status,error="发送失败",""
    try:
        smtp=open_smtp(cfg)
        transmitting=True
        refused=smtp.send_message(message,from_addr=cfg["username"],to_addrs=[recipient])
        if refused:
            error="SMTP拒绝收件人"
        else:
            status="SMTP已接收"
    except (smtplib.SMTPRecipientsRefused,smtplib.SMTPSenderRefused,smtplib.SMTPDataError) as exc:
        error=error_label(exc)
    except Exception as exc:
        status="待确认" if transmitting else "发送失败"
        error=error_label(exc)
    finally:
        if smtp is not None:smtp.close()
    with Session(engine) as db:
        row=db.get(EmailSendLog,log_id)
        row.status=status;row.error=error
        db.commit()
    return {"status":status,"error":error,"log_id":log_id}

@router.get("/logs")
def logs(page:int=1):
    page=max(1,page)
    with Session(engine) as db:
        total=db.scalar(select(func.count()).select_from(EmailSendLog))
        rows=db.scalars(select(EmailSendLog).order_by(EmailSendLog.id.desc()).offset((page-1)*10).limit(10)).all()
        return {"code":0,"data":{"total":total,"list":[{c.name:getattr(r,c.name) for c in r.__table__.columns if c.name!="body"} for r in rows]}}

@router.get("/logs/{id}")
def log_detail(id:int):
    with Session(engine) as db:
        row=db.get(EmailSendLog,id)
        if not row:raise HTTPException(404,"发送记录不存在")
        return {"code":0,"data":{c.name:getattr(row,c.name) for c in row.__table__.columns}}

class TestMailInput(BaseModel):
    recipient: str

@router.post("/send-test")
def send_test(body:TestMailInput):
    # Deliberately avoid the SCC-CTI-TASK subject to prevent accidental Flow execution.
    cfg=config_snapshot()
    result=send_logged(cfg,body.recipient.strip(),"SCC SMTP connection test","This is an SCC SMTP delivery test.")
    return {"code":0,"data":result}


# Teams Webhook transport. Legacy SMTP records remain readable.
class TeamsInput(BaseModel):
    webhook_url: str = ""

def validate_teams_url(value):
    from urllib.parse import urlsplit
    try:
        u=urlsplit(value)
        host=(u.hostname or "").lower()
        if (u.scheme!="https" or u.username or u.password or u.fragment or
            u.port not in (None,443) or not host.endswith((".logic.azure.com",".api.powerplatform.com",".powerautomate.com"))):
            raise ValueError()
    except ValueError:
        raise HTTPException(422,"请输入微软工作流的 HTTPS Webhook 地址")
    return value

def teams_snapshot():
    with Session(engine) as db:
        row=db.get(TeamsMailSettings,1)
        if not row or not row.webhook_url:
            raise HTTPException(422,"请先在公共配置 → 邮箱配置保存 Teams Webhook")
        return validate_teams_url(row.webhook_url)

@router.get("/teams")
def get_teams():
    with Session(engine) as db:
        row=db.get(TeamsMailSettings,1)
        return {"code":0,"data":{"configured":bool(row and row.webhook_url)}}

@router.put("/teams")
def save_teams(body:TeamsInput):
    with Session(engine) as db:
        row=db.get(TeamsMailSettings,1)
        if not row:
            row=TeamsMailSettings(id=1)
            db.add(row)
        if body.webhook_url.strip():
            row.webhook_url=validate_teams_url(body.webhook_url.strip())
        elif not row.webhook_url:
            raise HTTPException(422,"请输入 Webhook 地址")
        db.commit()
        return {"code":0,"data":{"configured":True}}

def send_teams_logged(url,payload,subject):
    import httpx
    import json
    validate_teams_url(url)
    body=json.dumps(payload,ensure_ascii=False)
    card={"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive",
        "contentUrl":None,"content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json",
        "type":"AdaptiveCard","version":"1.2","body":[{"type":"TextBlock","text":body}]}}]}
    with Session(engine) as db:
        row=EmailSendLog(task_id=payload["task_id"],sender="Teams Webhook / Outlook",
            recipient="; ".join(payload["to"]),subject=subject,body=body,status="发送中")
        db.add(row);db.commit();db.refresh(row);log_id=row.id
    status,error="待确认","请求结果未确认，请核对微软流运行记录，勿直接重发"
    try:
        response=httpx.post(url,json=card,timeout=30,follow_redirects=False)
        if 200<=response.status_code<300:
            status,error="Webhook已接收",""
        elif response.status_code in (400,401,403,404,405,413,415,422):
            status,error="发送失败","Webhook HTTP "+str(response.status_code)
        else:
            error="Webhook HTTP "+str(response.status_code)+"，请核对运行记录"
    except httpx.RequestError as exc:
        error="Webhook请求异常："+type(exc).__name__+"，请核对运行记录"
    with Session(engine) as db:
        row=db.get(EmailSendLog,log_id)
        row.status=status;row.error=error;db.commit()
    return {"status":status,"error":error,"log_id":log_id}
