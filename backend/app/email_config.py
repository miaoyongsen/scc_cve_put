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

@router.post("/test")
def test_connection():
    cfg=config_snapshot()
    smtp=None
    try:
        smtp=open_smtp(cfg)
        return {"code":0,"data":{"success":True,"message":"SMTP TLS连接及账号认证成功"}}
    except Exception as exc:
        raise HTTPException(502,error_label(exc))
    finally:
        if smtp is not None:smtp.close()

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
