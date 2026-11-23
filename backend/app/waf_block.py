"""S3-backed WAF block request workflow."""
import ipaddress
import json
import os
import re
import threading
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, Text, DateTime, select, or_
from sqlalchemy.orm import Mapped, mapped_column, Session

from .core import Base, engine, auth

router = APIRouter(prefix="/api/v1/waf", dependencies=[Depends(auth)])

BUCKET = "scc-cn-prd-co-autoplat-external-request"
REGION = "cn-north-1"
ENDPOINT = "https://s3.cn-north-1.amazonaws.com.cn"
REQUEST_PREFIX = "scc_is/request/"
RESPONSE_PREFIX = "scc_is/response/"
BLOCK_BY = [
    "cn_aws", "cn_aliyun", "cn_azure",
    "seahkt_azure", "seahkt_gcp", "seahkt_aws",
]
BLOCK_REASON = "Malicious IP detected by MSOC"
_id_lock = threading.Lock()


class WafBlockRequest(Base):
    __tablename__ = "waf_block_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_request_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    block_ip: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), default="提交中")
    service_request_id: Mapped[str] = mapped_column(String(100), default="")
    response_json: Mapped[str] = mapped_column(Text, default="")
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)


class WafBlockInput(BaseModel):
    # block_ip is deliberately the only user-editable request parameter.
    block_ip: str = Field(min_length=1, max_length=20000)


def normalize_block_ip(value: str) -> str:
    raw_items = [x.strip() for x in re.split(r"[,，;；\s]+", value or "") if x.strip()]
    if not raw_items:
        raise HTTPException(422, "请输入至少一个 IP 或 CIDR")
    normalized = []
    for item in raw_items:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise HTTPException(422, f"IP/CIDR 格式不正确：{item}")
        text = str(network)
        if text not in normalized:
            normalized.append(text)
    return ",".join(normalized)


def next_request_id(db: Session) -> str:
    # The deployment runs one Uvicorn worker. The process lock plus the
    # persisted daily maximum keeps IDs monotonic across restarts.
    today = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y%m%d")
    prefix = f"scc_is_{today}"
    rows = db.scalars(
        select(WafBlockRequest.client_request_id)
        .where(WafBlockRequest.client_request_id.like(prefix + "%"))
    ).all()
    sequence = max(
        (int(item[-4:]) for item in rows if re.fullmatch(re.escape(prefix) + r"\d{4}", item)),
        default=0,
    ) + 1
    if sequence > 9999:
        raise HTTPException(409, "当天封禁请求编号已达到上限")
    return f"{prefix}{sequence:04d}"


def s3_client():
    access_key = os.getenv("S3_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("S3_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY")
    session_token = os.getenv("S3_SESSION_TOKEN") or os.getenv("AWS_SESSION_TOKEN")
    if not access_key or not secret_key:
        raise HTTPException(503, "WAF S3 凭证未配置，请在 backend/.env 配置 S3_ACCESS_KEY_ID 和 S3_SECRET_ACCESS_KEY")
    kwargs = {
        "service_name": "s3",
        "region_name": REGION,
        "endpoint_url": ENDPOINT,
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
        "config": Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            connect_timeout=10,
            read_timeout=20,
            retries={"max_attempts": 2},
        ),
    }
    if session_token:
        kwargs["aws_session_token"] = session_token
    return boto3.client(**kwargs)


def dto(row: WafBlockRequest):
    return {
        "id": row.id,
        "client_request_id": row.client_request_id,
        "block_ip": row.block_ip,
        "status": row.status,
        "service_request_id": row.service_request_id,
        "response": json.loads(row.response_json) if row.response_json else None,
        "last_error": row.last_error,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


@router.get("/requests")
def list_requests(
    q: str = Query(default="", max_length=300),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
):
    with Session(engine) as db:
        stmt = select(WafBlockRequest)
        if q.strip():
            keyword = f"%{q.strip()}%"
            stmt = stmt.where(or_(
                WafBlockRequest.client_request_id.like(keyword),
                WafBlockRequest.block_ip.like(keyword),
                WafBlockRequest.service_request_id.like(keyword),
                WafBlockRequest.status.like(keyword),
            ))
        total = len(db.scalars(stmt).all())
        rows = db.scalars(
            stmt.order_by(WafBlockRequest.id.desc())
            .offset((page - 1) * size).limit(size)
        ).all()
        return {"code": 0, "data": {"list": [dto(row) for row in rows], "total": total}}


@router.post("/requests")
def submit_request(body: WafBlockInput):
    block_ip = normalize_block_ip(body.block_ip)
    with _id_lock:
        with Session(engine) as db:
            request_id = next_request_id(db)
            row = WafBlockRequest(
                client_request_id=request_id,
                block_ip=block_ip,
                status="提交中",
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            row_id = row.id

    payload = {
        "serviceId": 200,
        "params": {
            "block_ip": block_ip,
            "block_by": BLOCK_BY,
            "block_reason": BLOCK_REASON,
            "client_request_id": request_id,
        },
    }
    object_key = REQUEST_PREFIX + request_id + ".json"
    try:
        client = s3_client()
        client.put_object(
            Bucket=BUCKET,
            Key=object_key,
            Body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            ContentType="application/json; charset=utf-8",
        )
        with Session(engine) as db:
            row = db.get(WafBlockRequest, row_id)
            row.status = "已提交，待回执"
            row.last_error = ""
            row.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
            return {"code": 0, "data": dto(row)}
    except HTTPException as exc:
        error = exc.detail
    except (ClientError, BotoCoreError) as exc:
        error = str(exc)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    with Session(engine) as db:
        row = db.get(WafBlockRequest, row_id)
        row.status = "提交失败"
        row.last_error = str(error)[:4000]
        row.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(row)
        if "凭证未配置" in str(error):
            raise HTTPException(503, str(error))
        raise HTTPException(502, f"S3 封禁请求上传失败：{error}")


@router.post("/requests/{client_request_id}/query")
def query_request(client_request_id: str):
    if not re.fullmatch(r"scc_is_\d{12}", client_request_id):
        raise HTTPException(422, "Client Request ID 格式不正确")
    with Session(engine) as db:
        row = db.scalar(select(WafBlockRequest).where(
            WafBlockRequest.client_request_id == client_request_id
        ))
        if row is None:
            raise HTTPException(404, "未找到该封禁请求")
        row_id = row.id

    object_key = RESPONSE_PREFIX + client_request_id + ".json"
    try:
        response = s3_client().get_object(Bucket=BUCKET, Key=object_key)
        raw = response["Body"].read().decode("utf-8")
        result = json.loads(raw)
        if result.get("client_request_id") not in (None, client_request_id):
            raise HTTPException(502, "响应文件中的 client_request_id 与查询请求不一致")
        with Session(engine) as db:
            row = db.get(WafBlockRequest, row_id)
            row.service_request_id = str(result.get("service_request_id") or "")
            row.status = str(result.get("status") or "未知")
            row.response_json = json.dumps(result, ensure_ascii=False)
            row.last_error = ""
            row.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
            return {"code": 0, "data": {"found": True, "request": dto(row)}}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NotFound"):
            with Session(engine) as db:
                row = db.get(WafBlockRequest, row_id)
                return {"code": 0, "data": {"found": False, "request": dto(row)}}
        raise HTTPException(502, f"S3 查询失败：{exc.response.get('Error', {}).get('Message', str(exc))}")
    except HTTPException:
        raise
    except (BotoCoreError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(502, f"读取封禁结果失败：{exc}")


@router.get("/requests/{client_request_id}")
def get_request(client_request_id: str):
    with Session(engine) as db:
        row = db.scalar(select(WafBlockRequest).where(
            WafBlockRequest.client_request_id == client_request_id
        ))
        if row is None:
            raise HTTPException(404, "未找到该封禁请求")
        return {"code": 0, "data": dto(row)}
