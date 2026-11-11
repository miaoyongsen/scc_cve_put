"""Independent crawler script editor, host Python subprocess execution and JSON v1 ingestion.
RSS code and configuration are intentionally untouched.
"""
import json
import hashlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, Text, DateTime, select, Boolean
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth

class CrawlerScript(Base):
    __tablename__="crawler_scripts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    code: Mapped[str] = mapped_column(Text)
    content_type: Mapped[str] = mapped_column(String(30),default="vulnerability",nullable=False)
    ai_enabled: Mapped[bool] = mapped_column(Boolean,default=False,nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))

class CrawlerFinding(Base):
    __tablename__="crawler_findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    script_id: Mapped[int] = mapped_column(Integer, index=True)
    url: Mapped[str] = mapped_column(Text)
    cve: Mapped[str] = mapped_column(String(40), index=True, default="")
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(20), default="未知")
    payload: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))

Base.metadata.create_all(engine)
from sqlalchemy import inspect, text
if "content_type" not in {c["name"] for c in inspect(engine).get_columns("crawler_scripts")}:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE crawler_scripts ADD COLUMN content_type VARCHAR(30) NOT NULL DEFAULT 'vulnerability'"))
if "ai_enabled" not in {c["name"] for c in inspect(engine).get_columns("crawler_scripts")}:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE crawler_scripts ADD COLUMN ai_enabled BOOLEAN NOT NULL DEFAULT 0"))
router=APIRouter(prefix="/api/v1/crawlers",dependencies=[Depends(auth)])
CVE=re.compile(r"^CVE-\d{4}-\d{4,}$",re.I)
LEVELS={"严重","高危","中危","低危","未知"}
class ScriptInput(BaseModel):
    name:str=Field(min_length=1,max_length=100)
    code:str=Field(min_length=1,max_length=100000)
    content_type:str=Field(default="vulnerability")
    ai_enabled:bool=False

def dto(x):
    return {"id":x.id,"name":x.name,"code":x.code,"content_type":("article" if x.content_type=="article_review" else x.content_type),"ai_enabled":x.ai_enabled,"updated_at":x.updated_at}

def validate_item(item,index):
    if not isinstance(item,dict):raise ValueError(f"items[{index}] 必须为对象")
    title=item.get("title")
    url=item.get("url")
    if not isinstance(title,str) or not title.strip() or len(title)>500:
        raise ValueError(f"items[{index}].title 必须是非空字符串（最多500字）")
    from urllib.parse import urlparse
    if not isinstance(url,str) or len(url)>2000 or urlparse(url).scheme not in ("https","http") or not urlparse(url).hostname:
        raise ValueError(f"items[{index}].url 必须是有效 HTTP(S) 地址")
    cve=(item.get("cve") or "").upper()
    if not isinstance(cve,str) or (cve and not CVE.fullmatch(cve)):
        raise ValueError(f"items[{index}].cve 格式错误")
    severity=item.get("severity") or "未知"
    if severity not in LEVELS:raise ValueError(f"items[{index}].severity 不支持：{severity}")
    score=item.get("cvss_score")
    if score is not None and (type(score) not in (float,int) or not 0<=score<=10):
        raise ValueError(f"items[{index}].cvss_score 必须在0到10之间")
    for key in ("description","solutions","disclosure"):
        if key in item and not isinstance(item[key],str):raise ValueError(f"items[{index}].{key} 必须为字符串")
    if item.get("disclosure"):
        from datetime import datetime
        d=datetime.fromisoformat(item["disclosure"].replace("Z","+00:00"))
        if d.tzinfo is None:raise ValueError(f"items[{index}].disclosure 必须包含时区")
    if "tags" in item and (not isinstance(item["tags"],list) or not all(isinstance(t,str) for t in item["tags"])):
        raise ValueError(f"items[{index}].tags 必须为字符串数组")
    source=item.get("source")
    if source is not None and (not isinstance(source,str) or len(source.strip())>100):
        raise ValueError(f"items[{index}].source 必须为不超过100字的字符串")
    result={**item,"cve":cve,"severity":severity}
    if len(json.dumps(result,ensure_ascii=False))>30000:raise ValueError(f"items[{index}] 超出大小限制")
    return result

def run_script(code, strict=True):
    # Runs with the same OS permissions as the backend service; trusted admins only.
    command=[sys.executable,"-c",code]
    try:
        proc=subprocess.run(command,input="",text=True,capture_output=True,timeout=35)
    except FileNotFoundError:
        raise HTTPException(503,"服务器 Python 解释器不可用")
    except subprocess.TimeoutExpired:
        raise HTTPException(408,"爬虫执行超过35秒")
    if len(proc.stdout)>2_000_000 or len(proc.stderr)>100_000:
        raise HTTPException(422,"脚本输出超出大小限制")
    if not strict:
        # Preview is for debugging: arbitrary text, JSON, and failure messages are all valid output.
        return {"stdout":proc.stdout,"stderr":proc.stderr,"exit_code":proc.returncode}
    if proc.returncode:
        raise HTTPException(422,{"stdout":proc.stdout[-3000:],"stderr":proc.stderr[-3000:],"exit_code":proc.returncode})
    try:payload=json.loads(proc.stdout)
    except ValueError:raise HTTPException(422,"stdout 必须仅输出一个 JSON 对象；日志请写入 stderr")
    if not isinstance(payload,dict) or payload.get("version")!="1.0" or not isinstance(payload.get("items"),list):
        raise HTTPException(422,"输出必须为 {version:'1.0',items:[...]}")
    if len(payload["items"])>500:raise HTTPException(422,"单次最多500条")
    try:items=[validate_item(item,i) for i,item in enumerate(payload["items"])]
    except (ValueError,TypeError) as exc:raise HTTPException(422,str(exc))
    return {"items":items,"stderr":proc.stderr[-3000:],"count":len(items)}

@router.get("")
def list_scripts():
    with Session(engine) as db:
        return {"code":0,"data":[dto(x) for x in db.scalars(select(CrawlerScript).order_by(CrawlerScript.id)).all()]}

@router.post("")
def create_script(body:ScriptInput):
    with Session(engine) as db:
        if db.scalar(select(CrawlerScript).where(CrawlerScript.name==body.name)):raise HTTPException(409,"名称已存在")
        x=CrawlerScript(name=body.name,code=body.code,content_type=("article" if body.content_type=="article_review" else body.content_type),ai_enabled=body.ai_enabled)
        db.add(x);db.commit();db.refresh(x)
        return {"code":0,"data":dto(x)}

@router.put("/{script_id}")
def update_script(script_id:int,body:ScriptInput):
    with Session(engine) as db:
        x=db.get(CrawlerScript,script_id)
        if not x:raise HTTPException(404,"脚本不存在")
        if db.scalar(select(CrawlerScript).where(CrawlerScript.name==body.name,CrawlerScript.id!=script_id)):raise HTTPException(409,"名称已存在")
        x.name=body.name;x.code=body.code;x.content_type=("article" if body.content_type=="article_review" else body.content_type);x.ai_enabled=body.ai_enabled;x.updated_at=datetime.now(timezone.utc)
        db.commit();return {"code":0,"data":dto(x)}

@router.delete("/{script_id}")
def delete_script(script_id:int):
    with Session(engine) as db:
        x=db.get(CrawlerScript,script_id)
        if not x:raise HTTPException(404,"脚本不存在")
        db.delete(x);db.commit()
    return {"code":0,"message":"deleted"}

@router.post("/{script_id}/test")
def test_script(script_id:int):
    with Session(engine) as db:
        x=db.get(CrawlerScript,script_id)
        if not x:raise HTTPException(404,"脚本不存在")
        code=x.code
    return {"code":0,"data":run_script(code,strict=False)}

@router.post("/{script_id}/collect")
def _collect_script(script_id:int):
    with Session(engine) as db:
        x=db.get(CrawlerScript,script_id)
        if not x:raise HTTPException(404,"脚本不存在")
        code=x.code
        script_name=x.name
        content_type=x.content_type
        ai_enabled=x.ai_enabled
    if content_type=="article_review":content_type="article"
    result=run_script(code)
    inserted=0
    from .core import Vulnerability
    from .eligibility import evaluate
    from .review import Review, has_unknown_pending_review, resolve_unknown_reviews
    from .worker import upsert
    from .legacy_notify import send_vulnerability
    from .core import log_run
    inserted=0
    primary=0
    secondary=0
    filtered=0
    notified=0
    notification_errors=[]
    duplicates=[]
    pushed=[]
    pending=[]
    collection_time=datetime.now().astimezone().isoformat(timespec="seconds")
    for item in result["items"]:
        source=(item.get("source") or "").strip() or script_name
        item={**item,"source":source}
        if content_type=="vulnerability" and item.get("severity")=="未知" and item.get("cve"):
            from .collector import nvd_severity
            from .core import Vulnerability
            with Session(engine) as check_db:
                known=check_db.scalar(select(Vulnerability.id).where(Vulnerability.cve==item["cve"]))
            if not known:item["severity"]=nvd_severity(item["cve"])
        tier,keyword,rejected=evaluate(item) if content_type=="vulnerability" else ("article",None,None)
        upgrade_candidate = False
        if content_type=="vulnerability" and item.get("cve") and item.get("severity") in ("高危", "严重"):
            with Session(engine) as check_db:
                upgrade_candidate = has_unknown_pending_review(check_db, item.get("cve"))
        from .eligibility import allow_unknown_review_upgrade
        tier,keyword,rejected=allow_unknown_review_upgrade(
            item,tier,keyword,rejected,upgrade_candidate
        )
        if rejected:
            filtered+=1
            continue
        key=hashlib.sha256(("crawler:"+str(script_id)+":"+item["url"]).encode()).hexdigest()
        normalized={"key":key,"title":item["title"],"description":item.get("description") or "",
                    "severity":item["severity"],"cve":item["cve"],
                    "disclosure":collection_time if content_type in ("article","article_review") else (item.get("disclosure") or ""),
                    "solutions":item.get("solutions") or "",
                    "references":[item["url"]],"tags":item.get("tags") or [],
                    "from":source,"reason":[],"content_type":content_type}
        with Session(engine) as db:
            url_fingerprint=hashlib.md5(item["url"].encode("utf-8")).hexdigest()
            old=next((record for record in db.scalars(select(CrawlerFinding).where(CrawlerFinding.script_id==script_id)).all() if hashlib.md5(record.url.encode("utf-8")).hexdigest()==url_fingerprint),None)
            if old is None:
                db.add(CrawlerFinding(script_id=script_id,url=item["url"],cve=item["cve"],title=item["title"],severity=item["severity"],payload=json.dumps(item,ensure_ascii=False)))
                inserted+=1
            else:
                duplicates.append({"title":item["title"],"cve":item["cve"],"reason":"相同 URL 已采集"})
                old.cve=item["cve"]
                old.title=item["title"]
                old.severity=item["severity"]
                old.payload=json.dumps(item,ensure_ascii=False)
            # Shared persistence and CVE grouping; separate collection execution.
            new_cve=bool(item["cve"]) and not bool(db.scalar(select(Vulnerability.id).where(Vulnerability.cve==item["cve"])))
            pending_upgrade = (content_type=="vulnerability" and tier=="primary" and item["severity"] in ("高危","严重") and has_unknown_pending_review(db,item.get("cve")))
            notify=upsert(db,normalized,content_type=="vulnerability")
            if pending_upgrade:
                notify=True
            # Repeated URLs are not sent again.
            if content_type in ("article","article_review"):
                notify=old is None
            vuln=db.scalar(select(Vulnerability).where(Vulnerability.key==key))
            review=db.scalar(select(Review).where(Review.vulnerability_id==vuln.id))
            if review and content_type=="vulnerability" and not (pending_upgrade and review.status=="pending" and review.matched_keyword=="等级未知"):
                notify=False
            elif tier=="secondary" and content_type=="vulnerability":
                db.add(Review(vulnerability_id=vuln.id,status="pending",matched_keyword=keyword or ""))
                db.commit()
                notify=False
        if tier=="primary":
            primary+=1
        elif tier=="secondary":
            secondary+=1
        if tier=="secondary":pending.append({"title":item["title"],"cve":item["cve"]})
        log_run(normalized,tier,"待推送" if notify else ("待审核" if tier=="secondary" else "未推送"),keyword or "")
        if notify:
            try:
                outcome=send_vulnerability(normalized,ai_enabled=new_cve)
                if outcome and outcome.get("queued"):
                    log_run(normalized,tier,"待合并推送")
                elif outcome and any(outcome.values()):
                    notified+=1
                    log_run(normalized,tier,"推送成功")
                    pushed.append({"title":item["title"],"cve":item["cve"]})
                    if tier=="primary" and item["severity"] in ("高危","严重"):
                        resolve_unknown_reviews(item.get("cve"))
                else:
                    log_run(normalized,tier,"推送未成功","无有效通知渠道或被推送规则过滤")
            except Exception as exc:
                log_run(normalized,tier,"推送失败",str(exc))
                notification_errors.append(str(exc)[:160])
    return {"code":0,"data":{"inserted":inserted,"count":result["count"],
            "primary":primary,"secondary":secondary,"filtered":filtered,"content_type":content_type,
            "notifications":notified,"notification_errors":notification_errors,
            "duplicates":duplicates,"pushed":pushed,"pending":pending,"stderr":result["stderr"]}}

def collect_script(script_id:int):
    from .core import _active_run,begin_run,finish_run
    existing=_active_run.get()
    if existing:return _collect_script(script_id)
    from .notification_digest import begin_digest,end_digest,flush_digest
    run_id=begin_run("Python 爬虫")
    token=_active_run.set(run_id)
    digest_token=begin_digest()
    try:
        result=_collect_script(script_id)
        delivery=flush_digest()
        result["data"]["notifications"]+=delivery["notifications"]
        result["data"]["notification_errors"].extend(delivery["errors"])
        result["data"]["pushed"].extend(delivery["pushed"])
        finish_run(run_id,"部分失败" if result["data"]["notification_errors"] else "完成",
                   {"details":[{"name":str(script_id),"adapter":"python","http_status":None,"status":"partial" if result["data"]["notification_errors"] else "done",**result["data"]}],"errors":delivery["errors"]})
        return result
    except Exception as exc:
        finish_run(run_id,"失败",{"error":str(exc),"details":[{"name":str(script_id),"adapter":"python","status":"error","error":str(exc)}]})
        raise
    finally:
        end_digest(digest_token)
        _active_run.reset(token)

@router.post("/collect-all")
def collect_all_scripts():
    """Run all Python crawlers and send one digest per content type."""
    from .core import _active_run,begin_run,finish_run
    from .notification_digest import begin_digest,end_digest,flush_digest
    run_id=begin_run("全部 Python 爬虫")
    token=_active_run.set(run_id)
    digest_token=begin_digest()
    try:
        with Session(engine) as db:
            ids=[x.id for x in db.scalars(select(CrawlerScript.id).order_by(CrawlerScript.id)).all()]
        details=[]
        for script_id in ids:
            try:
                result=_collect_script(script_id)["data"]
                details.append({"id":script_id,"name":str(script_id),"adapter":"python","status":"partial" if result["notification_errors"] else "done",**result})
            except Exception as exc:
                details.append({"id":script_id,"name":str(script_id),"adapter":"python","status":"error","error":str(exc)[:500]})
        delivery=flush_digest()
        errors=list(delivery["errors"])
        if errors:details.append({"name":"合并推送","adapter":"notification","status":"error","error":"；".join(errors)})
        state="部分失败" if errors or any(x["status"] in ("partial","error") for x in details) else "完成"
        finish_run(run_id,state,{"details":details,"errors":errors,"notifications":delivery["notifications"]})
        return {"code":0,"data":{"total":len(ids),"success":sum(x["status"]=="done" for x in details),"details":details,"notifications":delivery["notifications"]}}
    except Exception as exc:
        finish_run(run_id,"失败",{"error":str(exc),"errors":[str(exc)]})
        raise
    finally:
        end_digest(digest_token)
        _active_run.reset(token)

@router.get("/findings")
def list_findings():
    with Session(engine) as db:
        rows=db.scalars(select(CrawlerFinding).order_by(CrawlerFinding.first_seen.asc(),CrawlerFinding.id.asc())).all()
        groups={}
        for row in rows:
            key=row.cve.upper() if row.cve else "ID-"+str(row.id)
            groups.setdefault(key,[]).append({"id":row.id,"script_id":row.script_id,"first_seen":row.first_seen,**json.loads(row.payload)})
        return {"code":0,"data":[{"cve":k if not k.startswith("ID-") else "","count":len(v),"items":v} for k,v in groups.items()]}
