from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, Text, DateTime, select, func
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth

router=APIRouter(prefix="/api/v1/mail",dependencies=[Depends(auth)])

class MailTemplate(Base):
    __tablename__="mail_templates"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    name: Mapped[str]=mapped_column(String(200))
    subject: Mapped[str]=mapped_column(Text,default="")
    body: Mapped[str]=mapped_column(Text,default="")
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))

class MailTask(Base):
    __tablename__="mail_tasks"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    name: Mapped[str]=mapped_column(String(200))
    cve: Mapped[str]=mapped_column(String(40),default="")
    recipients: Mapped[str]=mapped_column(Text)
    cc: Mapped[str]=mapped_column(Text,default="")
    subject: Mapped[str]=mapped_column(Text)
    body: Mapped[str]=mapped_column(Text)
    template_id: Mapped[int]=mapped_column(Integer,nullable=True)
    status: Mapped[str]=mapped_column(String(30),default="待发送")
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))

Base.metadata.create_all(engine)

class TemplateInput(BaseModel):
    name: str=Field(min_length=1,max_length=200)
    subject: str=Field(min_length=1)
    body: str=Field(min_length=1)

class TaskInput(BaseModel):
    name: str=Field(min_length=1,max_length=200)
    cve: str=Field(default="",max_length=40)
    recipients: str=Field(min_length=1)
    cc: str=""
    subject: str=Field(min_length=1)
    body: str=Field(min_length=1)
    template_id: Optional[int]=None

def dto(row):
    return {c.name:getattr(row,c.name) for c in row.__table__.columns}

def validate(body):
    values=body.model_dump()
    for key in ("name","subject","body","recipients"):
        if key in values and not values[key].strip():
            raise HTTPException(422,"必填字段不能为空")
    return values

def get_row(db,model,id):
    row=db.get(model,id)
    if row is None:raise HTTPException(404,"记录不存在")
    return row

@router.get("/templates")
def templates(q:str=""):
    with Session(engine) as db:
        stmt=select(MailTemplate)
        if q:stmt=stmt.where(MailTemplate.name.contains(q) | MailTemplate.subject.contains(q))
        return {"code":0,"data":[dto(r) for r in db.scalars(stmt.order_by(MailTemplate.id.desc())).all()]}

@router.post("/templates")
def create_template(body:TemplateInput):
    with Session(engine) as db:
        row=MailTemplate(**validate(body))
        db.add(row);db.commit();db.refresh(row)
        return {"code":0,"data":dto(row)}

@router.put("/templates/{id}")
def update_template(id:int,body:TemplateInput):
    with Session(engine) as db:
        row=get_row(db,MailTemplate,id)
        for k,v in validate(body).items():setattr(row,k,v)
        row.updated_at=datetime.now(timezone.utc)
        db.commit();db.refresh(row)
        return {"code":0,"data":dto(row)}

@router.delete("/templates/{id}")
def delete_template(id:int):
    with Session(engine) as db:
        db.delete(get_row(db,MailTemplate,id));db.commit()
    return {"code":0}

@router.get("/tasks")
def tasks(q:str="",page:int=1,size:int=20):
    page=max(1,page);size=max(1,min(100,size))
    with Session(engine) as db:
        stmt=select(MailTask)
        if q:stmt=stmt.where(MailTask.name.contains(q) | MailTask.cve.contains(q) | MailTask.subject.contains(q) | MailTask.recipients.contains(q))
        count=db.scalar(select(func.count()).select_from(stmt.subquery()))
        rows=db.scalars(stmt.order_by(MailTask.id.desc()).offset((page-1)*size).limit(size)).all()
        return {"code":0,"data":{"total":count,"list":[dto(r) for r in rows]}}

@router.post("/tasks")
def create_task(body:TaskInput):
    with Session(engine) as db:
        values=validate(body)
        if body.template_id is not None:get_row(db,MailTemplate,body.template_id)
        row=MailTask(**values)
        db.add(row);db.commit();db.refresh(row)
        return {"code":0,"data":dto(row)}

@router.get("/tasks/{id}")
def task_detail(id:int):
    with Session(engine) as db:return {"code":0,"data":dto(get_row(db,MailTask,id))}

@router.delete("/tasks/{id}")
def delete_task(id:int):
    with Session(engine) as db:
        db.delete(get_row(db,MailTask,id));db.commit()
    return {"code":0}
