from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine, auth
class AISettings(Base):
    __tablename__="ai_settings"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    model:Mapped[str]=mapped_column(String(120),default="")
    provider:Mapped[str]=mapped_column(String(120),default="")
    api_url:Mapped[str]=mapped_column(String(500),default="")
    system_prompt:Mapped[str]=mapped_column(Text,default="请严谨分析漏洞，区分已核实事实与推测，不编造CVE、受影响版本和修复建议。")
    active_skill:Mapped[int]=mapped_column(Integer,default=0)
class Skill(Base):
    __tablename__="ai_skill_templates"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    name:Mapped[str]=mapped_column(String(120))
    instructions:Mapped[str]=mapped_column(Text)
    output_format:Mapped[str]=mapped_column(Text,default="")
Base.metadata.create_all(engine)
router=APIRouter(prefix="/api/v1/settings/ai",dependencies=[Depends(auth)])
class SettingsInput(BaseModel):
    model:str=""
    provider:str=""
    api_url:str=""
    system_prompt:str=""
    active_skill:int=0
class SkillInput(BaseModel):
    name:str
    instructions:str
    output_format:str=""
@router.get("")
def get_settings():
    with Session(engine) as db:
        row=db.get(AISettings,1)
        return {"code":0,"data":{k:getattr(row,k) if row else (0 if k=="active_skill" else "") for k in ("model","provider","api_url","system_prompt","active_skill")}}
@router.put("")
def save_settings(body:SettingsInput):
    with Session(engine) as db:
        row=db.get(AISettings,1)
        if not row:row=AISettings(id=1);db.add(row)
        for k,v in body.dict().items():setattr(row,k,v)
        db.commit()
    return {"code":0}
@router.get("/skills")
def get_skills():
    with Session(engine) as db:
        return {"code":0,"data":[{"id":r.id,"name":r.name,"instructions":r.instructions,"output_format":r.output_format} for r in db.query(Skill).order_by(Skill.id.desc()).all()]}
@router.post("/skills")
def add_skill(body:SkillInput):
    with Session(engine) as db:
        row=Skill(**body.dict());db.add(row);db.commit()
        return {"code":0,"data":{"id":row.id}}
@router.put("/skills/{skill_id}")
def edit_skill(skill_id:int,body:SkillInput):
    with Session(engine) as db:
        row=db.get(Skill,skill_id)
        if not row:raise HTTPException(404,"Skill not found")
        for k,v in body.dict().items():setattr(row,k,v)
        db.commit()
    return {"code":0}
@router.delete("/skills/{skill_id}")
def remove_skill(skill_id:int):
    with Session(engine) as db:
        row=db.get(Skill,skill_id)
        if not row:raise HTTPException(404,"Skill not found")
        settings=db.get(AISettings,1)
        if settings and settings.active_skill==skill_id:settings.active_skill=0
        db.delete(row);db.commit()
    return {"code":0}
@router.get("/prompt")
def get_prompt():
    with Session(engine) as db:
        row=db.get(AISettings,1)
        skill=db.get(Skill,row.active_skill) if row and row.active_skill else None
        prompt=row.system_prompt if row else ""
        if skill:prompt+="\n\n# "+skill.name+"\n"+skill.instructions+"\n"+skill.output_format
        return {"code":0,"data":{"prompt":prompt}}
