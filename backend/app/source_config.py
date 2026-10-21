"""User-configurable source settings, stored in the same SQLite database."""
from pydantic import BaseModel, Field
from sqlalchemy import String, Text, select
from sqlalchemy.orm import Mapped, mapped_column, Session
from .core import Base, engine

class SourceSetting(Base):
    __tablename__="source_settings"
    id: Mapped[str] = mapped_column(String(80),primary_key=True)
    display_name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(default=False)
    endpoint: Mapped[str] = mapped_column(Text,default="")
    schedule_minutes: Mapped[int] = mapped_column(default=30)

Base.metadata.create_all(engine)

class SourceUpdate(BaseModel):
    display_name: str = Field(min_length=1,max_length=120)
    enabled: bool = False
    endpoint: str = Field(default="",max_length=2000)
    schedule_minutes: int = Field(default=30,ge=5,le=1440)

def list_sources():
    with Session(engine) as db:
        return [{"id":s.id,"display_name":s.display_name,"enabled":s.enabled,
                 "endpoint":s.endpoint,"schedule_minutes":s.schedule_minutes}
                for s in db.scalars(select(SourceSetting).order_by(SourceSetting.id)).all()]

def save_source(source_id, data):
    with Session(engine) as db:
        source=db.get(SourceSetting,source_id)
        if source is None:
            source=SourceSetting(id=source_id)
            db.add(source)
        for k,v in data.model_dump().items(): setattr(source,k,v)
        db.commit()
        return {"id":source_id,**data.model_dump()}
