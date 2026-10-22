"""Read-only RSS validation endpoint."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .core import auth, engine
from .settings import IntelSource
from .credentials import SourceCredential
from .collector import read_feed

router = APIRouter(prefix="/api/v1/source-check", dependencies=[Depends(auth)])

@router.post("/{source_id}")
def check_source(source_id: int):
    with Session(engine) as db:
        source = db.get(IntelSource, source_id)
        if source is None:
            raise HTTPException(404, "Source not found")
        if source.adapter != "rss":
            raise HTTPException(400, "Only RSS sources are supported")
        credential = db.get(SourceCredential, source_id)
        address = source.notes
        secret = credential.api_key if credential else ""
        header = credential.header_name if credential else "Authorization"
    try:
        items = list(read_feed(address, secret, header))
    except Exception as exc:
        return {"code": 1, "data": {"ok": False, "count": 0, "samples": []},
                "message": type(exc).__name__ + ": " + str(exc)[:180]}
    return {"code": 0, "data": {"ok": True, "count": len(items),
            "samples": [{"title": x["title"], "cve": x["cve"]} for x in items[:3]]},
            "message": "RSS parsed successfully; no records saved or notifications sent"}
