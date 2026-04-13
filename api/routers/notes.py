"""Per-case investigator notes — stored in Redis."""
from datetime import datetime, timezone
from fastapi import APIRouter
from pydantic import BaseModel
from config import get_redis as _r

router = APIRouter(tags=["notes"])


class NoteIn(BaseModel):
    body: str


@router.get("/cases/{case_id}/notes")
def get_notes(case_id: str):
    r = _r()
    data = r.hgetall(f"fo:notes:{case_id}")
    if not data:
        return {"body": "", "updated_at": None}
    return {
        "body": data.get(b"body", b"").decode(),
        "updated_at": data.get(b"updated_at", b"").decode() or None,
    }


@router.put("/cases/{case_id}/notes")
def save_notes(case_id: str, body: NoteIn):
    now = datetime.now(timezone.utc).isoformat()
    _r().hset(f"fo:notes:{case_id}", mapping={"body": body.body, "updated_at": now})
    return {"updated_at": now}
