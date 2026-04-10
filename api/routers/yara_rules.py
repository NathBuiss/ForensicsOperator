"""YARA rules library — CRUD and export endpoints."""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from config import settings, get_redis as _r

logger = logging.getLogger(__name__)
router = APIRouter(tags=["yara-rules"])

_RULE_KEY  = "fo:yara_rule:{id}"
_RULES_SET = "fo:yara_rules"


def _load(r, rule_id: str) -> dict | None:
    raw = r.hgetall(_RULE_KEY.format(id=rule_id))
    if not raw:
        return None
    raw["tags"] = json.loads(raw.get("tags", "[]"))
    return raw


class RuleIn(BaseModel):
    name: str
    description: str = ""
    tags: list[str] = []
    content: str


@router.get("/yara-rules")
def list_rules():
    r = _r()
    rules = [_load(r, rid) for rid in r.smembers(_RULES_SET)]
    rules = [ru for ru in rules if ru]
    rules.sort(key=lambda x: x.get("name", "").lower())
    return {"rules": rules, "total": len(rules)}


# NOTE: /yara-rules/export must be declared before /yara-rules/{rule_id}
# so FastAPI doesn't interpret "export" as a rule_id path param.
@router.get("/yara-rules/export")
def export_rules():
    """Export all library rules as a single combined .yar file."""
    r = _r()
    parts = []
    for rid in r.smembers(_RULES_SET):
        raw = r.hgetall(_RULE_KEY.format(id=rid))
        if raw and raw.get("content"):
            parts.append(f"// ── {raw.get('name', rid)} ──\n{raw['content'].strip()}")
    return Response(
        content="\n\n".join(parts),
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="yara_library.yar"'},
    )


@router.get("/yara-rules/{rule_id}")
def get_rule(rule_id: str):
    rule = _load(_r(), rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    return rule


@router.post("/yara-rules", status_code=201)
def create_rule(body: RuleIn):
    rule_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    r = _r()
    mapping = {
        "id":          rule_id,
        "name":        body.name.strip(),
        "description": body.description.strip(),
        "tags":        json.dumps(body.tags),
        "content":     body.content,
        "created_at":  now,
        "updated_at":  now,
    }
    r.hset(_RULE_KEY.format(id=rule_id), mapping=mapping)
    r.sadd(_RULES_SET, rule_id)
    mapping["tags"] = body.tags
    return mapping


@router.put("/yara-rules/{rule_id}")
def update_rule(rule_id: str, body: RuleIn):
    r = _r()
    if not r.exists(_RULE_KEY.format(id=rule_id)):
        raise HTTPException(status_code=404, detail="YARA rule not found")
    now = datetime.now(timezone.utc).isoformat()
    r.hset(_RULE_KEY.format(id=rule_id), mapping={
        "name":        body.name.strip(),
        "description": body.description.strip(),
        "tags":        json.dumps(body.tags),
        "content":     body.content,
        "updated_at":  now,
    })
    return _load(r, rule_id)


@router.delete("/yara-rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str):
    r = _r()
    r.delete(_RULE_KEY.format(id=rule_id))
    r.srem(_RULES_SET, rule_id)
