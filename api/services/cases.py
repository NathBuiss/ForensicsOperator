"""Case management — cases are stored in Redis as JSON hashes."""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from config import settings, get_redis

logger = logging.getLogger(__name__)
CASE_TTL = 0  # Cases don't expire by default


def create_case(name: str, description: str = "", analyst: str = "") -> dict:
    r = get_redis()
    case_id = uuid.uuid4().hex[:12]
    case = {
        "case_id": case_id,
        "name": name,
        "description": description,
        "analyst": analyst,
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "tags": json.dumps([]),
    }
    r.hset(f"case:{case_id}", mapping=case)
    r.sadd("cases:all", case_id)
    return case


def get_case(case_id: str) -> dict | None:
    r = get_redis()
    data = r.hgetall(f"case:{case_id}")
    if not data:
        return None
    for field in ("tags",):
        if field in data:
            try:
                data[field] = json.loads(data[field])
            except Exception:
                data[field] = []
    return data


def list_cases() -> list[dict]:
    r = get_redis()
    case_ids = r.smembers("cases:all")
    cases = []
    for cid in case_ids:
        case = get_case(cid)
        if case:
            cases.append(case)
    return sorted(cases, key=lambda c: c.get("created_at", ""), reverse=True)


def update_case(case_id: str, **fields) -> dict | None:
    r = get_redis()
    if not r.exists(f"case:{case_id}"):
        return None
    fields["updated_at"] = datetime.now(timezone.utc).isoformat()
    if "tags" in fields:
        fields["tags"] = json.dumps(fields["tags"])
    r.hset(f"case:{case_id}", mapping=fields)
    return get_case(case_id)


def delete_case(case_id: str) -> bool:
    r = get_redis()
    if not r.exists(f"case:{case_id}"):
        return False
    r.delete(f"case:{case_id}")
    r.srem("cases:all", case_id)
    # Also delete from ES
    from services.elasticsearch import delete_case_indices
    delete_case_indices(case_id)
    return True
