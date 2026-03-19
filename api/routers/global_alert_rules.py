"""
Global Alert Rule Library.

Rules are stored in Redis at fo:alert_rules:_global and are not tied to any
specific case. They can be run on demand against any case's Elasticsearch data
via the /cases/{case_id}/alert-rules/run-library endpoint.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime

import redis as redis_lib
from fastapi import APIRouter
from pydantic import BaseModel

from config import settings
from services.elasticsearch import _request as es_req

router = APIRouter(tags=["global-alert-rules"])

GLOBAL_KEY = "fo:alert_rules:_global"


def _redis() -> redis_lib.Redis:
    return redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


class AlertRuleIn(BaseModel):
    name: str
    description: str = ""
    artifact_type: str = ""
    query: str
    threshold: int = 1


class AlertRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    artifact_type: str | None = None
    query: str | None = None
    threshold: int | None = None


# ── Library CRUD ──────────────────────────────────────────────────────────────

@router.get("/alert-rules/library")
def list_library():
    """Return all global alert rules."""
    data = _redis().get(GLOBAL_KEY)
    return {"rules": json.loads(data) if data else []}


@router.post("/alert-rules/library", status_code=201)
def create_library_rule(body: AlertRuleIn):
    """Add a new rule to the global library."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    new_rule = {
        "id": str(uuid.uuid4())[:8],
        **body.dict(),
        "created_at": datetime.utcnow().isoformat(),
    }
    rules.append(new_rule)
    r.set(GLOBAL_KEY, json.dumps(rules))
    return new_rule


@router.put("/alert-rules/library/{rule_id}")
def update_library_rule(rule_id: str, body: AlertRuleUpdate):
    """Update an existing rule in the global library."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    updated = None
    for rl in rules:
        if rl["id"] == rule_id:
            patch = body.dict(exclude_none=True)
            rl.update(patch)
            updated = rl
            break
    if updated is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Rule not found")
    r.set(GLOBAL_KEY, json.dumps(rules))
    return updated


@router.delete("/alert-rules/library/{rule_id}", status_code=204)
def delete_library_rule(rule_id: str):
    """Remove a rule from the global library."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    r.set(GLOBAL_KEY, json.dumps([rl for rl in rules if rl["id"] != rule_id]))


# ── Run library against a case ────────────────────────────────────────────────

@router.post("/cases/{case_id}/alert-rules/run-library")
def run_library_against_case(case_id: str):
    """
    Execute every rule in the global library against the given case's data.

    Returns a list of matches (rules that fired) with sample events.
    """
    r = _redis()
    data = r.get(GLOBAL_KEY)
    rules: list[dict] = json.loads(data) if data else []

    if not rules:
        return {"matches": [], "rules_checked": 0}

    matches: list[dict] = []

    for rule in rules:
        artifact_type = rule.get("artifact_type", "").strip()
        index = (
            f"fo-case-{case_id}-{artifact_type}"
            if artifact_type
            else f"fo-case-{case_id}-*"
        )

        body = {
            "query": {
                "query_string": {
                    "query": rule["query"],
                    "default_operator": "AND",
                }
            },
            "size": 5,
            "_source": ["timestamp", "message", "host", "user", "fo_id", "artifact_type"],
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        try:
            resp = es_req("POST", f"/{index}/_search", body)
            count = resp["hits"]["total"]["value"]
            if count >= int(rule.get("threshold", 1)):
                matches.append({
                    "rule": rule,
                    "match_count": count,
                    "sample_events": [h["_source"] for h in resp["hits"]["hits"]],
                })
        except Exception:
            # Index may not exist yet for this artifact type — skip silently
            pass

    return {"matches": matches, "rules_checked": len(rules)}


@router.post("/cases/{case_id}/alert-rules/library/{rule_id}/run")
def run_single_rule_against_case(case_id: str, rule_id: str):
    """
    Execute a single rule from the global library against the given case.
    """
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    rule = next((rl for rl in rules if rl["id"] == rule_id), None)
    if rule is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Rule not found")

    artifact_type = rule.get("artifact_type", "").strip()
    index = (
        f"fo-case-{case_id}-{artifact_type}"
        if artifact_type
        else f"fo-case-{case_id}-*"
    )

    body = {
        "query": {
            "query_string": {
                "query": rule["query"],
                "default_operator": "AND",
            }
        },
        "size": 5,
        "_source": ["timestamp", "message", "host", "user", "fo_id", "artifact_type"],
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    try:
        resp = es_req("POST", f"/{index}/_search", body)
        count = resp["hits"]["total"]["value"]
        match = {
            "rule": rule,
            "match_count": count,
            "sample_events": [h["_source"] for h in resp["hits"]["hits"]],
        } if count >= int(rule.get("threshold", 1)) else None
    except Exception as exc:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "match": match,
        "rules_checked": 1,
        "fired": match is not None,
    }
