"""
Global Alert Rule Library.

Rules are stored in Redis at fo:alert_rules:_global and are not tied to any
specific case. They can be run on demand against any case's Elasticsearch data
via the /cases/{case_id}/alert-rules/run-library endpoint.

Built-in default rules are loaded from YAML files in api/alert_rules/.
Each file covers one MITRE-aligned category and contains a list of rule
definitions. To add new default rules, create or edit YAML files in that
directory — no code changes required.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path

import redis as redis_lib
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

try:
    import yaml  # type: ignore
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from config import settings
from services.elasticsearch import _request as es_req

logger = logging.getLogger(__name__)
router = APIRouter(tags=["global-alert-rules"])

GLOBAL_KEY        = "fo:alert_rules:_global"
GLOBAL_SEEDED_KEY = "fo:alert_rules:_global:seeded"

# Alert rules YAML directory — relative to this file's parent (api/)
_RULES_DIR = Path(__file__).parent.parent / "alert_rules"


# ── YAML rule loader ──────────────────────────────────────────────────────────

def _load_default_rules() -> list[dict]:
    """
    Load built-in detection rules from YAML files in api/alert_rules/.

    Each file must have the structure:
        category: <Category Name>
        rules:
          - name: ...
            description: ...
            artifact_type: ...
            query: ...
            threshold: 1

    Falls back to an empty list if PyYAML is unavailable or no files exist.
    """
    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — default rules cannot be loaded from YAML files")
        return []
    if not _RULES_DIR.exists():
        logger.warning("Alert rules directory %s not found", _RULES_DIR)
        return []

    rules: list[dict] = []
    for path in sorted(_RULES_DIR.glob("*.yaml")):
        try:
            with path.open() as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict) or "rules" not in data:
                logger.warning("Skipping %s — missing 'rules' key", path.name)
                continue
            category = data.get("category", "")
            for rule in data["rules"]:
                rules.append({
                    "name":          rule.get("name", ""),
                    "category":      rule.get("category", category),
                    "description":   rule.get("description", ""),
                    "artifact_type": rule.get("artifact_type", ""),
                    "query":         rule.get("query", ""),
                    "threshold":     int(rule.get("threshold", 1)),
                })
        except Exception as exc:
            logger.error("Failed to load alert rules from %s: %s", path.name, exc)
    return rules


_DEFAULT_RULES_CACHE: list[dict] | None = None


def _get_default_rules() -> list[dict]:
    global _DEFAULT_RULES_CACHE
    if _DEFAULT_RULES_CACHE is None:
        _DEFAULT_RULES_CACHE = _load_default_rules()
    return _DEFAULT_RULES_CACHE


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis() -> redis_lib.Redis:
    return redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def _make_rule(template: dict) -> dict:
    """Stamp a rule template with a fresh id and created_at."""
    return {
        "id":         str(uuid.uuid4())[:8],
        "created_at": datetime.utcnow().isoformat(),
        **template,
    }


def _seed_defaults_if_empty(r: redis_lib.Redis) -> None:
    """Populate the library with default rules the very first time it is accessed."""
    if r.get(GLOBAL_SEEDED_KEY):
        return
    existing = json.loads(r.get(GLOBAL_KEY) or "[]")
    if not existing:
        rules = [_make_rule(t) for t in _get_default_rules()]
        r.set(GLOBAL_KEY, json.dumps(rules))
    r.set(GLOBAL_SEEDED_KEY, "1")


# ── Pydantic models ───────────────────────────────────────────────────────────

class AlertRuleIn(BaseModel):
    name: str
    description: str = ""
    category: str = ""
    artifact_type: str = ""
    query: str
    threshold: int = 1


class AlertRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    artifact_type: str | None = None
    query: str | None = None
    threshold: int | None = None


# ── Library CRUD ──────────────────────────────────────────────────────────────

@router.get("/alert-rules/library")
def list_library():
    """Return all global alert rules. Seeds default rules on first call."""
    r = _redis()
    _seed_defaults_if_empty(r)
    data = r.get(GLOBAL_KEY)
    return {"rules": json.loads(data) if data else []}


@router.post("/alert-rules/library/seed", status_code=200)
def seed_library(replace: bool = False):
    """
    Load the built-in default rules into the library.

    replace=false (default) — append any defaults not already present (by name).
    replace=true            — clear the library and reload all defaults fresh.
    """
    r = _redis()
    defaults = _get_default_rules()
    existing: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")

    if replace:
        rules = [_make_rule(t) for t in defaults]
        r.set(GLOBAL_KEY, json.dumps(rules))
        r.set(GLOBAL_SEEDED_KEY, "1")
        return {"added": len(rules), "total": len(rules)}

    existing_names = {rl["name"].lower() for rl in existing}
    added = []
    for template in defaults:
        if template["name"].lower() not in existing_names:
            new_rule = _make_rule(template)
            existing.append(new_rule)
            added.append(new_rule)
    if added:
        r.set(GLOBAL_KEY, json.dumps(existing))
    r.set(GLOBAL_SEEDED_KEY, "1")
    return {"added": len(added), "total": len(existing)}


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
            pass

    return {"matches": matches, "rules_checked": len(rules)}


@router.post("/cases/{case_id}/alert-rules/library/{rule_id}/run")
def run_single_rule_against_case(case_id: str, rule_id: str):
    """Execute a single rule from the global library against the given case."""
    r = _redis()
    rules: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    rule = next((rl for rl in rules if rl["id"] == rule_id), None)
    if rule is None:
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
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "match": match,
        "rules_checked": 1,
        "fired": match is not None,
    }
