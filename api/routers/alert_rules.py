"""Alert rules per case — defined patterns checked on demand against ES."""
import json, uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import redis as redis_lib
from config import settings
from services.elasticsearch import _request as es_req

router = APIRouter(tags=["alert-rules"])

_RUN_KEY = "fo:alert_run:{case_id}"
_RUN_TTL = 7 * 86400   # keep last run for 7 days


def _r():
    return redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def _load_run(r: redis_lib.Redis, case_id: str) -> dict:
    data = r.get(_RUN_KEY.format(case_id=case_id))
    return json.loads(data) if data else {"ran_at": None, "rules_checked": 0, "matches": [], "analyses": {}}


def _save_run(r: redis_lib.Redis, case_id: str, run: dict) -> None:
    key = _RUN_KEY.format(case_id=case_id)
    r.set(key, json.dumps(run))
    r.expire(key, _RUN_TTL)


def _llm_analyze_match(rule: dict, match_count: int, sample_events: list) -> dict | None:
    """Run LLM analysis for one match; silently returns None if LLM not configured or fails."""
    try:
        from routers.llm_config import _build_alert_prompt, _call_llm, _get_config as _llm_cfg
        cfg = _llm_cfg(_r())
        if not cfg or not cfg.get("enabled"):
            return None
        prompt = _build_alert_prompt(rule["name"], rule.get("query", ""), match_count, sample_events)
        raw    = _call_llm(cfg, prompt)
        clean  = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
            clean = clean.rstrip("`").strip()
        analysis: dict = json.loads(clean)
        analysis["analyzed_at"] = datetime.now(timezone.utc).isoformat()
        analysis["model_used"]  = f"{cfg.get('provider','?')}/{cfg.get('model','?')}"
        return analysis
    except Exception:
        return None


class AlertRuleIn(BaseModel):
    name: str
    description: str = ""
    artifact_type: str = ""
    query: str
    threshold: int = 1


@router.get("/cases/{case_id}/alert-rules")
def list_rules(case_id: str):
    data = _r().get(f"fo:alert_rules:{case_id}")
    return {"rules": json.loads(data) if data else []}


@router.post("/cases/{case_id}/alert-rules")
def create_rule(case_id: str, body: AlertRuleIn):
    r = _r()
    key = f"fo:alert_rules:{case_id}"
    rules = json.loads(r.get(key) or "[]")
    new = {"id": str(uuid.uuid4())[:8], **body.dict(), "created_at": datetime.utcnow().isoformat()}
    rules.append(new)
    r.set(key, json.dumps(rules))
    return new


@router.post("/cases/{case_id}/alert-rules/{rule_id}/run")
def run_single_rule(case_id: str, rule_id: str):
    """Run a single case-specific rule against this case."""
    r = _r()
    data = r.get(f"fo:alert_rules:{case_id}")
    rules = json.loads(data) if data else []
    rule = next((rl for rl in rules if rl["id"] == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    idx  = f"fo-case-{case_id}-{rule['artifact_type']}" if rule.get("artifact_type") else f"fo-case-{case_id}-*"
    body = {
        "query": {"query_string": {"query": rule["query"], "default_operator": "AND"}},
        "size": 5,
        "_source": ["timestamp", "message", "host", "fo_id", "artifact_type"],
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    try:
        resp  = es_req("POST", f"/{idx}/_search", body)
        count = resp["hits"]["total"]["value"]
        match = {
            "rule": rule, "match_count": count,
            "sample_events": [h["_source"] for h in resp["hits"]["hits"]],
        } if count >= int(rule.get("threshold", 1)) else None
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"match": match, "rules_checked": 1, "fired": match is not None}


@router.delete("/cases/{case_id}/alert-rules/{rule_id}", status_code=204)
def delete_rule(case_id: str, rule_id: str):
    r = _r()
    key = f"fo:alert_rules:{case_id}"
    rules = json.loads(r.get(key) or "[]")
    r.set(key, json.dumps([rl for rl in rules if rl["id"] != rule_id]))


# ── Last run ───────────────────────────────────────────────────────────────────

@router.get("/cases/{case_id}/alert-rules/last-run")
def get_last_run(case_id: str):
    """Return the most recent check run (matches + cached analyses)."""
    return _load_run(_r(), case_id)


@router.post("/cases/{case_id}/alert-rules/last-run/analyze/{rule_id}")
def analyze_run_match(case_id: str, rule_id: str):
    """
    (Re-)run AI analysis for one match in the last run and persist it.
    Returns {analysis} so the frontend can update in-place.
    """
    r   = _r()
    run = _load_run(r, case_id)

    match = next((m for m in run.get("matches", []) if m["rule"]["id"] == rule_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not in last run")

    analysis = _llm_analyze_match(match["rule"], match["match_count"], match["sample_events"])
    if analysis is None:
        raise HTTPException(status_code=400, detail="LLM not configured or analysis failed.")

    run.setdefault("analyses", {})[rule_id] = analysis
    _save_run(r, case_id, run)
    return {"analysis": analysis}


# ── Check ──────────────────────────────────────────────────────────────────────

@router.post("/cases/{case_id}/alert-rules/check")
def check_rules(case_id: str):
    """Run all rules against current case, persist the run, return it."""
    r    = _r()
    data = r.get(f"fo:alert_rules:{case_id}")
    rules = json.loads(data) if data else []
    if not rules:
        run = {"ran_at": datetime.now(timezone.utc).isoformat(),
               "rules_checked": 0, "matches": [], "analyses": {}}
        _save_run(r, case_id, run)
        return run

    matches = []
    for rule in rules:
        idx  = f"fo-case-{case_id}-{rule['artifact_type']}" if rule.get("artifact_type") else f"fo-case-{case_id}-*"
        body = {"query": {"query_string": {"query": rule["query"], "default_operator": "AND"}},
                "size": 3, "_source": ["timestamp", "message", "host", "fo_id"]}
        try:
            resp  = es_req("POST", f"/{idx}/_search", body)
            count = resp["hits"]["total"]["value"]
            if count >= rule["threshold"]:
                matches.append({"rule": rule, "match_count": count,
                                 "sample_events": [h["_source"] for h in resp["hits"]["hits"]]})
        except Exception:
            pass

    run = {
        "ran_at":        datetime.now(timezone.utc).isoformat(),
        "rules_checked": len(rules),
        "matches":       matches,
        "analyses":      {},
    }
    _save_run(r, case_id, run)
    return run
