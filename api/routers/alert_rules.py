"""Alert rules per case — defined patterns checked on demand against ES."""
import json, uuid
from datetime import datetime
from fastapi import APIRouter
from pydantic import BaseModel
import redis as redis_lib
from config import settings
from services.elasticsearch import _request as es_req

router = APIRouter(tags=["alert-rules"])

def _r():
    return redis_lib.from_url(settings.REDIS_URL, decode_responses=True)

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

@router.delete("/cases/{case_id}/alert-rules/{rule_id}", status_code=204)
def delete_rule(case_id: str, rule_id: str):
    r = _r()
    key = f"fo:alert_rules:{case_id}"
    rules = json.loads(r.get(key) or "[]")
    r.set(key, json.dumps([rl for rl in rules if rl["id"] != rule_id]))

@router.post("/cases/{case_id}/alert-rules/check")
def check_rules(case_id: str):
    """Run all rules against current case, return matches."""
    r = _r()
    data = r.get(f"fo:alert_rules:{case_id}")
    rules = json.loads(data) if data else []
    if not rules:
        return {"matches": [], "rules_checked": 0}
    matches = []
    for rule in rules:
        idx = f"fo-case-{case_id}-{rule['artifact_type']}" if rule.get("artifact_type") else f"fo-case-{case_id}-*"
        body = {"query": {"query_string": {"query": rule["query"], "default_operator": "AND"}},
                "size": 3, "_source": ["timestamp", "message", "host", "fo_id"]}
        try:
            resp = es_req("POST", f"/{idx}/_search", body)
            count = resp["hits"]["total"]["value"]
            if count >= rule["threshold"]:
                matches.append({"rule": rule, "match_count": count,
                                 "sample_events": [h["_source"] for h in resp["hits"]["hits"]]})
        except Exception:
            pass
    return {"matches": matches, "rules_checked": len(rules)}
