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

GLOBAL_KEY        = "fo:alert_rules:_global"
GLOBAL_SEEDED_KEY = "fo:alert_rules:_global:seeded"

# ── Built-in detection rules ──────────────────────────────────────────────────
# Queries use Lucene query_string syntax against the indexed event fields.
# Fields reference:
#   evtx.*            — Windows Event Log fields (evtx.event_id, evtx.event_data.*)
#   suricata.*        — Suricata EVE JSON fields (suricata.event_type, suricata.alert.*)
#   network.*         — Network fields (src_ip, dest_ip, src_port, dest_port)
#   user.*            — User fields (user.name, user.domain)
#   process.*         — Process fields (process.name, process.cmdline)
#   message           — Human-readable event description (full-text search)
#   artifact_type     — Ingester that produced the event (evtx, suricata, syslog…)

DEFAULT_RULES: list[dict] = [
    {
        "name":          "Security Event Log Cleared",
        "description":   "The Windows Security audit log was cleared — this is a key anti-forensics indicator and should always be investigated.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:1102",
        "threshold":     1,
    },
    {
        "name":          "System Event Log Cleared",
        "description":   "The Windows System event log was cleared (Event ID 104). Often accompanies Security log clearing during intrusion clean-up.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:104",
        "threshold":     1,
    },
    {
        "name":          "Brute Force — Multiple Failed Logons",
        "description":   "More than 10 failed authentication attempts (EID 4625). Indicates a password spray or brute-force attack against local or network accounts.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4625",
        "threshold":     10,
    },
    {
        "name":          "Account Added to Privileged Group",
        "description":   "A user was added to a Global (4728), Local (4732), or Universal (4756) security group — common persistence or privilege escalation step.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4728 OR evtx.event_id:4732 OR evtx.event_id:4756",
        "threshold":     1,
    },
    {
        "name":          "New Service Installed",
        "description":   "A new Windows service was installed (EID 7045). Malware frequently uses services for persistence (e.g. malicious drivers, RAT services).",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:7045",
        "threshold":     1,
    },
    {
        "name":          "Scheduled Task Created",
        "description":   "A scheduled task was created (EID 4698). Review the task action — this is one of the most common persistence mechanisms.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4698",
        "threshold":     1,
    },
    {
        "name":          "PowerShell Script Block Logged",
        "description":   "PowerShell script block logging fired (EID 4104). All executed script blocks are captured — search for encoded commands, download cradles, and Invoke-Expression.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4104",
        "threshold":     1,
    },
    {
        "name":          "Explicit Credential Use (Possible Pass-the-Hash / RunAs)",
        "description":   "A process logged on using explicitly supplied credentials (EID 4648). Common during lateral movement, pass-the-hash, or RunAs abuse.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4648",
        "threshold":     1,
    },
    {
        "name":          "Audit Policy Modified",
        "description":   "The system audit policy was changed (EID 4719). Attackers modify audit policy to prevent logging of subsequent malicious actions.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4719",
        "threshold":     1,
    },
    {
        "name":          "Special Privileges Assigned at Logon",
        "description":   "Sensitive privileges were assigned to a new logon session (EID 4672). Look for SeDebugPrivilege or SeTcbPrivilege — indicators of privilege escalation or token manipulation.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4672",
        "threshold":     1,
    },
    {
        "name":          "Process Created by Office Application",
        "description":   "A new process was spawned (EID 4688) with a parent that is a Microsoft Office application — classic macro-based initial access pattern.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4688 AND (message:*winword* OR message:*excel* OR message:*powerpnt* OR message:*outlook*)",
        "threshold":     1,
    },
    {
        "name":          "Network Logon from External Host",
        "description":   "A network-type logon (type 3) occurred from a non-local IP address (EID 4624). Investigate the source — may indicate lateral movement or remote access.",
        "artifact_type": "evtx",
        "query":         "evtx.event_id:4624 AND evtx.event_data.LogonType:3 AND network.src_ip:* AND NOT network.src_ip:127.0.0.1 AND NOT network.src_ip:\"::1\"",
        "threshold":     1,
    },
    {
        "name":          "Suricata — High Severity Alert (Severity 1)",
        "description":   "Suricata fired a severity-1 (critical) alert. Review the signature and investigate the involved hosts immediately.",
        "artifact_type": "suricata",
        "query":         "suricata.event_type:alert AND suricata.alert.severity:1",
        "threshold":     1,
    },
    {
        "name":          "Suricata — Malware Signature Match",
        "description":   "Suricata detected a traffic pattern matching a known malware signature (ET MALWARE category). Indicates active infection or C2 communication.",
        "artifact_type": "suricata",
        "query":         "suricata.event_type:alert AND message:*ET\\ MALWARE*",
        "threshold":     1,
    },
]


def _redis() -> redis_lib.Redis:
    return redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def _make_rule(template: dict) -> dict:
    """Stamp a DEFAULT_RULES template with a fresh id and created_at."""
    return {
        "id":         str(uuid.uuid4())[:8],
        "created_at": datetime.utcnow().isoformat(),
        **template,
    }


def _seed_defaults_if_empty(r: redis_lib.Redis) -> None:
    """Populate the library with DEFAULT_RULES the very first time it is accessed."""
    if r.get(GLOBAL_SEEDED_KEY):
        return
    existing = json.loads(r.get(GLOBAL_KEY) or "[]")
    if not existing:
        rules = [_make_rule(t) for t in DEFAULT_RULES]
        r.set(GLOBAL_KEY, json.dumps(rules))
    r.set(GLOBAL_SEEDED_KEY, "1")


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
    existing: list[dict] = json.loads(r.get(GLOBAL_KEY) or "[]")
    if replace:
        rules = [_make_rule(t) for t in DEFAULT_RULES]
        r.set(GLOBAL_KEY, json.dumps(rules))
        r.set(GLOBAL_SEEDED_KEY, "1")
        return {"added": len(rules), "total": len(rules)}

    existing_names = {rl["name"].lower() for rl in existing}
    added = []
    for template in DEFAULT_RULES:
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
