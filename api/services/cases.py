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


def delete_case(case_id: str, background: bool = True) -> bool:
    """
    Delete a case and all its data.
    
    Args:
        case_id: The case ID to delete
        background: If True, return immediately and delete MinIO/ES data in background.
                   If False, wait for all deletions to complete (can take minutes for large cases).
    """
    r = get_redis()
    if not r.exists(f"case:{case_id}"):
        return False

    from services import storage
    from services.jobs import list_case_job_ids
    from services.module_runs import list_case_module_runs

    # ── Module runs: delete output MinIO objects + Redis records ──────────────────
    module_runs = list_case_module_runs(case_id)
    for run in module_runs:
        output_key = run.get("output_minio_key", "")
        if output_key:
            try:
                storage.delete_object(output_key)
            except Exception:
                pass
        run_id = run.get("run_id", "")
        if run_id:
            r.delete(f"fo:module_run:{run_id}")
    r.delete(f"fo:case:{case_id}:module_runs")

    # ── Redis job records (pipeline-delete in batches to avoid OOM) ──────────────
    job_ids = list_case_job_ids(case_id)
    BATCH = 1000
    for i in range(0, len(job_ids), BATCH):
        batch_keys = [f"job:{jid}" for jid in job_ids[i:i + BATCH]]
        r.delete(*batch_keys)
    r.delete(f"case:{case_id}:jobs")

    # ── Per-case Redis keys (notes, saved searches, alert rules) ──────────────────
    r.delete(
        f"case:{case_id}",
        f"fo:notes:{case_id}",
        f"fo:saved_searches:{case_id}",
        f"fo:alert_rules:{case_id}",
        f"fo:alert_run:{case_id}",
    )
    r.srem("cases:all", case_id)

    # ── Elasticsearch & MinIO: Can be slow for large cases ────────────────────────
    if background:
        # Return immediately, delete large data in background task
        from celery_app import app
        
        @app.task(name=f"delete_case_data_{case_id}")
        def delete_background():
            from services import storage
            from services.elasticsearch import delete_case_indices
            try:
                storage.delete_case_objects(case_id)
            except Exception as exc:
                logger.warning("MinIO cleanup failed for case %s: %s", case_id, exc)
            try:
                delete_case_indices(case_id)
            except Exception as exc:
                logger.warning("ES cleanup failed for case %s: %s", case_id, exc)
        
        delete_background.delay()
        logger.info("Case %s marked for deletion (data removed in background)", case_id)
    else:
        # Wait for everything to complete (old behavior)
        try:
            storage.delete_case_objects(case_id)
        except Exception as exc:
            logger.warning("MinIO cleanup failed for case %s: %s", case_id, exc)
        try:
            delete_case_indices(case_id)
        except Exception as exc:
            logger.warning("ES cleanup failed for case %s: %s", case_id, exc)
        logger.info("Fully deleted case %s", case_id)
    
    return True
