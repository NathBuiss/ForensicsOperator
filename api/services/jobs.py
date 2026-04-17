"""Job state management in Redis."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from config import settings, get_redis

logger = logging.getLogger(__name__)
JOB_TTL = 604800  # 7 days


def create_job(
    job_id: str,
    case_id: str,
    filename: str,
    minio_key: str,
    source_zip: str = "",
) -> dict:
    r = get_redis()
    job = {
        "job_id": job_id,
        "case_id": case_id,
        "status": "PENDING",
        "original_filename": filename,
        "minio_object_key": minio_key,
        "events_indexed": "0",
        "events_failed": "0",
        "error": "",
        "plugin_used": "",
        "plugin_stats": "{}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": "",
        "completed_at": "",
        "task_id": "",
        "source_zip": source_zip,
    }
    r.hset(f"job:{job_id}", mapping=job)
    r.expire(f"job:{job_id}", JOB_TTL)

    # Add to case job set
    r.sadd(f"case:{case_id}:jobs", job_id)
    r.expire(f"case:{case_id}:jobs", JOB_TTL)
    return job


def get_job(job_id: str) -> dict | None:
    r = get_redis()
    data = r.hgetall(f"job:{job_id}")
    if not data:
        return None
    # Deserialize JSON fields
    for field in ("plugin_stats",):
        if field in data:
            try:
                data[field] = json.loads(data[field])
            except (json.JSONDecodeError, TypeError):
                data[field] = {}
    for field in ("events_indexed", "events_failed"):
        if field in data:
            try:
                data[field] = int(data[field])
            except (ValueError, TypeError):
                data[field] = 0
    return data


def update_job(job_id: str, **fields) -> None:
    """Patch arbitrary fields on an existing job hash."""
    r = get_redis()
    key = f"job:{job_id}"
    r.hset(key, mapping={k: str(v) for k, v in fields.items()})
    r.expire(key, JOB_TTL)


def reset_job_for_retry(job_id: str) -> None:
    """Reset a FAILED job back to PENDING so it can be re-dispatched."""
    r = get_redis()
    key = f"job:{job_id}"
    r.hset(key, mapping={
        "status": "PENDING",
        "error": "",
        "events_indexed": "0",
        "plugin_used": "",
        "plugin_stats": "{}",
        "started_at": "",
        "completed_at": "",
        "task_id": "",
    })
    r.expire(key, JOB_TTL)


def delete_job(job_id: str, case_id: str) -> None:
    """Remove a job record from Redis and from the case's job set."""
    r = get_redis()
    r.delete(f"job:{job_id}")
    r.srem(f"case:{case_id}:jobs", job_id)


def list_case_jobs(case_id: str) -> list[dict]:
    r = get_redis()
    job_ids = r.smembers(f"case:{case_id}:jobs")
    jobs = []
    for jid in sorted(job_ids):
        job = get_job(jid)
        if job:
            jobs.append(job)
    return sorted(jobs, key=lambda j: j.get("started_at", ""), reverse=True)
