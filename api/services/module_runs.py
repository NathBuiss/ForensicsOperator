"""Module run state management in Redis."""
from __future__ import annotations

import json
import logging

import redis as redis_lib

from config import settings

logger = logging.getLogger(__name__)
MODULE_RUN_TTL = 604800  # 7 days


def get_redis() -> redis_lib.Redis:
    return redis_lib.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def create_module_run(
    run_id: str,
    case_id: str,
    module_id: str,
    source_files: list,
) -> dict:
    r = get_redis()
    run = {
        "run_id":           run_id,
        "case_id":          case_id,
        "module_id":        module_id,
        "status":           "PENDING",
        "source_files":     json.dumps(source_files),
        "started_at":       "",
        "completed_at":     "",
        "total_hits":       "0",
        "hits_by_level":    "{}",
        "results_preview":  "[]",
        "output_minio_key": "",
        "error":            "",
    }
    r.hset(f"fo:module_run:{run_id}", mapping=run)
    r.expire(f"fo:module_run:{run_id}", MODULE_RUN_TTL)
    r.sadd(f"fo:case:{case_id}:module_runs", run_id)
    r.expire(f"fo:case:{case_id}:module_runs", MODULE_RUN_TTL)
    return run


def get_module_run(run_id: str) -> dict | None:
    r = get_redis()
    data = r.hgetall(f"fo:module_run:{run_id}")
    if not data:
        return None
    return _deserialize(data)


def list_case_module_runs(case_id: str) -> list[dict]:
    r = get_redis()
    run_ids = r.smembers(f"fo:case:{case_id}:module_runs")
    runs = []
    for rid in run_ids:
        run = get_module_run(rid)
        if run:
            runs.append(run)
    return sorted(
        runs,
        key=lambda x: x.get("started_at") or x.get("run_id", ""),
        reverse=True,
    )


def update_module_run(run_id: str, **fields) -> None:
    r = get_redis()
    key = f"fo:module_run:{run_id}"
    r.hset(key, mapping={
        k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        for k, v in fields.items()
    })
    r.expire(key, MODULE_RUN_TTL)


def _deserialize(data: dict) -> dict:
    for field in ("source_files", "results_preview"):
        if field in data:
            try:
                data[field] = json.loads(data[field])
            except (json.JSONDecodeError, TypeError):
                data[field] = []
    for field in ("hits_by_level",):
        if field in data:
            try:
                data[field] = json.loads(data[field])
            except (json.JSONDecodeError, TypeError):
                data[field] = {}
    for field in ("total_hits",):
        if field in data:
            try:
                data[field] = int(data[field])
            except (ValueError, TypeError):
                data[field] = 0
    return data
