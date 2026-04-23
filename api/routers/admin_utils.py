"""Admin utility endpoints — system maintenance operations."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import get_redis, settings
from services import storage
from services import elasticsearch as es

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])


@router.post("/admin/purge-orphaned-data")
def purge_orphaned_data():
    """
    Delete all MinIO objects, ES indices, and Redis job records for cases
    that no longer exist in Redis (orphaned from deleted or expired cases).

    Safe to run at any time — active cases (present in cases:all) are never touched.
    """
    r = get_redis()
    active_cases: set[str] = r.smembers("cases:all")

    result = {
        "minio_cases_purged":    [],
        "es_cases_purged":       [],
        "redis_job_keys_deleted": 0,
    }

    # ── 1. MinIO: find case prefixes with no matching Redis record ────────────
    try:
        client = storage.get_minio()
        prefixes = client.list_objects(
            settings.MINIO_BUCKET, prefix="cases/", delimiter="/"
        )
        for obj in prefixes:
            if not obj.is_dir:
                continue
            case_id = obj.object_name.rstrip("/").split("/")[-1]
            if case_id not in active_cases:
                deleted = storage.delete_case_objects(case_id)
                result["minio_cases_purged"].append(
                    {"case_id": case_id, "objects_deleted": deleted}
                )
                logger.info("Purged orphaned MinIO case %s (%d objects)", case_id, deleted)
    except Exception as exc:
        logger.warning("MinIO purge error: %s", exc)

    # ── 2. ES: drop indices for non-active cases ──────────────────────────────
    try:
        indices_raw = es._request("GET", "/_cat/indices/fo-case-*?h=index&format=json")
        purged_es: set[str] = set()
        for item in indices_raw:
            idx = item.get("index", "")
            # Format: fo-case-{12-char-case-id}-{artifact_type}
            after_prefix = idx[len("fo-case-"):]  # e.g. "cfaeedc9fc03-evtx"
            case_id = after_prefix[:12]
            if case_id not in active_cases and case_id not in purged_es:
                try:
                    es._request("DELETE", f"/fo-case-{case_id}-*")
                    purged_es.add(case_id)
                    result["es_cases_purged"].append(case_id)
                    logger.info("Purged orphaned ES indices for case %s", case_id)
                except Exception as exc:
                    logger.warning("ES purge failed for %s: %s", case_id, exc)
    except Exception as exc:
        logger.warning("ES index list error: %s", exc)

    # ── 3. Redis: stale case:*:jobs sets and their job: hashes ───────────────
    try:
        cursor = 0
        deleted_keys = 0
        while True:
            cursor, keys = r.scan(cursor, match="case:*:jobs", count=500)
            for key in keys:
                parts = key.split(":")
                if len(parts) != 3:
                    continue
                case_id = parts[1]
                if case_id not in active_cases:
                    job_ids = list(r.smembers(key))
                    for i in range(0, len(job_ids), 1000):
                        batch = [f"job:{j}" for j in job_ids[i:i + 1000]]
                        r.delete(*batch)
                        deleted_keys += len(batch)
                    r.delete(key)
            if cursor == 0:
                break
        result["redis_job_keys_deleted"] = deleted_keys
        if deleted_keys:
            logger.info("Purged %d orphaned Redis job keys", deleted_keys)
    except Exception as exc:
        logger.warning("Redis job purge error: %s", exc)

    return result


class WipeConfirm(BaseModel):
    confirm: str


@router.post("/admin/wipe-all-data")
def wipe_all_data(body: WipeConfirm):
    """
    DESTRUCTIVE — delete ALL case data: every ES index, every MinIO case object,
    every Redis case/job key. Requires {"confirm": "WIPE"} in the request body.
    """
    if body.confirm != "WIPE":
        raise HTTPException(status_code=400, detail='Body must be {"confirm": "WIPE"}')

    r = get_redis()
    result = {"es_indices_deleted": [], "minio_objects_deleted": 0, "redis_keys_deleted": 0}

    # 1. Delete all fo-case-* ES indices
    try:
        indices_raw = es._request("GET", "/_cat/indices/fo-case-*?h=index&format=json")
        for item in indices_raw:
            idx = item.get("index", "")
            if idx:
                try:
                    es._request("DELETE", f"/{idx}")
                    result["es_indices_deleted"].append(idx)
                except Exception as exc:
                    logger.warning("ES delete failed for %s: %s", idx, exc)
    except Exception as exc:
        logger.warning("ES index list error: %s", exc)

    # 2. Delete all MinIO case objects
    try:
        client = storage.get_minio()
        prefixes = client.list_objects(settings.MINIO_BUCKET, prefix="cases/", delimiter="/")
        for obj in prefixes:
            if not obj.is_dir:
                continue
            case_id = obj.object_name.rstrip("/").split("/")[-1]
            deleted = storage.delete_case_objects(case_id)
            result["minio_objects_deleted"] += deleted
    except Exception as exc:
        logger.warning("MinIO wipe error: %s", exc)

    # 3. Delete all case + job Redis keys
    try:
        deleted = 0
        for pattern in ("case:*", "fo:case:*", "cases:*"):
            cursor = 0
            while True:
                cursor, keys = r.scan(cursor, match=pattern, count=500)
                if keys:
                    r.delete(*keys)
                    deleted += len(keys)
                if cursor == 0:
                    break
        result["redis_keys_deleted"] = deleted
        logger.warning("Wipe-all-data executed: %d ES indices, %d MinIO objects, %d Redis keys",
                       len(result["es_indices_deleted"]), result["minio_objects_deleted"], deleted)
    except Exception as exc:
        logger.warning("Redis wipe error: %s", exc)

    return result
