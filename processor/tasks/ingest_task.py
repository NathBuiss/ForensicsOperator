"""
Core ingest task: download artifact from MinIO, detect type, run plugin, index to ES.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import redis
import json

from celery_app import app
from plugin_loader import PluginLoader
from utils.file_type import detect_mime
from utils.es_bulk import ESBulkIndexer

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-service:6379/0")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio-service:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "forensics-cases")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch-service:9200")
BULK_SIZE = int(os.getenv("BULK_SIZE", "500"))

# Shared plugin loader instance (reused across tasks in the same worker)
_plugin_loader = PluginLoader(Path("/app/plugins"))


def get_redis() -> redis.Redis:
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def get_minio():
    from minio import Minio
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
    )


def update_job_status(r: redis.Redis, job_id: str, **fields) -> None:
    key = f"job:{job_id}"
    r.hset(key, mapping={k: json.dumps(v) if not isinstance(v, str) else v
                         for k, v in fields.items()})
    r.expire(key, 604800)  # 7 days TTL


@app.task(bind=True, name="ingest.process_artifact")
def process_artifact(
    self,
    job_id: str,
    case_id: str,
    minio_object_key: str,
    original_filename: str,
) -> dict[str, Any]:
    """
    Main ingest task.

    Args:
        job_id: Unique job identifier (also the Celery task ID).
        case_id: Case this artifact belongs to.
        minio_object_key: Object key in MinIO (e.g., "cases/abc123/job123/Security.evtx").
        original_filename: Original uploaded filename.

    Returns:
        Job result dict with stats.
    """
    r = get_redis()
    work_dir = Path(tempfile.mkdtemp(prefix=f"fo_{job_id}_"))
    local_file: Path | None = None

    try:
        update_job_status(r, job_id,
                          status="RUNNING",
                          started_at=datetime.now(timezone.utc).isoformat(),
                          task_id=self.request.id)

        # ── 1. Download artifact from MinIO ──────────────────────────────────
        logger.info("[%s] Downloading %s from MinIO", job_id, minio_object_key)
        minio = get_minio()
        local_file = work_dir / original_filename
        minio.fget_object(MINIO_BUCKET, minio_object_key, str(local_file))
        logger.info("[%s] Downloaded to %s (%d bytes)", job_id, local_file, local_file.stat().st_size)

        # ── 2. Detect MIME type ───────────────────────────────────────────────
        mime_type = detect_mime(local_file)
        logger.info("[%s] Detected MIME: %s", job_id, mime_type)
        update_job_status(r, job_id, mime_type=mime_type)

        # ── 3. Find matching plugin ───────────────────────────────────────────
        plugin_class = _plugin_loader.get_plugin(local_file, mime_type)
        if plugin_class is None:
            raise RuntimeError(
                f"No plugin found for '{original_filename}' (mime: {mime_type}). "
                "Upload a compatible plugin or check the filename/extension."
            )

        update_job_status(r, job_id, plugin_used=plugin_class.PLUGIN_NAME)

        # ── 4. Run plugin ────────────────────────────────────────────────────
        from plugins.base_plugin import PluginContext
        ctx = PluginContext(
            case_id=case_id,
            job_id=job_id,
            source_file_path=local_file,
            source_minio_url=f"minio://{MINIO_BUCKET}/{minio_object_key}",
            logger=logger,
        )
        plugin = plugin_class(ctx)
        plugin.setup()

        indexer = ESBulkIndexer(ELASTICSEARCH_URL)
        batch: list[dict] = []
        events_indexed = 0
        ingested_at = datetime.now(timezone.utc).isoformat()
        source_url = f"minio://{MINIO_BUCKET}/{minio_object_key}"

        from plugins.base_plugin import PluginParseError
        for raw_event in plugin.parse():
            # Merge base fields onto event
            event = _merge_base_fields(
                raw_event, case_id, job_id, source_url, ingested_at
            )
            batch.append(event)

            if len(batch) >= BULK_SIZE:
                indexer.bulk_index(case_id, batch)
                events_indexed += len(batch)
                batch = []
                update_job_status(r, job_id,
                                  events_indexed=str(events_indexed),
                                  progress_pct="")

        if batch:
            indexer.bulk_index(case_id, batch)
            events_indexed += len(batch)

        plugin.teardown()
        stats = plugin.get_stats()

        # ── 5. Mark complete ─────────────────────────────────────────────────
        result = {
            "status": "COMPLETED",
            "events_indexed": events_indexed,
            "plugin_stats": stats,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        update_job_status(r, job_id, **{k: str(v) if not isinstance(v, str) else v
                                         for k, v in result.items()},
                          plugin_stats=json.dumps(stats))
        logger.info("[%s] Completed: %d events indexed", job_id, events_indexed)
        return result

    except Exception as exc:
        logger.exception("[%s] Failed: %s", job_id, exc)
        update_job_status(r, job_id,
                          status="FAILED",
                          error=str(exc),
                          completed_at=datetime.now(timezone.utc).isoformat())
        raise

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


def _merge_base_fields(
    event: dict,
    case_id: str,
    job_id: str,
    source_minio_url: str,
    ingested_at: str,
) -> dict:
    """Ensure all base ForensicEvent fields are present."""
    base = {
        "fo_id": str(uuid.uuid4()),
        "case_id": case_id,
        "ingest_job_id": job_id,
        "source_file": source_minio_url,
        "ingested_at": ingested_at,
        "artifact_type": "generic",
        "timestamp": "",
        "timestamp_desc": "Unknown",
        "message": "",
        "tags": [],
        "analyst_note": "",
        "is_flagged": False,
        "mitre": {},
        "host": {},
        "user": {},
        "process": {},
        "network": {},
        "raw": {},
    }
    base.update(event)
    return base
