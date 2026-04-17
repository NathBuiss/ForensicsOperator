"""
Core ingest task: download artifact from MinIO, detect type, run plugin, index to ES.
"""
from __future__ import annotations

import io as _io
import logging
import os
import shutil
import tempfile
import uuid
import zipfile as _zipfile
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


# ── ZIP auto-expansion helpers ────────────────────────────────────────────────

_ZIP_SKIP_BASENAMES = {'.ds_store', 'thumbs.db', 'desktop.ini'}
_ZIP_SKIP_EXTS      = {'.zip'}          # no recursive nesting
JOB_TTL             = 604800            # 7 days — matches api/services/jobs.py


def _is_fo_zip(path: Path) -> bool:
    """Return True if the file is a ZIP archive that should be expanded into child jobs."""
    try:
        return _zipfile.is_zipfile(str(path))
    except Exception:
        return False


def _expand_zip_into_child_jobs(
    parent_job_id: str,
    case_id: str,
    zip_path: Path,
    r: redis.Redis,
) -> int:
    """
    Extract every entry from a ZIP and create individual child jobs, mirroring
    what _handle_zip_async() does in api/routers/ingest.py for direct uploads.

    Uses the FULL relative path from the ZIP as the job filename so that
    path-part based MIME detection in utils/file_type.py gives downstream
    plugins (e.g. scheduled_task, wer) the directory context they need.

    Returns the count of child jobs successfully dispatched.
    """
    minio_client = get_minio()
    count = 0

    with _zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Normalize: always forward slashes, no trailing slash
            entry_rel = info.filename.replace('\\', '/').rstrip('/')
            base_name = entry_rel.split('/')[-1]

            if not base_name or base_name.startswith('.'):
                continue
            if base_name.lower() in _ZIP_SKIP_BASENAMES:
                continue
            if Path(base_name).suffix.lower() in _ZIP_SKIP_EXTS:
                continue

            child_id  = uuid.uuid4().hex
            minio_key = f"cases/{case_id}/{child_id}/{entry_rel}"

            # ── Create child job record (schema matches api/services/jobs.py) ──
            now = datetime.now(timezone.utc).isoformat()
            r.hset(f"job:{child_id}", mapping={
                "job_id":            child_id,
                "case_id":           case_id,
                "status":            "UPLOADING",
                "original_filename": entry_rel,
                "minio_object_key":  minio_key,
                "events_indexed":    "0",
                "error":             "",
                "plugin_used":       "",
                "plugin_stats":      "{}",
                "created_at":        now,
                "started_at":        "",
                "completed_at":      "",
                "task_id":           "",
                "source_zip":        zip_path.name,
                "size_bytes":        str(info.file_size or info.compress_size or 1),
            })
            r.expire(f"job:{child_id}", JOB_TTL)
            r.sadd(f"case:{case_id}:jobs", child_id)
            r.expire(f"case:{case_id}:jobs", JOB_TTL)

            # ── Extract entry and upload to MinIO ─────────────────────────────
            try:
                with zf.open(info) as src:
                    data = src.read()
                actual_size = len(data)
                minio_client.put_object(
                    MINIO_BUCKET, minio_key,
                    _io.BytesIO(data), actual_size,
                )
                r.hset(f"job:{child_id}", mapping={
                    "minio_object_key": minio_key,
                    "size_bytes":       str(actual_size),
                    "status":           "PENDING",
                })
            except Exception as exc:
                logger.error(
                    "[%s] Failed to extract/upload '%s': %s", parent_job_id, entry_rel, exc,
                )
                r.hset(f"job:{child_id}", mapping={
                    "status":       "FAILED",
                    "error":        f"Extraction failed: {exc}",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                })
                continue

            # ── Dispatch child process_artifact task ──────────────────────────
            app.send_task(
                "ingest.process_artifact",
                args=[child_id, case_id, minio_key, entry_rel],
                queue="ingest",
            )
            count += 1

    return count


@app.task(bind=True, name="ingest.process_artifact", queue="ingest")
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
        # original_filename may be a full relative path (e.g. "persistence/tasks/System32/SilentCleanup")
        # when the artifact came from a ZIP — create parent dirs before downloading.
        local_file = work_dir / original_filename
        local_file.parent.mkdir(parents=True, exist_ok=True)
        minio.fget_object(MINIO_BUCKET, minio_object_key, str(local_file))
        logger.info("[%s] Downloaded to %s (%d bytes)", job_id, local_file, local_file.stat().st_size)

        # ── 2. Detect MIME type ───────────────────────────────────────────────
        mime_type = detect_mime(local_file)
        logger.info("[%s] Detected MIME: %s", job_id, mime_type)
        update_job_status(r, job_id, mime_type=mime_type)

        # ── 2b. ZIP auto-expansion ────────────────────────────────────────────
        # When a ZIP arrives via S3 triage pull the API never sees it, so
        # _handle_zip_async() never runs. Intercept here and create one child
        # job per entry — identical behaviour to the direct-upload path.
        # This makes every individual artifact file visible to modules.
        if _is_fo_zip(local_file):
            logger.info("[%s] ZIP detected — expanding into child jobs", job_id)
            child_count = _expand_zip_into_child_jobs(job_id, case_id, local_file, r)
            update_job_status(r, job_id,
                              status="COMPLETED",
                              plugin_used="archive (expanded)",
                              events_indexed="0",
                              completed_at=datetime.now(timezone.utc).isoformat())
            logger.info("[%s] ZIP expanded into %d child jobs", job_id, child_count)
            return {"status": "COMPLETED", "events_indexed": 0, "child_jobs": child_count}

        # ── 3. Find matching plugin ───────────────────────────────────────────
        plugin_class = _plugin_loader.get_plugin(local_file, mime_type)
        if plugin_class is None:
            update_job_status(r, job_id,
                              status="SKIPPED",
                              error=f"No plugin found for '{original_filename}' (mime: {mime_type}). "
                                    "Use a module to analyse this file type.",
                              completed_at=datetime.now(timezone.utc).isoformat())
            return

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
        ingested_at = datetime.now(timezone.utc).isoformat()
        source_url = f"minio://{MINIO_BUCKET}/{minio_object_key}"

        try:
            events_indexed = _run_plugin_and_index(
                plugin, indexer, r, job_id, case_id, source_url, ingested_at
            )
            stats = plugin.get_stats()
        except Exception as plugin_exc:
            plugin.teardown()
            # ── Plaso fallback ───────────────────────────────────────────────
            # Primary plugin failed — let log2timeline have a go.
            # log2timeline auto-detects hundreds of file formats and will
            # extract whatever events it can find in the file.
            logger.warning(
                "[%s] Plugin '%s' failed (%s) — trying log2timeline fallback",
                job_id, plugin_class.PLUGIN_NAME, plugin_exc,
            )
            update_job_status(r, job_id, plugin_used="plaso (fallback)")
            try:
                from plugins.plaso.plaso_plugin import PlasoPlugin
                fallback = PlasoPlugin.create_from_source(local_file, work_dir, ctx)
                fallback.setup()
                events_indexed = _run_plugin_and_index(
                    fallback, indexer, r, job_id, case_id, source_url, ingested_at
                )
                fallback.teardown()
                stats = fallback.get_stats()
                stats["fallback_reason"] = str(plugin_exc)
            except Exception as plaso_exc:
                logger.error("[%s] Plaso fallback also failed: %s", job_id, plaso_exc)
                # ── Strings last resort ──────────────────────────────────────
                # Both the primary plugin and plaso failed.  Run strings
                # extraction as the final safety net so the job always
                # completes rather than failing.  Even for stub/empty files
                # this produces 0 events but marks the job COMPLETED, keeping
                # the file available for module analysis.
                logger.warning(
                    "[%s] Trying strings fallback as last resort", job_id
                )
                update_job_status(r, job_id, plugin_used="strings (fallback)")
                try:
                    from plugins.strings_fallback.strings_fallback_plugin import StringsFallbackPlugin
                    strings_fb = StringsFallbackPlugin(ctx)
                    strings_fb.setup()
                    events_indexed = _run_plugin_and_index(
                        strings_fb, indexer, r, job_id, case_id, source_url, ingested_at
                    )
                    strings_fb.teardown()
                    stats = strings_fb.get_stats()
                    stats["fallback_reason"] = str(plugin_exc)
                except Exception as strings_exc:
                    logger.error(
                        "[%s] Strings fallback also failed: %s", job_id, strings_exc
                    )
                    raise plugin_exc  # surface the original error
        else:
            plugin.teardown()

        # ── 5. Mark complete ─────────────────────────────────────────────────
        result = {
            "status": "COMPLETED",
            "events_indexed": events_indexed,
            "plugin_stats": stats,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        update_job_status(r, job_id, **{
            k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
            for k, v in result.items()
        })
        logger.info("[%s] Completed: %d events indexed", job_id, events_indexed)
        return result

    except Exception as exc:
        logger.exception("[%s] Failed: %s", job_id, exc)
        update_job_status(r, job_id,
                          status="FAILED",
                          error=str(exc),
                          completed_at=datetime.now(timezone.utc).isoformat())
        # Re-raise as RuntimeError so the IPC back to the Celery main process
        # never requires importing custom exception classes (e.g. PluginFatalError
        # from plugins.base_plugin), which aren't on the main process's sys.path.
        raise RuntimeError(str(exc)) from None

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


@app.task(bind=True, name="ingest.s3_transfer", queue="ingest")
def s3_transfer(
    self,
    job_id: str,
    case_id: str,
    s3_config_key: str,
    s3_key: str,
    filename: str,
) -> None:
    """
    Stream a file from an external S3 bucket into internal MinIO, then
    dispatch process_artifact.  Runs entirely in the background — the HTTP
    request that triggered this returns immediately with a PENDING job ID.

    Job status lifecycle:
        PENDING  (created by API)
        UPLOADING  (this task: S3 → MinIO streaming)
        PENDING  (MinIO ready, waiting for process_artifact to start)
        RUNNING → COMPLETED / FAILED  (process_artifact)
    """
    r = get_redis()
    update_job_status(r, job_id,
                      status="UPLOADING",
                      started_at=datetime.now(timezone.utc).isoformat(),
                      task_id=self.request.id)

    # ── 1. Load S3 config from Redis ─────────────────────────────────────────
    cfg_raw = r.get(s3_config_key)
    if not cfg_raw:
        update_job_status(r, job_id,
                          status="FAILED",
                          error="S3 configuration not found — was it removed from Settings?",
                          completed_at=datetime.now(timezone.utc).isoformat())
        return

    cfg = json.loads(cfg_raw)

    # ── 2. Build external S3 client ───────────────────────────────────────────
    from minio import Minio
    endpoint = cfg.get("endpoint", "")
    for proto in ("https://", "http://"):
        if endpoint.lower().startswith(proto):
            endpoint = endpoint[len(proto):]
            break

    try:
        ext_client = Minio(
            endpoint,
            access_key=cfg.get("access_key", ""),
            secret_key=cfg.get("secret_key", ""),
            secure=cfg.get("use_ssl", True),
            region=cfg.get("region") or None,
        )

        # ── 3. Stream external S3 → internal MinIO (no temp file) ────────────
        stat      = ext_client.stat_object(cfg["bucket"], s3_key)
        file_size = stat.size
        minio_key = f"cases/{case_id}/{job_id}/{filename}"

        logger.info("[%s] S3 transfer: %s/%s → MinIO/%s (%d bytes)",
                    job_id, cfg["bucket"], s3_key, minio_key, file_size)

        response = None
        try:
            response   = ext_client.get_object(cfg["bucket"], s3_key)
            int_client = get_minio()
            if not int_client.bucket_exists(MINIO_BUCKET):
                int_client.make_bucket(MINIO_BUCKET)
            int_client.put_object(
                MINIO_BUCKET,
                minio_key,
                response,
                length=file_size,
                part_size=10 * 1024 * 1024,    # 10 MB multipart chunks
            )
        finally:
            if response is not None:
                try:
                    response.close()
                    response.release_conn()
                except Exception:
                    pass

        logger.info("[%s] S3 transfer complete — %d bytes written", job_id, file_size)

        # ── 4. Update job and dispatch ingest ─────────────────────────────────
        update_job_status(r, job_id, minio_object_key=minio_key, status="PENDING")
        app.send_task(
            "ingest.process_artifact",
            args=[job_id, case_id, minio_key, filename],
            queue="ingest",
        )

    except Exception as exc:
        logger.exception("[%s] S3 transfer failed: %s", job_id, exc)
        update_job_status(r, job_id,
                          status="FAILED",
                          error=f"S3 transfer failed: {exc}",
                          completed_at=datetime.now(timezone.utc).isoformat())
        raise RuntimeError(str(exc)) from None


def _run_plugin_and_index(
    plugin,
    indexer: ESBulkIndexer,
    r: redis.Redis,
    job_id: str,
    case_id: str,
    source_url: str,
    ingested_at: str,
) -> int:
    """Drive a plugin's parse() generator and bulk-index all events. Returns event count."""
    batch: list[dict] = []
    events_indexed = 0
    for raw_event in plugin.parse():
        event = _merge_base_fields(raw_event, case_id, job_id, source_url, ingested_at)
        batch.append(event)
        if len(batch) >= BULK_SIZE:
            indexer.bulk_index(case_id, batch)
            events_indexed += len(batch)
            batch = []
            update_job_status(r, job_id, events_indexed=str(events_indexed), progress_pct="")
    if batch:
        indexer.bulk_index(case_id, batch)
        events_indexed += len(batch)
    return events_indexed


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
        # Default to ingested_at — plugins with real timestamps override this.
        # Using "" would cause ES to reject the doc (date field rejects empty strings).
        "timestamp": ingested_at,
        "timestamp_desc": "Ingestion Time",
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
    # Coerce falsy timestamps (empty string, None) from plugins to ingested_at
    # so the event is never rejected by the ES date mapping.
    if not base.get("timestamp"):
        base["timestamp"] = ingested_at
        if not base.get("timestamp_desc") or base["timestamp_desc"] == "Unknown":
            base["timestamp_desc"] = "Ingestion Time"
    return base
