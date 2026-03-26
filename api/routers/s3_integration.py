"""
External S3 Integration.

Allows connecting to an external S3-compatible bucket (AWS S3, MinIO, Wasabi, etc.)
for artifact import and collector uploads.

Settings stored in Redis at fo:s3_config hash.
"""
from __future__ import annotations

import io
import json
import logging
import uuid
from typing import Optional

import redis as redis_lib
from fastapi import APIRouter, HTTPException, Query
from minio import Minio
from pydantic import BaseModel

from config import settings
from services import storage, jobs as job_svc
from services.cases import get_case

logger = logging.getLogger(__name__)
router = APIRouter(tags=["s3"])

_S3_CONFIG_KEY = "fo:s3_config"

# Fields that are safe to return to the frontend (secret_key is masked)
_PUBLIC_FIELDS = ("endpoint", "access_key", "bucket", "region", "vendor", "use_ssl")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _redis() -> redis_lib.Redis:
    return redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def _get_config(r: redis_lib.Redis) -> dict:
    """Load the external S3 config from Redis."""
    raw = r.get(_S3_CONFIG_KEY)
    return json.loads(raw) if raw else {}


def _build_external_client(cfg: dict) -> Minio:
    """Build a Minio client from the saved external S3 config."""
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No external S3 configuration saved.")

    endpoint = cfg["endpoint"]
    # Strip protocol prefix if present — Minio client expects host:port only
    for prefix in ("https://", "http://"):
        if endpoint.lower().startswith(prefix):
            endpoint = endpoint[len(prefix):]
            break

    return Minio(
        endpoint,
        access_key=cfg.get("access_key", ""),
        secret_key=cfg.get("secret_key", ""),
        secure=cfg.get("use_ssl", True),
        region=cfg.get("region") or None,
    )


def _dispatch_celery_task(job_id: str, case_id: str, minio_key: str, filename: str) -> None:
    """Dispatch a Celery ingest task via send_task."""
    from celery import Celery
    from kombu import Exchange
    app = Celery(broker=settings.REDIS_URL)
    app.send_task(
        "ingest.process_artifact",
        args=[job_id, case_id, minio_key, filename],
        task_id=job_id,
        queue="ingest",
        exchange=Exchange("forensics", type="direct"),
        routing_key="ingest",
    )


# ── Pydantic models ──────────────────────────────────────────────────────────

class S3ConfigIn(BaseModel):
    endpoint: str
    access_key: str
    secret_key: str = ""
    bucket: str
    region: str = ""
    vendor: str = "aws"      # aws | minio | wasabi | gcs | other
    use_ssl: bool = True


class S3ConfigOut(BaseModel):
    endpoint: str
    access_key: str
    secret_key_set: bool
    bucket: str
    region: str
    vendor: str
    use_ssl: bool


class S3ImportIn(BaseModel):
    s3_key: str
    filename: Optional[str] = None


# ── Admin config endpoints ────────────────────────────────────────────────────

@router.get("/admin/s3-config", response_model=S3ConfigOut)
def get_s3_config():
    """Return current external S3 configuration (secret key masked)."""
    r = _redis()
    cfg = _get_config(r)
    return S3ConfigOut(
        endpoint=cfg.get("endpoint", ""),
        access_key=cfg.get("access_key", ""),
        secret_key_set=bool(cfg.get("secret_key")),
        bucket=cfg.get("bucket", ""),
        region=cfg.get("region", ""),
        vendor=cfg.get("vendor", "aws"),
        use_ssl=cfg.get("use_ssl", True),
    )


@router.put("/admin/s3-config", response_model=S3ConfigOut)
def update_s3_config(body: S3ConfigIn):
    """Save external S3 configuration. If secret_key is empty, keeps the existing one."""
    r = _redis()
    existing = _get_config(r)

    cfg = {
        "endpoint":   body.endpoint,
        "access_key": body.access_key,
        "bucket":     body.bucket,
        "region":     body.region,
        "vendor":     body.vendor,
        "use_ssl":    body.use_ssl,
        # Keep existing secret key if new request sends empty string
        "secret_key": body.secret_key if body.secret_key else existing.get("secret_key", ""),
    }
    r.set(_S3_CONFIG_KEY, json.dumps(cfg))

    return S3ConfigOut(
        endpoint=cfg["endpoint"],
        access_key=cfg["access_key"],
        secret_key_set=bool(cfg["secret_key"]),
        bucket=cfg["bucket"],
        region=cfg["region"],
        vendor=cfg["vendor"],
        use_ssl=cfg["use_ssl"],
    )


@router.delete("/admin/s3-config", status_code=204)
def clear_s3_config():
    """Remove external S3 configuration."""
    _redis().delete(_S3_CONFIG_KEY)


@router.post("/admin/s3-config/test")
def test_s3_config():
    """
    Test the saved external S3 connection by attempting to list the bucket.
    Returns {"ok": true, "objects": <count>} on success, HTTP 502 on failure.
    """
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No external S3 configuration saved yet.")

    try:
        client = _build_external_client(cfg)
        # List up to 5 objects to verify the bucket is accessible
        objects = list(client.list_objects(cfg["bucket"], max_keys=5))
        return {
            "ok": True,
            "bucket": cfg["bucket"],
            "objects": len(objects),
            "message": f"Connected successfully. Found {len(objects)} object(s) in sample.",
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"S3 connection test failed: {exc}")


# ── Browse endpoint ───────────────────────────────────────────────────────────

@router.get("/s3/browse")
def browse_s3(
    prefix: str = Query("", description="Object key prefix (folder path)"),
    delimiter: str = Query("/", description="Delimiter for folder grouping"),
):
    """
    List objects in the configured external S3 bucket.
    Supports prefix-based browsing with delimiter for virtual folder navigation.
    """
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No external S3 configuration saved.")

    try:
        client = _build_external_client(cfg)
        result_objects = client.list_objects(
            cfg["bucket"],
            prefix=prefix or None,
            recursive=delimiter == "",
        )

        folders = []
        files = []
        for obj in result_objects:
            if obj.is_dir:
                folders.append({
                    "key": obj.object_name,
                    "type": "folder",
                })
            else:
                files.append({
                    "key": obj.object_name,
                    "type": "file",
                    "size": obj.size,
                    "last_modified": obj.last_modified.isoformat() if obj.last_modified else None,
                    "etag": obj.etag,
                })

        return {
            "prefix": prefix,
            "bucket": cfg["bucket"],
            "folders": folders,
            "files": files,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to browse S3: {exc}")


# ── Import to case endpoint ──────────────────────────────────────────────────

@router.post("/cases/{case_id}/s3-import")
def import_from_s3(case_id: str, body: S3ImportIn):
    """
    Import a file from the external S3 bucket into a case.

    1. Downloads the file from the external S3
    2. Uploads it to internal MinIO at the case's path
    3. Creates a job and dispatches the ingest task
    4. Returns the job_id
    """
    # Validate case exists
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Load external S3 config
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No external S3 configuration saved.")

    # Determine filename
    filename = body.filename or body.s3_key.rsplit("/", 1)[-1] or "unknown"

    try:
        ext_client = _build_external_client(cfg)
        # Download object from external S3
        response = ext_client.get_object(cfg["bucket"], body.s3_key)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to download '{body.s3_key}' from external S3: {exc}",
        )

    try:
        # Read into memory (for size) then upload to internal MinIO
        data = response.read()
        size = len(data)
        if size == 0:
            raise HTTPException(status_code=400, detail="Downloaded file is empty.")

        job_id = uuid.uuid4().hex
        minio_key = f"cases/{case_id}/{job_id}/{filename}"

        storage.upload_file(minio_key, data)

        # Create job record in Redis
        job_svc.create_job(job_id, case_id, filename, minio_key, source_zip="")

        # Dispatch Celery ingest task
        _dispatch_celery_task(job_id, case_id, minio_key, filename)

        return {
            "job_id": job_id,
            "case_id": case_id,
            "filename": filename,
            "s3_key": body.s3_key,
            "size_bytes": size,
            "status": "PENDING",
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to import '{filename}' into case: {exc}",
        )
    finally:
        response.close()
        response.release_conn()
