"""
External S3 Integration — two independent configurations.

  TRIAGE UPLOAD storage  (fo:s3_triage_config)
      Where agents push collected evidence (triage ZIPs, memory dumps, etc.).
      Analysts browse this bucket and pull files into cases on demand.

  CASE DATA IMPORT storage  (fo:s3_config)
      Browse any external S3-compatible bucket and import files into a case
      for parsing — AWS S3, MinIO, Wasabi, GCS, Scaleway Object Storage, …

Both configs are stored in Redis as JSON strings.
All file transfers stream directly: external S3 → internal MinIO, no full RAM buffer.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Optional

import redis
from fastapi import APIRouter, HTTPException, Query
from minio import Minio
from pydantic import BaseModel

from config import settings, get_redis as _redis
from services import storage, jobs as job_svc
from services.cases import get_case

logger = logging.getLogger(__name__)
router = APIRouter(tags=["s3"])

# ── Redis keys ────────────────────────────────────────────────────────────────
_S3_IMPORT_KEY  = "fo:s3_config"          # case data import (existing)
_S3_TRIAGE_KEY  = "fo:s3_triage_config"   # triage upload bucket (new)

_PUBLIC_FIELDS = ("endpoint", "access_key", "bucket", "region", "vendor", "use_ssl")

# Scaleway Object Storage regions → endpoint mapping
SCALEWAY_ENDPOINTS = {
    "nl-ams": "s3.nl-ams.scw.cloud",   # Amsterdam
    "fr-par": "s3.fr-par.scw.cloud",   # Paris
    "pl-waw": "s3.pl-waw.scw.cloud",   # Warsaw
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load(r: redis.Redis, key: str) -> dict:
    raw = r.get(key)
    return json.loads(raw) if raw else {}


def _save(r: redis.Redis, key: str, cfg: dict) -> None:
    r.set(key, json.dumps(cfg))


def _build_client(cfg: dict) -> Minio:
    """Build a Minio client pointing at the external S3 config."""
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No S3 configuration saved.")
    endpoint = cfg["endpoint"]
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


def _stream_to_minio(ext_client: Minio, ext_bucket: str, s3_key: str, minio_key: str) -> int:
    """
    Stream an object from an external S3 bucket directly into internal MinIO.

    Never buffers the full payload — uses MinIO multipart upload under the hood
    for objects larger than ~5 MB. Returns the number of bytes transferred.
    """
    # HEAD the object to get its size (required by put_object for non-chunked streams)
    try:
        stat = ext_client.stat_object(ext_bucket, s3_key)
        file_size = stat.size
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not stat '{s3_key}': {exc}")

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Remote object is empty.")

    response = None
    try:
        response = ext_client.get_object(ext_bucket, s3_key)
        int_client = storage.get_minio()
        storage.ensure_bucket()
        # Stream directly: external S3 → internal MinIO, no RAM accumulation
        int_client.put_object(
            settings.MINIO_BUCKET,
            minio_key,
            response,
            length=file_size,
            part_size=10 * 1024 * 1024,  # 10 MB multipart chunks for large files
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Transfer failed: {exc}")
    finally:
        if response is not None:
            try:
                response.close()
                response.release_conn()
            except Exception:
                pass

    return file_size


def _dispatch(job_id: str, case_id: str, minio_key: str, filename: str) -> None:
    from services.celery_dispatch import dispatch_ingest
    dispatch_ingest(job_id, case_id, minio_key, filename)


# ── Pydantic models ───────────────────────────────────────────────────────────

class S3ConfigIn(BaseModel):
    endpoint: str
    access_key: str
    secret_key: str = ""
    bucket: str
    region: str = ""
    vendor: str = "aws"   # aws | scaleway | minio | wasabi | gcs | other
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


# ── Shared config CRUD factory ────────────────────────────────────────────────

def _make_config_routes(redis_key: str, path_prefix: str, label: str):
    """
    Return (get_fn, put_fn, delete_fn, test_fn) handlers bound to a specific
    Redis key and URL prefix.  Avoids copy-pasting identical logic twice.
    """

    def get_cfg():
        r = _redis()
        cfg = _load(r, redis_key)
        return S3ConfigOut(
            endpoint=cfg.get("endpoint", ""),
            access_key=cfg.get("access_key", ""),
            secret_key_set=bool(cfg.get("secret_key")),
            bucket=cfg.get("bucket", ""),
            region=cfg.get("region", ""),
            vendor=cfg.get("vendor", "aws"),
            use_ssl=cfg.get("use_ssl", True),
        )

    def put_cfg(body: S3ConfigIn):
        r = _redis()
        existing = _load(r, redis_key)
        cfg = {
            "endpoint":   body.endpoint,
            "access_key": body.access_key,
            "bucket":     body.bucket,
            "region":     body.region,
            "vendor":     body.vendor,
            "use_ssl":    body.use_ssl,
            "secret_key": body.secret_key if body.secret_key else existing.get("secret_key", ""),
        }
        _save(r, redis_key, cfg)
        return S3ConfigOut(**{**cfg, "secret_key_set": bool(cfg["secret_key"])})

    def delete_cfg():
        _redis().delete(redis_key)

    def test_cfg():
        r = _redis()
        cfg = _load(r, redis_key)
        if not cfg or not cfg.get("endpoint"):
            raise HTTPException(status_code=400, detail=f"No {label} S3 config saved yet.")
        try:
            client = _build_client(cfg)
            objects = list(client.list_objects(cfg["bucket"], max_keys=5))
            return {
                "ok": True,
                "bucket": cfg["bucket"],
                "objects": len(objects),
                "message": f"Connected. Found {len(objects)} object(s) in sample.",
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Connection test failed: {exc}")

    return get_cfg, put_cfg, delete_cfg, test_cfg


# ── Case Data Import endpoints (/admin/s3-config) ─────────────────────────────
# Existing path — kept identical so current clients are not broken.

_imp_get, _imp_put, _imp_del, _imp_test = _make_config_routes(
    _S3_IMPORT_KEY, "/admin/s3-config", "import"
)

router.get("/admin/s3-config",        response_model=S3ConfigOut)(_imp_get)
router.put("/admin/s3-config",        response_model=S3ConfigOut)(_imp_put)
router.delete("/admin/s3-config",     status_code=204)(_imp_del)
router.post("/admin/s3-config/test")(_imp_test)


# ── Triage Upload S3 endpoints (/admin/s3-triage-config) ──────────────────────

_tri_get, _tri_put, _tri_del, _tri_test = _make_config_routes(
    _S3_TRIAGE_KEY, "/admin/s3-triage-config", "triage"
)

router.get("/admin/s3-triage-config",        response_model=S3ConfigOut)(_tri_get)
router.put("/admin/s3-triage-config",        response_model=S3ConfigOut)(_tri_put)
router.delete("/admin/s3-triage-config",     status_code=204)(_tri_del)
router.post("/admin/s3-triage-config/test")(_tri_test)


# ── Browse endpoints ──────────────────────────────────────────────────────────

def _browse(redis_key: str, label: str, prefix: str, delimiter: str):
    r = _redis()
    cfg = _load(r, redis_key)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail=f"No {label} S3 configuration saved.")
    try:
        client = _build_client(cfg)
        items = client.list_objects(
            cfg["bucket"],
            prefix=prefix or None,
            recursive=delimiter == "",
        )
        folders, files = [], []
        for obj in items:
            if obj.is_dir:
                folders.append({"key": obj.object_name, "type": "folder"})
            else:
                files.append({
                    "key":           obj.object_name,
                    "type":          "file",
                    "size":          obj.size,
                    "last_modified": obj.last_modified.isoformat() if obj.last_modified else None,
                    "etag":          obj.etag,
                })
        return {"prefix": prefix, "bucket": cfg["bucket"], "folders": folders, "files": files}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to browse S3: {exc}")


@router.get("/s3/browse")
def browse_import_s3(
    prefix: str = Query(""),
    delimiter: str = Query("/"),
):
    """Browse the case-data-import S3 bucket."""
    return _browse(_S3_IMPORT_KEY, "import", prefix, delimiter)


@router.get("/s3-triage/browse")
def browse_triage_s3(
    prefix: str = Query(""),
    delimiter: str = Query("/"),
):
    """Browse the triage-upload S3 bucket."""
    return _browse(_S3_TRIAGE_KEY, "triage", prefix, delimiter)


# ── Import: case data S3 → case ───────────────────────────────────────────────

@router.post("/cases/{case_id}/s3-import")
def import_from_s3(case_id: str, body: S3ImportIn):
    """
    Stream a file from the case-data-import S3 bucket into a case.

    Streams directly from external S3 to internal MinIO — no full-file
    RAM buffer, safe for multi-GB forensic images.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    r = _redis()
    cfg = _load(r, _S3_IMPORT_KEY)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No import S3 configuration saved.")

    filename = body.filename or body.s3_key.rsplit("/", 1)[-1] or "unknown"
    job_id   = uuid.uuid4().hex
    minio_key = f"cases/{case_id}/{job_id}/{filename}"

    ext_client = _build_client(cfg)
    size = _stream_to_minio(ext_client, cfg["bucket"], body.s3_key, minio_key)

    job_svc.create_job(job_id, case_id, filename, minio_key, source_zip="")
    _dispatch(job_id, case_id, minio_key, filename)

    return {
        "job_id":     job_id,
        "case_id":    case_id,
        "filename":   filename,
        "s3_key":     body.s3_key,
        "size_bytes": size,
        "status":     "PENDING",
    }


# ── Pull: triage S3 → case ───────────────────────────────────────────────────

@router.post("/cases/{case_id}/s3-triage-pull")
def pull_from_triage(case_id: str, body: S3ImportIn):
    """
    Pull a file from the triage-upload S3 bucket into a case for processing.

    Intended workflow: agents push collected archives to the triage bucket;
    analysts open a case, browse the bucket, and pull relevant archives here.
    Streams directly — safe for large triage ZIPs and memory dumps.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    r = _redis()
    cfg = _load(r, _S3_TRIAGE_KEY)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(
            status_code=400,
            detail="No triage S3 configuration saved. Configure it in Settings → Triage Upload Storage.",
        )

    filename  = body.filename or body.s3_key.rsplit("/", 1)[-1] or "unknown"
    job_id    = uuid.uuid4().hex
    minio_key = f"cases/{case_id}/{job_id}/{filename}"

    ext_client = _build_client(cfg)
    size = _stream_to_minio(ext_client, cfg["bucket"], body.s3_key, minio_key)

    job_svc.create_job(job_id, case_id, filename, minio_key, source_zip="")
    _dispatch(job_id, case_id, minio_key, filename)

    return {
        "job_id":     job_id,
        "case_id":    case_id,
        "filename":   filename,
        "s3_key":     body.s3_key,
        "size_bytes": size,
        "status":     "PENDING",
    }


# ── Scaleway region helper ─────────────────────────────────────────────────────

@router.get("/s3/scaleway-regions")
def scaleway_regions():
    """Return the list of Scaleway Object Storage regions and their endpoints."""
    return [
        {"region": k, "endpoint": v, "label": {
            "nl-ams": "Amsterdam (nl-ams)",
            "fr-par": "Paris (fr-par)",
            "pl-waw": "Warsaw (pl-waw)",
        }[k]}
        for k in SCALEWAY_ENDPOINTS
    ]
