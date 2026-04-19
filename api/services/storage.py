"""MinIO storage service with retry logic for transient connection failures."""
from __future__ import annotations

import io
import logging
import time
from typing import IO

from config import settings

logger = logging.getLogger(__name__)

# Error substrings that indicate a transient connection problem worth retrying.
_CONN_ERRORS = (
    "connection refused",
    "max retries exceeded",
    "timeout",
    "reset by peer",
    "broken pipe",
    "connection reset",
    "read timeout",
    "write timeout",
    "remote end closed",
    "incomplete read",
    "econnreset",
    "epipe",
)


def _is_transient(exc: Exception) -> bool:
    return any(k in str(exc).lower() for k in _CONN_ERRORS)


def _retry(fn, max_tries: int = 3, base_delay: float = 1.0):
    """
    Call *fn()* up to *max_tries* times with exponential back-off.

    Only retries when the exception looks like a transient network failure.
    All other errors are re-raised immediately on the first occurrence.
    """
    last_exc: Exception | None = None
    for attempt in range(max_tries):
        try:
            return fn()
        except Exception as exc:
            if _is_transient(exc):
                last_exc = exc
                if attempt < max_tries - 1:
                    wait = base_delay * (2 ** attempt)
                    logger.warning(
                        "MinIO transient error (attempt %d/%d): %s — retrying in %.0f s",
                        attempt + 1, max_tries, exc, wait,
                    )
                    time.sleep(wait)
                    continue
            raise
    raise last_exc  # type: ignore[misc]


def get_minio():
    from minio import Minio
    return Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=False,
    )


def ensure_bucket() -> None:
    client = get_minio()

    def _check():
        if not client.bucket_exists(settings.MINIO_BUCKET):
            client.make_bucket(settings.MINIO_BUCKET)
            logger.info("Created MinIO bucket: %s", settings.MINIO_BUCKET)

    _retry(_check)


def upload_file(object_key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
    """Upload raw bytes to MinIO with retry. Returns the object key."""
    client = get_minio()
    ensure_bucket()

    def _do():
        client.put_object(
            settings.MINIO_BUCKET,
            object_key,
            io.BytesIO(data),
            length=len(data),
            content_type=content_type,
        )

    _retry(_do)
    logger.info("Uploaded %s (%d bytes)", object_key, len(data))
    return object_key


def upload_fileobj(object_key: str, fileobj: IO, size: int) -> str:
    """
    Upload a file-like object to MinIO with retry.

    Critical: the file position is reset to 0 before each attempt so that
    retries after a partial write do not send truncated data.
    """
    client = get_minio()
    ensure_bucket()

    def _do():
        try:
            fileobj.seek(0)
        except (AttributeError, OSError):
            pass
        client.put_object(
            settings.MINIO_BUCKET,
            object_key,
            fileobj,
            length=size,
        )

    _retry(_do)
    return object_key


def download_fileobj(object_key: str) -> bytes:
    """Download an object from MinIO and return its contents as bytes."""
    client = get_minio()
    try:
        resp = client.get_object(settings.MINIO_BUCKET, object_key)
        return resp.read()
    finally:
        try:
            resp.close()
            resp.release_conn()
        except Exception:
            pass


def delete_object(object_key: str) -> None:
    """Remove an object from MinIO (no-op if it doesn't exist)."""
    client = get_minio()
    _retry(lambda: client.remove_object(settings.MINIO_BUCKET, object_key))
    logger.info("Deleted MinIO object: %s", object_key)


def delete_case_objects(case_id: str) -> int:
    """
    Delete ALL MinIO objects under cases/{case_id}/ by prefix.

    More reliable than per-job deletion because it works even after job Redis
    records have expired (7-day TTL). Returns count of objects deleted.
    """
    client = get_minio()
    prefix = f"cases/{case_id}/"
    objects = client.list_objects(settings.MINIO_BUCKET, prefix=prefix, recursive=True)
    keys = [o.object_name for o in objects]
    if not keys:
        return 0
    from minio.deleteobjects import DeleteObject
    errors = list(client.remove_objects(
        settings.MINIO_BUCKET,
        [DeleteObject(k) for k in keys],
    ))
    deleted = len(keys) - len(errors)
    if errors:
        logger.warning("MinIO prefix delete %s: %d errors", prefix, len(errors))
    logger.info("Deleted %d MinIO objects under %s", deleted, prefix)
    return deleted


def get_presigned_url(object_key: str, expires_seconds: int = 3600) -> str:
    """Generate a presigned download URL."""
    from datetime import timedelta
    client = get_minio()
    return client.presigned_get_object(
        settings.MINIO_BUCKET,
        object_key,
        expires=timedelta(seconds=expires_seconds),
    )
