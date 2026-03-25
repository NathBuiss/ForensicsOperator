"""MinIO storage service with retry logic for transient connection failures."""
from __future__ import annotations

import io
import logging
import time
from typing import AsyncIterator

from config import settings

logger = logging.getLogger(__name__)

_CONN_ERRORS = ("connection refused", "max retries", "timeout", "reset by peer", "broken pipe")


def _retry(fn, max_tries: int = 3, base_delay: float = 1.0):
    """Retry *fn()* with exponential backoff on transient connection errors."""
    last_exc = None
    for attempt in range(max_tries):
        try:
            return fn()
        except Exception as exc:
            msg = str(exc).lower()
            if any(k in msg for k in _CONN_ERRORS):
                last_exc = exc
                if attempt < max_tries - 1:
                    wait = base_delay * (2 ** attempt)
                    logger.warning(
                        "MinIO attempt %d/%d failed (%s). Retrying in %.0fs…",
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
    """Upload bytes to MinIO with retry. Returns the object key."""
    client = get_minio()
    ensure_bucket()
    _retry(lambda: client.put_object(
        settings.MINIO_BUCKET,
        object_key,
        io.BytesIO(data),
        length=len(data),
        content_type=content_type,
    ))
    logger.info("Uploaded %s (%d bytes)", object_key, len(data))
    return object_key


def upload_fileobj(object_key: str, fileobj: io.IOBase, size: int) -> str:
    """Upload a file-like object to MinIO with retry."""
    client = get_minio()
    ensure_bucket()
    _retry(lambda: client.put_object(
        settings.MINIO_BUCKET,
        object_key,
        fileobj,
        length=size,
    ))
    return object_key


def get_presigned_url(object_key: str, expires_seconds: int = 3600) -> str:
    """Generate a presigned download URL."""
    from datetime import timedelta
    client = get_minio()
    return client.presigned_get_object(
        settings.MINIO_BUCKET,
        object_key,
        expires=timedelta(seconds=expires_seconds),
    )
