"""MinIO storage service."""
from __future__ import annotations

import io
import logging
from typing import AsyncIterator

from config import settings

logger = logging.getLogger(__name__)


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
    if not client.bucket_exists(settings.MINIO_BUCKET):
        client.make_bucket(settings.MINIO_BUCKET)
        logger.info("Created MinIO bucket: %s", settings.MINIO_BUCKET)


def upload_file(object_key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
    """Upload bytes to MinIO. Returns the object key."""
    client = get_minio()
    ensure_bucket()
    client.put_object(
        settings.MINIO_BUCKET,
        object_key,
        io.BytesIO(data),
        length=len(data),
        content_type=content_type,
    )
    logger.info("Uploaded %s (%d bytes)", object_key, len(data))
    return object_key


def upload_fileobj(object_key: str, fileobj: io.IOBase, size: int) -> str:
    """Upload a file-like object to MinIO."""
    client = get_minio()
    ensure_bucket()
    client.put_object(
        settings.MINIO_BUCKET,
        object_key,
        fileobj,
        length=size,
    )
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
