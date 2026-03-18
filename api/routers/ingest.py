"""File upload and ingest job dispatch."""
from __future__ import annotations

import io
import uuid
import logging

from fastapi import APIRouter, File, HTTPException, UploadFile
from typing import List

from services import storage, jobs as job_svc
from services.cases import get_case
from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])


def _dispatch_celery_task(job_id: str, case_id: str, minio_key: str, filename: str):
    """Dispatch a Celery ingest task."""
    from celery import Celery
    import os
    app = Celery(broker=settings.REDIS_URL)
    app.send_task(
        "ingest.process_artifact",
        args=[job_id, case_id, minio_key, filename],
        task_id=job_id,
    )


@router.post("/cases/{case_id}/ingest")
async def ingest_files(case_id: str, files: List[UploadFile] = File(...)):
    """
    Upload one or more forensics files to a case and enqueue processing.

    Accepts: .evtx, .plaso, .pf, $MFT, NTUSER.DAT, SYSTEM, SOFTWARE, SAM, .lnk
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    dispatched = []

    for upload in files:
        job_id = uuid.uuid4().hex
        filename = upload.filename or "unknown"
        minio_key = f"cases/{case_id}/{job_id}/{filename}"

        # Read file content
        try:
            content = await upload.read()
            if not content:
                logger.warning("Empty file: %s", filename)
                continue
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to read {filename}: {exc}")

        # Upload to MinIO
        try:
            storage.upload_file(minio_key, content, upload.content_type or "application/octet-stream")
        except Exception as exc:
            logger.error("MinIO upload failed for %s: %s", filename, exc)
            raise HTTPException(status_code=500, detail=f"Storage upload failed: {exc}")

        # Create job record
        job_svc.create_job(job_id, case_id, filename, minio_key)

        # Dispatch Celery task
        try:
            _dispatch_celery_task(job_id, case_id, minio_key, filename)
        except Exception as exc:
            logger.error("Celery dispatch failed for %s: %s", filename, exc)
            raise HTTPException(status_code=500, detail=f"Task dispatch failed: {exc}")

        dispatched.append({
            "job_id": job_id,
            "filename": filename,
            "status": "PENDING",
            "size_bytes": len(content),
        })

    if not dispatched:
        raise HTTPException(status_code=400, detail="No valid files uploaded")

    return {"case_id": case_id, "jobs": dispatched}
