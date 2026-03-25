"""File upload and ingest job dispatch."""
from __future__ import annotations

import io
import os
import shutil
import tempfile
import uuid
import logging
import zipfile

from fastapi import APIRouter, File, HTTPException, UploadFile
from typing import List

from services import storage, jobs as job_svc
from services.cases import get_case
from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])


def _dispatch_celery_task(job_id: str, case_id: str, minio_key: str, filename: str) -> None:
    """Dispatch a Celery ingest task via send_task (no direct processor import needed)."""
    from celery import Celery
    app = Celery(broker=settings.REDIS_URL)
    app.send_task(
        "ingest.process_artifact",
        args=[job_id, case_id, minio_key, filename],
        task_id=job_id,
        queue="ingest",
    )


def _ingest_one(
    case_id: str,
    filename: str,
    fileobj,
    size: int,
    dispatched: list,
    errors: list,
    source_zip: str | None = None,
) -> None:
    """Upload a single file to MinIO and dispatch an ingest job (streaming, no RAM copy).

    On failure the error is appended to *errors* so the caller can continue
    processing remaining files.  No exception is raised.
    """
    if size == 0:
        logger.warning("Skipping empty file: %s", filename)
        return

    job_id   = uuid.uuid4().hex
    minio_key = f"cases/{case_id}/{job_id}/{filename}"

    try:
        storage.upload_fileobj(minio_key, fileobj, size)
    except Exception as exc:
        logger.error("Storage upload failed for '%s': %s", filename, exc)
        errors.append({"filename": filename, "error": f"Storage upload failed: {exc}"})
        return

    job_svc.create_job(job_id, case_id, filename, minio_key, source_zip=source_zip or "")

    try:
        _dispatch_celery_task(job_id, case_id, minio_key, filename)
    except Exception as exc:
        logger.error("Task dispatch failed for '%s': %s", filename, exc)
        errors.append({"filename": filename, "error": f"Task dispatch failed: {exc}"})
        return

    entry: dict = {
        "job_id":     job_id,
        "filename":   filename,
        "status":     "PENDING",
        "size_bytes": size,
    }
    if source_zip:
        entry["source_zip"] = source_zip
    dispatched.append(entry)


def _handle_zip(
    case_id: str, zip_name: str, zip_fileobj, dispatched: list, errors: list,
) -> None:
    """
    Extract a zip archive and ingest each contained file as a separate job.

    Uses a tmpdir so the zip is never fully loaded into memory -- each file is
    extracted, streamed to MinIO, then immediately deleted from disk.
    If individual files fail, errors are recorded and processing continues.
    """
    with tempfile.TemporaryDirectory(prefix="fo_zip_") as tmpdir:
        # ── Write the uploaded zip to disk ──────────────────────────────────
        zip_path = os.path.join(tmpdir, zip_name)
        with open(zip_path, "wb") as out:
            shutil.copyfileobj(zip_fileobj, out)

        try:
            zf = zipfile.ZipFile(zip_path, "r")
        except zipfile.BadZipFile:
            errors.append({"filename": zip_name, "error": "Not a valid zip archive"})
            return

        pre_count = len(dispatched)
        with zf:
            for entry in zf.namelist():
                # Skip directories, hidden files, and nested zip files
                entry_name = os.path.basename(entry)
                if not entry_name or entry.endswith("/") or entry_name.startswith("."):
                    continue
                if entry_name.lower().endswith(".zip"):
                    logger.info("Skipping nested zip '%s' inside '%s'", entry_name, zip_name)
                    continue

                extracted_path = os.path.join(tmpdir, f"{uuid.uuid4().hex}_{entry_name}")
                try:
                    with zf.open(entry) as src, open(extracted_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                except Exception as exc:
                    logger.warning("Could not extract '%s' from '%s': %s", entry, zip_name, exc)
                    errors.append({
                        "filename": entry_name,
                        "source_zip": zip_name,
                        "error": f"Extraction failed: {exc}",
                    })
                    continue

                file_size = os.path.getsize(extracted_path)
                if file_size == 0:
                    continue

                # Stream extracted file to MinIO then clean up immediately
                try:
                    with open(extracted_path, "rb") as f:
                        _ingest_one(
                            case_id, entry_name, f, file_size,
                            dispatched, errors, source_zip=zip_name,
                        )
                finally:
                    try:
                        os.unlink(extracted_path)
                    except OSError:
                        pass

        if len(dispatched) == pre_count and not errors:
            errors.append({
                "filename": zip_name,
                "error": "Zip archive contained no processable files",
            })


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post("/cases/{case_id}/ingest")
async def ingest_files(case_id: str, files: List[UploadFile] = File(...)):
    """
    Upload one or more forensics files (or zip archives) to a case and enqueue processing.

    Accepts: .evtx, .plaso, .pf, $MFT, NTUSER.DAT, SYSTEM, SOFTWARE, SAM,
             .lnk, .jsonl, .csv  and  .zip (contents extracted, each file processed separately)

    Supports uploading multiple files at once (e.g. directory/folder uploads).
    Each file gets its own job ID and is processed independently — if one file
    fails, the remaining files continue.

    Large files are streamed directly to MinIO — they are never fully loaded into
    the API process memory, so uploads of several GB are safe.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    dispatched: list = []
    errors: list = []

    for upload in files:
        filename = upload.filename or "unknown"

        # Determine file size by seeking the underlying SpooledTemporaryFile.
        # For files >1 MB FastAPI has already spooled them to disk, so this is
        # O(1) and does not allocate the file contents in memory.
        # Fall back to reading content-length header if seek is not supported.
        try:
            file_obj = upload.file
            try:
                file_obj.seek(0, 2)
                size = file_obj.tell()
                file_obj.seek(0)
            except (AttributeError, OSError):
                # Non-seekable stream — read into memory to get size
                data = await upload.read()
                size = len(data)
                file_obj = io.BytesIO(data)
        except Exception as exc:
            logger.error("Cannot determine size of '%s': %s", filename, exc)
            errors.append({"filename": filename, "error": f"Cannot determine file size: {exc}"})
            continue

        if filename.lower().endswith(".zip"):
            _handle_zip(case_id, filename, file_obj, dispatched, errors)
        else:
            _ingest_one(case_id, filename, file_obj, size, dispatched, errors)

    if not dispatched and not errors:
        raise HTTPException(status_code=400, detail="No valid files uploaded")

    if not dispatched and errors:
        raise HTTPException(
            status_code=400,
            detail="All files failed to ingest",
            headers={"X-Ingest-Errors": str(len(errors))},
        )

    response: dict = {"case_id": case_id, "jobs": dispatched}
    if errors:
        response["errors"] = errors
    return response
