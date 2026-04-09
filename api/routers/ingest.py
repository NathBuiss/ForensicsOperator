"""File upload and ingest job dispatch.

Strategy:
  1. Stream each uploaded file to a local temp file in 4 MB async chunks.
     Using UploadFile.read() (which internally uses run_in_threadpool) ensures
     the event loop is never blocked, so other requests remain responsive even
     during 500 MB+ uploads.
  2. Return job IDs immediately after spooling, with status UPLOADING.
  3. Upload from the temp file to MinIO in a BackgroundTask — so the HTTP
     response is sent before the (potentially slow) MinIO transfer completes.
     This prevents proxy timeout errors (Traefik / Vite dev proxy) on large files.

Status lifecycle: UPLOADING → PENDING → RUNNING → COMPLETED | FAILED
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
from typing import List

from services import storage, jobs as job_svc
from services.cases import get_case

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])

# Temp directory for in-progress chunked uploads
_CHUNK_DIR = Path(tempfile.gettempdir()) / "fo_chunks"
_CHUNK_DIR.mkdir(exist_ok=True)


# ── Celery dispatch ────────────────────────────────────────────────────────────

def _dispatch_celery_task(job_id: str, case_id: str, minio_key: str, filename: str) -> None:
    """Dispatch a Celery ingest task via direct Redis push."""
    from services.celery_dispatch import dispatch_ingest
    dispatch_ingest(job_id, case_id, minio_key, filename)


# ── Background upload helper ──────────────────────────────────────────────────

def _bg_upload_and_dispatch(
    job_id: str,
    case_id: str,
    minio_key: str,
    filename: str,
    tmp_path: str,
    source_zip: str = "",
) -> None:
    """
    BackgroundTask: stream file from local staging to MinIO, then dispatch Celery task.

    Runs after the HTTP response has been sent, so the browser never waits for
    the potentially slow MinIO upload.  Status transitions:
      UPLOADING → (MinIO upload complete) → PENDING → (Celery processes) → COMPLETED / FAILED
    """
    try:
        size = os.path.getsize(tmp_path)
        with open(tmp_path, "rb") as f:
            storage.upload_fileobj(minio_key, f, size)

        job_svc.update_job(job_id, minio_object_key=minio_key, status="PENDING")

        try:
            _dispatch_celery_task(job_id, case_id, minio_key, filename)
        except Exception as exc:
            logger.error("Celery dispatch failed for '%s': %s", filename, exc)
            job_svc.update_job(job_id, status="FAILED", error=f"Task dispatch failed: {exc}")

    except Exception as exc:
        logger.error("Background MinIO upload failed for '%s': %s", filename, exc)
        try:
            job_svc.update_job(job_id, status="FAILED", error=f"Upload failed: {exc}")
        except Exception:
            pass
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── Single-file ingest (async) ─────────────────────────────────────────────────

def _ingest_one_async(
    case_id: str,
    filename: str,
    tmp_path: str,
    size: int,
    dispatched: list,
    errors: list,
    background_tasks: BackgroundTasks,
    source_zip: str = "",
) -> None:
    """Create job record, register background upload, append to dispatched."""
    if size == 0:
        logger.warning("Skipping empty file: %s", filename)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return

    job_id    = uuid.uuid4().hex
    minio_key = f"cases/{case_id}/{job_id}/{filename}"

    job_svc.create_job(job_id, case_id, filename, "", source_zip=source_zip)
    job_svc.update_job(job_id, status="UPLOADING", size_bytes=size)

    background_tasks.add_task(
        _bg_upload_and_dispatch, job_id, case_id, minio_key, filename, tmp_path, source_zip
    )

    entry: dict = {
        "job_id":     job_id,
        "filename":   filename,
        "status":     "UPLOADING",
        "size_bytes": size,
    }
    if source_zip:
        entry["source_zip"] = source_zip
    dispatched.append(entry)


# ── ZIP extraction ─────────────────────────────────────────────────────────────

def _handle_zip_async(
    case_id: str,
    zip_name: str,
    zip_tmp_path: str,
    dispatched: list,
    errors: list,
    background_tasks: BackgroundTasks,
) -> None:
    """
    Extract a zip archive to a temp dir, create one async ingest job per file.

    The zip temp file is cleaned up once all members have been staged.
    """
    try:
        zf = zipfile.ZipFile(zip_tmp_path, "r")
    except zipfile.BadZipFile:
        errors.append({"filename": zip_name, "error": "Not a valid zip archive"})
        try:
            os.unlink(zip_tmp_path)
        except OSError:
            pass
        return

    pre_count = len(dispatched)
    with zf:
        for entry in zf.namelist():
            entry_name = os.path.basename(entry)
            if not entry_name or entry.endswith("/") or entry_name.startswith("."):
                continue
            if entry_name.lower().endswith(".zip"):
                logger.info("Skipping nested zip '%s' inside '%s'", entry_name, zip_name)
                continue

            # Extract to a per-file temp file
            try:
                tmp_fd, extracted_path = tempfile.mkstemp(prefix="fo_zip_", suffix=f"_{entry_name}")
                os.close(tmp_fd)
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
            _ingest_one_async(
                case_id, entry_name, extracted_path, file_size,
                dispatched, errors, background_tasks, source_zip=zip_name,
            )

    # Clean up the zip itself
    try:
        os.unlink(zip_tmp_path)
    except OSError:
        pass

    if len(dispatched) == pre_count and not errors:
        errors.append({
            "filename": zip_name,
            "error": "Zip archive contained no processable files",
        })


# ── Chunked upload endpoint ────────────────────────────────────────────────────

@router.post("/cases/{case_id}/ingest/chunk")
async def ingest_chunk(
    case_id: str,
    upload_id: str = Form(...),
    filename: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    chunk: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
):
    """
    Receive one chunk of a large file upload.

    The client splits a file into fixed-size pieces and POSTs them sequentially.
    Each piece is appended to a per-upload temp file. When the final chunk arrives
    the assembled file is handed off to the normal ingest pipeline.

    This avoids proxy body-size limits and read timeouts entirely — each chunk
    is a small request (typically 50 MB) that completes in a few seconds.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Sanitise upload_id so it's safe to use as a filename component
    if not re.fullmatch(r'[0-9a-f\-]{8,64}', upload_id):
        raise HTTPException(status_code=400, detail="Invalid upload_id")

    safe_name = re.sub(r'[^\w.\-]', '_', filename)[:200]
    tmp_path = str(_CHUNK_DIR / f"{upload_id}_{safe_name}")

    try:
        data = await chunk.read()
        # Append mode so chunks accumulate in order
        with open(tmp_path, "ab") as f:
            f.write(data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store chunk: {exc}")

    # Not the last chunk — acknowledge and wait for more
    if chunk_index < total_chunks - 1:
        return {"status": "partial", "chunk": chunk_index, "received": chunk_index + 1}

    # Final chunk — hand off to normal ingest pipeline
    size = os.path.getsize(tmp_path)
    dispatched: list = []
    errors: list = []

    try:
        if filename.lower().endswith(".zip"):
            _handle_zip_async(case_id, filename, tmp_path, dispatched, errors, background_tasks)
        else:
            _ingest_one_async(case_id, filename, tmp_path, size, dispatched, errors, background_tasks)
    except Exception as exc:
        logger.error("Failed to register chunked ingest for '%s': %s", filename, exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Server error: {exc}")

    if errors:
        raise HTTPException(status_code=400, detail=errors[0]["error"])

    return {"case_id": case_id, "jobs": dispatched}


# ── Endpoint ───────────────────────────────────────────────────────────────────

@router.post("/cases/{case_id}/ingest")
async def ingest_files(
    case_id: str,
    files: List[UploadFile] = File(...),
    background_tasks: BackgroundTasks = None,
):
    """
    Upload one or more forensics files (or zip archives) to a case and enqueue processing.

    Files are spooled to local disk immediately (fast), the HTTP response is sent at
    once with UPLOADING job IDs, and the actual MinIO transfer happens in the background.
    This prevents Traefik / proxy timeouts on large files (500 MB+).

    Status lifecycle: UPLOADING → PENDING → RUNNING → COMPLETED | FAILED
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    dispatched: list = []
    errors: list = []

    for upload in files:
        filename = upload.filename or "unknown"

        # ── Stream upload to a local temp file ────────────────────────────────
        # Uses UploadFile.read() in 4 MB chunks so the event loop is never
        # blocked for more than a few milliseconds, even for 500 MB+ files.
        # Each read() call is internally dispatched to a thread pool by
        # Starlette, keeping other requests responsive during large uploads.
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(prefix="fo_ingest_", suffix=f"_{filename}")
            os.close(tmp_fd)

            size = 0
            chunk_size = 4 * 1024 * 1024  # 4 MB chunks
            with open(tmp_path, "wb") as out:
                while True:
                    chunk = await upload.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
                    size += len(chunk)

        except Exception as exc:
            logger.error("Cannot spool '%s' to disk: %s", filename, exc)
            # Clean up partial temp file if it was created
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            errors.append({"filename": filename, "error": f"Failed to receive file: {exc}"})
            continue

        try:
            if filename.lower().endswith(".zip"):
                _handle_zip_async(case_id, filename, tmp_path, dispatched, errors, background_tasks)
            else:
                _ingest_one_async(case_id, filename, tmp_path, size, dispatched, errors, background_tasks)
        except Exception as exc:
            logger.error("Failed to register ingest job for '%s': %s", filename, exc)
            errors.append({"filename": filename, "error": f"Server error: {exc}"})
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

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
