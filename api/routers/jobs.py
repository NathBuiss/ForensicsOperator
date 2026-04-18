"""Job status endpoints."""
import logging

from fastapi import APIRouter, HTTPException

from services import jobs as job_svc
from services import storage
from services import elasticsearch as es

logger = logging.getLogger(__name__)
router = APIRouter(tags=["jobs"])


@router.get("/jobs/{job_id}")
def get_job(job_id: str):
    """Poll a single job's status and progress."""
    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/cases/{case_id}/jobs")
def list_case_jobs(case_id: str):
    """List all jobs for a case."""
    jobs = job_svc.list_case_jobs(case_id)
    return {"case_id": case_id, "jobs": jobs, "total": len(jobs)}


@router.post("/jobs/batch")
def get_jobs_batch(body: dict):
    """
    Return status for up to 500 job IDs in a single request.

    Accepts: {"job_ids": ["id1", "id2", ...]}
    Returns: array of job objects (missing IDs are silently omitted).

    Used by the Ingest UI to replace N individual polling calls with one,
    preventing ERR_INSUFFICIENT_RESOURCES when a ZIP produces hundreds of jobs.
    """
    job_ids = body.get("job_ids", [])[:500]
    results = []
    for jid in job_ids:
        job = job_svc.get_job(jid)
        if job:
            results.append(job)
    return results


@router.post("/jobs/{job_id}/retry")
def retry_job(job_id: str):
    """
    Retry a failed ingest job.

    Re-dispatches the Celery task with the original arguments and resets the
    job status to PENDING.  Only jobs whose current status is FAILED can be
    retried.
    """
    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("status") not in ("FAILED", "PENDING"):
        raise HTTPException(
            status_code=409,
            detail=f"Only FAILED or PENDING jobs can be retried (current status: {job.get('status')})",
        )

    case_id           = job["case_id"]
    minio_object_key  = job["minio_object_key"]
    original_filename = job["original_filename"]
    s3_config_key     = job.get("s3_config_key", "")
    s3_source_key     = job.get("s3_source_key", "")

    # Reset job state in Redis
    job_svc.reset_job_for_retry(job_id)

    # Re-dispatch — S3-originated jobs restart from the transfer phase so
    # the full S3 → MinIO → ingest pipeline runs again (handles partial
    # transfers, overwritten objects, etc.).
    try:
        if s3_source_key and s3_config_key:
            from services.celery_dispatch import dispatch_s3_transfer
            dispatch_s3_transfer(job_id, case_id, s3_config_key, s3_source_key, original_filename)
        else:
            from services.celery_dispatch import dispatch_ingest
            dispatch_ingest(job_id, case_id, minio_object_key, original_filename)
    except Exception as exc:
        logger.exception("Failed to re-dispatch Celery task for job %s", job_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to dispatch retry task: {exc}",
        )

    return {
        "job_id": job_id,
        "status": "PENDING",
        "message": "Job has been re-queued for processing",
    }


@router.delete("/jobs/{job_id}")
def delete_job(job_id: str):
    """
    Permanently delete an ingestion job and all its data:
      - Job metadata from Redis (and child job records if this was a ZIP)
      - Source file from MinIO
      - All indexed events from Elasticsearch

    Active jobs (RUNNING, UPLOADING) are rejected — wait for them to finish.
    """
    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("status") in ("RUNNING", "UPLOADING"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete an active job (status: {job.get('status')}). Wait for it to finish.",
        )

    case_id = job["case_id"]

    # Collect this job + any child jobs created from a ZIP expansion
    jobs_to_delete = [job]
    if job.get("plugin_used", "").startswith("archive"):
        original_zip = job.get("original_filename", "")
        all_case_jobs = job_svc.list_case_jobs(case_id)
        for child in all_case_jobs:
            if child.get("source_zip") == original_zip and child["job_id"] != job_id:
                jobs_to_delete.append(child)

    deleted_ids = []
    for j in jobs_to_delete:
        jid = j["job_id"]
        minio_key = j.get("minio_object_key", "")

        # Remove source file from MinIO
        if minio_key:
            try:
                storage.delete_object(minio_key)
            except Exception as exc:
                logger.warning("MinIO delete skipped for %s: %s", minio_key, exc)

        # Remove indexed events from Elasticsearch
        try:
            es._request(
                "POST",
                f"/fo-case-{case_id}-*/_delete_by_query?conflicts=proceed",
                {"query": {"term": {"ingest_job_id": jid}}},
            )
        except Exception as exc:
            logger.warning("ES delete_by_query skipped for job %s: %s", jid, exc)

        job_svc.delete_job(jid, case_id)
        deleted_ids.append(jid)

    logger.info("Deleted job %s and %d child(ren) for case %s", job_id, len(deleted_ids) - 1, case_id)
    return {"job_id": job_id, "deleted": True, "children_deleted": len(deleted_ids) - 1}
