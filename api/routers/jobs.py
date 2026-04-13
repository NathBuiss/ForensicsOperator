"""Job status endpoints."""
import logging

from fastapi import APIRouter, HTTPException

from services import jobs as job_svc

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

    case_id = job["case_id"]
    minio_object_key = job["minio_object_key"]
    original_filename = job["original_filename"]

    # Reset job state in Redis
    job_svc.reset_job_for_retry(job_id)

    # Re-dispatch the Celery ingest task
    try:
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
