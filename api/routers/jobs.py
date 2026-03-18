"""Job status endpoints."""
from fastapi import APIRouter, HTTPException
from services import jobs as job_svc

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
