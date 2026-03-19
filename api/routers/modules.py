"""Modules registry and module run management."""
from __future__ import annotations

import uuid
import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.jobs import list_case_jobs
from services.cases import get_case
from services import module_runs as run_svc
from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["modules"])

# ── Module registry ───────────────────────────────────────────────────────────
# input_extensions : list of file extensions to match (lower-case, with dot)
# input_filenames  : list of exact basenames to match (case-insensitive)
# Both empty       → accept ANY source file (e.g. "strings")
# Non-empty        → match if extension OR filename matches

MODULES: list[dict] = [
    {
        "id":               "hayabusa",
        "name":             "Hayabusa",
        "description":      "Sigma-based EVTX threat hunting with 4 000+ built-in detection rules",
        "input_extensions": [".evtx"],
        "input_filenames":  [],
        "available":        True,
    },
    {
        "id":               "hindsight",
        "name":             "Hindsight",
        "description":      "Chrome, Firefox and Edge browser forensics — history, downloads, cookies, form data",
        "input_extensions": [".db", ".sqlite"],
        "input_filenames":  [
            "History", "places.sqlite", "Cookies", "Web Data",
            "Login Data", "Favicons", "Shortcuts", "Top Sites",
        ],
        "available":        True,
    },
    {
        "id":               "strings",
        "name":             "Strings",
        "description":      "Extract printable strings (≥ 8 chars) from any file — useful for binary triage",
        "input_extensions": [],   # empty = accept ALL files
        "input_filenames":  [],
        "available":        True,
    },
    {
        "id":               "regripper",
        "name":             "RegRipper",
        "description":      "Deep Windows registry analysis — 200+ plugins covering persistence, MRU, ShimCache, UserAssist and more",
        "input_extensions": [".dat", ".hive"],
        "input_filenames":  [
            "NTUSER.DAT", "SYSTEM", "SOFTWARE", "SAM",
            "SECURITY", "USRCLASS.DAT",
        ],
        "available":        True,
    },
    {
        "id":                  "chainsaw",
        "name":                "Chainsaw",
        "description":         "Rapid EVTX analysis using Sigma rules",
        "input_extensions":    [".evtx"],
        "input_filenames":     [],
        "available":           False,
        "unavailable_reason":  "Sigma rules bundle required — coming soon.",
    },
    {
        "id":                  "evtxecmd",
        "name":                "EvtxECmd",
        "description":         "Eric Zimmermann's EVTX timeline reconstruction",
        "input_extensions":    [".evtx"],
        "input_filenames":     [],
        "available":           False,
        "unavailable_reason":  "Windows/.NET only — not supported on Linux.",
    },
    {
        "id":                  "volatility3",
        "name":                "Volatility 3",
        "description":         "Memory forensics — processes, network, registry from RAM dumps",
        "input_extensions":    [".raw", ".vmem", ".dmp", ".mem", ".lime"],
        "input_filenames":     [],
        "available":           False,
        "unavailable_reason":  "Coming soon.",
    },
]

_MODULES_BY_ID: dict[str, dict] = {m["id"]: m for m in MODULES}


# ── Request models ────────────────────────────────────────────────────────────

class CreateModuleRunRequest(BaseModel):
    module_id: str
    job_ids: list[str]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/modules")
def list_modules():
    return {"modules": MODULES}


@router.get("/cases/{case_id}/sources")
def list_case_sources(case_id: str):
    """Return completed ingest jobs for a case (usable as module inputs)."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    jobs = list_case_jobs(case_id)
    sources = [
        {
            "job_id":            j["job_id"],
            "original_filename": j.get("original_filename", ""),
            "plugin_used":       j.get("plugin_used", ""),
            "events_indexed":    j.get("events_indexed", 0),
            "minio_object_key":  j.get("minio_object_key", ""),
        }
        for j in jobs
        if j.get("status") == "COMPLETED"
    ]
    return {"sources": sources}


@router.post("/cases/{case_id}/module-runs", status_code=201)
def create_module_run(case_id: str, req: CreateModuleRunRequest):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    module = _MODULES_BY_ID.get(req.module_id)
    if not module:
        raise HTTPException(status_code=404, detail=f"Module '{req.module_id}' not found")
    if not module.get("available"):
        reason = module.get("unavailable_reason", "Module unavailable")
        raise HTTPException(status_code=400, detail=reason)
    if not req.job_ids:
        raise HTTPException(status_code=400, detail="At least one source job is required")

    all_jobs = {j["job_id"]: j for j in list_case_jobs(case_id)}
    source_files: list[dict] = []
    for job_id in req.job_ids:
        job = all_jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
        if job.get("status") != "COMPLETED":
            raise HTTPException(
                status_code=400,
                detail=f"Job '{job_id}' has not completed yet (status: {job.get('status')})",
            )
        source_files.append({
            "job_id":    job_id,
            "filename":  job.get("original_filename", ""),
            "minio_key": job.get("minio_object_key", ""),
        })

    run_id = uuid.uuid4().hex
    run_svc.create_module_run(run_id, case_id, req.module_id, source_files)

    try:
        from celery import Celery
        celery_app = Celery(broker=settings.REDIS_URL)
        celery_app.send_task(
            "module.run",
            args=[run_id, case_id, req.module_id, source_files],
            task_id=run_id,
        )
    except Exception as exc:
        logger.error("Celery dispatch failed for module run %s: %s", run_id, exc)
        run_svc.update_module_run(run_id, status="FAILED", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Task dispatch failed: {exc}")

    return {"run_id": run_id, "status": "PENDING"}


@router.get("/cases/{case_id}/module-runs")
def list_module_runs(case_id: str):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"runs": run_svc.list_case_module_runs(case_id)}


@router.get("/module-runs/{run_id}")
def get_module_run(run_id: str):
    run = run_svc.get_module_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Module run not found")
    return run
