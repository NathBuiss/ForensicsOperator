"""
Analysis Modules registry and run management.

Modules are on-demand analysis tools that run asynchronously via Celery
against files already ingested into a case.  They differ from Ingesters:

  Ingesters  — parse uploaded raw files into the timeline (EVTX, logs, etc.)
  Modules    — perform deeper forensic analysis on stored artifacts
               (threat hunting, malware scanning, metadata extraction…)

Each module run is independent: you select source files from the case,
launch the module, and results appear in the Module Runs panel without
affecting the main event timeline.

Module definitions live in api/modules_registry/*.yaml  — add a new YAML file
to register a new module without touching this code.
"""
from __future__ import annotations

import importlib.util
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

try:
    import yaml as _yaml  # type: ignore
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from services.jobs import list_case_jobs
from services.cases import get_case
from services import module_runs as run_svc
from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["modules"])

CUSTOM_MODULES_DIR = Path(os.getenv("MODULES_DIR", "/app/modules"))

# Module definitions are loaded from YAML files in api/modules_registry/
_REGISTRY_DIR = Path(__file__).parent.parent / "modules_registry"


# ── YAML registry loader ──────────────────────────────────────────────────────
# input_extensions : list of file extensions to match (lower-case, with dot)
# input_filenames  : list of exact basenames to match (case-insensitive)
# Both empty       → accept ANY source file (e.g. "strings")
# Non-empty        → match if extension OR filename matches

def _load_modules_from_registry() -> list[dict]:
    """
    Load module definitions from api/modules_registry/*.yaml.

    Each YAML file defines one module:
        id: hayabusa
        name: Hayabusa
        description: ...
        input_extensions: [".evtx"]
        input_filenames: []
        available: true
        # optional fields:
        unavailable_reason: "..."
        category: "Threat Hunting"
        tags: [sigma, evtx]
    """
    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — module registry cannot be loaded from YAML files")
        return []
    if not _REGISTRY_DIR.exists():
        logger.warning("Modules registry directory %s not found", _REGISTRY_DIR)
        return []

    modules: list[dict] = []
    for path in sorted(_REGISTRY_DIR.glob("*.yaml")):
        try:
            with path.open() as fh:
                data = _yaml.safe_load(fh)
            if not isinstance(data, dict) or not data.get("id"):
                logger.warning("Skipping %s — missing 'id' field", path.name)
                continue
            module: dict = {
                "id":               data["id"],
                "name":             data.get("name", data["id"]),
                "description":      data.get("description", ""),
                "input_extensions": data.get("input_extensions") or [],
                "input_filenames":  data.get("input_filenames") or [],
                "available":        bool(data.get("available", True)),
                "category":         data.get("category", ""),
                "tags":             data.get("tags") or [],
            }
            if not module["available"]:
                module["unavailable_reason"] = data.get("unavailable_reason", "Unavailable")
            modules.append(module)
        except Exception as exc:
            logger.error("Failed to load module from %s: %s", path.name, exc)
    return modules


_MODULES_CACHE: list[dict] | None = None


def _get_modules() -> list[dict]:
    global _MODULES_CACHE
    if _MODULES_CACHE is None:
        _MODULES_CACHE = _load_modules_from_registry()
    return _MODULES_CACHE


def _get_modules_by_id() -> dict[str, dict]:
    return {m["id"]: m for m in _get_modules()}


# ── Request models ────────────────────────────────────────────────────────────

class CreateModuleRunRequest(BaseModel):
    module_id: str
    job_ids: list[str]
    params: dict[str, Any] = {}   # module-specific parameters (e.g. custom YARA rules)


# ── Endpoints ─────────────────────────────────────────────────────────────────

def _get_custom_modules() -> list[dict]:
    """Scan CUSTOM_MODULES_DIR and return metadata for each *_module.py file."""
    if not CUSTOM_MODULES_DIR.exists():
        return []
    built_in_ids = {m["id"] for m in _get_modules()}
    result = []
    for f in sorted(CUSTOM_MODULES_DIR.glob("*_module.py")):
        module_id = f.stem[: -len("_module")]  # strip trailing _module
        if module_id in built_in_ids:
            continue  # skip if it shadows a built-in
        try:
            spec = importlib.util.spec_from_file_location(f"_meta_{module_id}", f)
            if spec is None or spec.loader is None:
                raise RuntimeError("Cannot create module spec")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            result.append({
                "id":               module_id,
                "name":             getattr(mod, "MODULE_NAME", module_id.replace("_", " ").title()),
                "description":      getattr(mod, "MODULE_DESCRIPTION", "Custom analysis module"),
                "input_extensions": getattr(mod, "INPUT_EXTENSIONS", []),
                "input_filenames":  getattr(mod, "INPUT_FILENAMES", []),
                "available":        True,
                "custom":           True,
            })
        except Exception as exc:
            result.append({
                "id":                  module_id,
                "name":                module_id.replace("_", " ").title(),
                "description":         f"Load error: {exc}",
                "input_extensions":    [],
                "input_filenames":     [],
                "available":           False,
                "unavailable_reason":  f"Load error: {exc}",
                "custom":              True,
            })
    return result


@router.get("/modules")
def list_modules():
    return {"modules": _get_modules() + _get_custom_modules()}


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

    module = _get_modules_by_id().get(req.module_id)
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
            args=[run_id, case_id, req.module_id, source_files, req.params],
            task_id=run_id,
            queue="modules",
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


# ── YARA utilities ────────────────────────────────────────────────────────────

class ValidateYaraRequest(BaseModel):
    rules: str


@router.post("/modules/yara/validate")
def validate_yara_rules(req: ValidateYaraRequest):
    """
    Validate YARA rules syntax without running a scan.
    Returns {valid: true} or {valid: false, error: "..."}.
    """
    try:
        import yara  # type: ignore
        yara.compile(source=req.rules)
        return {"valid": True}
    except ImportError:
        # yara-python not available in the API container — skip validation
        return {"valid": True, "warning": "yara-python not available in API; validation skipped"}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}
