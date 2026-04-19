"""Case CRUD endpoints."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from services import cases as case_svc
from services.elasticsearch import list_artifact_types, count_case_events

router = APIRouter(tags=["cases"])


class CaseCreate(BaseModel):
    name: str
    description: str = ""
    analyst: str = ""


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    analyst: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None


@router.get("/cases")
def list_cases():
    """List all cases with summary stats."""
    cases = case_svc.list_cases()
    result = []
    for case in cases:
        case["event_count"] = count_case_events(case["case_id"])
        case["artifact_types"] = list_artifact_types(case["case_id"])
        result.append(case)
    return {"cases": result, "total": len(result)}


@router.post("/cases", status_code=201)
def create_case(body: CaseCreate):
    """Create a new case."""
    case = case_svc.create_case(body.name, body.description, body.analyst)
    return case


@router.get("/cases/{case_id}")
def get_case(case_id: str):
    """Get a single case with index summary."""
    case = case_svc.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case["event_count"] = count_case_events(case_id)
    case["artifact_types"] = list_artifact_types(case_id)
    return case


@router.put("/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate):
    """Update case metadata."""
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    case = case_svc.update_case(case_id, **updates)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.delete("/cases/{case_id}", status_code=204)
def delete_case(case_id: str, background: bool = True):
    """
    Delete a case and all its data.
    
    By default, returns immediately (204) and deletes large data (MinIO, Elasticsearch)
    in the background. This prevents timeouts for large cases with GBs of data.
    
    Set ?background=false to wait for all deletions to complete (not recommended for large cases).
    """
    if not case_svc.delete_case(case_id, background=background):
        raise HTTPException(status_code=404, detail="Case not found")
