"""Search and timeline endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List

from services import elasticsearch as es
from services.cases import get_case
from config import settings

router = APIRouter(tags=["search"])


@router.get("/cases/{case_id}/timeline")
def get_timeline(
    case_id: str,
    artifact_type: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    sort_field: str = "timestamp",
    sort_order: str = "asc",
    page: int = 0,
    size: int = Query(100, le=1000),
):
    """
    Paginated cross-artifact timeline for a case.
    Use artifact_type to filter to a specific index (e.g. evtx, prefetch).
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    result = es.search_events(
        case_id=case_id,
        artifact_type=artifact_type,
        from_ts=from_ts,
        to_ts=to_ts,
        page=page,
        size=size,
        sort_field=sort_field,
        sort_order=sort_order,
    )

    hits = result.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    events = [h["_source"] for h in hits.get("hits", [])]

    return {
        "case_id": case_id,
        "total": total,
        "page": page,
        "size": size,
        "artifact_type": artifact_type,
        "events": events,
    }


@router.get("/cases/{case_id}/search")
def search(
    case_id: str,
    q: str = "",
    artifact_type: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    hostname: Optional[str] = None,
    username: Optional[str] = None,
    event_id: Optional[int] = None,
    channel: Optional[str] = None,
    flagged: Optional[bool] = None,
    tags: Optional[List[str]] = Query(None),
    regexp: bool = False,
    sort_field: str = "timestamp",
    sort_order: str = "asc",
    page: int = 0,
    size: int = Query(50, le=1000),
):
    """Full-text + field-level search within a case."""
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    extra_filters = []
    if hostname:
        extra_filters.append({"term": {"host.hostname.keyword": hostname}})
    if username:
        extra_filters.append({"term": {"user.name.keyword": username}})
    if event_id is not None:
        extra_filters.append({"term": {"evtx.event_id": event_id}})
    if channel:
        extra_filters.append({"term": {"evtx.channel.keyword": channel}})
    if flagged is not None:
        extra_filters.append({"term": {"is_flagged": flagged}})
    if tags:
        extra_filters.append({"terms": {"tags": tags}})

    result = es.search_events(
        case_id=case_id,
        query=q,
        artifact_type=artifact_type,
        from_ts=from_ts,
        to_ts=to_ts,
        extra_filters=extra_filters,
        page=page,
        size=size,
        regexp=regexp,
        sort_field=sort_field,
        sort_order=sort_order,
    )

    hits = result.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    events = [{"_id": h["_id"], "_index": h["_index"], **h["_source"]}
              for h in hits.get("hits", [])]

    return {
        "case_id": case_id,
        "query": q,
        "total": total,
        "page": page,
        "size": size,
        "events": events,
    }


@router.get("/cases/{case_id}/search/facets")
def get_facets(
    case_id: str,
    q: str = "",
    artifact_type: Optional[str] = None,
):
    """Aggregation facets for the search filter panel."""
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    aggs = es.get_search_facets(case_id, query=q, artifact_type=artifact_type)
    return {"case_id": case_id, "facets": aggs}


@router.get("/cases/{case_id}/events/{fo_id}")
def get_event(case_id: str, fo_id: str):
    """Fetch a single event by ID (full document including raw)."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


class TagUpdate(BaseModel):
    tags: List[str]


class NoteUpdate(BaseModel):
    note: str


@router.put("/cases/{case_id}/events/{fo_id}/tag")
def tag_event(case_id: str, fo_id: str, body: TagUpdate):
    """Set tags on an event."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    index = event.get("_index", f"fo-case-{case_id}-generic")
    doc_id = event.get("_id", fo_id)
    success = es.update_event(case_id, index, doc_id, {"tags": body.tags})
    if not success:
        raise HTTPException(status_code=500, detail="Update failed")
    return {"fo_id": fo_id, "tags": body.tags}


@router.put("/cases/{case_id}/events/{fo_id}/flag")
def flag_event(case_id: str, fo_id: str):
    """Toggle the is_flagged field on an event."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    new_flag = not event.get("is_flagged", False)
    index = event.get("_index", f"fo-case-{case_id}-generic")
    doc_id = event.get("_id", fo_id)
    es.update_event(case_id, index, doc_id, {"is_flagged": new_flag})
    return {"fo_id": fo_id, "is_flagged": new_flag}


@router.put("/cases/{case_id}/events/{fo_id}/note")
def note_event(case_id: str, fo_id: str, body: NoteUpdate):
    """Set an analyst note on an event."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    index = event.get("_index", f"fo-case-{case_id}-generic")
    doc_id = event.get("_id", fo_id)
    es.update_event(case_id, index, doc_id, {"analyst_note": body.note})
    return {"fo_id": fo_id, "analyst_note": body.note}
