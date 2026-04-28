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


@router.get("/cases/{case_id}/iocs")
def get_iocs(case_id: str, size: int = Query(50, le=200)):
    """
    Return the top observed values for IOC-relevant fields across the whole case.
    Each category is an aggregation bucket list: [{value, count}].
    """
    from services.elasticsearch import _request as es_req
    import urllib.error

    index = f"fo-case-{case_id}-*"
    body = {
        "size": 0,
        "aggs": {
            "src_ips":      {"terms": {"field": "network.src_ip.keyword",    "size": size}},
            "dst_ips":      {"terms": {"field": "network.dst_ip.keyword",    "size": size}},
            "hostnames":    {"terms": {"field": "host.hostname.keyword",     "size": size}},
            "usernames":    {"terms": {"field": "user.name.keyword",         "size": size}},
            "processes":    {"terms": {"field": "process.name.keyword",      "size": size}},
            "domains":      {"terms": {"field": "network.dst_domain.keyword","size": size}},
            "urls":         {"terms": {"field": "http.request_path.keyword", "size": size}},
            "user_agents":  {"terms": {"field": "http.user_agent.keyword",   "size": size}},
            "cmdlines":     {"terms": {"field": "process.cmdline.keyword",   "size": size}},
            "hashes_md5":   {"terms": {"field": "process.hash_md5.keyword",  "size": size}},
            "hashes_sha256":{"terms": {"field": "process.hash_sha256.keyword","size": size}},
            "reg_keys":     {"terms": {"field": "registry.key.keyword",      "size": size}},
        },
    }
    try:
        result = es_req("POST", f"/{index}/_search", body)
        aggs = result.get("aggregations", {})

        def buckets(key):
            return [
                {"value": b["key"], "count": b["doc_count"]}
                for b in aggs.get(key, {}).get("buckets", [])
                if b["key"]
            ]

        return {
            "src_ips":       buckets("src_ips"),
            "dst_ips":       buckets("dst_ips"),
            "hostnames":     buckets("hostnames"),
            "usernames":     buckets("usernames"),
            "processes":     buckets("processes"),
            "domains":       buckets("domains"),
            "urls":          buckets("urls"),
            "user_agents":   buckets("user_agents"),
            "cmdlines":      buckets("cmdlines"),
            "hashes_md5":    buckets("hashes_md5"),
            "hashes_sha256": buckets("hashes_sha256"),
            "reg_keys":      buckets("reg_keys"),
        }
    except (urllib.error.HTTPError, Exception):
        return {k: [] for k in ["src_ips","dst_ips","hostnames","usernames","processes",
                                 "domains","urls","user_agents","cmdlines",
                                 "hashes_md5","hashes_sha256","reg_keys"]}


@router.get("/whois/{ip}")
def whois_lookup(ip: str):
    """RDAP/WHOIS lookup for an IP address via rdap.org."""
    import ipaddress as _ipaddr
    import json as _json
    import urllib.request as _req
    import urllib.error as _err

    try:
        addr = _ipaddr.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        kind = (
            "Loopback"    if addr.is_loopback    else
            "Link-local"  if addr.is_link_local  else
            "Multicast"   if addr.is_multicast   else
            "Reserved"    if addr.is_reserved    else
            "Private"
        )
        return {
            "ip": ip,
            "org": f"{kind} / RFC-reserved",
            "country": "—",
            "cidr": "—",
            "handle": "—",
            "description": "Private, loopback, link-local, or reserved address space.",
        }

    url = f"https://rdap.org/ip/{ip}"
    try:
        request = _req.Request(url, headers={"Accept": "application/rdap+json, application/json"})
        with _req.urlopen(request, timeout=8) as resp:
            data = _json.loads(resp.read())
    except _err.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"RDAP lookup failed: HTTP {exc.code}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"RDAP lookup: {exc}")

    # CIDR from start/end address range
    cidr = ""
    start_addr = data.get("startAddress", "")
    end_addr   = data.get("endAddress",   "")
    if start_addr and end_addr:
        try:
            nets = list(_ipaddr.summarize_address_range(
                _ipaddr.ip_address(start_addr),
                _ipaddr.ip_address(end_addr),
            ))
            cidr = ", ".join(str(n) for n in nets[:4])
        except Exception:
            cidr = f"{start_addr} – {end_addr}"

    # Org name from registrant/administrative vCard
    org = data.get("name", "")
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if not any(r in roles for r in ("registrant", "administrative")):
            continue
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1:
            for prop in vcard[1]:
                if isinstance(prop, list) and prop and prop[0] == "fn":
                    fn = prop[3] if len(prop) > 3 else ""
                    if fn:
                        org = fn
                        break

    # First remark description
    description = ""
    for remark in data.get("remarks", []):
        if isinstance(remark, dict):
            desc_list = remark.get("description", [])
            if isinstance(desc_list, list) and desc_list:
                description = desc_list[0]
                break

    return {
        "ip":          ip,
        "org":         org,
        "country":     data.get("country", "—"),
        "cidr":        cidr or data.get("handle", "—"),
        "handle":      data.get("handle", "—"),
        "description": description,
    }
