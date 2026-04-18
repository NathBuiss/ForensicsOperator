"""Elasticsearch service — index management and querying."""
from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

ES_URL = settings.ELASTICSEARCH_URL

INDEX_TEMPLATE = {
    "index_patterns": ["fo-case-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s",
            "index.mapping.total_fields.limit": 2000,
            "codec": "best_compression",
        },
        "mappings": {
            "dynamic": "true",
            "properties": {
                "fo_id":          {"type": "keyword"},
                "case_id":        {"type": "keyword"},
                "artifact_type":  {"type": "keyword"},
                "source_file":    {"type": "keyword", "index": False},
                "ingest_job_id":  {"type": "keyword"},
                "ingested_at":    {"type": "date"},
                "timestamp":      {"type": "date"},
                "timestamp_desc": {"type": "keyword"},
                "message":        {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
                },
                "tags":           {"type": "keyword"},
                "analyst_note":   {"type": "text"},
                "is_flagged":     {"type": "boolean"},
                "host":           {"type": "object", "dynamic": True},
                "user":           {"type": "object", "dynamic": True},
                "process":        {"type": "object", "dynamic": True},
                "network":        {"type": "object", "dynamic": True},
                "mitre":          {"type": "object", "dynamic": True},
                "evtx":           {"type": "object", "dynamic": True},
                "prefetch":       {"type": "object", "dynamic": True},
                "mft":            {"type": "object", "dynamic": True},
                "registry":       {"type": "object", "dynamic": True},
                "lnk":            {"type": "object", "dynamic": True},
                "plaso":          {"type": "object", "dynamic": True},
                "raw":            {"type": "object", "enabled": False},
            },
        },
    },
    "priority": 100,
    "composed_of": [],
}


def _request(method: str, path: str, body: dict | None = None) -> dict:
    url = f"{ES_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def apply_index_template() -> None:
    """Apply the shared index template for all fo-case-* indices."""
    try:
        _request("PUT", "/_index_template/fo-cases-template", INDEX_TEMPLATE)
        logger.info("Applied fo-cases-template")
    except Exception as exc:
        logger.warning("Could not apply index template: %s", exc)


def list_case_indices(case_id: str) -> list[str]:
    """Return all Elasticsearch indices for a given case."""
    try:
        result = _request("GET", f"/_cat/indices/fo-case-{case_id}-*?format=json")
        return [idx["index"] for idx in result]
    except Exception:
        return []


def list_artifact_types(case_id: str) -> list[str]:
    """Return distinct artifact types present in the case."""
    indices = list_case_indices(case_id)
    prefix = f"fo-case-{case_id}-"
    return [idx[len(prefix):] for idx in indices if idx.startswith(prefix)]


def count_case_events(case_id: str) -> int:
    """Return total event count across all case indices."""
    try:
        result = _request("GET", f"/fo-case-{case_id}-*/_count")
        return result.get("count", 0)
    except Exception:
        return 0


_SEARCH_FIELDS = [
    "message", "host.hostname", "user.name",
    "process.name", "process.cmdline", "process.args",
]


def search_events(
    case_id: str,
    query: str = "",
    artifact_type: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
    extra_filters: list[dict] | None = None,
    page: int = 0,
    size: int = 100,
    sort_field: str = "timestamp",
    sort_order: str = "asc",
    regexp: bool = False,
) -> dict[str, Any]:
    """
    Search events in a case with full-text query and field filters.
    Returns ES hits response dict.
    """
    index = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"

    must_clauses: list[dict] = []
    filter_clauses: list[dict] = []

    if query:
        if regexp:
            # ES regexp on the unanalyzed full-text field — supports ., .*, [a-z], (a|b) but NOT \d \w \s
            must_clauses.append({"regexp": {"message.keyword": {"value": query, "case_insensitive": True, "flags": "ALL"}}})
        else:
            must_clauses.append({"query_string": {"query": query, "default_operator": "AND", "fields": _SEARCH_FIELDS}})

    if from_ts or to_ts:
        range_filter: dict = {"range": {"timestamp": {}}}
        if from_ts:
            range_filter["range"]["timestamp"]["gte"] = from_ts
        if to_ts:
            range_filter["range"]["timestamp"]["lte"] = to_ts
        filter_clauses.append(range_filter)

    if extra_filters:
        filter_clauses.extend(extra_filters)

    es_query: dict[str, Any] = {
        "bool": {
            "must": must_clauses or [{"match_all": {}}],
            "filter": filter_clauses,
        }
    }

    body = {
        "query": es_query,
        "from": page * size,
        "size": size,
        "sort": [{sort_field: {"order": sort_order}}, {"_doc": {"order": "asc"}}],
        "_source": {
            "excludes": ["raw"]
        },
    }

    try:
        result = _request("POST", f"/{index}/_search", body)
        return result
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 404):
            return {"hits": {"total": {"value": 0}, "hits": []}}
        raise


def get_search_facets(
    case_id: str,
    query: str = "",
    artifact_type: str | None = None,
) -> dict[str, Any]:
    """Return aggregation buckets for the facet panel."""
    index = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"

    must = [{"query_string": {"query": query, "fields": _SEARCH_FIELDS}}] if query else [{"match_all": {}}]

    body = {
        "query": {"bool": {"must": must}},
        "size": 0,
        "aggs": {
            "by_artifact_type": {"terms": {"field": "artifact_type", "size": 20}},
            "by_hostname":      {"terms": {"field": "host.hostname.keyword", "size": 20}},
            "by_username":      {"terms": {"field": "user.name.keyword", "size": 20}},
            "by_event_id":      {"terms": {"field": "evtx.event_id", "size": 30}},
            "by_channel":       {"terms": {"field": "evtx.channel.keyword", "size": 20}},
            "events_over_time": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "day",
                    "min_doc_count": 1,
                }
            },
        },
    }

    try:
        result = _request("POST", f"/{index}/_search", body)
        return result.get("aggregations", {})
    except Exception:
        return {}


def get_event_by_id(case_id: str, fo_id: str) -> dict | None:
    """Fetch a single event by its fo_id."""
    body = {
        "query": {"term": {"fo_id": fo_id}},
        "size": 1,
    }
    try:
        result = _request("POST", f"/fo-case-{case_id}-*/_search", body)
        hits = result.get("hits", {}).get("hits", [])
        if hits:
            return {"_id": hits[0]["_id"], "_index": hits[0]["_index"], **hits[0]["_source"]}
        return None
    except Exception:
        return None


def update_event(case_id: str, index: str, doc_id: str, partial: dict) -> bool:
    """Partially update an event document."""
    try:
        _request("POST", f"/{index}/_update/{doc_id}", {"doc": partial})
        return True
    except Exception:
        return False


def delete_case_indices(case_id: str) -> None:
    """Delete all indices for a case."""
    try:
        _request("DELETE", f"/fo-case-{case_id}-*")
        logger.info("Deleted all indices for case %s", case_id)
    except Exception as exc:
        logger.warning("Error deleting case %s indices: %s", case_id, exc)
