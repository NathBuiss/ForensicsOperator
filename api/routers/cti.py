"""
Cyber Threat Intelligence (CTI) Integration.

Manages STIX/TAXII feed subscriptions, manual STIX bundle imports, and IOC
matching against case data. Supports STIX 2.1 indicators (hashes, IPs, domains,
URLs, email addresses, file names).

IOCs are stored in Redis and automatically matched when alert rules or modules run.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import redis as redis_lib
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import settings
from services.elasticsearch import _request as es_req

logger = logging.getLogger(__name__)
router = APIRouter(tags=["cti"])

# ── Redis key layout ─────────────────────────────────────────────────────────
# fo:cti:feeds                → JSON list of feed configs
# fo:cti:iocs:type:{type}     → Redis SET of JSON IOC objects per type
# fo:cti:iocs:hash:{value}    → indicator detail for fast hash lookups
# fo:cti:iocs:detail:{id}     → full indicator JSON by indicator ID

FEEDS_KEY     = "fo:cti:feeds"
IOC_TYPE_KEY  = "fo:cti:iocs:type:{type}"   # .format(type=...)
IOC_HASH_KEY  = "fo:cti:iocs:hash:{value}"  # .format(value=...)
IOC_DETAIL_KEY = "fo:cti:iocs:detail:{id}"  # .format(id=...)

IOC_TYPES = ("hash", "ip", "domain", "url", "email", "filename")


def _redis() -> redis_lib.Redis:
    return redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


# ── Pydantic models ──────────────────────────────────────────────────────────

class FeedCreate(BaseModel):
    name: str
    type: str  # "taxii" | "stix_url" | "manual"
    url: str = ""
    api_key: str = ""
    collection: str = ""
    poll_interval_hours: int = 24


class FeedUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    api_key: Optional[str] = None
    collection: Optional[str] = None
    poll_interval_hours: Optional[int] = None
    enabled: Optional[bool] = None


class BundleImport(BaseModel):
    bundle: dict


# ── Feed helpers ─────────────────────────────────────────────────────────────

def _load_feeds(r: redis_lib.Redis) -> list[dict]:
    raw = r.get(FEEDS_KEY)
    return json.loads(raw) if raw else []


def _save_feeds(r: redis_lib.Redis, feeds: list[dict]) -> None:
    r.set(FEEDS_KEY, json.dumps(feeds))


def _find_feed(feeds: list[dict], feed_id: str) -> dict | None:
    return next((f for f in feeds if f["id"] == feed_id), None)


# ── STIX pattern parser ─────────────────────────────────────────────────────

# Regex patterns for common STIX 2.1 indicator patterns
_STIX_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("hash",     re.compile(r"\[file:hashes\.\w+\s*=\s*'([^']+)'\]",       re.IGNORECASE)),
    ("hash",     re.compile(r"\[file:hashes\.'[^']+'\s*=\s*'([^']+)'\]",   re.IGNORECASE)),
    ("ip",       re.compile(r"\[ipv[46]-addr:value\s*=\s*'([^']+)'\]",     re.IGNORECASE)),
    ("domain",   re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]",      re.IGNORECASE)),
    ("url",      re.compile(r"\[url:value\s*=\s*'([^']+)'\]",              re.IGNORECASE)),
    ("email",    re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]",       re.IGNORECASE)),
    ("filename", re.compile(r"\[file:name\s*=\s*'([^']+)'\]",              re.IGNORECASE)),
]


def _parse_stix_pattern(pattern: str) -> list[tuple[str, str]]:
    """
    Extract (ioc_type, value) pairs from a STIX indicator pattern string.

    Uses simple regex matching rather than a full STIX pattern evaluator.
    Returns an empty list if no known pattern is matched.
    """
    results: list[tuple[str, str]] = []
    for ioc_type, regex in _STIX_PATTERNS:
        for match in regex.finditer(pattern):
            value = match.group(1).strip()
            if value:
                results.append((ioc_type, value))
    return results


# ── IOC storage helpers ──────────────────────────────────────────────────────

def _store_ioc(
    r: redis_lib.Redis,
    ioc_type: str,
    value: str,
    indicator_id: str = "",
    feed_id: str = "",
    feed_name: str = "",
    indicator_name: str = "",
    created: str = "",
) -> None:
    """Store a single IOC in Redis."""
    ioc_obj = {
        "type":           ioc_type,
        "value":          value.lower() if ioc_type != "url" else value,
        "indicator_id":   indicator_id,
        "feed_id":        feed_id,
        "feed_name":      feed_name,
        "indicator_name": indicator_name,
        "created":        created or datetime.now(timezone.utc).isoformat(),
    }
    ioc_json = json.dumps(ioc_obj, sort_keys=True)

    # Add to the type-specific set
    type_key = IOC_TYPE_KEY.format(type=ioc_type)
    r.sadd(type_key, ioc_json)

    # Fast lookup keys for hashes
    if ioc_type == "hash":
        hash_key = IOC_HASH_KEY.format(value=value.lower())
        r.set(hash_key, ioc_json)

    # Store detail by indicator ID
    if indicator_id:
        detail_key = IOC_DETAIL_KEY.format(id=indicator_id)
        r.set(detail_key, ioc_json)


def _process_stix_bundle(
    r: redis_lib.Redis,
    bundle: dict,
    feed_id: str = "",
    feed_name: str = "",
) -> int:
    """
    Parse a STIX 2.1 bundle, extract indicators, and store IOCs.
    Returns the number of IOCs stored.
    """
    objects = bundle.get("objects", [])
    count = 0

    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        indicator_id = obj.get("id", "")
        indicator_name = obj.get("name", "")
        created = obj.get("created", "")

        extracted = _parse_stix_pattern(pattern)
        for ioc_type, value in extracted:
            _store_ioc(
                r,
                ioc_type=ioc_type,
                value=value,
                indicator_id=indicator_id,
                feed_id=feed_id,
                feed_name=feed_name,
                indicator_name=indicator_name,
                created=created,
            )
            count += 1

    return count


def _count_feed_iocs(r: redis_lib.Redis, feed_id: str) -> int:
    """Count total IOCs belonging to a specific feed across all type sets."""
    total = 0
    for ioc_type in IOC_TYPES:
        type_key = IOC_TYPE_KEY.format(type=ioc_type)
        members = r.smembers(type_key)
        for m in members:
            try:
                obj = json.loads(m)
                if obj.get("feed_id") == feed_id:
                    total += 1
            except (json.JSONDecodeError, TypeError):
                pass
    return total


def _remove_feed_iocs(r: redis_lib.Redis, feed_id: str) -> int:
    """Remove all IOCs belonging to a specific feed. Returns count removed."""
    removed = 0
    for ioc_type in IOC_TYPES:
        type_key = IOC_TYPE_KEY.format(type=ioc_type)
        members = r.smembers(type_key)
        to_remove = []
        for m in members:
            try:
                obj = json.loads(m)
                if obj.get("feed_id") == feed_id:
                    to_remove.append(m)
                    # Clean up detail/hash keys
                    if obj.get("indicator_id"):
                        r.delete(IOC_DETAIL_KEY.format(id=obj["indicator_id"]))
                    if ioc_type == "hash":
                        r.delete(IOC_HASH_KEY.format(value=obj["value"]))
            except (json.JSONDecodeError, TypeError):
                pass
        if to_remove:
            r.srem(type_key, *to_remove)
            removed += len(to_remove)
    return removed


# ── TAXII 2.1 client helpers ────────────────────────────────────────────────

def _taxii_fetch(feed: dict) -> dict:
    """
    Fetch STIX objects from a TAXII 2.1 collection endpoint.

    Implements the minimum viable TAXII 2.1 client:
      GET {url}/collections/{collection}/objects/
      Accept: application/taxii+json;version=2.1

    Returns a STIX bundle dict.
    """
    import urllib.request
    import urllib.error

    base_url = feed["url"].rstrip("/")
    collection = feed.get("collection", "")

    if collection:
        objects_url = f"{base_url}/collections/{collection}/objects/"
    else:
        objects_url = f"{base_url}/objects/"

    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }
    if feed.get("api_key"):
        headers["Authorization"] = f"Bearer {feed['api_key']}"

    req = urllib.request.Request(objects_url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
            # TAXII 2.1 envelope has "objects" at top level
            if "objects" in data:
                return {"type": "bundle", "objects": data["objects"]}
            return data
    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"TAXII server returned HTTP {exc.code}: {exc.reason}",
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"TAXII fetch failed: {exc}")


def _stix_url_fetch(feed: dict) -> dict:
    """
    Fetch a STIX bundle JSON from a plain URL.
    """
    import urllib.request
    import urllib.error

    url = feed["url"]
    headers: dict[str, str] = {"Accept": "application/json"}
    if feed.get("api_key"):
        headers["Authorization"] = f"Bearer {feed['api_key']}"

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"STIX URL returned HTTP {exc.code}: {exc.reason}",
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"STIX URL fetch failed: {exc}")


# ── Feed endpoints ───────────────────────────────────────────────────────────

@router.get("/cti/feeds")
def list_feeds():
    """List all configured CTI feeds."""
    r = _redis()
    feeds = _load_feeds(r)
    return {"feeds": feeds}


@router.post("/cti/feeds", status_code=201)
def add_feed(body: FeedCreate):
    """Add a new CTI feed configuration."""
    if body.type not in ("taxii", "stix_url", "manual"):
        raise HTTPException(
            status_code=422,
            detail="Feed type must be 'taxii', 'stix_url', or 'manual'.",
        )
    if body.type != "manual" and not body.url:
        raise HTTPException(status_code=422, detail="URL is required for non-manual feeds.")

    r = _redis()
    feeds = _load_feeds(r)
    feed = {
        "id":                  str(uuid.uuid4())[:8],
        "name":                body.name,
        "type":                body.type,
        "url":                 body.url,
        "api_key":             body.api_key,
        "collection":          body.collection,
        "poll_interval_hours": body.poll_interval_hours,
        "enabled":             True,
        "last_pull":           None,
        "ioc_count":           0,
        "created_at":          datetime.now(timezone.utc).isoformat(),
    }
    feeds.append(feed)
    _save_feeds(r, feeds)
    return feed


@router.put("/cti/feeds/{feed_id}")
def update_feed(feed_id: str, body: FeedUpdate):
    """Update an existing feed configuration."""
    r = _redis()
    feeds = _load_feeds(r)
    feed = _find_feed(feeds, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    patch = body.dict(exclude_none=True)
    feed.update(patch)
    _save_feeds(r, feeds)
    return feed


@router.delete("/cti/feeds/{feed_id}", status_code=204)
def delete_feed(feed_id: str):
    """Remove a feed and all its IOCs."""
    r = _redis()
    feeds = _load_feeds(r)
    feed = _find_feed(feeds, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    # Remove IOCs belonging to this feed
    _remove_feed_iocs(r, feed_id)

    # Remove feed from list
    feeds = [f for f in feeds if f["id"] != feed_id]
    _save_feeds(r, feeds)


@router.post("/cti/feeds/{feed_id}/pull")
def pull_feed(feed_id: str):
    """Manually pull IOCs from a feed now."""
    r = _redis()
    feeds = _load_feeds(r)
    feed = _find_feed(feeds, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed_type = feed["type"]

    if feed_type == "manual":
        raise HTTPException(
            status_code=400,
            detail="Manual feeds do not support auto-pull. Use POST /cti/import instead.",
        )

    # Fetch STIX bundle from source
    if feed_type == "taxii":
        bundle = _taxii_fetch(feed)
    elif feed_type == "stix_url":
        bundle = _stix_url_fetch(feed)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown feed type: {feed_type}")

    # Remove old IOCs from this feed before re-importing
    _remove_feed_iocs(r, feed_id)

    # Process bundle
    count = _process_stix_bundle(r, bundle, feed_id=feed_id, feed_name=feed["name"])

    # Update feed metadata
    feed["last_pull"] = datetime.now(timezone.utc).isoformat()
    feed["ioc_count"] = count
    _save_feeds(r, feeds)

    return {"feed_id": feed_id, "iocs_imported": count, "last_pull": feed["last_pull"]}


# ── Direct STIX import ──────────────────────────────────────────────────────

@router.post("/cti/import")
def import_bundle(body: BundleImport):
    """
    Import a STIX 2.1 bundle JSON directly.

    Parses indicator objects, extracts patterns (hash, ip, domain, url,
    email, filename), and stores each IOC in Redis with source metadata.
    """
    bundle = body.bundle
    if not isinstance(bundle, dict):
        raise HTTPException(status_code=422, detail="Bundle must be a JSON object.")

    r = _redis()
    count = _process_stix_bundle(r, bundle, feed_id="manual", feed_name="Manual Import")
    return {"iocs_imported": count}


# ── IOC endpoints ────────────────────────────────────────────────────────────

@router.get("/cti/iocs")
def list_iocs(
    type: Optional[str] = Query(None, description="Filter by IOC type"),
    q: Optional[str] = Query(None, description="Search IOC values"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
):
    """List all IOCs with optional filtering and pagination."""
    r = _redis()
    types_to_scan = [type] if type and type in IOC_TYPES else list(IOC_TYPES)

    all_iocs: list[dict] = []
    for ioc_type in types_to_scan:
        type_key = IOC_TYPE_KEY.format(type=ioc_type)
        members = r.smembers(type_key)
        for m in members:
            try:
                obj = json.loads(m)
                if q and q.lower() not in obj.get("value", "").lower():
                    continue
                all_iocs.append(obj)
            except (json.JSONDecodeError, TypeError):
                pass

    # Sort by created desc
    all_iocs.sort(key=lambda x: x.get("created", ""), reverse=True)

    total = len(all_iocs)
    start = (page - 1) * size
    end = start + size
    page_iocs = all_iocs[start:end]

    return {
        "iocs":  page_iocs,
        "total": total,
        "page":  page,
        "size":  size,
        "pages": (total + size - 1) // size if total > 0 else 0,
    }


@router.get("/cti/iocs/stats")
def ioc_stats():
    """Count IOCs by type."""
    r = _redis()
    stats: dict[str, int] = {}
    total = 0
    for ioc_type in IOC_TYPES:
        type_key = IOC_TYPE_KEY.format(type=ioc_type)
        count = r.scard(type_key)
        stats[ioc_type] = count
        total += count
    stats["total"] = total
    return stats


@router.delete("/cti/iocs", status_code=204)
def clear_iocs():
    """Clear all IOCs from the database."""
    r = _redis()
    # Remove all type sets
    for ioc_type in IOC_TYPES:
        type_key = IOC_TYPE_KEY.format(type=ioc_type)
        members = r.smembers(type_key)
        # Clean up detail/hash keys
        for m in members:
            try:
                obj = json.loads(m)
                if obj.get("indicator_id"):
                    r.delete(IOC_DETAIL_KEY.format(id=obj["indicator_id"]))
                if obj.get("type") == "hash":
                    r.delete(IOC_HASH_KEY.format(value=obj["value"]))
            except (json.JSONDecodeError, TypeError):
                pass
        r.delete(type_key)

    # Reset IOC counts on all feeds
    feeds = _load_feeds(r)
    for feed in feeds:
        feed["ioc_count"] = 0
    _save_feeds(r, feeds)


# ── Case IOC matching ────────────────────────────────────────────────────────

# Fields to check against each IOC type when scanning case events
_MATCH_FIELDS: dict[str, list[str]] = {
    "hash":     ["process.hash.md5", "process.hash.sha1", "process.hash.sha256",
                 "file.hash.md5", "file.hash.sha1", "file.hash.sha256", "message"],
    "ip":       ["network.src_ip", "network.dst_ip", "network.dest_ip",
                 "source.ip", "destination.ip", "message"],
    "domain":   ["dns.question.name", "url.domain", "host.hostname", "message"],
    "url":      ["url.full", "url.original", "message"],
    "email":    ["email.from.address", "email.to.address", "user.email", "message"],
    "filename": ["file.name", "process.executable", "process.name", "message"],
}

# Size of ES scroll batches when scanning events
_MATCH_BATCH_SIZE = 500


def _get_nested(doc: dict, dotted_key: str) -> Any:
    """Safely traverse a nested dict by dotted key path."""
    parts = dotted_key.split(".")
    current: Any = doc
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


@router.post("/cases/{case_id}/cti/match")
def match_case_iocs(case_id: str):
    """
    Scan all events in a case against the IOC database.

    Queries Elasticsearch for all events in the case, then checks relevant
    fields against loaded IOCs. Returns a list of matches.
    """
    r = _redis()

    # Load all IOCs into memory grouped by type
    ioc_sets: dict[str, dict[str, dict]] = {}  # type -> {value_lower: ioc_obj}
    for ioc_type in IOC_TYPES:
        type_key = IOC_TYPE_KEY.format(type=ioc_type)
        members = r.smembers(type_key)
        lookup: dict[str, dict] = {}
        for m in members:
            try:
                obj = json.loads(m)
                val = obj.get("value", "").lower()
                if val:
                    lookup[val] = obj
            except (json.JSONDecodeError, TypeError):
                pass
        if lookup:
            ioc_sets[ioc_type] = lookup

    if not ioc_sets:
        return {"matches": [], "events_scanned": 0, "message": "No IOCs loaded"}

    # Scan ES events in batches using search_after
    index = f"fo-case-{case_id}-*"
    matches: list[dict] = []
    events_scanned = 0
    search_after: list | None = None

    while True:
        body: dict[str, Any] = {
            "query": {"match_all": {}},
            "size": _MATCH_BATCH_SIZE,
            "sort": [{"_doc": "asc"}],
            "_source": True,
        }
        if search_after:
            body["search_after"] = search_after

        try:
            resp = es_req("POST", f"/{index}/_search", body)
        except Exception as exc:
            logger.error("ES query failed during CTI match for case %s: %s", case_id, exc)
            break

        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break

        for hit in hits:
            source = hit.get("_source", {})
            event_fo_id = source.get("fo_id", hit.get("_id", ""))
            events_scanned += 1

            # Check each IOC type against relevant fields
            for ioc_type, lookup in ioc_sets.items():
                fields = _MATCH_FIELDS.get(ioc_type, ["message"])
                for field in fields:
                    field_value = _get_nested(source, field)
                    if field_value is None:
                        continue

                    field_str = str(field_value).lower()

                    # For each IOC value, check if it appears in the field
                    for ioc_value, ioc_obj in lookup.items():
                        if ioc_value in field_str:
                            matches.append({
                                "event_fo_id":  event_fo_id,
                                "ioc_type":     ioc_type,
                                "ioc_value":    ioc_obj.get("value", ioc_value),
                                "indicator_id": ioc_obj.get("indicator_id", ""),
                                "feed_name":    ioc_obj.get("feed_name", ""),
                                "matched_field": field,
                            })

        # Prepare next batch
        search_after = hits[-1].get("sort")
        if not search_after:
            break

    return {
        "matches":        matches,
        "events_scanned": events_scanned,
        "iocs_checked":   sum(len(v) for v in ioc_sets.values()),
    }
