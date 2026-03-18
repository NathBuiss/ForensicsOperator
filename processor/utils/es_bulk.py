"""Elasticsearch bulk indexing helper."""
from __future__ import annotations

import json
import logging
from typing import Any

import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


def _index_name(case_id: str, artifact_type: str) -> str:
    return f"fo-case-{case_id}-{artifact_type}"


class ESBulkIndexer:
    def __init__(self, es_url: str) -> None:
        self.es_url = es_url.rstrip("/")

    def bulk_index(self, case_id: str, events: list[dict[str, Any]]) -> None:
        """Bulk index a list of events into the appropriate case indices."""
        if not events:
            return

        lines = []
        for event in events:
            artifact_type = event.get("artifact_type", "generic")
            index = _index_name(case_id, artifact_type)
            doc_id = event.get("fo_id", "")
            action = {"index": {"_index": index, "_id": doc_id}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(event))

        body = "\n".join(lines) + "\n"
        url = f"{self.es_url}/_bulk"

        req = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read())
                if result.get("errors"):
                    error_items = [
                        item for item in result.get("items", [])
                        if item.get("index", {}).get("error")
                    ]
                    logger.warning(
                        "Bulk indexing had %d errors (of %d total)",
                        len(error_items), len(events)
                    )
                    for item in error_items[:3]:
                        logger.debug("Bulk error: %s", item)
                else:
                    logger.debug("Bulk indexed %d events", len(events))
        except urllib.error.HTTPError as exc:
            body_str = exc.read().decode("utf-8", errors="replace")
            logger.error("ES bulk HTTP error %d: %s", exc.code, body_str[:500])
            raise
        except Exception as exc:
            logger.error("ES bulk failed: %s", exc)
            raise
