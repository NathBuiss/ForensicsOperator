"""Collector script download endpoint.

GET /collector/download
  Query params:
    platform  : "py" | "win" | "linux"   (default: py)
    case_id   : str  (optional — embedded in the script)
    api_url   : str  (optional — embedded in the script)
    collect   : str  (optional — comma-separated artifact types, e.g. "evtx,registry")

Returns the configured collect.py script as a file download with EMBEDDED_CONFIG
injected so it works out-of-the-box on the target system.
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

logger = logging.getLogger(__name__)
router = APIRouter(tags=["collector"])

# Resolved at import time — works both inside the Docker container and locally.
_SCRIPT_CANDIDATES = [
    Path("/app/static/collect.py"),          # Docker container path
    Path(__file__).parent.parent.parent / "collector" / "collect.py",  # local dev
]

_INJECT_PATTERN = re.compile(
    r"^EMBEDDED_CONFIG\s*:\s*dict\s*=\s*\{\}",
    re.MULTILINE,
)


def _find_collect_script() -> Path:
    for p in _SCRIPT_CANDIDATES:
        if p.exists():
            return p
    raise FileNotFoundError(
        "collect.py not found — checked: " + ", ".join(str(p) for p in _SCRIPT_CANDIDATES)
    )


def _inject_config(source: str, config: dict) -> str:
    """Replace the EMBEDDED_CONFIG placeholder with the actual config dict."""
    repr_str = repr(config)  # safe Python literal
    replacement = f"EMBEDDED_CONFIG: dict = {repr_str}"
    new_source, n = _INJECT_PATTERN.subn(replacement, source)
    if n == 0:
        logger.warning("EMBEDDED_CONFIG placeholder not found in collect.py — returning as-is")
    return new_source


@router.get("/collector/download")
def download_collector(
    platform: str = Query(default="py", description="py | win | linux"),
    case_id: Optional[str] = Query(default=None),
    api_url: Optional[str] = Query(default=None),
    collect: Optional[str] = Query(default=None, description="comma-separated artifact keys"),
):
    """Return a configured collect.py script as a file download."""
    platform = platform.lower()
    if platform not in ("py", "win", "linux"):
        raise HTTPException(status_code=400, detail="platform must be 'py', 'win', or 'linux'")

    try:
        script_path = _find_collect_script()
        source = script_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        logger.error("collect.py not found: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to read collect.py: %s", exc)
        raise HTTPException(status_code=500, detail="Could not load collector script")

    # Build embedded config — only include keys that were provided
    config: dict = {}
    if case_id:
        config["case_id"] = case_id
    if api_url:
        config["api_url"] = api_url.rstrip("/")
    if collect:
        config["collect"] = [k.strip() for k in collect.split(",") if k.strip()]

    configured_source = _inject_config(source, config)

    # Choose filename based on platform hint
    if platform == "win":
        filename = "fo-collector.py"
        media_type = "text/x-python"
    elif platform == "linux":
        filename = "fo-collector.py"
        media_type = "text/x-python"
    else:
        filename = "fo-collector.py"
        media_type = "text/x-python"

    return Response(
        content=configured_source.encode("utf-8"),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
