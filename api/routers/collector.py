"""Collector script download endpoint.

GET /collector/download
  Query params:
    platform  : "py" | "win" | "linux"   (default: py)
    case_id   : str  (optional — embedded in the script)
    api_url   : str  (optional — embedded in the script)
    collect   : str  (optional — comma-separated artifact types, e.g. "evtx,registry")

GET /network/interfaces
  Returns candidate API URLs derived from the server's network interfaces so the
  frontend can offer "Detect IPs" suggestions in the collector config step.

Returns the configured collect.py script as a file download with EMBEDDED_CONFIG
injected so it works out-of-the-box on the target system.
"""
from __future__ import annotations

import os
import re
import socket
import logging
import subprocess
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


# ── Network interface discovery ───────────────────────────────────────────────

def _detect_outbound_ip() -> Optional[str]:
    """Return the primary outbound IPv4 address (no packet sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _detect_gateway_ip() -> Optional[str]:
    """On Linux containers, the default gateway is usually the host machine."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True, timeout=3,
        )
        # "default via 172.17.0.1 dev eth0 ..."
        parts = out.split()
        via_idx = parts.index("via") if "via" in parts else -1
        if via_idx >= 0 and via_idx + 1 < len(parts):
            return parts[via_idx + 1]
    except Exception:
        pass
    return None


@router.get("/network/interfaces")
def get_network_interfaces():
    """
    Return candidate API endpoint URLs for use in the collector config wizard.
    Priority: FO_PUBLIC_URL env var → host gateway → outbound IP.
    The frontend presents these as one-click suggestions in the 'Detect IPs' step.
    """
    api_port = os.getenv("FO_PUBLIC_PORT", "8000")
    candidates: list[dict] = []
    seen_ips: set[str] = set()

    def _add(ip: str, label: str, iface: str = "") -> None:
        if ip and ip not in seen_ips and not ip.startswith("127."):
            seen_ips.add(ip)
            candidates.append({
                "ip":    ip,
                "url":   f"http://{ip}:{api_port}/api/v1",
                "label": label,
                "iface": iface,
            })

    # 1. Explicit public URL configured by operator
    public_url = os.getenv("FO_PUBLIC_URL", "").strip().rstrip("/")
    if public_url:
        # Extract just the host portion if it's a full URL
        try:
            host = public_url.split("//")[-1].split("/")[0].split(":")[0]
            candidates.append({
                "ip":    host,
                "url":   public_url if "/api/v1" in public_url else f"{public_url}/api/v1",
                "label": "configured",
                "iface": "FO_PUBLIC_URL",
            })
            seen_ips.add(host)
        except Exception:
            pass

    # 2. Docker host (default gateway — usually the bare-metal / VM running Docker)
    gw = _detect_gateway_ip()
    _add(gw, "docker host", "gateway")

    # 3. Container's own outbound IP
    outbound = _detect_outbound_ip()
    _add(outbound, "this container", "outbound")

    # 4. Hostname resolution
    try:
        hostname = socket.gethostname()
        host_ip  = socket.gethostbyname(hostname)
        _add(host_ip, "hostname", hostname)
    except Exception:
        pass

    return {"candidates": candidates, "port": int(api_port)}
