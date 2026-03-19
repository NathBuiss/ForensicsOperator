"""Collector script download endpoint + network/ingress helpers.

GET  /collector/download        — return configured collect.py
GET  /network/interfaces        — discover candidate upload URLs
POST /collector/ingress         — create a K8s LoadBalancer service for external access
GET  /collector/ingress         — query status / external IP of the LB service
"""
from __future__ import annotations

import json
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

# ── Script discovery ──────────────────────────────────────────────────────────
# Order matters: check Docker-mounted path first, then local dev fallback.

_SCRIPT_CANDIDATES = [
    Path("/app/collector/collect.py"),                        # docker-compose volume mount
    Path(__file__).parent.parent / "collector" / "collect.py",  # local: api/../collector/
    Path(__file__).parent.parent.parent / "collector" / "collect.py",  # mono-repo root
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
    repr_str   = repr(config)
    replacement = f"EMBEDDED_CONFIG: dict = {repr_str}"
    new_source, n = _INJECT_PATTERN.subn(replacement, source)
    if n == 0:
        logger.warning("EMBEDDED_CONFIG placeholder not found in collect.py")
    return new_source


# ── Download endpoint ─────────────────────────────────────────────────────────

@router.get("/collector/download")
def download_collector(
    platform: str = Query(default="py", description="py | win | linux"),
    case_id: Optional[str] = Query(default=None),
    api_url: Optional[str] = Query(default=None),
    collect: Optional[str] = Query(default=None),
):
    """Return a configured collect.py script as a file download."""
    platform = platform.lower()
    if platform not in ("py", "win", "linux"):
        raise HTTPException(status_code=400, detail="platform must be 'py', 'win', or 'linux'")

    try:
        source = _find_collect_script().read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        logger.error("collect.py not found: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to read collect.py: %s", exc)
        raise HTTPException(status_code=500, detail="Could not load collector script")

    config: dict = {}
    if case_id:
        config["case_id"] = case_id
    if api_url:
        config["api_url"] = api_url.rstrip("/")
    if collect:
        config["collect"] = [k.strip() for k in collect.split(",") if k.strip()]

    return Response(
        content=_inject_config(source, config).encode("utf-8"),
        media_type="text/x-python",
        headers={
            "Content-Disposition": 'attachment; filename="fo-collector.py"',
            "Cache-Control": "no-store",
        },
    )


# ── Network interface discovery ───────────────────────────────────────────────

_API_PORT = os.getenv("FO_PUBLIC_PORT", "8000")


def _parse_ip_addr() -> list[dict]:
    """Parse `ip addr show` to get all non-loopback IPv4 interface addresses."""
    results = []
    try:
        out = subprocess.check_output(["ip", "addr", "show"], text=True, timeout=5)
        iface = ""
        for line in out.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                # "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                iface = line.split(":")[1].strip().split("@")[0]
            elif line.startswith("inet ") and "127." not in line:
                # "inet 192.168.1.100/24 brd ..."
                ip = line.split()[1].split("/")[0]
                results.append({"ip": ip, "iface": iface})
    except Exception:
        pass
    return results


def _detect_gateway_ip() -> Optional[str]:
    """Default gateway = Docker host on bridge networks."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=3,
        )
        parts = out.split()
        idx = parts.index("via") if "via" in parts else -1
        if idx >= 0 and idx + 1 < len(parts):
            return parts[idx + 1]
    except Exception:
        pass
    return None


def _detect_outbound_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _is_kubernetes() -> bool:
    return os.path.isfile("/var/run/secrets/kubernetes.io/serviceaccount/token")


def _get_k8s_service_ips() -> list[dict]:
    """Query kubectl for LoadBalancer / NodePort services and return their IPs."""
    results = []
    try:
        out = subprocess.check_output(
            ["kubectl", "get", "svc", "--all-namespaces", "-o", "json"],
            text=True, timeout=8,
        )
        data = json.loads(out)
        for item in data.get("items", []):
            svc_name = item.get("metadata", {}).get("name", "")
            ns       = item.get("metadata", {}).get("namespace", "default")
            svc_type = item.get("spec", {}).get("type", "")
            # LoadBalancer external IPs
            for ing in item.get("status", {}).get("loadBalancer", {}).get("ingress", []):
                addr = ing.get("ip") or ing.get("hostname")
                if addr:
                    results.append({
                        "ip":    addr,
                        "iface": f"k8s/{ns}/{svc_name}",
                        "label": f"LoadBalancer ({svc_name})",
                        "k8s":   True,
                    })
            # NodePort — include cluster IP as candidate
            if svc_type == "NodePort":
                cluster_ip = item.get("spec", {}).get("clusterIP", "")
                if cluster_ip and cluster_ip != "None":
                    results.append({
                        "ip":    cluster_ip,
                        "iface": f"k8s/{ns}/{svc_name}",
                        "label": f"NodePort ({svc_name})",
                        "k8s":   True,
                    })
    except Exception:
        pass
    return results


@router.get("/network/interfaces")
def get_network_interfaces():
    """
    Return candidate API endpoint URLs ordered by usefulness.
    The frontend renders them as one-click chips in the collector config step.
    """
    candidates: list[dict] = []
    seen: set[str] = set()

    def _add(ip: str, label: str, iface: str = "", k8s: bool = False) -> None:
        if ip and ip not in seen and not ip.startswith("127."):
            seen.add(ip)
            candidates.append({
                "ip":    ip,
                "url":   f"http://{ip}:{_API_PORT}/api/v1",
                "label": label,
                "iface": iface,
                "k8s":   k8s,
            })

    # 1. Operator-configured public URL (highest priority)
    public_url = os.getenv("FO_PUBLIC_URL", "").strip().rstrip("/")
    if public_url:
        host = public_url.split("//")[-1].split("/")[0].split(":")[0]
        url  = public_url if "/api/v1" in public_url else f"{public_url}/api/v1"
        candidates.append({"ip": host, "url": url, "label": "configured", "iface": "FO_PUBLIC_URL", "k8s": False})
        seen.add(host)

    # 2. Kubernetes LoadBalancer / NodePort services
    if _is_kubernetes():
        for entry in _get_k8s_service_ips():
            _add(entry["ip"], entry["label"], entry["iface"], k8s=True)

    # 3. All non-loopback interface IPs (from ip addr)
    for entry in _parse_ip_addr():
        # Distinguish Docker bridge (172.x) from real LAN (192.168.x / 10.x)
        ip = entry["ip"]
        if ip.startswith("172."):
            label = "docker bridge"
        elif ip.startswith("10.") or ip.startswith("192.168."):
            label = "LAN"
        else:
            label = "interface"
        _add(ip, label, entry["iface"])

    # 4. Default gateway (Docker host on bridge networks)
    _add(_detect_gateway_ip(), "docker host", "gateway")

    # 5. Outbound IP (fallback)
    _add(_detect_outbound_ip(), "outbound", "socket")

    return {
        "candidates":  candidates,
        "port":        int(_API_PORT),
        "in_kubernetes": _is_kubernetes(),
    }


# ── Kubernetes LoadBalancer ingress management ────────────────────────────────

_LB_SVC_NAME      = os.getenv("FO_LB_SERVICE_NAME", "fo-collector-lb")
_LB_NAMESPACE     = os.getenv("FO_NAMESPACE", "default")
_LB_TARGET_PORT   = int(os.getenv("FO_API_PORT", "8000"))
_LB_APP_LABEL     = os.getenv("FO_APP_LABEL", "fo-api")

_LB_MANIFEST = {
    "apiVersion": "v1",
    "kind":       "Service",
    "metadata": {
        "name":      _LB_SVC_NAME,
        "namespace": _LB_NAMESPACE,
        "labels":    {"managed-by": "forensicsoperator"},
    },
    "spec": {
        "type":     "LoadBalancer",
        "selector": {"app": _LB_APP_LABEL},
        "ports":    [{"port": _LB_TARGET_PORT, "targetPort": _LB_TARGET_PORT, "protocol": "TCP"}],
    },
}


def _kubectl(*args: str, input_data: Optional[str] = None) -> tuple[int, str, str]:
    """Run a kubectl command, return (returncode, stdout, stderr)."""
    cmd = ["kubectl"] + list(args)
    try:
        r = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "kubectl not found"
    except subprocess.TimeoutExpired:
        return 1, "", "kubectl timed out"


@router.post("/collector/ingress", status_code=201)
def create_collector_ingress():
    """
    Create a Kubernetes LoadBalancer Service that exposes the API externally
    so remote collectors can upload artifacts.
    Requires: kubectl in PATH + RBAC permission to create Services.
    """
    if not _is_kubernetes():
        raise HTTPException(
            status_code=400,
            detail="Not running in Kubernetes — use the FO_PUBLIC_URL env var to set the external URL manually.",
        )
    manifest_json = json.dumps(_LB_MANIFEST)
    rc, out, err = _kubectl("apply", "-f", "-", input_data=manifest_json)
    if rc != 0:
        logger.error("kubectl apply failed: %s", err)
        raise HTTPException(status_code=500, detail=f"kubectl apply failed: {err.strip()}")

    # Immediately query status
    return _get_lb_status()


@router.get("/collector/ingress")
def get_collector_ingress():
    """Query the status and external IP of the collector LoadBalancer service."""
    if not _is_kubernetes():
        raise HTTPException(
            status_code=400,
            detail="Not running in Kubernetes.",
        )
    return _get_lb_status()


@router.delete("/collector/ingress", status_code=204)
def delete_collector_ingress():
    """Remove the collector LoadBalancer service."""
    if not _is_kubernetes():
        raise HTTPException(status_code=400, detail="Not running in Kubernetes.")
    rc, _, err = _kubectl(
        "delete", "svc", _LB_SVC_NAME, "-n", _LB_NAMESPACE, "--ignore-not-found",
    )
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"kubectl delete failed: {err.strip()}")


def _get_lb_status() -> dict:
    rc, out, err = _kubectl(
        "get", "svc", _LB_SVC_NAME,
        "-n", _LB_NAMESPACE,
        "-o", "json",
    )
    if rc != 0:
        return {"name": _LB_SVC_NAME, "status": "not_found", "external_ip": None, "external_url": None}

    try:
        svc   = json.loads(out)
        ingresses = svc.get("status", {}).get("loadBalancer", {}).get("ingress", [])
        ip    = ingresses[0].get("ip") if ingresses else None
        host  = ingresses[0].get("hostname") if ingresses else None
        addr  = ip or host
        return {
            "name":         _LB_SVC_NAME,
            "namespace":    _LB_NAMESPACE,
            "status":       "ready" if addr else "pending",
            "external_ip":  addr,
            "external_url": f"http://{addr}:{_LB_TARGET_PORT}/api/v1" if addr else None,
        }
    except Exception as exc:
        return {"name": _LB_SVC_NAME, "status": "error", "external_ip": None, "external_url": None, "error": str(exc)}
