"""Collector script download endpoint + network/ingress helpers.

GET  /collector/download        — return configured collect.py
GET  /network/interfaces        — discover candidate upload URLs
POST /collector/ingress         — create a K8s LoadBalancer service for external access
GET  /collector/ingress         — query status / external IP of the LB service
DELETE /collector/ingress       — remove the K8s LoadBalancer service
"""
from __future__ import annotations

import io
import json
import os
import re
import socket
import ssl
import logging
import subprocess
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import List, Optional

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

# ForensicHarvester source tree (for the package download).
# /opt/forensic_harvester is baked by the Dockerfile (never shadowed by volume mounts).
# Remaining entries are fallbacks for local dev (docker-compose bind mount or bare venv).
_HARVESTER_CANDIDATES = [
    Path("/opt/forensic_harvester"),                                      # Docker image (K8s / prod)
    Path("/app/forensic_harvester"),                                      # docker-compose bind mount
    Path(__file__).parent.parent / "forensic_harvester",                  # local: api/../forensic_harvester
    Path(__file__).parent.parent.parent / "forensic_harvester",           # mono-repo root
]

def _find_harvester_dir() -> Path:
    for p in _HARVESTER_CANDIDATES:
        if p.is_dir() and (p / "forensic_harvester.py").exists():
            return p
    raise FileNotFoundError(
        "forensic_harvester/ not found — checked: " + ", ".join(str(p) for p in _HARVESTER_CANDIDATES)
    )

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
    api_token: Optional[str] = Query(default=None, description="JWT bearer token embedded in the script"),
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
    if api_token:
        config["api_token"] = api_token

    return Response(
        content=_inject_config(source, config).encode("utf-8"),
        media_type="text/x-python",
        headers={
            "Content-Disposition": 'attachment; filename="fo-collector.py"',
            "Cache-Control": "no-store",
        },
    )


# ── ForensicHarvester package download ───────────────────────────────────────

_RUN_BAT = """\
@echo off
echo ForensicHarvester — starting collection...
python forensic_harvester.py
pause
"""

_RUN_SH = """\
#!/bin/sh
# ForensicHarvester — run on Linux or macOS
python3 forensic_harvester.py
"""

_README = """\
ForensicHarvester — Forensic Triage Package
============================================

Requirements
------------
  Python 3.8 or newer — no additional packages required.
  (pyyaml and tqdm are NOT needed; this build uses only the standard library.)

Running
-------
  Windows:        double-click run.bat   OR   python forensic_harvester.py
  Linux / macOS:  sh run.sh              OR   python3 forensic_harvester.py

Configuration
-------------
  config.json is pre-filled with the categories you selected in the UI.
  Edit it if you want to change the collection level or add/remove categories.

Output
------
  A ZIP archive is created in the ./output/ directory when collection finishes.
  Upload it to ForensicsOperator: open a case → Upload / Ingest tab.

Modes
-----
  Live system (default):
      python forensic_harvester.py

  Dead-box — already mounted directory:
      python forensic_harvester.py --mode image --image-path /mnt/evidence

  Dead-box — raw disk image (.dd / .img):
      python forensic_harvester.py --mode image --image-path disk.dd
      (requires pytsk3: pip install pytsk3)
"""


@router.get("/collector/package")
def download_harvester_package(
    categories: Optional[str] = Query(default=None, description="Comma-separated category keys"),
    level: str = Query(default="complete", description="small | complete | exhaustive"),
    source_path: Optional[str] = Query(default=None, description="Pre-mounted path for dead-box mode"),
):
    """
    Return a ZIP bundle containing the ForensicHarvester source tree + pre-filled config.json.
    No external Python packages required — runs with standard-library Python 3.8+.
    """
    try:
        harvester_dir = _find_harvester_dir()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    # Build config.json from request params
    cat_list = [c.strip() for c in categories.split(",") if c.strip()] if categories else []
    config = {
        "mode":              "image" if source_path else "live",
        "image_path":        source_path or None,
        "level":             level,
        "categories":        cat_list,
        "output_dir":        "./output",
        "threads":           4,
        "create_zip":        True,
        "keep_unzipped":     False,
        "hash_collected":    True,
        "quiet":             False,
        "max_file_size_mb":  0,
    }

    # Build the ZIP in memory
    buf = io.BytesIO()
    _SKIP_DIRS = {"__pycache__", ".git", "tests", ".pytest_cache"}
    _SKIP_EXTS = {".pyc", ".pyo", ".egg-info"}

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        # Add all Python source files from the forensic_harvester tree
        for f in harvester_dir.rglob("*"):
            if not f.is_file():
                continue
            if any(part in _SKIP_DIRS for part in f.parts):
                continue
            if f.suffix in _SKIP_EXTS:
                continue
            # Skip yaml config — replaced by config.json
            if f.name in ("config.yaml", "config.yml"):
                continue
            arc_name = "fo-harvester/" + str(f.relative_to(harvester_dir))
            zf.write(f, arc_name)

        # Inject pre-filled config.json
        zf.writestr("fo-harvester/config.json", json.dumps(config, indent=2))

        # Launchers
        zf.writestr("fo-harvester/run.bat", _RUN_BAT)
        zf.writestr("fo-harvester/run.sh",  _RUN_SH)
        zf.writestr("fo-harvester/README.txt", _README)

    cat_label = f"-{level}" + (f"-{len(cat_list)}cats" if cat_list else "")
    filename = f"fo-harvester{cat_label}.zip"

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
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
    """Default gateway — on Docker bridge networks this is the host machine's docker bridge IP."""
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


def _resolve_host_docker_internal() -> Optional[str]:
    """
    Resolve host.docker.internal — set automatically by Docker Desktop on Mac/Windows.

    On Linux Docker with bridge networking this hostname may not be set unless
    '--add-host=host-gateway' is in the run flags. Returns None if not resolvable.
    """
    try:
        addr = socket.gethostbyname("host.docker.internal")
        if addr and not addr.startswith("127."):
            return addr
    except (socket.gaierror, OSError):
        pass
    # Also scan /etc/hosts for Docker-injected entries
    try:
        for line in Path("/etc/hosts").read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "host.docker.internal" in line or "host-gateway" in line:
                parts = line.split()
                if parts and not parts[0].startswith("127."):
                    return parts[0]
    except Exception:
        pass
    return None


def _ip_label(ip: str) -> str:
    """Return a human-readable label for an IP based on its range."""
    if ip.startswith("172."):
        return "docker bridge"
    if ip.startswith("192.168."):
        return "LAN"
    if ip.startswith("10."):
        return "private network"
    if ip.startswith("169.254."):
        return "link-local"
    return "interface"


def _only_docker_ips(candidates: list[dict]) -> bool:
    """Return True if all detected IPs (excluding FO_PUBLIC_URL) are Docker-internal."""
    non_config = [c for c in candidates if c.get("iface") != "FO_PUBLIC_URL"]
    if not non_config:
        return False
    return all(
        c["ip"].startswith("172.") or c["ip"].startswith("10.")
        for c in non_config
        if not c.get("k8s")
    )


def _is_kubernetes() -> bool:
    """Return True when running inside a Kubernetes pod (service account is mounted)."""
    return os.path.isfile("/var/run/secrets/kubernetes.io/serviceaccount/token")


# ── Kubernetes LoadBalancer service settings (used by helpers + endpoints) ────

_LB_SVC_NAME    = os.getenv("FO_LB_SERVICE_NAME", "fo-collector-lb")
_LB_NAMESPACE   = os.getenv("FO_NAMESPACE", "default")
_LB_TARGET_PORT = int(os.getenv("FO_API_PORT", "8000"))
_LB_APP_LABEL   = os.getenv("FO_APP_LABEL", "fo-api")


# ── Kubernetes in-cluster API helpers ─────────────────────────────────────────

_K8S_HOST      = "https://kubernetes.default.svc"
_K8S_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_K8S_CA_PATH    = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
_K8S_NS_PATH    = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")


def _k8s_namespace() -> str:
    """Read the pod's namespace from the mounted service account files."""
    try:
        return _K8S_NS_PATH.read_text().strip() or _LB_NAMESPACE
    except Exception:
        return _LB_NAMESPACE


def _k8s_request(
    method: str,
    path: str,
    body: Optional[dict] = None,
) -> tuple[int, dict]:
    """
    Make an authenticated request to the Kubernetes API server using the
    in-cluster service account token.  No kubectl needed.
    Returns (http_status_code, parsed_json_response).
    """
    try:
        token = _K8S_TOKEN_PATH.read_text().strip()
    except Exception as exc:
        logger.error("Cannot read K8s service account token: %s", exc)
        return 0, {"error": "cannot read service account token"}

    url  = f"{_K8S_HOST}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")

    ssl_ctx = ssl.create_default_context()
    if _K8S_CA_PATH.is_file():
        ssl_ctx.load_verify_locations(str(_K8S_CA_PATH))
    else:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, {"message": raw.decode(errors="replace")[:500]}
    except Exception as exc:
        logger.error("K8s API request failed [%s %s]: %s", method, path, exc)
        return 0, {"error": str(exc)}


def _get_k8s_service_ips() -> list[dict]:
    """Query the K8s API for LoadBalancer / NodePort services and return their IPs."""
    status, data = _k8s_request("GET", "/api/v1/services")
    if status != 200:
        return []
    results = []
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
        # NodePort — include cluster IP as a reachable candidate
        if svc_type == "NodePort":
            cluster_ip = item.get("spec", {}).get("clusterIP", "")
            if cluster_ip and cluster_ip != "None":
                results.append({
                    "ip":    cluster_ip,
                    "iface": f"k8s/{ns}/{svc_name}",
                    "label": f"NodePort ({svc_name})",
                    "k8s":   True,
                })
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

    # 3. host.docker.internal — Docker Desktop Mac/Windows injects the host IP here
    host_docker = _resolve_host_docker_internal()
    if host_docker:
        _add(host_docker, "host machine (Docker Desktop)", "host.docker.internal")

    # 4. All non-loopback interface IPs (from ip addr)
    for entry in _parse_ip_addr():
        _add(entry["ip"], _ip_label(entry["ip"]), entry["iface"])

    # 5. Default gateway (Docker bridge host on Linux Docker)
    gw = _detect_gateway_ip()
    if gw:
        # Only show the gateway if it's not already in the list
        _add(gw, "docker host (gateway)", "gateway")

    # 6. Outbound socket IP (last resort)
    _add(_detect_outbound_ip(), "outbound", "socket")

    # Attach a helper flag so the frontend can show a "set FO_PUBLIC_URL" tip
    only_internal = _only_docker_ips(candidates)

    return {
        "candidates":     candidates,
        "port":           int(_API_PORT),
        "in_kubernetes":  _is_kubernetes(),
        "only_docker_ips": only_internal,
        "public_url_hint": (
            "No external IP detected. Set FO_PUBLIC_URL=http://<your-lan-ip>:8000 "
            "in docker-compose.yml for collectors to reach this server."
            if only_internal and not _is_kubernetes() else None
        ),
    }


# ── Kubernetes LoadBalancer ingress management ────────────────────────────────
# The pod's service account needs the following RBAC permissions.
# Apply once to your cluster before using these endpoints:
#
#   kubectl apply -f - <<'EOF'
#   apiVersion: rbac.authorization.k8s.io/v1
#   kind: Role
#   metadata:
#     name: fo-service-manager
#     namespace: <your-namespace>
#   rules:
#   - apiGroups: [""]
#     resources: ["services"]
#     verbs: ["get", "list", "create", "delete"]
#   ---
#   apiVersion: rbac.authorization.k8s.io/v1
#   kind: RoleBinding
#   metadata:
#     name: fo-service-manager
#     namespace: <your-namespace>
#   subjects:
#   - kind: ServiceAccount
#     name: default          # or your custom SA name
#     namespace: <your-namespace>
#   roleRef:
#     kind: Role
#     name: fo-service-manager
#     apiGroup: rbac.authorization.k8s.io
#   EOF

def _build_lb_manifest(namespace: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind":       "Service",
        "metadata": {
            "name":      _LB_SVC_NAME,
            "namespace": namespace,
            "labels":    {"managed-by": "forensicsoperator"},
        },
        "spec": {
            "type":     "LoadBalancer",
            "selector": {"app": _LB_APP_LABEL},
            "ports":    [{"port": _LB_TARGET_PORT, "targetPort": _LB_TARGET_PORT, "protocol": "TCP"}],
        },
    }


@router.post("/collector/ingress", status_code=201)
def create_collector_ingress():
    """
    Create a Kubernetes LoadBalancer Service that exposes the API externally
    so remote collectors can upload artifacts.
    Uses the pod's in-cluster service account — no kubectl required.
    The service account needs RBAC: create/get/delete on services in its namespace.
    """
    if not _is_kubernetes():
        raise HTTPException(
            status_code=400,
            detail="Not running in Kubernetes — use the FO_PUBLIC_URL env var to set the external URL manually.",
        )
    ns       = _k8s_namespace()
    manifest = _build_lb_manifest(ns)
    status, body = _k8s_request("POST", f"/api/v1/namespaces/{ns}/services", body=manifest)

    if status == 409:
        # Service already exists — return current status
        logger.info("LoadBalancer service %s already exists", _LB_SVC_NAME)
    elif status not in (200, 201):
        msg = body.get("message", str(body))[:300]
        logger.error("K8s API error creating service (%d): %s", status, msg)
        raise HTTPException(status_code=500, detail=f"Kubernetes API error ({status}): {msg}")

    return _get_lb_status()


@router.get("/collector/ingress")
def get_collector_ingress():
    """Query the status and external IP of the collector LoadBalancer service."""
    if not _is_kubernetes():
        raise HTTPException(status_code=400, detail="Not running in Kubernetes.")
    return _get_lb_status()


@router.get("/collector/ingress/rbac")
def get_ingress_rbac():
    """
    Return a ready-to-apply RBAC Role + RoleBinding manifest that grants the
    pod's default service account permission to create/get/delete Services.
    Apply once: kubectl apply -f <(curl -s .../collector/ingress/rbac)
    """
    ns = _k8s_namespace() if _is_kubernetes() else _LB_NAMESPACE
    manifest = f"""apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: fo-service-manager
  namespace: {ns}
rules:
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: fo-service-manager
  namespace: {ns}
subjects:
- kind: ServiceAccount
  name: default
  namespace: {ns}
roleRef:
  kind: Role
  name: fo-service-manager
  apiGroup: rbac.authorization.k8s.io
"""
    return Response(
        content=manifest,
        media_type="text/yaml",
        headers={"Content-Disposition": 'attachment; filename="fo-rbac.yaml"'},
    )


@router.delete("/collector/ingress", status_code=204)
def delete_collector_ingress():
    """Remove the collector LoadBalancer service."""
    if not _is_kubernetes():
        raise HTTPException(status_code=400, detail="Not running in Kubernetes.")
    ns = _k8s_namespace()
    status, body = _k8s_request(
        "DELETE", f"/api/v1/namespaces/{ns}/services/{_LB_SVC_NAME}",
    )
    if status not in (200, 202, 404):
        msg = body.get("message", str(body))[:300]
        raise HTTPException(status_code=500, detail=f"Kubernetes API error ({status}): {msg}")


def _get_lb_status() -> dict:
    ns = _k8s_namespace()
    status, data = _k8s_request(
        "GET", f"/api/v1/namespaces/{ns}/services/{_LB_SVC_NAME}",
    )
    if status == 404:
        return {"name": _LB_SVC_NAME, "status": "not_found", "external_ip": None, "external_url": None}
    if status != 200:
        return {
            "name": _LB_SVC_NAME, "status": "error",
            "external_ip": None, "external_url": None,
            "error": data.get("message", "")[:200],
        }
    ingresses = data.get("status", {}).get("loadBalancer", {}).get("ingress", [])
    ip   = ingresses[0].get("ip")       if ingresses else None
    host = ingresses[0].get("hostname") if ingresses else None
    addr = ip or host
    return {
        "name":         _LB_SVC_NAME,
        "namespace":    ns,
        "status":       "ready" if addr else "pending",
        "external_ip":  addr,
        "external_url": f"http://{addr}:{_LB_TARGET_PORT}/api/v1" if addr else None,
    }
