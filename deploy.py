#!/usr/bin/env python3
"""
TraceX — universal deploy script.

Works against any Kubernetes cluster: k3s, k3d, minikube, kind,
Docker Desktop, or any remote cluster.

Usage:
    python3 deploy.py               # Deploy (or re-deploy after changes)
    python3 deploy.py --no-build    # Skip Docker image build step
    python3 deploy.py --status      # Show pods / services / ingress
    python3 deploy.py --destroy     # Delete namespace (or whole k3d cluster)
    python3 deploy.py --logs api    # Stream logs  (api | processor | frontend)

All settings are in config.json — no other file needs to be edited.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

ROOT = Path(__file__).parent
K8S  = ROOT / "k8s"
NS   = "forensics-operator"   # overwritten by load_config()

APPLY_ORDER = [
    K8S / "namespace.yaml",
    K8S / "storage",
    K8S / "redis",
    K8S / "minio",
    K8S / "elasticsearch",
    K8S / "kibana",
    K8S / "configmaps",
    K8S / "api",
    K8S / "processor",
    K8S / "frontend",
    K8S / "ingress",
]

SERVICES = ["api", "processor", "frontend"]


# ── Output helpers ────────────────────────────────────────────────────────────

def step(msg):  print(f"\n→ {msg}")
def ok(msg):    print(f"  ✓ {msg}")
def warn(msg):  print(f"  ⚠  {msg}")
def info(msg):  print(f"     {msg}")

def die(msg):
    print(f"\n  ✗  ERROR: {msg}\n")
    sys.exit(1)


def run(cmd, capture=False, check=True, stdin_text=None, shell=False):
    if not capture and not shell:
        info("$ " + " ".join(str(c) for c in cmd))
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=False,
        input=stdin_text,
        shell=shell,
    )
    if check and result.returncode != 0:
        if capture:
            print(result.stderr or result.stdout or "(no output)")
        die(f"Command failed (exit {result.returncode})")
    return result


def cmd_exists(name):
    return shutil.which(name) is not None


# ── Config ────────────────────────────────────────────────────────────────────

def load_config():
    path = ROOT / "config.json"
    if not path.exists():
        die("config.json not found. Run this script from the tracex directory.")
    with open(path) as f:
        raw = json.load(f)
    # Strip _comment* and _readme keys
    def clean(d):
        if isinstance(d, dict):
            return {k: clean(v) for k, v in d.items() if not k.startswith("_")}
        return d
    cfg = clean(raw)
    # Expose namespace globally so all helpers can reference it
    global NS
    NS = cfg.get("namespace", "forensics-operator")
    return cfg


def image_name(svc, cfg):
    reg = cfg["images"]["registry"].rstrip("/")
    prefix = f"{reg}/" if reg else ""
    return f"{prefix}forensics-operator/{svc}:{cfg['images']['tag']}"


def build_substitutions(cfg, pull_policy):
    es_heap = cfg["resources"]["elasticsearch_heap_mb"]
    auth    = cfg.get("auth", {})
    res     = cfg["resources"]
    return {
        "__FO_NAMESPACE__":        NS,
        "__FO_API_IMAGE__":        image_name("api",       cfg),
        "__FO_PROCESSOR_IMAGE__":  image_name("processor", cfg),
        "__FO_FRONTEND_IMAGE__":   image_name("frontend",  cfg),
        "__FO_PULL_POLICY__":      pull_policy,
        "__FO_MINIO_ACCESS_KEY__": cfg["secrets"]["minio_access_key"],
        "__FO_MINIO_SECRET_KEY__": cfg["secrets"]["minio_secret_key"],
        "__FO_JWT_SECRET__":       cfg["secrets"].get("jwt_secret", "CHANGE_ME_IN_PRODUCTION"),
        "__FO_ADMIN_USERNAME__":   cfg["secrets"].get("admin_username", "admin"),
        "__FO_ADMIN_PASSWORD__":   cfg["secrets"].get("admin_password", "TracexAdmin1!"),
        "__FO_AUTH_ENABLED__":     str(auth.get("auth_enabled", True)).lower(),
        "__FO_JWT_EXPIRE_HOURS__": str(auth.get("jwt_expire_hours", 8)),
        "__FO_ES_HEAP__":          f"{es_heap}m",
        "__FO_ES_STORAGE__":       f"{cfg['resources']['elasticsearch_storage_gi']}Gi",
        "__FO_MINIO_STORAGE__":    f"{cfg['resources']['minio_storage_gi']}Gi",
        "__FO_REDIS_STORAGE__":    f"{cfg['resources']['redis_storage_gi']}Gi",
        "__FO_HOSTNAME__":         cfg["access"]["hostname"],
        # API resources
        "__FO_API_MEMORY_REQUEST__":  res.get("api_memory_request", "512Mi"),
        "__FO_API_MEMORY_LIMIT__":    res.get("api_memory_limit", "2Gi"),
        "__FO_API_CPU_REQUEST__":     res.get("api_cpu_request", "100m"),
        "__FO_API_CPU_LIMIT__":       res.get("api_cpu_limit", "1000m"),
        # Processor resources
        "__FO_PROCESSOR_MEMORY_REQUEST__":  res.get("processor_memory_request", "1Gi"),
        "__FO_PROCESSOR_MEMORY_LIMIT__":    res.get("processor_memory_limit", "8Gi"),
        "__FO_PROCESSOR_CPU_REQUEST__":     res.get("processor_cpu_request", "500m"),
        "__FO_PROCESSOR_CPU_LIMIT__":       res.get("processor_cpu_limit", "4000m"),
        # MinIO resources
        "__FO_MINIO_MEMORY_REQUEST__":  res.get("minio_memory_request", "1Gi"),
        "__FO_MINIO_MEMORY_LIMIT__":    res.get("minio_memory_limit", "4Gi"),
        "__FO_MINIO_CPU_REQUEST__":     res.get("minio_cpu_request", "250m"),
        "__FO_MINIO_CPU_LIMIT__":       res.get("minio_cpu_limit", "1000m"),
        # Frontend resources
        "__FO_FRONTEND_MEMORY_REQUEST__":  res.get("frontend_memory_request", "128Mi"),
        "__FO_FRONTEND_MEMORY_LIMIT__":    res.get("frontend_memory_limit", "512Mi"),
        "__FO_FRONTEND_CPU_REQUEST__":     res.get("frontend_cpu_request", "50m"),
        "__FO_FRONTEND_CPU_LIMIT__":       res.get("frontend_cpu_limit", "200m"),
    }


# ── Cluster detection ─────────────────────────────────────────────────────────

def get_current_context():
    r = run(["kubectl", "config", "current-context"], capture=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def cluster_reachable():
    r = run(["kubectl", "cluster-info"], capture=True, check=False)
    return r.returncode == 0


def detect_engine():
    """
    Return a string identifying the cluster engine so we know how to load images.
    Detection order (first match wins):

      k3d          — context name starts with "k3d-"
      docker-desktop — context is "docker-desktop" or "docker-for-desktop"
      minikube     — context is "minikube" OR minikube binary exists
      kind         — context starts with "kind-" OR kind binary exists
      k3s          — k3s binary found on PATH
      registry     — none of the above; a registry must be configured
    """
    ctx = get_current_context()

    if ctx.startswith("k3d-"):
        return "k3d", ctx[4:]   # (engine, cluster_name)

    if ctx in ("docker-desktop", "docker-for-desktop"):
        return "docker-desktop", ctx

    if ctx == "minikube" or cmd_exists("minikube"):
        return "minikube", ctx

    if ctx.startswith("kind-") or cmd_exists("kind"):
        cluster = ctx[5:] if ctx.startswith("kind-") else ctx
        return "kind", cluster

    if cmd_exists("k3s"):
        return "k3s", ctx

    return "registry", ctx


# ── Cluster setup ─────────────────────────────────────────────────────────────

def setup_cluster(cfg):
    step("Connecting to cluster")

    desired_ctx = cfg["cluster"].get("context", "").strip()
    if desired_ctx:
        run(["kubectl", "config", "use-context", desired_ctx])

    if cluster_reachable():
        ctx = get_current_context()
        ok(f"Connected — context: {ctx}")
        return

    # Not connected — offer k3d fallback
    if cfg["cluster"].get("auto_create_k3d", False):
        warn("No cluster reachable. auto_create_k3d is true → creating k3d cluster.")
        install_k3d()
        create_k3d_cluster(cfg)
    else:
        die(
            "kubectl cannot reach any cluster.\n\n"
            "  Fix options:\n"
            "    1. Start your cluster (k3s, minikube, Docker Desktop Kubernetes, etc.)\n"
            "    2. Set the correct context:  kubectl config use-context <name>\n"
            "    3. For k3s: export KUBECONFIG=/etc/rancher/k3s/k3s.yaml\n"
            "    4. Set 'cluster.auto_create_k3d: true' in config.json to create a local k3d cluster automatically."
        )


# ── k3d cluster creation (auto_create_k3d path only) ─────────────────────────

def install_k3d():
    if cmd_exists("k3d"):
        ok(f"k3d already installed")
        return
    step("Installing k3d")
    if cmd_exists("brew"):
        run(["brew", "install", "k3d"])
    else:
        run("curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash",
            shell=True)
    if not cmd_exists("k3d"):
        die("k3d install failed. Install manually: https://k3d.io/")
    ok("k3d installed")


def create_k3d_cluster(cfg):
    name = cfg["cluster"]["name"]
    port = cfg["access"]["http_port"]

    r = run(["k3d", "cluster", "list", "-o", "json"], capture=True, check=False)
    try:
        existing = [c["name"] for c in json.loads(r.stdout or "[]")]
    except Exception:
        existing = []

    if name in existing:
        ok(f"k3d cluster '{name}' already exists — reusing")
    else:
        step(f"Creating k3d cluster '{name}'")
        run([
            "k3d", "cluster", "create", name,
            "--port", f"{port}:{port}@loadbalancer",
            "--port", "443:443@loadbalancer",
            "--agents", "0",
        ])
        ok(f"Cluster '{name}' created")

    run(["k3d", "kubeconfig", "merge", name, "--kubeconfig-merge-default"], capture=True)
    run(["kubectl", "config", "use-context", f"k3d-{name}"], capture=True)
    ok(f"kubectl context → k3d-{name}")


# ── Image build ───────────────────────────────────────────────────────────────

def build_images(cfg, no_cache=False):
    step("Building Docker images" + (" (--no-cache)" if no_cache else ""))
    cache_flag = ["--no-cache"] if no_cache else []
    for svc in SERVICES:
        img = image_name(svc, cfg)
        print(f"  Building {img} ...")
        if svc in ("processor", "api"):
            # Build from repo root so cross-directory COPYs work:
            #   processor: needs COPY plugins/ ...
            #   api:       needs COPY collector/collect.py ...
            run(["docker", "build", "-t", img,
                 "-f", str(ROOT / svc / "Dockerfile"),
                 str(ROOT)] + cache_flag)
        else:
            run(["docker", "build", "-t", img, str(ROOT / svc)] + cache_flag)
        ok(f"Built {img}")


# ── Image loading — one method per engine ─────────────────────────────────────

def load_images(cfg):
    """
    Push or import images depending on configuration and detected engine.

    If images.registry is set → push to registry (works with any cluster).
    Otherwise → auto-detect the engine and load images directly.
    """
    if cfg["images"]["registry"]:
        push_to_registry(cfg)
        return "Always"   # always pull so nodes pick up the newly pushed image

    engine, engine_id = detect_engine()
    step(f"Loading images into cluster (engine: {engine})")

    if engine == "k3d":
        _load_k3d(cfg, engine_id)
    elif engine == "docker-desktop":
        _load_docker_desktop(cfg)
    elif engine == "minikube":
        _load_minikube(cfg)
    elif engine == "kind":
        _load_kind(cfg, engine_id)
    elif engine == "k3s":
        _load_k3s(cfg)
    else:
        die(
            "Cannot auto-load images: cluster engine not recognised and no registry is set.\n\n"
            "  Options:\n"
            "    1. Set 'images.registry' in config.json (e.g. 'docker.io/youruser/').\n"
            "    2. Manually load images and re-run with --no-build."
        )

    return "Never"   # images loaded directly, don't pull


def push_to_registry(cfg):
    step("Pushing images to registry")
    for svc in SERVICES:
        img = image_name(svc, cfg)
        run(["docker", "push", img])
        ok(f"Pushed {img}")
    # NOTE: returns "Always" so that after a push, nodes always pull the new image.
    # "IfNotPresent" would silently keep the old cached image even after a push.


def _load_k3d(cfg, cluster_name):
    for svc in SERVICES:
        img = image_name(svc, cfg)
        run(["k3d", "image", "import", img, "-c", cluster_name])
        ok(f"Loaded {img} → k3d:{cluster_name}")


def _load_docker_desktop(cfg):
    # Docker Desktop K8s shares the host Docker daemon — images are already visible.
    for svc in SERVICES:
        ok(f"Already available (shared daemon): {image_name(svc, cfg)}")


def _load_minikube(cfg):
    for svc in SERVICES:
        img = image_name(svc, cfg)
        run(["minikube", "image", "load", img])
        ok(f"Loaded {img} → minikube")


def _load_kind(cfg, cluster_name):
    for svc in SERVICES:
        img = image_name(svc, cfg)
        cmd = ["kind", "load", "docker-image", img]
        if cluster_name:
            cmd += ["--name", cluster_name]
        run(cmd)
        ok(f"Loaded {img} → kind:{cluster_name}")


def _load_k3s(cfg):
    """
    k3s uses containerd. Images must be saved as a tar and imported via
    'k3s ctr images import'. This typically requires root / sudo.
    """
    tmp_dir = Path("/tmp/fo_images")
    tmp_dir.mkdir(exist_ok=True)

    for svc in SERVICES:
        img = image_name(svc, cfg)
        tar = tmp_dir / f"{svc}.tar"

        print(f"  Saving {img} ...")
        run(["docker", "save", img, "-o", str(tar)])

        # Try with and without sudo
        for cmd_prefix in [[], ["sudo"]]:
            r = run(
                cmd_prefix + ["k3s", "ctr", "images", "import", str(tar)],
                capture=True, check=False,
            )
            if r.returncode == 0:
                break
        else:
            warn(
                f"Could not import {img} automatically.\n"
                f"  Run manually: sudo k3s ctr images import {tar}"
            )
            continue

        tar.unlink(missing_ok=True)
        ok(f"Loaded {img} → k3s")

    try:
        tmp_dir.rmdir()
    except OSError:
        pass


# ── TLS certificate ───────────────────────────────────────────────────────────

def _ensure_namespace():
    """Create the target namespace if it doesn't already exist."""
    manifest = f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {NS}\n"
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=manifest, capture_output=True, text=True,
    )


def setup_tls_secret(cfg):
    """
    Create the 'forensics-tls' K8s Secret used by the Traefik Ingress for TLS.

    Priority:
      1. config.json tls_cert + tls_key paths  → use those files
      2. Secret already exists                 → skip (don't rotate automatically)
      3. Neither                               → generate a self-signed cert via openssl
    """
    secret_name = "forensics-tls"
    hostname     = cfg["access"]["hostname"]

    cert_path = cfg["access"].get("tls_cert", "").strip()
    key_path  = cfg["access"].get("tls_key",  "").strip()

    # Always re-apply if the user has explicitly provided cert files
    if cert_path and key_path:
        step("Creating TLS secret from provided certificate")
        run(["kubectl", "delete", "secret", secret_name, "-n", NS,
             "--ignore-not-found"], capture=True)
        run(["kubectl", "create", "secret", "tls", secret_name,
             "--cert", cert_path, "--key", key_path, "-n", NS])
        ok(f"TLS secret '{secret_name}' created from {cert_path}")
        return

    # Skip if secret already present (avoid breaking existing browser trust)
    r = run(["kubectl", "get", "secret", secret_name, "-n", NS],
            capture=True, check=False)
    if r.returncode == 0:
        ok(f"TLS secret '{secret_name}' already exists — keeping it")
        return

    # Auto-generate a self-signed certificate
    step(f"Generating self-signed TLS certificate for {hostname}")
    if not cmd_exists("openssl"):
        die(
            "openssl not found — cannot auto-generate a certificate.\n"
            "  Install openssl or set tls_cert / tls_key in config.json."
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp      = Path(tmpdir)
        cfg_file = tmp / "openssl.cnf"
        key_file = tmp / "tls.key"
        cert_file = tmp / "tls.crt"

        cfg_file.write_text(f"""\
[req]
distinguished_name = req_dn
x509_extensions    = v3_req
prompt             = no

[req_dn]
CN = {hostname}

[v3_req]
keyUsage           = keyEncipherment, dataEncipherment
extendedKeyUsage   = serverAuth
subjectAltName     = DNS:{hostname}
""")
        run(
            ["openssl", "req", "-x509", "-nodes", "-days", "3650",
             "-newkey", "rsa:2048",
             "-config",  str(cfg_file),
             "-keyout",  str(key_file),
             "-out",     str(cert_file)],
            capture=True,
        )
        run(["kubectl", "create", "secret", "tls", secret_name,
             "--cert", str(cert_file),
             "--key",  str(key_file),
             "-n", NS])

    ok(f"TLS secret '{secret_name}' created (self-signed, valid 10 years)")


# ── Stale resource cleanup ────────────────────────────────────────────────────

# Resources that have been removed from the manifests but may still exist in an
# existing cluster.  `kubectl apply` never deletes objects it no longer manages,
# so we remove them explicitly here — once they're gone the step is a no-op.
_STALE_RESOURCES = [
    # upload-buffering (Buffer middleware) — removed because Traefik's Buffer
    # middleware reads the *entire* request body before forwarding, triggering
    # an i/o timeout on large uploads.  The API already streams uploads natively
    # so this middleware is both redundant and harmful.
    ("middleware", "upload-buffering"),
]


def cleanup_stale_resources():
    step("Removing legacy cluster resources")
    any_removed = False
    for kind, name in _STALE_RESOURCES:
        r = run(
            ["kubectl", "delete", kind, name, "-n", NS, "--ignore-not-found"],
            capture=True, check=False,
        )
        out = (r.stdout or "").strip()
        if "deleted" in out:
            ok(f"Removed legacy {kind}/{name} from {NS}")
            any_removed = True
    if not any_removed:
        ok("No legacy resources found — nothing to remove")


# ── Manifest application ──────────────────────────────────────────────────────

def _targets_kube_system(path):
    """Return True if a manifest file contains 'namespace: kube-system'."""
    try:
        return "namespace: kube-system" in path.read_text()
    except OSError:
        return False


def apply_all_manifests(cfg, pull_policy, setup_traefik=False):
    step("Applying Kubernetes manifests")
    subs = build_substitutions(cfg, pull_policy)

    def apply_one(path):
        import re
        content = path.read_text()
        for k, v in subs.items():
            content = content.replace(k, str(v))
        r = subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=content, capture_output=True, text=True,
        )
        if r.returncode != 0:
            stderr = r.stderr or ""
            # StatefulSet immutable-field error: delete the StatefulSet (PVCs are
            # retained by Kubernetes) and re-apply so the new spec can be created.
            if "StatefulSet" in stderr and "Forbidden" in stderr and "spec" in stderr:
                name_match = re.search(r"^\s*name:\s+(\S+)", content, re.MULTILINE)
                ns_match   = re.search(r"^\s*namespace:\s+(\S+)", content, re.MULTILINE)
                if name_match and ns_match:
                    sts_name = name_match.group(1)
                    sts_ns   = ns_match.group(1)
                    warn(f"StatefulSet '{sts_name}' has immutable field changes — "
                         f"deleting and recreating (PVCs/data are preserved)")
                    run(["kubectl", "delete", "statefulset", sts_name,
                         "-n", sts_ns, "--ignore-not-found"], capture=True)
                    r2 = subprocess.run(
                        ["kubectl", "apply", "-f", "-"],
                        input=content, capture_output=True, text=True,
                    )
                    if r2.returncode != 0:
                        print(r2.stderr)
                        die(f"kubectl apply failed for {path.name} after delete-and-recreate")
                    for line in r2.stdout.strip().splitlines():
                        info(line)
                    return
            print(stderr)
            die(f"kubectl apply failed for {path.name}")
        for line in r.stdout.strip().splitlines():
            info(line)

    for item in APPLY_ORDER:
        if item.is_file() and item.suffix == ".yaml":
            if _targets_kube_system(item) and not setup_traefik:
                warn(f"Skipping {item.name} — targets kube-system (use --setup-traefik to apply)")
                continue
            info(str(item.relative_to(ROOT)))
            apply_one(item)
        elif item.is_dir():
            for f in sorted(item.glob("*.yaml")):
                if _targets_kube_system(f) and not setup_traefik:
                    warn(f"Skipping {f.name} — targets kube-system (use --setup-traefik to apply)")
                    continue
                info(str(f.relative_to(ROOT)))
                apply_one(f)

    ok("All manifests applied")


# ── Post-deploy ───────────────────────────────────────────────────────────────

def rollout_restart_apps():
    """
    Force a rolling restart of the three application deployments.

    Required when images are loaded directly into containerd (k3s / kind) with
    a fixed tag — Kubernetes has no way to detect the image changed, so it won't
    restart pods on its own.  This sets the restart annotation and waits up to
    5 minutes per deployment (processor has 3 init containers that may need to
    wait for ES / Redis / MinIO, so a generous timeout is needed).
    """
    step("Restarting application pods (api · processor · frontend)")
    for svc in SERVICES:
        r = run(
            ["kubectl", "rollout", "restart", f"deployment/{svc}", "-n", NS],
            capture=True, check=False,
        )
        if r.returncode == 0:
            ok(f"Restart triggered: {svc}")
        else:
            warn(f"Could not restart {svc} — skipping (may not exist on first deploy)")

    # Wait for each rollout to finish
    for svc in SERVICES:
        r = run(
            ["kubectl", "rollout", "status", f"deployment/{svc}", "-n", NS, "--timeout=5m0s"],
            capture=True, check=False,
        )
        if r.returncode == 0:
            ok(f"Rollout complete: {svc}")
        else:
            warn(f"Rollout timeout for {svc} — pods may still be initialising (check: kubectl get pods -n {NS})")


def clear_stale_celery_tasks():
    """
    Recover any tasks stuck in the 'celery' default queue.

    Old dispatch code passed exchange=Exchange(...) to a minimal Celery app,
    causing Kombu to fall back to the 'celery' queue instead of 'ingest' or
    'modules'.  Workers never consume 'celery', so those tasks would be stuck
    forever.  This step moves them to 'default', which workers DO listen on.
    """
    step("Recovering tasks stuck in 'celery' queue → moving to 'default'")

    # Check how many tasks are stuck
    r_len = run(
        ["kubectl", "exec", "-n", NS, "deploy/redis", "--",
         "redis-cli", "LLEN", "celery"],
        capture=True, check=False,
    )
    if r_len.returncode != 0:
        warn("Could not reach Redis — skipping stuck-task recovery")
        return

    count = int(r_len.stdout.strip() or "0")
    if count == 0:
        ok("No stuck tasks in 'celery' queue")
        return

    warn(f"Found {count} stuck task(s) in 'celery' queue — moving to 'default'")
    # Lua script: atomically move all items from 'celery' to 'default'
    lua = "local n=redis.call('llen','celery'); for i=1,n do redis.call('rpoplpush','celery','default') end; return n"
    r_move = run(
        ["kubectl", "exec", "-n", NS, "deploy/redis", "--",
         "redis-cli", "EVAL", lua, "0"],
        capture=True, check=False,
    )
    if r_move.returncode == 0:
        ok(f"Moved {count} stuck task(s) from 'celery' → 'default' for reprocessing")
    else:
        warn("Could not move stuck tasks — they may need manual recovery")


def verify_celery_queues():
    """
    Verify that Celery workers are consuming from the correct queues.
    """
    step("Verifying Celery queue configuration")
    
    # Check queue lengths
    for queue in ["ingest", "modules", "celery"]:
        r = run(
            ["kubectl", "exec", "-n", NS, "deploy/redis", "--",
             "redis-cli", "llen", queue],
            capture=True, check=False,
        )
        if r.returncode == 0:
            count = r.stdout.strip()
            info(f"Queue '{queue}': {count} tasks")
    
    # Check worker logs for queue consumption
    r = run(
        ["kubectl", "logs", "-n", NS, "-l", "app=processor", "--tail=20"],
        capture=True, check=False,
    )
    if r.returncode == 0 and "ready" in r.stdout.lower():
        ok("Celery workers are running")
    else:
        warn("Celery workers may not be ready yet")


def wait_for_elasticsearch():
    step("Waiting for Elasticsearch (up to 3 minutes)")
    for i in range(36):
        r = run([
            "kubectl", "exec", "-n", NS, "elasticsearch-0", "--",
            "curl", "-sf",
            "http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=5s",
        ], capture=True, check=False)
        if r.returncode == 0:
            ok("Elasticsearch is ready")
            return
        print(f"\r  Waiting {'.' * (i % 4 + 1):<4}", end="", flush=True)
        time.sleep(5)
    print()
    warn("Elasticsearch took too long — it may still be starting up")


def apply_es_template():
    tmpl = ROOT / "elasticsearch" / "index_templates" / "fo-cases-template.json"
    if not tmpl.exists():
        return
    step("Applying Elasticsearch index template")
    r = run([
        "kubectl", "exec", "-n", NS, "elasticsearch-0", "--",
        "curl", "-sf", "-X", "PUT",
        "http://localhost:9200/_index_template/fo-cases-template",
        "-H", "Content-Type: application/json",
        "-d", tmpl.read_text(),
    ], capture=True, check=False)
    ok("Template applied") if r.returncode == 0 else warn("Could not apply template yet — retry with --no-build")


def get_ingress_ip(cfg):
    # Return hostname from config - user manages their own ingress
    return cfg["access"]["hostname"]


def print_summary(cfg):
    hostname   = cfg["access"]["hostname"]
    https_port = cfg["access"].get("https_port", 443)
    port_str   = f":{https_port}" if https_port != 443 else ""
    ip         = get_ingress_ip(cfg)
    auto_cert  = not (cfg["access"].get("tls_cert") and cfg["access"].get("tls_key"))

    print()
    print("┌" + "─" * 58 + "┐")
    print("│  TraceX deployed!                                      │")
    print("└" + "─" * 58 + "┘")
    cert_note = (
        "\n  Note: using a self-signed certificate — your browser will\n"
        "  show a security warning. Accept it to proceed.\n"
        "  To use your own cert, set tls_cert/tls_key in config.json.\n"
    ) if auto_cert else ""
    print(f"""
  1. Add this line to /etc/hosts (one-time, requires sudo):

       echo "{ip}  {hostname}" | sudo tee -a /etc/hosts

  2. Open in your browser (HTTP auto-redirects to HTTPS):
{cert_note}
       Web UI:    https://{hostname}{port_str}/
       API docs:  https://{hostname}{port_str}/api/v1/docs
       Kibana:    https://{hostname}{port_str}/kibana/
       MinIO:     https://{hostname}{port_str}/minio/

  Useful commands:

       ./foctl status k8s                  # pod / service health
       ./foctl logs api k8s               # stream API logs
       ./foctl logs processor k8s         # stream processor logs
       ./foctl deploy k8s --restart       # re-apply + restart pods (skip rebuild)
       ./foctl deploy k8s --no-build      # re-apply manifests without rebuilding images
       ./foctl deploy k8s --no-cache      # force full Docker rebuild (ignore cache)
       ./foctl destroy k8s                # remove all cluster resources
""")


# ── Status / Logs / Destroy ───────────────────────────────────────────────────

def cmd_status():
    run(["kubectl", "get", "pods",    "-n", NS, "-o", "wide"])
    run(["kubectl", "get", "svc",     "-n", NS])
    run(["kubectl", "get", "ingress", "-n", NS])


def cmd_logs(svc):
    if svc not in SERVICES:
        die(f"Unknown service '{svc}'. Choose from: {', '.join(SERVICES)}")
    run(["kubectl", "logs", "-n", NS, "-l", f"app={svc}", "-f", "--tail=100"])


def cmd_destroy(cfg):
    ctx = get_current_context()
    print(f"\n  Context  : {ctx}")
    print(f"  Namespace: {NS}")
    print(f"\n  This deletes ALL data. Type the namespace name to confirm:")
    if input("  > ").strip() != NS:
        print("  Aborted.")
        return

    engine, engine_id = detect_engine()
    if engine == "k3d" and cfg["cluster"].get("auto_create_k3d", False):
        run(["k3d", "cluster", "delete", engine_id])
        ok(f"k3d cluster '{engine_id}' deleted")
    else:
        run(["kubectl", "delete", "namespace", NS, "--ignore-not-found"])
        ok(f"Namespace '{NS}' deleted")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="TraceX — universal deploy")
    p.add_argument("--no-build",      action="store_true", help="Skip Docker image build")
    p.add_argument("--no-cache",      action="store_true", help="Pass --no-cache to docker build (force full rebuild)")
    p.add_argument("--restart",       action="store_true",
                   help="Skip build AND image load — just re-apply manifests and force-restart pods. "
                        "Use after 'git pull' when images are already in the registry/cluster.")
    p.add_argument("--status",        action="store_true", help="Show pod/service status")
    p.add_argument("--destroy",       action="store_true", help="Delete namespace / cluster")
    p.add_argument("--logs",          metavar="SERVICE",   help="Stream logs (api/processor/frontend)")
    p.add_argument("--setup-traefik", action="store_true",
                   help="Also apply kube-system manifests (traefik-config.yaml). "
                        "Use only on first deploy or when intentionally reconfiguring Traefik. "
                        "WARNING: this restarts Traefik and will break Tailscale operator DNS until re-applied.")
    args = p.parse_args()

    cfg = load_config()

    if args.status:  cmd_status();     return
    if args.logs:    cmd_logs(args.logs); return
    if args.destroy: cmd_destroy(cfg); return

    # --restart implies --no-build
    if args.restart:
        args.no_build = True

    # ── Deployment ────────────────────────────────────────────────────────────
    mode = "Restart-only" if args.restart else ("No-build" if args.no_build else "Full")
    print(f"\n  TraceX — Deploying ({mode})\n")
    info(f"Context  : {cfg['cluster'].get('context') or '(current)'}")
    info(f"Hostname : {cfg['access']['hostname']}")
    info(f"Registry : {cfg['images']['registry'] or '(none — direct load)'}")
    info(f"ES heap  : {cfg['resources']['elasticsearch_heap_mb']} MB")

    # ⚠️  CRITICAL: This script ONLY manages the forensics-operator namespace
    info("\n  ⚠️  This script will NOT touch:")
    info("     - analyse namespace (CoreDNS, Bloodhound, etc.)")
    info("     - kube-system namespace (Traefik, k3s system)")
    info("     - tailscale namespace")
    info("     - Any other namespace")
    info(f"     Only {NS} namespace will be modified.\n")

    # 1. Verify Docker is up (needed for build/load — not required for --no-build/--restart)
    if not args.no_build:
        if not cmd_exists("docker"):
            die("Docker not found. Install Docker Desktop or the Docker CLI.")
        if run(["docker", "info"], capture=True, check=False).returncode != 0:
            die("Docker daemon is not running.")
        ok("Docker is running")

    # 2. Verify / switch kubectl context
    setup_cluster(cfg)

    # 3. Build images
    if not args.no_build:
        build_images(cfg, no_cache=getattr(args, 'no_cache', False))

    # 4. Load images into the cluster (auto-detects engine).
    #    Skipped with --no-build / --restart: manifests are re-applied as-is.
    if not args.no_build:
        pull_policy = load_images(cfg)
    else:
        pull_policy = "IfNotPresent" if cfg["images"]["registry"] else "Never"
        ok("Skipping image load (--no-build)")

    # 5. Ensure namespace exists, then create/verify TLS secret
    _ensure_namespace()
    setup_tls_secret(cfg)

    # 7. Remove any cluster objects that were deleted from the manifests
    cleanup_stale_resources()

    # 8. Apply all manifests with substituted values
    apply_all_manifests(cfg, pull_policy, setup_traefik=args.setup_traefik)

    # 9. Wait for Elasticsearch BEFORE restarting app pods — the processor has
    #    an init container that blocks until ES is up.  Restarting first would
    #    cause the processor rollout to time out waiting for that init container.
    wait_for_elasticsearch()
    apply_es_template()

    # 10. Force-restart app pods so they pick up the newly loaded images.
    #     (k3s loads images directly into containerd — kubectl apply alone does
    #      NOT trigger a rollout when the image tag is unchanged.)
    rollout_restart_apps()

    # 11. Clear any stale Celery tasks from the default queue
    clear_stale_celery_tasks()

    # 12. Verify Celery workers are consuming from correct queues
    verify_celery_queues()

    # 13. Done
    print_summary(cfg)


if __name__ == "__main__":
    main()
