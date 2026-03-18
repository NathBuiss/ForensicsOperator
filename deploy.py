#!/usr/bin/env python3
"""
ForensicsOperator — universal deploy script.

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
import time
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

ROOT = Path(__file__).parent
K8S  = ROOT / "k8s"
NS   = "forensics-operator"

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

NGINX_INGRESS_MANIFEST = (
    "https://raw.githubusercontent.com/kubernetes/ingress-nginx"
    "/controller-v1.10.1/deploy/static/provider/cloud/deploy.yaml"
)

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
        die("config.json not found. Run this script from the forensicsOperator directory.")
    with open(path) as f:
        raw = json.load(f)
    # Strip _comment* and _readme keys
    def clean(d):
        if isinstance(d, dict):
            return {k: clean(v) for k, v in d.items() if not k.startswith("_")}
        return d
    return clean(raw)


def image_name(svc, cfg):
    reg = cfg["images"]["registry"].rstrip("/")
    prefix = f"{reg}/" if reg else ""
    return f"{prefix}forensics-operator/{svc}:{cfg['images']['tag']}"


def build_substitutions(cfg, pull_policy):
    es_heap = cfg["resources"]["elasticsearch_heap_mb"]
    return {
        "__FO_API_IMAGE__":        image_name("api",       cfg),
        "__FO_PROCESSOR_IMAGE__":  image_name("processor", cfg),
        "__FO_FRONTEND_IMAGE__":   image_name("frontend",  cfg),
        "__FO_PULL_POLICY__":      pull_policy,
        "__FO_MINIO_ACCESS_KEY__": cfg["secrets"]["minio_access_key"],
        "__FO_MINIO_SECRET_KEY__": cfg["secrets"]["minio_secret_key"],
        "__FO_ES_HEAP__":          f"{es_heap}m",
        "__FO_ES_STORAGE__":       f"{cfg['resources']['elasticsearch_storage_gi']}Gi",
        "__FO_MINIO_STORAGE__":    f"{cfg['resources']['minio_storage_gi']}Gi",
        "__FO_REDIS_STORAGE__":    f"{cfg['resources']['redis_storage_gi']}Gi",
        "__FO_HOSTNAME__":         cfg["access"]["hostname"],
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
            "--k3s-arg", "--disable=traefik@server:0",
            "--agents", "0",
        ])
        ok(f"Cluster '{name}' created")

    run(["k3d", "kubeconfig", "merge", name, "--kubeconfig-merge-default"], capture=True)
    run(["kubectl", "config", "use-context", f"k3d-{name}"], capture=True)
    ok(f"kubectl context → k3d-{name}")


# ── Image build ───────────────────────────────────────────────────────────────

def build_images(cfg):
    step("Building Docker images")
    for svc in SERVICES:
        img = image_name(svc, cfg)
        print(f"  Building {img} ...")
        run(["docker", "build", "-t", img, str(ROOT / svc)])
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
        return "IfNotPresent"   # cluster will pull from registry

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


# ── NGINX Ingress ─────────────────────────────────────────────────────────────

def ensure_nginx_ingress():
    step("Checking NGINX Ingress Controller")
    r = run(["kubectl", "get", "ns", "ingress-nginx"], capture=True, check=False)
    if r.returncode == 0:
        ok("Already installed")
        return
    print("  Not found — installing ...")
    run(["kubectl", "apply", "-f", NGINX_INGRESS_MANIFEST])
    print("  Waiting for ingress-nginx to become ready (~60 s) ...")
    run([
        "kubectl", "rollout", "status",
        "deployment/ingress-nginx-controller",
        "-n", "ingress-nginx",
        "--timeout=120s",
    ])
    ok("NGINX Ingress Controller ready")


# ── Manifest application ──────────────────────────────────────────────────────

def apply_all_manifests(cfg, pull_policy):
    step("Applying Kubernetes manifests")
    subs = build_substitutions(cfg, pull_policy)

    def apply_one(path):
        content = path.read_text()
        for k, v in subs.items():
            content = content.replace(k, str(v))
        r = subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=content, capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(r.stderr)
            die(f"kubectl apply failed for {path.name}")
        for line in r.stdout.strip().splitlines():
            info(line)

    for item in APPLY_ORDER:
        if item.is_file() and item.suffix == ".yaml":
            info(str(item.relative_to(ROOT)))
            apply_one(item)
        elif item.is_dir():
            for f in sorted(item.glob("*.yaml")):
                info(str(f.relative_to(ROOT)))
                apply_one(f)

    ok("All manifests applied")


# ── Post-deploy ───────────────────────────────────────────────────────────────

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


def get_ingress_ip():
    r = run([
        "kubectl", "get", "svc", "ingress-nginx-controller",
        "-n", "ingress-nginx",
        "-o", "jsonpath={.status.loadBalancer.ingress[0].ip}",
    ], capture=True, check=False)
    return r.stdout.strip() or "127.0.0.1"


def print_summary(cfg):
    hostname = cfg["access"]["hostname"]
    port     = cfg["access"]["http_port"]
    port_str = f":{port}" if port != 80 else ""
    ip       = get_ingress_ip()

    print()
    print("┌" + "─" * 58 + "┐")
    print("│  ForensicsOperator deployed!                           │")
    print("└" + "─" * 58 + "┘")
    print(f"""
  1. Add this line to /etc/hosts (one-time, requires sudo):

       echo "{ip}  {hostname}" | sudo tee -a /etc/hosts

  2. Open in your browser:

       Web UI:    http://{hostname}{port_str}/
       API docs:  http://{hostname}{port_str}/api/v1/docs
       Kibana:    http://{hostname}{port_str}/kibana/
       MinIO:     http://{hostname}{port_str}/minio/

  Useful commands:

       python3 deploy.py --status          # pod health
       python3 deploy.py --logs api        # stream API logs
       python3 deploy.py --logs processor  # stream processor logs
       python3 deploy.py --no-build        # re-apply config without rebuilding
       python3 deploy.py --destroy         # remove everything
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
    p = argparse.ArgumentParser(description="ForensicsOperator — universal deploy")
    p.add_argument("--no-build", action="store_true", help="Skip Docker image build")
    p.add_argument("--status",   action="store_true", help="Show pod/service status")
    p.add_argument("--destroy",  action="store_true", help="Delete namespace / cluster")
    p.add_argument("--logs",     metavar="SERVICE",   help="Stream logs (api/processor/frontend)")
    args = p.parse_args()

    cfg = load_config()

    if args.status:  cmd_status();     return
    if args.logs:    cmd_logs(args.logs); return
    if args.destroy: cmd_destroy(cfg); return

    # ── Deployment ────────────────────────────────────────────────────────────
    print("\n  ForensicsOperator — Deploying\n")
    info(f"Context  : {cfg['cluster'].get('context') or '(current)'}")
    info(f"Hostname : {cfg['access']['hostname']}")
    info(f"Registry : {cfg['images']['registry'] or '(none — direct load)'}")
    info(f"ES heap  : {cfg['resources']['elasticsearch_heap_mb']} MB")

    # 1. Verify Docker is up (needed for build/load)
    if not cmd_exists("docker"):
        die("Docker not found. Install Docker Desktop or the Docker CLI.")
    if run(["docker", "info"], capture=True, check=False).returncode != 0:
        die("Docker daemon is not running.")
    ok("Docker is running")

    # 2. Verify / switch kubectl context
    setup_cluster(cfg)

    # 3. Build images
    if not args.no_build:
        build_images(cfg)

    # 4. Load images into the cluster (auto-detects engine)
    pull_policy = load_images(cfg)

    # 5. Ensure NGINX ingress controller is present
    ensure_nginx_ingress()

    # 6. Apply all manifests with substituted values
    apply_all_manifests(cfg, pull_policy)

    # 7. Wait for Elasticsearch, apply index template
    wait_for_elasticsearch()
    apply_es_template()

    # 8. Done
    print_summary(cfg)


if __name__ == "__main__":
    main()
