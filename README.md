# TraceX

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-005571.svg)](https://www.elastic.co/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.25+-326CE5.svg)](https://kubernetes.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docs.docker.com/compose/)

**TraceX** is an open-source digital forensics and incident response (DFIR) platform. Upload forensic artifacts from compromised systems, parse them automatically, run Sigma and YARA detection rules, run specialized analysis tools (Hayabusa, RegRipper, Volatility3, and more), and investigate incidents — all from one web interface.

Runs on **Docker Compose** for single-server and laptop deployments, or on **Kubernetes** for team and production environments.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
  - [Docker (single server / laptop)](#docker-single-server--laptop)
  - [Kubernetes — existing cluster](#kubernetes--existing-cluster)
  - [Kubernetes — new local cluster with k3d](#kubernetes--new-local-cluster-with-k3d)
  - [foctl reference](#foctl-reference)
- [Configuration](#configuration)
  - [Docker: .env](#docker-env)
  - [Kubernetes: config.json](#kubernetes-configjson)
- [Supported Artifact Formats](#supported-artifact-formats)
- [Detection Rules](#detection-rules)
- [Analysis Modules](#analysis-modules)
- [Studio — Custom Code](#studio--custom-code)
- [Remote Artifact Collection](#remote-artifact-collection)
- [User Management](#user-management)
- [API](#api)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

---

## Features

| | Capability |
|---|---|
| **Ingestion** | 20+ forensic formats auto-detected by MIME type — EVTX, MFT, Registry hives, Prefetch, LNK, PCAP, Plaso/L2T, Syslog, Zeek, Suricata, browser DBs, Android, iOS, disk images |
| **Detection** | 145+ built-in Sigma rules across 13 MITRE ATT&CK categories; import from Sigma HQ (4 000+ rules); AI-generated rules |
| **Analysis** | Hayabusa, RegRipper, YARA, Hindsight, OleTools, PE analysis, Volatility3, strings extraction, pattern search, CTI IOC matching |
| **Search** | Elasticsearch full-text search with facets, saved queries, timeline view, CSV export |
| **AI assistance** | LLM integration (OpenAI, Anthropic, Ollama) for rule generation, alert explanation, and incident summarisation |
| **Studio** | Browser-based IDE to write custom ingesters, analysis modules, YARA rules, and alert rules |
| **Threat intel** | STIX/TAXII feed ingestion; IOC matching across all cases |
| **Collection** | Deploy a PowerShell/Bash collector script to live endpoints; artifacts upload to a case automatically |
| **Access control** | JWT authentication; admin and analyst roles |
| **Scalability** | HPA-managed Kubernetes workers; Celery ingest and module queues; shared Redis connection pool; gzip-compressed ES bulk indexing |

---

## Architecture

```
  Browser
     │
     ▼
┌────────────────────────────────────────────────────────┐
│  nginx reverse proxy   :80                             │
│  (proxy service in Docker / Traefik in Kubernetes)     │
└──────────────┬─────────────────────────┬───────────────┘
               │  /api/                  │  /
               ▼                         ▼
┌──────────────────────┐     ┌─────────────────────────┐
│  API  (FastAPI)      │     │  Frontend  (React+Vite) │
│  :8000               │     │  served by nginx:alpine │
└──┬──────────┬────────┘     └─────────────────────────┘
   │          │
   ▼          ▼
┌──────┐  ┌────────┐  ┌──────────────────┐
│Redis │  │ MinIO  │  │  Elasticsearch   │
│:6379 │  │ :9000  │  │      :9200       │
└──────┘  └────────┘  └──────────────────┘
   │
   ▼ (Celery broker)
┌─────────────────────────────────────────────────┐
│  Processor — Celery workers                     │
│  ┌──────────────────┐  ┌──────────────────────┐ │
│  │  worker-ingest   │  │   worker-modules     │ │
│  │  queue: ingest   │  │   queue: modules     │ │
│  │  concurrency: 4  │  │   concurrency: 2     │ │
│  └──────────────────┘  └──────────────────────┘ │
└─────────────────────────────────────────────────┘
```

| Component | Technology | Notes |
|-----------|-----------|-------|
| Frontend | React 18 + Vite + Tailwind | Built to `nginx:alpine` static server |
| API | FastAPI / Python 3.11 | Uvicorn, 4 workers, shared Redis pool |
| Workers | Celery 5.3 + | Separate queues for I/O-bound ingest vs CPU-bound modules |
| Search | Elasticsearch 8.13 | gzip-compressed bulk indexing, 5 s refresh |
| Broker/state | Redis 7.2 | Job state (7-day TTL), rule library, sessions |
| Artifacts | MinIO | S3-compatible; bucket `forensics-cases` |
| K8s ingress | Traefik | TLS termination, host-based routing |
| Autoscaling | K8s HPA | API: 2–6 replicas; Processor: 2–8 replicas |

---

## Quick Start

### Choose your path

| Goal | Command |
|------|---------|
| Laptop / single server | `./foctl deploy docker` |
| Existing Kubernetes cluster | `./foctl deploy k8s` |
| New local cluster (k3d) | `./foctl deploy k8s-new` |

### Minimal Docker deploy

```bash
git clone https://github.com/your-org/tracex.git
cd tracex

# Creates .env from .env.example and starts all services
./foctl deploy docker
```

Open **http://localhost** — default credentials: `admin` / `TracexAdmin1!`

> Change the admin password immediately: **Settings → Users → admin → Change Password**

---

## Deployment

### Docker (single server / laptop)

Docker Compose runs every component in containers on a single machine. A `nginx` reverse proxy routes all traffic through port 80. No Kubernetes required.

**Prerequisites:** Docker with Compose v2, Python 3 (for `foctl` config helpers)

```bash
# First run: .env is created automatically from .env.example
./foctl deploy docker

# Access:
#   Web UI      → http://localhost/
#   API docs    → http://localhost/api/v1/docs
#   Kibana      → http://localhost:5601/
#   MinIO UI    → http://localhost:9001/
```

**Manual steps (no foctl):**

```bash
cp .env.example .env
$EDITOR .env                  # set JWT_SECRET at minimum

docker compose -f docker-compose.prod.yml up -d --build
```

To stop or remove everything:

```bash
./foctl destroy docker        # prompts for confirmation; deletes volumes
```

---

### Kubernetes — existing cluster

`foctl` delegates all K8s work to `deploy.py`, which builds images, applies manifests, waits for rollout, and prints access URLs.

**Prerequisites:** `kubectl` configured for your cluster, Python 3, Docker

```bash
# Edit config.json — set hostname, namespace, secrets at minimum
$EDITOR config.json

./foctl deploy k8s
```

Access at `http://<hostname>/` (or `https://` if TLS is configured in `config.json`).

```bash
./foctl status k8s            # pod status, ingress, HPA
./foctl logs api k8s          # stream API logs
./foctl update k8s            # rebuild + redeploy
./foctl destroy k8s           # tear down (delegates to deploy.py --destroy)
```

**Supported clusters:** k3s, k3d, minikube, kind, Docker Desktop, GKE, EKS, AKS, Rancher.

---

### Kubernetes — new local cluster with k3d

`k3d` runs Kubernetes nodes as Docker containers. `foctl deploy k8s-new` installs k3d if needed, creates a cluster, and then runs `deploy.py` against it.

**Prerequisites:** Docker, Python 3. `k3d` is installed automatically via Homebrew (macOS) or `curl` (Linux).

```bash
# Optional: set cluster name and port in config.json
# "cluster": { "name": "tracex" }
# "access":  { "http_port": 80 }

./foctl deploy k8s-new
```

The cluster stays running between sessions. Re-run `./foctl deploy k8s-new` to redeploy after code changes.

```bash
# Clean up the entire cluster when done
k3d cluster delete tracex
```

---

### foctl reference

```
Usage:  ./foctl <command> [args]

DEPLOY
  deploy docker             Docker Compose — builds images, starts services, waits for health
  deploy k8s                Deploy to the current kubectl context (runs deploy.py)
  deploy k8s-new            Create k3d cluster + deploy (installs k3d if missing)

OPERATIONS  (mode auto-detected if omitted)
  status  [docker|k8s]      Service / pod health overview
  logs    <svc> [mode]      Stream logs — svc: api | worker-ingest | worker-modules | all
  update  [docker|k8s]      Rebuild images + redeploy
  destroy [docker|k8s]      Remove all services and data (confirms first)
  config                    Show parsed config.json + redacted .env

  (no args)                 Interactive menu
```

---

## Configuration

### Docker: .env

Copy `.env.example` to `.env` and set at minimum:

```bash
# REQUIRED — generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
JWT_SECRET=

# Credentials for MinIO object storage
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
```

Full variable reference:

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | *(required)* | JWT signing key — use `secrets.token_hex(32)` |
| `JWT_EXPIRE_HOURS` | `8` | Token lifetime in hours |
| `AUTH_ENABLED` | `true` | Set `false` for trusted-LAN / dev only |
| `MINIO_ACCESS_KEY` | `minioadmin` | MinIO root username |
| `MINIO_SECRET_KEY` | `minioadmin` | MinIO root password |
| `ES_HEAP_SIZE` | `1g` | Elasticsearch JVM heap — set to ~50% of available RAM |
| `REDIS_MAXMEM` | `2gb` | Redis memory cap |
| `API_WORKERS` | `4` | Uvicorn worker processes |
| `INGEST_CONCURRENCY` | `4` | Parallel ingest tasks per worker |
| `MODULE_CONCURRENCY` | `2` | Parallel module tasks per worker (CPU-bound — keep low) |
| `WORKER_MAX_TASKS` | `50` | Tasks per child before process recycle |
| `BULK_SIZE` | `1000` | Elasticsearch bulk indexing batch size |
| `FO_PUBLIC_URL` | *(empty)* | Public URL shown on the Collector page |

---

### Kubernetes: config.json

```jsonc
{
  "namespace": "tracex",
  "cluster": {
    "name": "tracex",  // k3d cluster name (k8s-new mode)
    "context": ""                  // kubectl context; empty = current context
  },
  "images": {
    "registry": "",                // Docker registry prefix; empty = load directly into cluster
    "tag": "latest"
  },
  "access": {
    "hostname": "forensics.local",
    "http_port": 80,
    "https_port": 443,
    "tls_cert": "",                // Path to TLS certificate PEM
    "tls_key": ""
  },
  "secrets": {
    "minio_access_key": "minioadmin",
    "minio_secret_key": "minioadmin",
    "jwt_secret": "CHANGE_ME_IN_PRODUCTION",
    "admin_username": "admin",
    "admin_password": "TracexAdmin1!"
  },
  "resources": {
    "elasticsearch_heap_mb": 2048,
    "elasticsearch_storage_gi": 50,
    "minio_storage_gi": 100,
    "redis_storage_gi": 10,
    "api_memory_request": "512Mi",
    "api_memory_limit": "2Gi",
    "processor_memory_request": "1Gi",
    "processor_memory_limit": "4Gi"
  }
}
```

**LLM integration** — configure at **Settings → LLM Config** in the UI:
- **OpenAI** — API key + model (e.g. `gpt-4o`)
- **Anthropic** — API key + model (e.g. `claude-opus-4-6`)
- **Ollama** — base URL + model (e.g. `http://ollama:11434`, `llama3`)

**S3 import** — configure at **Settings → S3 Storage** to import artifacts from AWS S3, MinIO, Wasabi, or GCS.

---

## Supported Artifact Formats

Files are automatically routed to the correct parser by MIME type. ZIP archives are extracted and each file dispatched individually.

| Category | Format | File / Pattern |
|----------|--------|---------------|
| **Windows** | EVTX | `*.evtx` |
| | Prefetch | `*.pf` |
| | Master File Table | `$MFT` |
| | Registry hives | `NTUSER.DAT`, `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY` |
| | LNK / Shortcut | `*.lnk` |
| **Memory** | Plaso / log2timeline | `*.plaso`, `*.json`, `*.jsonl` |
| **Network** | PCAP | `*.pcap`, `*.pcapng` |
| | Zeek | `conn.log`, `dns.log`, `http.log` |
| | Suricata | `eve.json` |
| **Browser** | Chrome, Firefox, Edge | `History`, `Cookies`, `places.sqlite` |
| **Mobile** | Android | `mmssms.db`, `contacts2.db`, `calllog.db` |
| | iOS | `sms.db`, `call_history.db`, `AddressBook.sqlitedb` |
| **Logs** | Syslog | `*.log` |
| | Web server logs | `access.log`, `access_log` |
| **Generic** | NDJSON / JSONL | `*.ndjson`, `*.jsonl` |
| | Disk image | `*.dd`, `*.E01` (requires libewf) |

Custom parsers can be written in Python and deployed without restarting via the **Studio**.

---

## Detection Rules

### Built-in library — 145 rules

Rules are pre-loaded from `api/alert_rules/` and cover 13 MITRE ATT&CK categories:

```
Initial Access · Execution · Persistence · Privilege Escalation
Defense Evasion · Credential Access · Discovery · Lateral Movement
Command & Control · Exfiltration · Impact · Anti-Forensics · Authentication
```

Load defaults at **Alert Library → Load Defaults**.

### Sigma HQ integration

Sync 4 000+ rules from the official Sigma repository:

```bash
# Sync critical and high severity rules
curl -X POST http://localhost/api/v1/sigma/sync \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"levels": ["critical", "high"]}'
```

See [`docs/SIGMA_HQ_INTEGRATION.md`](docs/SIGMA_HQ_INTEGRATION.md) for full documentation.

### Sigma rule format

```yaml
title: Suspicious PowerShell Download Cradle
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'DownloadString'
    condition: selection
level: high
```

Import via **Alert Library → Import Sigma**, or generate from natural language with **Generate with AI**.

### YARA library

Manage rules at **YARA Library** — create, validate, and export. Run against any case via **Modules → YARA**.

---

## Analysis Modules

Run from the **Modules** panel on any case timeline page. Each module downloads source files from MinIO, runs analysis, and indexes results back into Elasticsearch.

| Module | Description |
|--------|-------------|
| **Hayabusa** | Sigma-based EVTX threat hunting (3 000+ built-in rules) |
| **YARA** | Pattern-based detection against your rule library |
| **RegRipper** | Deep Windows registry analysis |
| **Hindsight** | Browser forensics — Chrome, Firefox, Edge history, cookies, logins |
| **OleTools** | Office document macro / VBA detection |
| **PE Analysis** | Windows executable structure, imports, exports, sections |
| **Strings** | Extract and flag suspicious strings from binary files |
| **ExifTool** | EXIF and document metadata extraction |
| **Pattern Search** | Regex/keyword search across source files |
| **CTI IOC Match** | Match events against loaded STIX/TAXII IOCs |
| **Volatility3** | Memory forensics (Beta — requires memory dump) |

Custom modules can be added via the **Studio** without rebuilding the image.

---

## Studio — Custom Code

The **Studio** (sidebar → Studio) is a browser-based editor for extending the platform without image rebuilds.

### Custom ingesters

Write a Python class that parses a new file format:

```python
from base_plugin import BasePlugin, PluginContext, ParsedEvent

class MyFormatPlugin(BasePlugin):
    PLUGIN_NAME = "my-format"
    SUPPORTED_EXTENSIONS = [".myext"]

    def parse(self, file_path: str, context: PluginContext):
        with open(file_path) as f:
            for line in f:
                yield ParsedEvent(
                    timestamp="2024-01-01T00:00:00Z",
                    message=line.strip(),
                    source_file=file_path,
                )
```

Save the file in Studio → the processor picks it up on the next task without restarting.

### Custom analysis modules

```python
def run(context):
    findings = []
    for path in context.source_files:
        # ... analyse path ...
        findings.append({
            "filename": path,
            "message": "Suspicious pattern found",
            "level":   "high",
        })
    return findings
```

### Alert rules (Sigma or custom YAML)

The **Validate** button parses Sigma YAML and previews the generated Elasticsearch query before saving.

---

## Remote Artifact Collection

The **Collector** page generates a PowerShell or Bash script that collects forensic artifacts from live endpoints and uploads them to a case automatically.

1. Create a case and navigate to **Collector**
2. Select the OS and artifact types
3. Download or copy the generated script
4. Run on the endpoint as administrator / root:
   ```powershell
   # Windows (PowerShell, as Administrator)
   Invoke-WebRequest http://your-server/api/v1/collector/script/CASE_ID -OutFile collect.ps1
   .\collect.ps1
   ```
5. Artifacts appear in the case as soon as they upload

Set `FO_PUBLIC_URL` in `.env` (Docker) or `access.hostname` in `config.json` (K8s) so the generated script points to the correct server address.

---

## User Management

### Web UI

**Settings → Users** (admin only) — create, promote, and delete users.

### CLI

```bash
# Kubernetes
kubectl exec -n tracex deploy/api -- \
  python3 manage_users.py create analyst1 --role analyst --password changeme

# Docker
docker compose -f docker-compose.prod.yml exec api \
  python3 manage_users.py list
```

Available commands: `create`, `list`, `delete`, `password`

### Roles

| Action | Admin | Analyst |
|--------|-------|---------|
| Create / delete cases | ✅ | ✅ |
| Upload artifacts | ✅ | ✅ |
| Run modules and alert rules | ✅ | ✅ |
| Studio editor | ✅ | ✅ |
| Manage alert / YARA library | ✅ | ✅ |
| Manage users | ✅ | ❌ |
| Configure LLM / S3 | ✅ | ❌ |

---

## API

Interactive documentation is available at `/api/v1/docs` (Swagger UI) and `/api/v1/redoc`.

### Authentication

```bash
# Obtain a token
TOKEN=$(curl -s -X POST http://localhost/api/v1/auth/token \
  -d "username=admin&password=TracexAdmin1!" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Use it
curl http://localhost/api/v1/cases -H "Authorization: Bearer $TOKEN"
```

### Core endpoints

```
Cases
  GET    /api/v1/cases                        List all cases
  POST   /api/v1/cases                        Create a case
  DELETE /api/v1/cases/{id}                   Delete a case

Ingest
  POST   /api/v1/cases/{id}/ingest            Upload a file (or ZIP)
  GET    /api/v1/jobs/{id}                    Poll job status

Search
  POST   /api/v1/search                       Full-text search (ES query)
  GET    /api/v1/search/saved                 List saved searches
  POST   /api/v1/search/saved                 Save a search

Alert rules
  GET    /api/v1/alert-rules/library          List global rule library
  POST   /api/v1/alert-rules/library          Create a rule
  POST   /api/v1/alert-rules/sigma/parse      Validate + preview Sigma YAML
  POST   /api/v1/cases/{id}/alert-rules/run-library   Run all library rules

Modules
  POST   /api/v1/cases/{id}/modules/run       Run an analysis module
  GET    /api/v1/module-runs/{id}             Poll module run status
```

---

## Troubleshooting

### Services not starting (Docker)

```bash
./foctl logs all docker
# or
docker compose -f docker-compose.prod.yml logs --tail=50
```

### Pods not starting (Kubernetes)

```bash
./foctl status k8s
kubectl describe pod -n tracex <pod-name>
kubectl logs  -n tracex <pod-name>
```

### Elasticsearch not ready

```bash
# Docker
docker compose -f docker-compose.prod.yml exec elasticsearch \
  curl -sf http://localhost:9200/_cluster/health?pretty

# Kubernetes
kubectl exec -n tracex elasticsearch-0 -- \
  curl -sf http://localhost:9200/_cluster/health?pretty
```

### Ingest jobs stuck in PENDING

```bash
# Check queue lengths (Docker)
docker compose -f docker-compose.prod.yml exec redis redis-cli llen ingest

# Check worker logs
./foctl logs worker-ingest docker
./foctl logs worker-modules docker
```

### Reset admin password

```bash
# Docker
docker compose -f docker-compose.prod.yml exec api \
  python3 manage_users.py password admin --password newpassword

# Kubernetes
kubectl exec -n tracex deploy/api -- \
  python3 manage_users.py password admin --password newpassword
```

### Studio changes not taking effect

The processor hot-reloads custom plugins on the next task. If a change is not picked up:

```bash
# Docker — restart worker-ingest
docker compose -f docker-compose.prod.yml restart worker-ingest

# Kubernetes
kubectl rollout restart deployment/processor-deployment -n tracex
```

### Common error table

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| 502 Bad Gateway | API container not ready | Check `./foctl logs api` |
| Login returns 401 | JWT_SECRET mismatch after redeploy | Regenerate token; verify JWT_SECRET unchanged |
| Upload fails at 413 | nginx body size limit hit | Raise `client_max_body_size` in `nginx/nginx.prod.conf` |
| ES bulk errors in worker logs | Elasticsearch OOM or disk full | Raise `ES_HEAP_SIZE`; check disk space |
| No data after ingest | Wrong plugin matched | Check job logs — `artifact_type` shown in each log line |

---

## Development

### Project structure

```
tracex/
├── api/                     FastAPI backend
│   ├── main.py              App entry, router registration
│   ├── config.py            Settings from env; shared Redis pool
│   ├── auth/                JWT auth + RBAC
│   ├── routers/             API endpoints — one file per domain
│   ├── services/            ES / Redis / MinIO helpers
│   └── alert_rules/         Built-in Sigma rule YAMLs
├── processor/               Celery workers
│   ├── celery_app.py        Celery configuration + compression
│   ├── tasks/               ingest_task.py, module_task.py
│   └── utils/               ESBulkIndexer (requests.Session + gzip), file_type
├── plugins/                 Built-in artifact parsers (hot-loaded from shared volume)
│   ├── base_plugin.py       Plugin contract — BasePlugin, ParsedEvent
│   └── evtx/, mft/, ...     One directory per format
├── frontend/                React SPA
│   ├── src/pages/           Page-level components
│   ├── src/components/      Shared UI components
│   └── src/api/client.js    Typed API client (BASE = '/api/v1')
├── collector/               Remote collection script
├── k8s/                     Kubernetes manifests
│   ├── api/, processor/     Deployments, Services, HPAs
│   ├── redis/, minio/       StatefulSets and Services
│   └── storage/             PVC definitions
├── nginx/
│   └── nginx.prod.conf      Reverse proxy config (Docker mode)
├── docs/                    Extended documentation
├── docker-compose.yml       Development compose (live source mounts)
├── docker-compose.prod.yml  Production compose (baked images, nginx proxy)
├── .env.example             Environment variable template
├── config.json              Kubernetes deployment configuration
├── deploy.py                Kubernetes deploy script (build + apply + wait)
├── manage_users.py          CLI user management
└── foctl                    Unified deployment CLI
```

### Running locally (Docker dev mode)

```bash
# Dev compose mounts source code — hot-reload for API and workers
docker compose up -d

# Frontend dev server with hot-reload
# (started automatically by docker compose — access at http://localhost:3000)

# Stream API logs
docker compose logs -f api
```

### Running locally (k3d)

```bash
./foctl deploy k8s-new
# UI at http://localhost (or the port you configured)
```

### Elasticsearch indices

```
fo-case-{case_id}-evtx
fo-case-{case_id}-mft
fo-case-{case_id}-registry
... (one index per artifact type per case)
```

Template: `elasticsearch/index_templates/fo-cases-template.json`

---

## License

[MIT](LICENSE)

---

