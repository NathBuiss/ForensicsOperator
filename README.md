# ForensicsOperator

A Kubernetes-native forensics analysis platform. Upload Windows forensics artefacts (Plaso timelines, Event Logs, Prefetch files, MFT, Registry hives, LNK files), have them automatically parsed and indexed into Elasticsearch, then explore them through a web UI or Kibana.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Component Breakdown](#component-breakdown)
3. [Prerequisites](#prerequisites)
4. [Quick Start — Local Development](#quick-start--local-development)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Configuration Reference](#configuration-reference)
7. [Supported File Formats](#supported-file-formats)
8. [Index System](#index-system)
9. [Plugin System](#plugin-system)
10. [API Reference](#api-reference)
11. [Directory Structure](#directory-structure)

---

## Architecture Overview

```
                        ┌─────────────────────────────────────────┐
                        │              Kubernetes Cluster         │
                        │                                         │
  Browser               │  ┌──────────┐     ┌──────────────────┐  │
     │                  │  │ Frontend │     │   Kibana (UI)    │  │
     │  HTTPS           │  │  React   │     │  (power users)   │  │
     ▼                  │  └────┬─────┘     └────────┬─────────┘  │
  ┌──────────┐          │       │                    │            │
  │  NGINX   │◄─────────┤  ┌────▼─────────────────────────────┐   │
  │ Ingress  │          │  │         FastAPI (api-service)    │   │
  └──────────┘          │  │  /cases  /ingest  /search  /jobs │   │
                        │  └────┬───────────────────┬─────────┘   │
                        │       │                   │             │
                        │  ┌────▼──────┐    ┌───────▼──────────┐  │
                        │  │   Redis   │    │  Elasticsearch   │  │
                        │  │ (job state│    │  (event index)   │  │
                        │  │  & queue) │    └──────────────────┘  │
                        │  └────┬──────┘                          │
                        │       │ Celery tasks                    │
                        │  ┌────▼──────────────────────────────┐  │
                        │  │     Celery Processor Workers      │  │
                        │  │  ┌──────────────────────────────┐ │  │
                        │  │  │       Plugin Loader          │ │  │
                        │  │  │  evtx / prefetch / plaso /   │ │  │
                        │  │  │  mft / registry / lnk / ...  │ │  │
                        │  │  └──────────────────────────────┘ │  │
                        │  └──────────┬────────────────────────┘  │
                        │             │                           │
                        │  ┌──────────▼───┐   ┌────────────────┐  │
                        │  │    MinIO     │   │  Plugins PVC   │  │
                        │  │ (raw files)  │   │ (shared volume)│  │
                        │  └──────────────┘   └────────────────┘  │
                        └─────────────────────────────────────────┘
```

**Data flow:**
1. Analyst uploads file via the web UI → API streams it to **MinIO** and enqueues a **Celery** task.
2. A **Processor** worker picks up the task, downloads the file from MinIO, detects the type, and dispatches to the matching **Plugin**.
3. The Plugin parses the file and yields normalised event dicts which are bulk-indexed into **Elasticsearch** under `fo-case-{caseId}-{artifactType}`.
4. The web UI queries the API → Elasticsearch for timeline display, search, and faceting.

---

## Component Breakdown

| Service | Image | Purpose |
|---|---|---|
| `frontend` | Node 20 / nginx | React SPA — timeline, search, ingest UI |
| `api` | Python 3.11 | FastAPI REST API, case/job management |
| `processor` | Ubuntu 22.04 + Plaso | Celery workers, file parsing |
| `elasticsearch` | 8.13.0 | Event index — one index per artifact type per case |
| `kibana` | 8.13.0 | Power-user query/dashboard UI |
| `redis` | 7.2 | Celery broker + job state store |
| `minio` | latest | S3-compatible raw evidence storage |

---

## Prerequisites

### Local development (docker-compose)

| Tool | Version | Install |
|---|---|---|
| Docker | ≥ 24 | https://docs.docker.com/get-docker/ |
| docker compose | v2 | bundled with Docker Desktop |
| make | any | `brew install make` (macOS) |

### Kubernetes deployment

| Tool | Version |
|---|---|
| kubectl | ≥ 1.27 |
| A cluster | k3s / minikube / GKE / EKS / AKS |
| NGINX Ingress Controller | any |
| A ReadWriteMany StorageClass | for the shared plugins volume |

---

## Quick Start — Local Development

> Everything runs via Docker. No local Python or Node.js required.

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd forensicsOperator

# 2. Start the full stack
make dev
# equivalently: docker compose up --build

# 3. Wait ~60 seconds for Elasticsearch to initialise, then open:
#   Web UI:     http://localhost:3000
#   API docs:   http://localhost:8000/docs
#   Kibana:     http://localhost:5601
#   MinIO:      http://localhost:9001  (user: minioadmin / minioadmin)
```

**First use:**
1. Open http://localhost:3000
2. Click **+ New** in the sidebar → enter a case name
3. Click the case → **Ingest** tab
4. Drag and drop forensics files (`.evtx`, `.plaso`, `.pf`, `$MFT`, etc.)
5. Watch the job progress bar; when done, click **Timeline** to explore events

**Tear down:**
```bash
make dev-down   # stops containers and removes volumes
```

---

## Kubernetes Deployment

All configuration lives in **`config.json`** — the only file you need to edit. The `deploy.py` script handles everything else: cluster creation, image builds, manifest templating, and health checks.

### 1. Edit config.json

Only change what you need — most defaults work out of the box.

```jsonc
{
  "cluster": {
    // Leave context empty to use whatever kubectl is already pointing at.
    // Set it to switch: e.g. "default", "k3s", "my-prod-cluster"
    "context": "",

    // Only set to true if you have NO cluster at all.
    // deploy.py will then install k3d and create one automatically.
    "auto_create_k3d": false
  },
  "access": {
    "hostname": "forensics.local",  // what you type in your browser
    "http_port": 80
  },
  "secrets": {
    "minio_access_key": "minioadmin",
    "minio_secret_key": "ForensicsM1ni0!"   // change this
  },
  "resources": {
    "elasticsearch_heap_mb": 512,           // use 256 if RAM is limited
    "elasticsearch_storage_gi": 10,
    "minio_storage_gi": 20,
    "redis_storage_gi": 2
  },
  "images": {
    // Leave empty to load images directly into the cluster (see below).
    // Set to push/pull via a registry: "docker.io/youruser/"
    "registry": "",
    "tag": "latest"
  }
}
```

### 2. Point kubectl at your cluster

For **k3s**, kubeconfig is usually at `/etc/rancher/k3s/k3s.yaml`:

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
# Verify it works:
kubectl get nodes
```

For any other cluster, just make sure `kubectl get nodes` returns something before running deploy.py.

### 3. Run deploy.py

```bash
python3 deploy.py
```

The script auto-detects your cluster engine and loads images accordingly:

| Engine detected | How images are loaded |
|---|---|
| k3d | `k3d image import` |
| k3s | `k3s ctr images import` (via sudo if needed) |
| minikube | `minikube image load` |
| kind | `kind load docker-image` |
| Docker Desktop | shared Docker daemon — already available |
| Any + registry set | `docker push` → cluster pulls |

The full deploy sequence:
1. Check Docker is running
2. Verify (or switch to) the correct kubectl context
3. Build the three Docker images
4. Load images into the cluster using the right method
5. Install NGINX Ingress Controller if not present
6. Apply all K8s manifests (values from config.json substituted in)
7. Wait for Elasticsearch to be ready
8. Apply the Elasticsearch index template
9. Print the `/etc/hosts` line to add and all URLs

### 4. Add the /etc/hosts entry (printed by the script)

```bash
echo "127.0.0.1  forensics.local" | sudo tee -a /etc/hosts
```

### Other commands

```bash
python3 deploy.py --no-build   # re-apply config changes without rebuilding images
python3 deploy.py --status     # show all pods, services, ingress
python3 deploy.py --logs api   # stream API logs
python3 deploy.py --destroy    # delete namespace (or k3d cluster if auto-created)

make deploy          # alias for python3 deploy.py
make status
make logs-api
make logs-proc
```

---

## Configuration Reference

All services are configured via environment variables. In Kubernetes, these come from `k8s/configmaps/api-config.yaml` and secrets.

### API & Processor — shared variables

| Variable | Default | Description |
|---|---|---|
| `ELASTICSEARCH_URL` | `http://elasticsearch-service:9200` | Elasticsearch HTTP endpoint |
| `REDIS_URL` | `redis://redis-service:6379/0` | Redis connection URL |
| `MINIO_ENDPOINT` | `minio-service:9000` | MinIO S3 endpoint (no `http://`) |
| `MINIO_ACCESS_KEY` | `minioadmin` | MinIO access key |
| `MINIO_SECRET_KEY` | `minioadmin` | MinIO secret key |
| `MINIO_BUCKET` | `forensics-cases` | Bucket name for raw evidence files |

### API-only variables

| Variable | Default | Description |
|---|---|---|
| `PLUGINS_DIR` | `/app/plugins` | Path to the mounted plugins volume |
| `DEFAULT_PAGE_SIZE` | `100` | Default events per page |
| `MAX_PAGE_SIZE` | `1000` | Maximum events per page |

### Processor-only variables

| Variable | Default | Description |
|---|---|---|
| `BULK_SIZE` | `500` | Events per Elasticsearch bulk request |

### Local development `.env` override

Create a `.env` file in the project root (it is gitignored) to override docker-compose defaults:

```env
MINIO_ACCESS_KEY=mykey
MINIO_SECRET_KEY=mysecretpassword
ELASTICSEARCH_URL=http://elasticsearch:9200
REDIS_URL=redis://redis:6379/0
```

---

## Supported File Formats

| Format | Extension / Filename | Parser library | Notes |
|---|---|---|---|
| Windows Event Log | `.evtx` | `python-evtx` | All channels: Security, System, Application, PowerShell, etc. |
| Plaso timeline | `.plaso` | `psort.py` or SQLite | Requires Plaso tools in the processor image (installed from GIFT PPA) |
| Windows Prefetch | `.pf` | `pyscca` (libscca) or raw struct | Win8.1+ (MAM compressed) requires `pyscca`; Win7 and older work without it |
| NTFS Master File Table | `$MFT` (exact filename) | `mft` Python lib or `analyzeMFT.py` | Include deleted files |
| Registry hives | `NTUSER.DAT`, `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY` | `python-registry` | Walks all keys and values |
| LNK shortcuts | `.lnk` | `LnkParse3` | Target path, timestamps, machine ID |

**Adding support for more formats:** See the [Plugin System](#plugin-system) section.

---

## Index System

Events are stored in Elasticsearch using the naming convention:

```
fo-case-{caseId}-{artifactType}
```

Examples:
```
fo-case-abc123def456-evtx
fo-case-abc123def456-prefetch
fo-case-abc123def456-mft
fo-case-abc123def456-registry
fo-case-abc123def456-lnk
fo-case-abc123def456-timeline   ← Plaso events with unknown type
```

**Why separate indices?**

- Each index can have type-specific fields (`evtx.event_id`, `prefetch.run_count`, etc.)
- The Timeline view queries `fo-case-{id}-*` (all types, sorted by timestamp)
- EVTX-only views query `fo-case-{id}-evtx`
- You can set per-type retention policies in Elasticsearch ILM

**Base event schema** (present in every document regardless of type):

```json
{
  "fo_id":         "uuid — unique event ID",
  "case_id":       "case this event belongs to",
  "artifact_type": "evtx | prefetch | mft | registry | lnk | timeline | ...",
  "source_file":   "minio://forensics-cases/cases/.../Security.evtx",
  "ingest_job_id": "celery task UUID",
  "ingested_at":   "ISO8601 — when it was indexed",
  "timestamp":     "ISO8601 UTC — the authoritative event time",
  "timestamp_desc":"what the timestamp means (e.g. 'Last Run Time')",
  "message":       "human-readable event summary",
  "is_flagged":    false,
  "analyst_note":  "",
  "tags":          [],
  "host":          { "hostname": "...", "fqdn": "...", "ip": [] },
  "user":          { "name": "...", "domain": "...", "sid": "..." },
  "process":       { "name": "...", "path": "...", "pid": 0, "cmdline": "..." },
  "network":       { "src_ip": "...", "src_port": null },
  "mitre":         { "tactic": "...", "technique_id": "T1234", "technique_name": "..." },
  "raw":           { }   // original parsed data — stored but not indexed
}
```

Artifact-specific fields live in a sub-object named after the type (e.g., `evtx.event_id`, `prefetch.run_count`).

**Querying in Kibana:** Use index pattern `fo-case-*` for all cases, or `fo-case-abc123*` for a single case.

---

## Plugin System

The plugin system lets you add support for new file formats or enrichment logic without modifying the core platform — just drop a Python file into the plugins volume.

### How it works

1. On each Celery task, the `PluginLoader` scans `/app/plugins/**/*_plugin.py` for classes that inherit from `BasePlugin`.
2. For the uploaded file, it calls `plugin_class.can_handle(file_path, mime_type)` on each loaded plugin until one matches.
3. The matching plugin is instantiated and its `parse()` generator is iterated, bulk-indexing yielded events.
4. The API exposes `GET /api/v1/plugins` and `POST /api/v1/plugins/reload` — no pod restarts needed.

### Writing a plugin

Create a file named `*_plugin.py` anywhere in the plugins volume:

```python
# plugins/my_format/my_format_plugin.py
from __future__ import annotations
import uuid
from pathlib import Path
from typing import Any, Generator
from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

class MyFormatPlugin(BasePlugin):
    PLUGIN_NAME            = "my_format"          # unique slug
    PLUGIN_VERSION         = "1.0.0"
    DEFAULT_ARTIFACT_TYPE  = "my_format"          # ES index suffix
    SUPPORTED_EXTENSIONS   = [".xyz"]             # file extensions
    SUPPORTED_MIME_TYPES   = ["application/x-xyz"]

    def parse(self) -> Generator[dict[str, Any], None, None]:
        try:
            # self.ctx.source_file_path is a pathlib.Path to the downloaded file
            with open(self.ctx.source_file_path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise PluginFatalError(f"Cannot open file: {e}")

        # Yield one dict per event
        yield {
            "fo_id":         str(uuid.uuid4()),
            "artifact_type": "my_format",         # routes to fo-case-{id}-my_format
            "timestamp":     "2025-01-01T00:00:00Z",  # ISO8601 UTC, required
            "message":       "Example event from my_format",  # required
            "host":          {"hostname": "target-host"},
            "my_format": {   # artifact-specific sub-object
                "custom_field": "value",
            },
            "raw": {},
        }

    def get_stats(self) -> dict:
        return {"records_read": 1}
```

**BasePlugin API:**

| Method/Attribute | Required | Description |
|---|---|---|
| `PLUGIN_NAME` | yes | Unique slug (used in logs and `/api/v1/plugins`) |
| `PLUGIN_VERSION` | yes | Semantic version string |
| `DEFAULT_ARTIFACT_TYPE` | yes | ES index suffix (e.g. `evtx`, `prefetch`) |
| `SUPPORTED_EXTENSIONS` | yes | List of file extensions like `[".evtx"]` |
| `SUPPORTED_MIME_TYPES` | yes | List of MIME types |
| `get_handled_filenames()` | no | Override to match by filename (e.g. `["$MFT"]`) |
| `can_handle(path, mime)` | no | Override for custom detection logic |
| `setup()` | no | Called once before `parse()` |
| `parse()` | **yes** | Generator — yield one event dict per record |
| `teardown()` | no | Called after `parse()` completes |
| `get_stats()` | no | Return dict included in job result |

**Errors:**
- `PluginParseError` — skips the current record, continues processing
- `PluginFatalError` — marks the entire job as FAILED

**The `PluginContext` object** (`self.ctx`):

| Field | Type | Description |
|---|---|---|
| `case_id` | str | Case this ingest belongs to |
| `job_id` | str | Celery task UUID |
| `source_file_path` | Path | Local path to the downloaded file |
| `source_minio_url` | str | Original MinIO URL for provenance |
| `config` | dict | Plugin-specific config (for future use) |
| `logger` | Logger | Python logger for this plugin |

### Deploying a plugin

**docker-compose (local dev):**
```bash
# Plugins directory is bind-mounted at ./plugins
# Just add your file and restart:
cp my_format/my_format_plugin.py plugins/my_format/
docker compose restart api processor
# Or hot-reload without restart:
curl -X POST http://localhost:8000/api/v1/plugins/reload
```

**Kubernetes:**
```bash
# Copy to the running processor pod
PROC_POD=$(kubectl get pod -n forensics-operator -l app=processor -o jsonpath='{.items[0].metadata.name}')
kubectl cp my_format/ forensics-operator/$PROC_POD:/app/plugins/

# Hot-reload (no pod restart needed)
make reload-plugins
# or:
curl -X POST http://forensics.example.com/api/v1/plugins/reload
```

The API pod also needs the plugin for the `/api/v1/plugins` listing. Since both share the same PVC, copying to one pod makes it visible to both after reload.

---

## API Reference

Base URL: `http://localhost:8000/api/v1` (local) or `https://forensics.example.com/api/v1` (K8s)

Interactive docs: `http://localhost:8000/docs`

### Cases

```
GET    /cases                         List all cases
POST   /cases                         Create a case  {"name": "...", "description": "...", "analyst": "..."}
GET    /cases/{caseId}                Get case + event counts + artifact types
PUT    /cases/{caseId}                Update case metadata
DELETE /cases/{caseId}                Delete case + all its Elasticsearch indices
```

### Ingest

```
POST   /cases/{caseId}/ingest         Upload files (multipart/form-data, field: "files")
                                      Returns: [{ "job_id": "...", "filename": "...", "status": "PENDING" }]
```

### Jobs

```
GET    /cases/{caseId}/jobs           List all jobs for a case
GET    /jobs/{jobId}                  Poll job status
                                      status: PENDING | RUNNING | COMPLETED | FAILED
                                      fields: events_indexed, plugin_used, plugin_stats, error
```

### Timeline & Search

```
GET    /cases/{caseId}/timeline       Paginated events sorted by timestamp
  ?artifact_type=evtx                 Filter to one index (omit for all)
  ?from=2025-01-01T00:00:00Z         Start of time range
  ?to=2025-12-31T23:59:59Z           End of time range
  ?page=0&size=100

GET    /cases/{caseId}/search         Full-text + field search
  ?q=mimikatz                         Elasticsearch query string syntax
  ?artifact_type=evtx
  ?hostname=DESKTOP-ABC
  ?username=jdoe
  ?event_id=4624
  ?channel=Security
  ?flagged=true
  ?tags=lateral_movement
  ?page=0&size=50

GET    /cases/{caseId}/search/facets  Aggregation buckets for filter UI
  ?q=...&artifact_type=...
  Returns: { facets: { by_artifact_type, by_hostname, by_username, by_event_id, by_channel } }
```

### Event Annotation

```
GET    /cases/{caseId}/events/{foId}          Full event (including raw)
PUT    /cases/{caseId}/events/{foId}/flag      Toggle is_flagged
PUT    /cases/{caseId}/events/{foId}/tag       Set tags  {"tags": ["lateral_movement"]}
PUT    /cases/{caseId}/events/{foId}/note      Set analyst note  {"note": "Confirmed malicious"}
```

### Plugins

```
GET    /plugins                        List loaded plugins + metadata
POST   /plugins/reload                 Rescan plugins volume and hot-reload
```

### Health

```
GET    /health                         Liveness probe (always 200)
GET    /health/ready                   Readiness probe (checks ES + Redis)
```

---

## Directory Structure

```
forensicsOperator/
│
├── api/                        FastAPI service
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 App factory, router registration
│   ├── config.py               Settings via environment variables
│   ├── routers/
│   │   ├── cases.py            /api/v1/cases CRUD
│   │   ├── ingest.py           /api/v1/cases/{id}/ingest (upload + dispatch)
│   │   ├── jobs.py             /api/v1/jobs status polling
│   │   ├── search.py           /api/v1/cases/{id}/timeline + /search
│   │   ├── plugins.py          /api/v1/plugins list + reload
│   │   └── health.py           /api/v1/health liveness/readiness
│   └── services/
│       ├── elasticsearch.py    Index management, search queries
│       ├── storage.py          MinIO upload/download helpers
│       ├── jobs.py             Job state read/write in Redis
│       └── cases.py            Case CRUD in Redis
│
├── processor/                  Celery worker service
│   ├── Dockerfile              Ubuntu 22.04 + Plaso (GIFT PPA) + pip deps
│   ├── requirements.txt
│   ├── celery_app.py           Celery app factory
│   ├── plugin_loader.py        Dynamic plugin discovery from /app/plugins
│   ├── tasks/
│   │   └── ingest_task.py      Main task: download → detect → plugin → index
│   └── utils/
│       ├── file_type.py        MIME detection (python-magic + extension fallback)
│       └── es_bulk.py          Elasticsearch bulk indexing helper
│
├── plugins/                    Plugin volume (shared between api + processor)
│   ├── base_plugin.py          BasePlugin ABC — the contract every plugin must satisfy
│   ├── evtx/
│   │   └── evtx_plugin.py      Windows Event Log parser (python-evtx)
│   ├── prefetch/
│   │   └── prefetch_plugin.py  Windows Prefetch parser (pyscca or raw struct)
│   ├── plaso/
│   │   └── plaso_plugin.py     Plaso storage reader (psort or SQLite)
│   ├── mft/
│   │   └── mft_plugin.py       NTFS MFT parser (mft lib or analyzeMFT.py)
│   ├── registry/
│   │   └── registry_plugin.py  Windows Registry hive parser (python-registry)
│   └── lnk/
│       └── lnk_plugin.py       Windows LNK shortcut parser (LnkParse3)
│
├── frontend/                   React SPA (Vite + Tailwind)
│   ├── Dockerfile              Node 20 build → nginx serve
│   ├── nginx.conf              SPA routing + caching headers
│   ├── package.json
│   ├── vite.config.js          Dev proxy: /api → localhost:8000
│   └── src/
│       ├── App.jsx             Router setup
│       ├── api/client.js       API client (fetch wrapper)
│       ├── pages/
│       │   ├── Dashboard.jsx   Case list with stats
│       │   ├── CaseDetail.jsx  Tab container (Timeline / Search / Ingest)
│       │   ├── Timeline.jsx    Infinite-scroll event list with filters
│       │   ├── Search.jsx      Full-text search + facet panel
│       │   ├── Ingest.jsx      File dropzone + job status cards
│       │   └── Plugins.jsx     Plugin management
│       └── components/
│           ├── layout/Layout.jsx  Sidebar + main content shell
│           └── shared/EventDetail.jsx  Slide-over panel for event annotation
│
├── k8s/                        Kubernetes manifests
│   ├── namespace.yaml
│   ├── ingress/ingress.yaml    NGINX Ingress (path routing for all services)
│   ├── storage/plugins-pvc.yaml  Shared RWX volume for plugins
│   ├── elasticsearch/          StatefulSet + headless service + data PVC
│   ├── kibana/                 Deployment + service
│   ├── redis/                  Deployment + service + data PVC
│   ├── minio/                  Deployment + service + data PVC + Secret
│   ├── api/                    Deployment (2 replicas) + service + init containers
│   ├── processor/              Deployment (2 replicas) + init containers
│   ├── frontend/               Deployment (2 replicas) + service
│   └── configmaps/api-config.yaml  Shared environment config
│
├── elasticsearch/
│   └── index_templates/
│       └── fo-cases-template.json   ES index template for all fo-case-* indices
│
├── scripts/
│   └── bootstrap.sh            Deploy to K8s + apply ES template
│
├── docker-compose.yml          Full local dev stack
├── Makefile                    build / push / deploy / logs / shell targets
├── .env.example                Template for local environment overrides
├── .gitignore
└── README.md                   This file
```

---

## Useful make targets

```bash
make dev              # Start local docker-compose stack (with live reload)
make dev-down         # Tear down local stack and remove volumes

make build            # Build all Docker images
make push             # Build and push to registry (set REGISTRY=...)

make deploy           # Apply all K8s manifests in dependency order
make undeploy         # Delete the entire forensics-operator namespace
make status           # kubectl get all -n forensics-operator

make logs-api         # Stream API logs
make logs-proc        # Stream processor logs

make shell-api        # bash into API pod
make shell-proc       # bash into processor pod

make reload-plugins   # HTTP POST to /api/v1/plugins/reload

# Deploy a custom plugin to a running cluster:
make copy-plugin PLUGIN=./my_plugin/my_plugin_plugin.py
```

---

## Troubleshooting

**"No plugin found for file.xyz"**
The file extension or MIME type isn't matched by any loaded plugin. Either:
- Rename the file to a supported extension (e.g., `Security` → `Security.evtx`)
- Write a plugin for the format and deploy it

**"psort.py: command not found" in processor logs**
The Plaso tools didn't install correctly. The processor Dockerfile uses the GIFT PPA; rebuild the image. Alternatively, the plaso plugin falls back to direct SQLite reading for `.plaso` files.

**"MAM-compressed prefetch requires pyscca"**
Windows 8.1+ Prefetch files use MAM compression. Install `libscca-python`:
```bash
# In the processor container
pip3 install libscca-python
# Then reload plugins
```

**Elasticsearch index not created after upload**
Check processor logs: `make logs-proc`. Common causes:
- MinIO not reachable (check `MINIO_ENDPOINT`)
- Elasticsearch not reachable (check `ELASTICSEARCH_URL`)
- No plugin matched the file (check file extension)

**Frontend shows blank page**
The API isn't reachable. Check `make logs-api` and verify the `ELASTICSEARCH_URL` and `REDIS_URL` env vars are correct. The `/api/v1/health/ready` endpoint will tell you which dependency is down.
