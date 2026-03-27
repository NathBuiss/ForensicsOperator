# TraceX — Digital Forensics Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.25+-blue.svg)](https://kubernetes.io/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)

A **Kubernetes-native digital forensics and incident response (DFIR) platform**. Ingest forensic artifacts from anywhere, automatically parse them, run Sigma/YARA detection rules, analyze threats with AI assistance, and investigate incidents — all from a single web interface.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Ingestion Formats](#ingestion-formats)
- [Detection Rules](#detection-rules)
- [Analysis Modules](#analysis-modules)
- [Studio Editor](#studio-editor)
- [Threat Intelligence](#threat-intelligence)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [User Management](#user-management)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## Features

| Category | What it does |
|----------|--------------|
| **Multi-format ingestion** | 20+ forensic formats: EVTX, Prefetch, MFT, Registry, LNK, PCAP, Plaso, Syslog, browser DBs, Android/iOS, Zeek, Suricata |
| **Full-text search** | Elasticsearch-backed search with facets, saved queries, timeline view, CSV export |
| **Detection rules** | 145+ built-in Sigma rules; create, import, AI-generate, and run against any case |
| **YARA scanning** | Rule library with per-rule validation; run selected rules against file collections |
| **Analysis modules** | Hayabusa, RegRipper, Hindsight, OleTools, PE analysis, strings extraction, pattern search, CTI matching |
| **Studio editor** | Browser-based IDE for custom ingesters, modules, YARA rules, and alert rules |
| **Remote collection** | Deploy a collector script to gather artifacts from live endpoints |
| **Threat intelligence** | STIX/TAXII feed integration, IOC matching across cases |
| **S3 integration** | Import artifacts directly from AWS S3 or MinIO-compatible buckets |
| **AI assistance** | LLM-powered rule generation, alert analysis, and search suggestions (OpenAI, Anthropic, Ollama) |
| **RBAC** | Admin and analyst roles with JWT authentication |
| **Metrics dashboard** | Real-time cluster health monitoring |

---

## Architecture

```
┌─────────────────────────────────────┐
│         Frontend  (React + Vite)    │
│             Nginx · Port 3000       │
└────────────────┬────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│          API Server  (FastAPI)      │
│               Port 8000             │
└──────┬──────────┬────────┬──────────┘
       │          │        │
  ┌────▼───┐ ┌───▼────┐ ┌─▼──────────────┐
  │ Redis  │ │ MinIO  │ │ Elasticsearch  │
  │ :6379  │ │ :9000  │ │    :9200       │
  └────────┘ └────────┘ └────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│     Processor  (Celery Workers)     │
│    Queues: ingest · modules         │
└─────────────────────────────────────┘
```

**Components:**

| Component | Technology | Role |
|-----------|-----------|------|
| Frontend | React 18 + Vite + Tailwind | Web UI served by Nginx |
| API | FastAPI 0.100+ / Python 3.10+ | REST API, auth, job dispatch |
| Processor | Celery 5.3+ | Async artifact parsing & module execution |
| Search | Elasticsearch 8.13+ | Full-text search and analytics |
| State | Redis 7.2+ | Job state, rule library, sessions |
| Storage | MinIO | Object storage for uploaded artifacts |

---

## Quick Start

### Prerequisites

- **Docker** — for building images
- **Kubernetes cluster** — any of: k3d (local dev), k3s, minikube, kind, or Docker Desktop
- **Python 3.10+** and **kubectl** on your PATH

### Deploy

```bash
# 1. Clone
git clone https://github.com/your-org/forensicsOperator.git
cd forensicsOperator

# 2. Deploy (builds images, applies manifests, waits for readiness)
python3 deploy.py
```

### Access the UI

```bash
# Print URLs and pod status
python3 deploy.py --status
```

Default credentials:
- **Username:** `admin`
- **Password:** `admin`

> Change the default password immediately via **Settings > Users**.

### Local development with k3d

```bash
# Install k3d
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# Create a cluster with a LoadBalancer
k3d cluster create tracex --port "8080:80@loadbalancer"

# Deploy
python3 deploy.py
# UI is at http://localhost:8080
```

---

## Ingestion Formats

Upload files individually, or ZIP archives containing multiple artifacts.

| Artifact | Plugin | Recognised by |
|----------|--------|---------------|
| Windows Event Logs | `evtx` | `.evtx` |
| Prefetch files | `prefetch` | `.pf` |
| Master File Table | `mft` | `$MFT` |
| Registry hives | `registry` | `NTUSER.DAT`, `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY` |
| LNK / Shortcut | `lnk` | `.lnk` |
| Plaso / L2T | `plaso` | `.plaso`, `.json`, `.jsonl` |
| Syslog | `syslog` | `.log` |
| PCAP | `pcap` | `.pcap`, `.pcapng` |
| Browser databases | `browser` | `History`, `Cookies`, `places.sqlite` |
| Android | `android` | `mmssms.db`, `contacts2.db`, `calllog.db` |
| iOS | `ios` | `sms.db`, `call_history.db`, `AddressBook.sqlitedb` |
| Suricata | `suricata` | `eve.json` |
| Zeek | `zeek` | `conn.log`, `dns.log`, `http.log` |
| Web server logs | `access_log` | `access.log`, `access_log` |

Custom ingesters can be written in Python and deployed via the **Studio**.

---

## Detection Rules

### Sigma Rules (Alert Library)

145+ built-in detection rules across 13 MITRE ATT&CK-aligned categories:

```
Initial Access · Execution · Persistence · Privilege Escalation
Defense Evasion · Credential Access · Discovery · Lateral Movement
Command & Control · Exfiltration · Impact · Anti-Forensics · Authentication
```

**Usage:**

1. Go to **Alert Library** in the sidebar
2. Click **Load Defaults** to seed the built-in rules
3. Click **New Rule** to create a custom rule, or **Import Sigma** to import YAML
4. Use **Generate with AI** to create rules from natural language
5. Run all library rules against a case from the case's **Alert Rules** panel
6. Click the ▶ button on any rule to run it individually

The **Sigma Validator** (toolbar button on the Alert Library page) lets you paste any Sigma YAML and immediately verify it parses correctly.

### YARA Rules

The **YARA Library** page manages your YARA rule collection:

- Create, edit, and delete rules
- Inline **YARA Validator** to verify syntax before saving
- Export the entire library as a single `.yar` file
- When running the YARA module on a case, choose specific rules to apply

---

## Analysis Modules

Run from the **Modules** section on any case timeline page.

| Module | Description |
|--------|-------------|
| **Hayabusa** | Sigma-based EVTX threat hunting |
| **YARA** | Pattern matching with library or custom rules |
| **RegRipper** | Windows registry forensic analysis |
| **Strings** | Extract and flag suspicious strings from binaries |
| **Hindsight** | Browser forensics (Chrome, Firefox) via pyhindsight |
| **OleTools** | Office document macro / VBA detection |
| **PE Analysis** | Windows executable structure inspection |
| **ExifTool** | File metadata extraction |
| **Pattern Search** | Regex/keyword search across source files |
| **CTI IOC Match** | Match events against loaded threat-intel IOCs |
| **Wintriage** | Windows triage (runs wintriage and ingests output) |
| **Cuckoo Sandbox** | Dynamic malware analysis (requires external Cuckoo) |

The module results panel has a collapsible filter bar — click the funnel icon to show/hide filters when you have many results.

---

## Studio Editor

The **Studio** (sidebar → Studio) is a browser-based code editor with four sections:

### Ingesters
Write Python classes that parse new file formats. Files are saved to the ingesters volume and hot-loaded by the processor.

```python
from base_plugin import BasePlugin, PluginContext, ParsedEvent

class MyFormatIngester(BasePlugin):
    PLUGIN_NAME = "my-format"
    SUPPORTED_EXTENSIONS = [".myext"]

    def parse(self, file_path: str, context: PluginContext):
        with open(file_path) as f:
            for line in f:
                yield ParsedEvent(
                    timestamp="2024-01-01T00:00:00Z",
                    message=line.strip(),
                )
```

### Modules
Write Python functions that analyse source files and return structured findings.

### YARA Rules
Create and edit YARA rules directly in the Studio with the same dark-background code editor. Changes are saved to the YARA library immediately. Click **Validate** to check syntax before saving.

### Alert Rules
Create and edit alert rules as Sigma YAML or custom YAML in the Studio. The **Validate** button calls the Sigma parser to preview the ES query. On save, Sigma rules are automatically parsed into ES query format; custom YAML rules (`name:` + `query:`) are saved as-is.

**Sigma format** (recommended):
```yaml
title: Suspicious PowerShell Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
level: high
```

**Custom format:**
```yaml
name: Failed Logins
description: Detect brute force attempts
artifact_type: evtx
query: evtx.event_id:4625
threshold: 5
```

---

## Threat Intelligence

1. Go to **Threat Intel** in the sidebar
2. Add a STIX/TAXII feed or import a STIX 2.x bundle manually
3. Pull IOCs from configured feeds
4. Run **IOC Match** from any case to find indicators across all ingested data

---

## Configuration

### Environment variables

Configured via `k8s/configmaps/api-config.yaml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTICSEARCH_URL` | `http://elasticsearch-service:9200` | Elasticsearch endpoint |
| `REDIS_URL` | `redis://redis-service:6379/0` | Redis endpoint |
| `MINIO_ENDPOINT` | `minio-service:9000` | MinIO endpoint |
| `MINIO_BUCKET` | `forensics-cases` | Storage bucket |
| `AUTH_ENABLED` | `true` | Enable JWT authentication |
| `JWT_SECRET` | `CHANGE_ME_IN_PRODUCTION` | JWT signing secret |
| `JWT_EXPIRE_HOURS` | `8` | Token lifetime |

### LLM integration

Configure an LLM provider at **Settings > LLM Config**:

- **OpenAI** — provide API key + model (e.g. `gpt-4o`)
- **Anthropic** — provide API key + model (e.g. `claude-opus-4-6`)
- **Ollama** — provide base URL + model (e.g. `llama3`)

Once configured, AI features appear throughout the UI: rule generation, alert analysis, search assist.

### S3 integration (optional)

Configure at **Settings > S3 Storage** to import artifacts from AWS S3, MinIO, Wasabi, or GCS.

---

## Deployment

### Environments

| Environment | Command | Notes |
|-------------|---------|-------|
| Local (k3d) | `python3 deploy.py` | Builds and loads images into k3d cluster |
| CI / staging | `python3 deploy.py` | Requires `kubectl` pointed at target cluster |
| Production | `python3 deploy.py` | Use a private registry and proper secrets |

### Useful deploy commands

```bash
# Full deploy (build + apply)
python3 deploy.py

# Status and URLs
python3 deploy.py --status

# Stream logs
python3 deploy.py --logs api
python3 deploy.py --logs processor
python3 deploy.py --logs frontend
```

### Scaling

```bash
# Scale processor workers for higher throughput
kubectl -n forensics-operator scale deployment processor-deployment --replicas=4

# Check pod status
kubectl -n forensics-operator get pods
```

---

## User Management

### Via web UI

**Settings > Users** (admin only) — create, edit, and delete users.

### Via CLI

```bash
# Create admin user
python3 manage_users.py create admin --role admin --password changeme

# Create analyst user
python3 manage_users.py create analyst1 --role analyst --password changeme

# List users
python3 manage_users.py list

# Delete user
python3 manage_users.py delete username

# Reset password
python3 manage_users.py password username --password newpassword
```

**Roles:**

| Action | Admin | Analyst |
|--------|-------|---------|
| Create / delete cases | ✅ | ✅ |
| Upload files | ✅ | ✅ |
| Run modules & rules | ✅ | ✅ |
| Manage alert/YARA library | ✅ | ✅ |
| Studio editor | ✅ | ✅ |
| Manage users | ✅ | ❌ |
| Configure LLM / S3 | ✅ | ❌ |

---

## Troubleshooting

### Pods not starting

```bash
python3 deploy.py --status
kubectl -n forensics-operator describe pod <pod-name>
```

### Ingestion failures

```bash
# Stream processor logs
python3 deploy.py --logs processor

# Retry a failed job from the case timeline UI (kebab menu on the job row)
```

### Elasticsearch health

```bash
kubectl -n forensics-operator exec -it elasticsearch-0 -- \
  curl localhost:9200/_cluster/health?pretty
```

### Reset admin password

```bash
python3 manage_users.py password admin --password newpassword
```

### Studio changes not taking effect

The processor hot-reloads custom ingesters. If a change doesn't apply, restart the processor:
```bash
kubectl -n forensics-operator rollout restart deployment/processor-deployment
```

---

## Development

### Project structure

```
forensicsOperator/
├── api/                    # FastAPI backend
│   ├── main.py             # App entry point, router registration
│   ├── config.py           # Settings from env
│   ├── auth/               # JWT auth + RBAC
│   ├── routers/            # API endpoints (one file per domain)
│   ├── services/           # ES / Redis / MinIO helpers
│   └── alert_rules/        # Built-in Sigma rule YAMLs
├── processor/              # Celery workers
│   ├── tasks/              # ingest_task.py, module_task.py
│   └── utils/              # ES bulk, file type detection
├── plugins/                # Built-in artifact parsers
│   ├── base_plugin.py      # Plugin contract (BasePlugin)
│   └── evtx/, mft/, ...    # One directory per format
├── frontend/               # React SPA
│   ├── src/pages/          # Page components
│   ├── src/components/     # Shared UI components
│   └── src/api/client.js   # Typed API client
├── collector/              # Remote collection script
├── k8s/                    # Kubernetes manifests
├── deploy.py               # One-command deploy script
└── manage_users.py         # CLI user management
```

### Writing a custom ingester

1. Open **Studio > Ingesters** and click **New Ingester**
2. Name it (e.g. `my_format`) — a `my_format_ingester.py` stub is created
3. Implement the `parse()` generator method
4. Click **Validate** to check Python syntax
5. Click **Save** — the processor picks it up automatically

### Writing a custom analysis module

1. Open **Studio > Modules** and click **New Module**
2. Implement the `run()` function — return a list of finding dicts
3. Each dict needs at minimum: `filename`, `message`, `level`

### API documentation

Swagger UI: `http://<host>/api/v1/docs`
ReDoc:       `http://<host>/api/v1/redoc`

---

## License

MIT
