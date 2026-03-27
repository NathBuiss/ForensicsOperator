# ForensicsOperator — Kubernetes-Native Digital Forensics Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.25+-blue.svg)](https://kubernetes.io/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Celery](https://img.shields.io/badge/celery-5.3+-green.svg)](https://docs.celeryq.dev/)

A complete **digital forensics and incident response (DFIR)** platform that runs on Kubernetes. Ingest forensic artifacts from anywhere, automatically parse them, run detection rules, analyze threats with AI assistance, and investigate incidents — all from a single web interface.

Built for **SOC teams**, **incident responders**, and **forensic analysts** who need to process large volumes of forensic data quickly and detect threats automatically.

---

## Table of Contents

- [What This Does](#what-this-does)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Components](#components)
  - [API Server](#api-server)
  - [Processor (Celery Workers)](#processor-celery-workers)
  - [Frontend](#frontend)
  - [Elasticsearch](#elasticsearch)
  - [Redis](#redis)
  - [MinIO](#minio)
- [Detection Rules](#detection-rules)
  - [Built-in Rules](#built-in-rules)
  - [Custom Rules](#custom-rules)
  - [Sigma HQ Integration](#sigma-hq-integration)
- [Analysis Modules](#analysis-modules)
- [Plugin System](#plugin-system)
- [Data Collection](#data-collection)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Performance Tuning](#performance-tuning)
- [Contributing](#contributing)
- [License](#license)

---

## What This Does

ForensicsOperator automates the **entire forensic investigation workflow**:

```
1. COLLECT → 2. INGEST → 3. PARSE → 4. DETECT → 5. ANALYZE → 6. REPORT
```

### Real-World Use Cases

**Incident Response:**
- Collect artifacts from compromised endpoints (Windows, Linux, macOS)
- Automatically parse EVTX, MFT, Registry, Prefetch, LNK files
- Run 145+ detection rules to identify attacker TTPs
- Generate incident reports with timeline and IOCs

**Threat Hunting:**
- Search across all cases with full-text Elasticsearch queries
- Run YARA rules against file collections
- Execute custom analysis modules (Hayabusa, RegRipper, etc.)
- Export findings to STIX/TAXII for threat intel sharing

**Malware Analysis:**
- Upload suspicious files for automated analysis
- Run PE analysis, strings extraction, OLE macros detection
- Integrate with VirusTotal, Any.run, Hybrid Analysis
- Correlate malware samples across multiple cases

**Compliance & Auditing:**
- Maintain chain of custody for all artifacts
- Audit log of all user actions
- Role-based access control (admin, analyst, viewer)
- Export reports in PDF/HTML/CSV formats

---

## Key Features

### 📥 Multi-Format Ingestion

Support for **20+ forensic artifact types**:

| Category | Formats |
|----------|---------|
| **Windows** | EVTX, Prefetch, MFT, Registry hives, LNK files |
| **Logs** | Syslog, Apache/Nginx access logs, Zeek, Suricata |
| **Memory** | Plaso/L2T, Volatility3 memory dumps |
| **Network** | PCAP, PCAPNG |
| **Browser** | Chrome, Firefox, Edge, Safari (history, cookies, logins) |
| **Mobile** | Android ADB backups, iOS backups |
| **Generic** | NDJSON, CSV, TXT |

Files are automatically detected by MIME type and routed to the appropriate parser.

### 🔍 Full-Text Search

- **Elasticsearch-backed** search across all ingested data
- **Faceted search** by artifact type, host, user, timestamp
- **Saved searches** for repeated queries
- **Export** search results to CSV

### 🎯 Detection Rules

**145+ built-in detection rules** covering:

- **MITRE ATT&CK** techniques (90%+ coverage)
- **Sigma** rule format (import/export supported)
- **13 categories**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Command & Control, Exfiltration, Impact, Anti-Forensics, Authentication
- **Artifact-specific rules**: EVTX, Suricata, Sysmon, Registry, Prefetch, LNK, MFT, Browser, Zeek

Rules can be:
- **Created** via web UI or YAML import
- **Edited** with Sigma YAML support
- **Generated** by AI (LLM integration)
- **Run** on-demand against any case
- **Triggered** automatically on ingest (optional)

### 🧩 Analysis Modules

Pre-built analysis tools:

| Module | Purpose | Status |
|--------|---------|--------|
| **Hayabusa** | Sigma-based EVTX threat hunting | ✅ Production |
| **YARA** | Pattern-based malware detection | ✅ Production |
| **RegRipper** | Windows registry analysis | ✅ Production |
| **Strings** | Extract strings from binaries | ✅ Production |
| **Hindsight** | Browser forensics (Chrome, Firefox) | ✅ Production |
| **OleTools** | OLE/Macro analysis | ✅ Production |
| **PE Analysis** | Portable Executable inspection | ✅ Production |
| **ExifTool** | Metadata extraction | ✅ Production |
| **Wintriage** | Windows triage collection | ✅ Production |
| **Volatility3** | Memory forensics | ⚠️ Beta |

**Custom modules** can be written in Python and deployed via the web UI (Studio editor).

### 🤖 AI Assistance

LLM integration for:

- **Sigma rule generation** from natural language descriptions
- **Alert analysis** and explanation
- **Incident summarization**
- **IOC extraction** from reports

Supports:
- OpenAI (GPT-4, GPT-3.5-turbo)
- Anthropic (Claude)
- Ollama (local models)

### 👥 Role-Based Access Control

Three roles with increasing permissions:

| Action | Admin | Analyst | Viewer |
|--------|-------|---------|--------|
| Create/Delete Cases | ✅ | ✅ | ❌ |
| Upload Files | ✅ | ✅ | ❌ |
| Run Analysis Modules | ✅ | ✅ | ❌ |
| Create Detection Rules | ✅ | ❌ | ❌ |
| Manage Users | ✅ | ❌ | ❌ |
| View All Cases | ✅ | ✅ | ❌ |
| View Assigned Cases | ✅ | ✅ | ✅ |

### 📊 Dashboards & Reporting

- **Kibana** integration for advanced visualizations
- **Built-in metrics** dashboard (API performance, queue health)
- **PDF/HTML report** generation for cases and analysis results
- **STIX/TAXII** export for threat intelligence sharing

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Frontend (React + Vite)                │
│                           Port 3000                         │
│                         (Nginx static)                      │
└────────────────────────────────┬────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    API Server (FastAPI)                     │
│                           Port 8000                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Auth      │  │   Cases     │  │   Detection Rules   │  │
│  │   (JWT)     │  │   Ingest    │  │   Sigma/YARA        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────┬─────────────┬─────────────┬───────────────────────┘
          │             │             │
    ┌─────▼─────┐ ┌────▼──────┐ ┌──▼──────────────┐
    │   Redis   │ │  MinIO    │ │  Elasticsearch  │
    │  (state)  │ │  (files)  │ │    (search)     │
    │  :6379    │ │  :9000    │ │      :9200      │
    └───────────┘ └───────────┘ └─────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│              Processor (Celery Workers × 2)                 │
│                    Queues: ingest, modules                  │
│  ┌──────────────────┐  ┌─────────────────────────────────┐  │
│  │  Ingest Tasks    │  │     Module Tasks                │  │
│  │  - Parse EVTX    │  │  - Hayabusa                     │  │
│  │  - Parse MFT     │  │  - YARA                         │  │
│  │  - Parse LNK     │  │  - RegRipper                    │  │
│  │  - Index to ES   │  │  - Custom modules               │  │
│  └──────────────────┘  └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Frontend** | React + Vite + TypeScript | Web UI |
| **API** | FastAPI + Python 3.10+ | REST API |
| **Workers** | Celery 5.3+ | Async task processing |
| **Search** | Elasticsearch 8.13+ | Full-text search, analytics |
| **Cache** | Redis 7.2+ | Job state, sessions, queues |
| **Storage** | MinIO | Object storage for artifacts |
| **Visualization** | Kibana 8.13+ | Dashboards, advanced queries |
| **Ingress** | Traefik 2.x | Reverse proxy, TLS termination |

---

## Quick Start

### Prerequisites

- **Docker** (for building images)
- **Kubernetes cluster** — any of:
  - k3s (recommended for production)
  - k3d (recommended for development)
  - minikube
  - kind
  - Docker Desktop Kubernetes
- **Python 3.10+** (for deploy script)
- **kubectl** configured for your cluster

### 5-Minute Deploy

```bash
# 1. Clone the repository
git clone https://github.com/yourorg/forensics-operator.git
cd forensics-operator

# 2. Edit config.json (optional — defaults work for most setups)
vim config.json

# 3. Deploy
python3 deploy.py
```

That's it! The deploy script will:
- Build Docker images (API, processor, frontend)
- Load images into your cluster
- Apply Kubernetes manifests
- Wait for services to be ready
- Print access URLs

### Access the Platform

```
Web UI:    https://forensics.local/
API docs:  https://forensics.local/api/v1/docs
Kibana:    https://forensics.local/kibana/
MinIO:     https://forensics.local/minio/
```

**Default credentials:**
- Username: `admin`
- Password: `TracexAdmin1!` (change immediately!)

### First Steps

1. **Create a case** — Click "New Case" and give it a name
2. **Upload artifacts** — Drag & drop EVTX, Prefetch, MFT, or any supported format
3. **Wait for processing** — Status changes: UPLOADING → PENDING → RUNNING → COMPLETED
4. **Search data** — Use the search bar or Kibana for advanced queries
5. **Run detection rules** — Click "Alert Rules" → "Run Library" to detect threats
6. **Run analysis modules** — Select files → "Run Module" → Choose Hayabusa/YARA/etc.

---

## Components

### API Server

**Location:** `api/`

FastAPI-based REST API that handles:
- Authentication (JWT)
- Case management
- File ingestion
- Job status polling
- Detection rule management
- Module execution
- User management

**Key Files:**
```
api/
├── main.py                 # FastAPI application entry
├── config.py               # Configuration from env vars
├── auth/
│   ├── dependencies.py     # JWT validation, role checks
│   └── service.py          # User management in Redis
├── routers/
│   ├── ingest.py           # File upload, job dispatch
│   ├── jobs.py             # Job status polling
│   ├── modules.py          # Module execution
│   ├── alert_rules.py      # Case-specific alert rules
│   ├── global_alert_rules.py  # Global rule library
│   ├── yara_rules.py       # YARA rule management
│   ├── editor.py           # Custom module editor (Studio)
│   ├── cases.py            # Case CRUD
│   ├── search.py           # Elasticsearch queries
│   ├── export.py           # Data export
│   ├── collector.py        # Collector script generation
│   ├── cti.py              # Threat intel (STIX/TAXII)
│   ├── llm_config.py       # LLM integration
│   ├── s3_integration.py   # S3 import (optional)
│   ├── health.py           # Health checks
│   └── auth.py             # Login/logout
└── services/
    ├── elasticsearch.py    # ES client wrapper
    ├── jobs.py             # Job state in Redis
    ├── cases.py            # Case management
    └── storage.py          # MinIO operations
```

**API Documentation:** `/api/v1/docs` (Swagger UI)

### Processor (Celery Workers)

**Location:** `processor/`

Celery workers that process forensic artifacts asynchronously.

**Queues:**
- **ingest** — I/O-bound file parsing and indexing
- **modules** — CPU-bound analysis (Hayabusa, YARA, etc.)
- **default** — Fallback for uncategorized tasks

**Key Files:**
```
processor/
├── celery_app.py           # Celery configuration
├── tasks/
│   ├── ingest_task.py      # File ingestion task
│   └── module_task.py      # Module execution task
├── utils/
│   ├── es_bulk.py          # ES bulk indexing
│   └── file_type.py        # MIME type detection
└── plugin_loader.py        # Plugin discovery
```

**Scaling:**
- Default: 2 replicas, 4 concurrency each (8 parallel tasks)
- Increase replicas for higher throughput
- Increase concurrency for I/O-bound workloads
- Decrease concurrency for CPU-bound modules

### Frontend

**Location:** `frontend/`

React + Vite single-page application.

**Features:**
- Case management
- File upload with progress
- Search interface
- Detection rule editor
- Module execution UI
- User management (admin)

**Build:**
```bash
cd frontend
npm install
npm run build
```

### Elasticsearch

**Location:** `elasticsearch/`

Elasticsearch 8.13+ cluster for search and analytics.

**Index Pattern:**
```
fo-case-{case_id}-{artifact_type}
Examples:
  - fo-case-abc123-evtx
  - fo-case-abc123-prefetch
  - fo-case-abc123-mft
```

**Index Template:** `elasticsearch/index_templates/fo-cases-template.json`

**Heap Size:** Configurable via `config.json` (default: 2GB)

### Redis

**Location:** `redis/`

Redis 7.2+ for:
- Celery message broker
- Job state storage
- User sessions
- Detection rules library

**Persistence:** AOF enabled (append-only file)

**Storage:** 10GB PVC (configurable)

### MinIO

**Location:** `minio/`

MinIO S3-compatible object storage for:
- Uploaded artifacts
- Analysis results
- Generated reports

**Bucket:** `forensics-cases`

**Storage:** Configurable via `config.json` (default: 100GB)

---

## Detection Rules

### Built-in Rules

**145 rules across 13 categories:**

| Category | Rules | Artifact Types |
|----------|-------|----------------|
| Anti-Forensics | 5 | EVTX |
| Authentication | 12 | EVTX |
| Privilege Escalation | 5 | EVTX |
| Persistence | 7 | EVTX, Registry |
| Execution | 15 | EVTX, PowerShell |
| Lateral Movement | 5 | EVTX |
| Defense Evasion | 6 | EVTX, Sysmon |
| Credential Access | 6 | EVTX |
| Discovery | 5 | EVTX |
| Command & Control | 6 | Suricata |
| Exfiltration | 5 | Suricata, EVTX |
| Initial Access | 6 | EVTX |
| Impact | 6 | EVTX |

**Rule Files:** `api/alert_rules/*.yaml`

### Custom Rules

Create rules via:

**1. Web UI:**
- Navigate to Alert Rules → New Rule
- Fill in name, description, query, threshold
- Select artifact type (EVTX, Suricata, etc.)

**2. YAML Import:**
```yaml
category: Execution
rules:
  - name: PowerShell Download Cradle
    description: PowerShell downloaded and executed a script
    artifact_type: evtx
    query: "evtx.event_id:4104 AND (message:*IEX* OR message:*Invoke-Expression*)"
    threshold: 1
```

**3. Sigma Import:**
- Paste Sigma YAML in the import dialog
- Automatically converted to Elasticsearch query

**4. AI Generation:**
- Click "Generate with AI"
- Describe the rule in natural language
- LLM generates Sigma YAML

### Sigma HQ Integration

**Sync 4000+ rules from Sigma HQ:**

```bash
# Sync critical rules only (recommended)
curl -X POST https://forensics.local/api/v1/sigma/sync \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"levels": ["critical"]}'

# Sync high + critical
curl -X POST https://forensics.local/api/v1/sigma/sync \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"levels": ["high", "critical"]}'

# Check sync status
curl https://forensics.local/api/v1/sigma/status \
  -H "Authorization: Bearer $TOKEN"
```

**Requirements:**
- `pysigma` Python package (optional, can be installed on-demand)
- Admin role

**Documentation:** `docs/SIGMA_HQ_INTEGRATION.md`

---

## Analysis Modules

### Built-in Modules

| Module | Description | Input | Output |
|--------|-------------|-------|--------|
| **Hayabusa** | Sigma-based EVTX threat hunting | EVTX files | Alerts, statistics |
| **YARA** | Pattern-based malware detection | Any file | Matches, rules fired |
| **RegRipper** | Windows registry analysis | Registry hives | Parsed keys, values |
| **Strings** | Extract strings from binaries | Any file | String list |
| **Hindsight** | Browser forensics | Chrome/Firefox/Edge | History, downloads, logins |
| **OleTools** | OLE/Macro analysis | Office documents | Macros, VBA code |
| **PE Analysis** | Portable Executable inspection | EXE, DLL | Imports, exports, sections |
| **ExifTool** | Metadata extraction | Images, documents | EXIF, metadata |
| **Wintriage** | Windows triage collection | Memory/disk | Triage report |
| **Grep Search** | Text search across files | Any text file | Matches |

### Custom Modules

Create custom analysis modules in Python:

**Example:** `modules/my_module.py`
```python
"""Custom analysis module."""
from processor.tasks.module_task import BaseModule

class MyModule(BaseModule):
    MODULE_NAME = "my_module"
    DESCRIPTION = "My custom analysis"
    
    def run(self):
        # Download source files from MinIO
        for file_path in self.source_files:
            # Analyze file
            results = self.analyze(file_path)
            
            # Report findings
            self.add_hit({
                "file": file_path,
                "finding": results,
                "severity": "high"
            })
        
        return self.summary()
```

**Deploy via UI:**
1. Navigate to Studio → Modules → New Module
2. Paste code
3. Click "Save & Deploy"
4. Module available in analysis dropdown

---

## Plugin System

### Built-in Plugins

**17 parsers for different artifact types:**

| Plugin | Formats | Status |
|--------|---------|--------|
| EVTX | .evtx | ✅ Production |
| Prefetch | .pf | ✅ Production |
| LNK | .lnk | ✅ Production |
| Registry | SYSTEM, SOFTWARE, SAM, NTUSER.DAT | ✅ Production |
| MFT | $MFT | ✅ Production |
| Plaso | .plaso, .csv | ✅ Production |
| Hayabusa | .evtx | ✅ Production |
| Zeek | .log, .bro | ✅ Production |
| Suricata | .eve.json | ✅ Production |
| Syslog | .log | ✅ Production |
| Browser | Chrome, Firefox, Edge | ✅ Production |
| PCAP | .pcap, .pcapng | ⚠️ Beta |
| Android | ADB backups | ⚠️ Beta |
| iOS | iOS backups | ⚠️ Beta |
| Access Log | Apache, Nginx | ✅ Production |
| NDJSON | .ndjson, .jsonl | ✅ Production |
| MACOS ULS | Unified Logging | ⚠️ Beta |

### Plugin Architecture

**Base Plugin:** `plugins/base_plugin.py`

```python
from abc import ABC, abstractmethod

class BasePlugin(ABC):
    PLUGIN_NAME: str
    SUPPORTED_FILES: list[str]
    
    @abstractmethod
    def parse(self) -> Generator[dict, None, None]:
        """Parse file and yield events."""
        pass
```

**Example Plugin:** `plugins/evtx/evtx_plugin.py`
```python
from plugins.base_plugin import BasePlugin
from Evtx.Evtx import Evtx

class EvtxPlugin(BasePlugin):
    PLUGIN_NAME = "evtx"
    SUPPORTED_FILES = ["*.evtx"]
    
    def parse(self):
        with Evtx(self.context.source_file_path) as evtx:
            for record in evtx.records():
                yield {
                    "timestamp": record.timestamp().isoformat(),
                    "event_id": record.event_id(),
                    "message": record.xml(),
                    "artifact_type": "evtx"
                }
```

### Custom Plugins

Create custom parsers via Studio editor:
1. Navigate to Studio → Plugins → New Plugin
2. Define `PLUGIN_NAME` and `SUPPORTED_FILES`
3. Implement `parse()` method
4. Save & deploy

---

## Data Collection

### Remote Collector

Deploy collector scripts on endpoints to gather artifacts:

**Supported OS:**
- Windows (PowerScript)
- Linux (Bash)
- macOS (Bash)

**Collected Artifacts:**
- Windows: EVTX, Prefetch, MFT, Registry, LNK, PowerShell logs
- Linux: Syslog, auth.log, bash_history, cron
- macOS: Unified logs, bash_history, launch agents

**Usage:**
1. Navigate to Collector → Generate Script
2. Select OS and artifacts
3. Download script
4. Run on endpoint (requires admin/root)
5. Script uploads artifacts to case automatically

**Example (Windows):**
```powershell
# Download collector script
Invoke-WebRequest -Uri "https://forensics.local/api/v1/collector/script/abc123" -OutFile "collect.ps1"

# Run as administrator
.\collect.ps1 -CaseId abc123
```

---

## Configuration

### config.json

Main configuration file:

```json
{
  "cluster": {
    "context": "k3d-forensics",
    "auto_create_k3d": false
  },
  "images": {
    "registry": "",
    "tag": "latest"
  },
  "namespace": "forensics-operator",
  "access": {
    "hostname": "forensics.local",
    "http_port": 80,
    "https_port": 443,
    "tls_cert": "",
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
  },
  "auth": {
    "auth_enabled": true,
    "jwt_expire_hours": 8
  }
}
```

### Environment Variables

**API:**
```bash
ELASTICSEARCH_URL=http://elasticsearch-service:9200
REDIS_URL=redis://redis-service:6379/0
MINIO_ENDPOINT=minio-service:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
JWT_SECRET=your_secret_here
ADMIN_PASSWORD=TracexAdmin1!
```

**Processor:**
```bash
REDIS_URL=redis://redis-service:6379/0
ELASTICSEARCH_URL=http://elasticsearch-service:9200
MINIO_ENDPOINT=minio-service:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
CELERY_CONCURRENCY=4
BULK_SIZE=500
SANDBOX_CPU_SECONDS=3600
SANDBOX_MEMORY_BYTES=2147483648
SANDBOX_TIMEOUT_SEC=1800
```

---

## Deployment

### Production Deployment (k3s)

```bash
# 1. Install k3s
curl -sfL https://get.k3s.io | sh -

# 2. Configure kubectl
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# 3. Clone and configure
git clone https://github.com/yourorg/forensics-operator.git
cd forensics-operator
vim config.json

# 4. Deploy
python3 deploy.py

# 5. Configure DNS/hosts
echo "YOUR_SERVER_IP  forensics.local" | sudo tee -a /etc/hosts

# 6. Access
open https://forensics.local
```

### Development Deployment (k3d)

```bash
# 1. Install k3d
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# 2. Create cluster
k3d cluster create forensics -p 80:80@loadbalancer -p 443:443@loadbalancer

# 3. Deploy
python3 deploy.py

# 4. Access
open https://forensics.local
```

### Update Deployment

```bash
# Pull latest changes
git pull

# Rebuild and redeploy
python3 deploy.py

# Or just restart pods (if images already in registry)
python3 deploy.py --restart
```

### Uninstall

```bash
# Delete namespace (keeps PVCs)
python3 deploy.py --destroy

# Or delete everything including PVCs
kubectl delete namespace forensics-operator
kubectl delete pvc -n forensics-operator --all
```

---

## API Reference

### Authentication

```bash
# Login
curl -X POST https://forensics.local/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "TracexAdmin1!"}'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}

# Use token in subsequent requests
curl https://forensics.local/api/v1/cases \
  -H "Authorization: Bearer eyJ..."
```

### Key Endpoints

**Cases:**
```bash
GET    /api/v1/cases              # List cases
POST   /api/v1/cases              # Create case
GET    /api/v1/cases/{id}         # Get case details
DELETE /api/v1/cases/{id}         # Delete case
```

**Ingest:**
```bash
POST   /api/v1/cases/{id}/ingest  # Upload files
GET    /api/v1/jobs/{id}          # Get job status
```

**Search:**
```bash
POST   /api/v1/search             # Search Elasticsearch
GET    /api/v1/search/saved       # List saved searches
POST   /api/v1/search/saved       # Save search
```

**Detection Rules:**
```bash
GET    /api/v1/alert-rules/library        # List rules
POST   /api/v1/alert-rules/library        # Create rule
PUT    /api/v1/alert-rules/library/{id}   # Update rule
DELETE /api/v1/alert-rules/library/{id}   # Delete rule
POST   /api/v1/alert-rules/sigma/parse    # Parse Sigma YAML
POST   /api/v1/alert-rules/library/sigma  # Import Sigma rule
POST   /api/v1/cases/{id}/alert-rules/run-library  # Run rules
```

**Modules:**
```bash
POST   /api/v1/cases/{id}/modules/run  # Run analysis module
GET    /api/v1/module-runs/{id}        # Get module run status
```

**Full API Docs:** `https://forensics.local/api/v1/docs`

---

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n forensics-operator

# Describe failing pod
kubectl describe pod -n forensics-operator <pod-name>

# Check logs
kubectl logs -n forensics-operator <pod-name>
```

### Elasticsearch Not Ready

```bash
# Check ES health
kubectl exec -n forensics-operator elasticsearch-0 -- \
  curl -s http://localhost:9200/_cluster/health

# Wait for yellow status
kubectl exec -n forensics-operator elasticsearch-0 -- \
  curl -s "http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=30s"
```

### Celery Tasks Stuck

```bash
# Check queue lengths
kubectl exec -n forensics-operator deploy/redis -- \
  redis-cli llen ingest
kubectl exec -n forensics-operator deploy/redis -- \
  redis-cli llen modules

# Check worker logs
kubectl logs -n forensics-operator -l app=processor --tail=100

# Recover stuck tasks (auto-done by deploy.py)
python3 deploy.py --restart
```

### Detection Rules Not Appearing

```bash
# Check if YAML files are in API pod
kubectl exec -n forensics-operator deploy/api -- \
  ls /app/alert_rules/*.yaml | wc -l
# Should return: 24

# If not, rebuild API image
python3 deploy.py
```

### Search Not Working

```bash
# Check Elasticsearch indices
kubectl exec -n forensics-operator elasticsearch-0 -- \
  curl -s http://localhost:9200/_cat/indices?v

# Check index template
kubectl exec -n forensics-operator elasticsearch-0 -- \
  curl -s http://localhost:9200/_index_template/fo-cases-template
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| 502 Bad Gateway | API pod not ready | `kubectl logs -n forensics-operator -l app=api` |
| Jobs stuck in PENDING | Workers not consuming | Check worker logs, verify Redis connection |
| Search returns 0 results | No data indexed | Check ingest job status, ES logs |
| Upload fails | MinIO unreachable | Check MinIO pod, credentials |
| Login fails | JWT secret mismatch | Verify `JWT_SECRET` in config |

---

## Security

### Hardening Recommendations

1. **Change default credentials immediately**
   ```json
   {
     "secrets": {
       "admin_password": "StrongPassword123!",
       "jwt_secret": "RandomSecretKey32Characters!"
     }
   }
   ```

2. **Enable TLS with valid certificate**
   ```json
   {
     "access": {
       "tls_cert": "/path/to/cert.pem",
       "tls_key": "/path/to/key.pem"
     }
   }
   ```

3. **Restrict API access**
   - Use network policies
   - Enable authentication
   - Use role-based access

4. **Secure MinIO**
   - Change default credentials
   - Enable TLS
   - Restrict bucket access

5. **Audit logging**
   - Enable audit log for all admin actions
   - Store logs externally
   - Monitor for suspicious activity

### RBAC Matrix

| Action | Admin | Analyst | Viewer |
|--------|-------|---------|--------|
| Create/Delete Cases | ✅ | ✅ | ❌ |
| View All Cases | ✅ | ✅ | ❌ |
| Upload Files | ✅ | ✅ | ❌ |
| Run Modules | ✅ | ✅ | ❌ |
| Create Custom Modules | ✅ | ❌ | ❌ |
| Edit Detection Rules | ✅ | ❌ | ❌ |
| Manage Users | ✅ | ❌ | ❌ |
| View Audit Logs | ✅ | ✅ | ❌ |

---

## Performance Tuning

### Elasticsearch

**Heap Size:**
```json
{
  "resources": {
    "elasticsearch_heap_mb": 4096  // Increase for large datasets
  }
}
```

**Shard Allocation:**
- 1 shard per 50GB of data
- Adjust via index template

### Processor Workers

**Increase Throughput:**
```yaml
# k8s/processor/deployment.yaml
spec:
  replicas: 4  # More pods
  containers:
  - env:
    - name: CELERY_CONCURRENCY
      value: "8"  # More tasks per pod
```

**CPU-Bound Modules:**
```yaml
resources:
  limits:
    cpu: "4"  # More CPU for Hayabusa, YARA
  requests:
    cpu: "2"
```

### API Server

**Increase Limits:**
```yaml
resources:
  limits:
    memory: "4Gi"
    cpu: "2"
```

### Redis

**Increase Memory:**
```yaml
args:
  - "--maxmemory 2gb"
  - "--maxmemory-policy allkeys-lru"
```

### Benchmark Targets

| Metric | Target |
|--------|--------|
| Ingest speed | 100 MB/min |
| Search latency | < 500ms |
| Rule evaluation | < 100ms/rule |
| Module execution | Varies by module |

---

## Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourorg/forensics-operator.git
cd forensics-operator

# Create k3d cluster
k3d cluster create forensics-dev -p 80:80@loadbalancer

# Deploy
python3 deploy.py

# Make changes, rebuild
python3 deploy.py --restart
```

### Code Style

- **Python:** Black, flake8
- **JavaScript:** ESLint, Prettier
- **TypeScript:** Strict mode enabled

### Testing

```bash
# API tests
cd api
pytest

# Processor tests
cd processor
pytest

# Frontend tests
cd frontend
npm test
```

### Pull Request Process

1. Fork repository
2. Create feature branch
3. Make changes
4. Run tests
5. Submit PR with description
6. Wait for review

### Documentation

- Update `README-GITHUB.md` for user-facing changes
- Update `docs/` for technical documentation
- Include examples for new features

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Support

- **Documentation:** `/docs` directory
- **API Docs:** `/api/v1/docs`
- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions

---

## Changelog

### v2.0.0 (2026-03-27)
- Added 78 new detection rules (145 total)
- Sigma HQ integration (4000+ rules)
- Application behavior report module
- Enhanced RBAC
- Performance improvements

### v1.0.0 (2026-01-01)
- Initial release
- 67 detection rules
- Basic RBAC
- Core ingestion and analysis

---

*Built with ❤️ by the ForensicsOperator Team*
