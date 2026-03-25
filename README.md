# TraceX — Forensic Investigation Platform

A Kubernetes-native digital forensics analysis platform for incident response teams. Ingest forensic artifacts, search timelines, run detection rules, and analyze threats — all from a single web interface.

## Features

- **Multi-format ingestion** — EVTX, Prefetch, MFT, Registry hives, LNK, Plaso/L2T, Syslog, PCAP, browser databases, Android/iOS artifacts, and more
- **Full-text search** — Elasticsearch-backed search with facets, saved queries, and CSV export
- **Sigma detection rules** — Import, create, and AI-generate Sigma rules; run against any case
- **Analysis modules** — Hayabusa, YARA, RegRipper, PE analysis, OLE/macro analysis, strings extraction
- **Threat intelligence** — STIX/TAXII feed integration, IOC matching across cases
- **Remote collection** — Deploy a collector script to gather artifacts from endpoints
- **S3 integration** — Import artifacts from external S3-compatible buckets
- **LLM analysis** — AI-powered rule generation and alert analysis (OpenAI, Anthropic, Ollama)
- **Performance dashboard** — Real-time cluster health monitoring
- **RBAC** — Admin and analyst roles with JWT authentication
- **Studio editor** — Build custom ingesters and modules from the browser

## Architecture

```
                  +-----------+
                  |  Frontend |  React + Vite
                  |  (Nginx)  |  Port 3000
                  +-----+-----+
                        |
                  +-----v-----+
                  |    API    |  FastAPI
                  |  Server   |  Port 8000
                  +--+--+--+--+
                     |  |  |
           +---------+  |  +---------+
           |            |            |
     +-----v----+ +----v-----+ +----v-----+
     |  Redis   | | Elastic  | |  MinIO   |
     | (state)  | | (search) | | (files)  |
     +----------+ +----------+ +----------+
           |
     +-----v------+
     | Processor  |  Celery workers
     | (parsing)  |  Queues: ingest, modules
     +------------+
```

## Quick Start

### Prerequisites

- **Docker** (for building images)
- **Kubernetes cluster** — any of:
  - [k3d](https://k3d.io) (recommended for local dev)
  - [k3s](https://k3s.io)
  - [minikube](https://minikube.sigs.k8s.io)
  - [kind](https://kind.sigs.k8s.io)
  - Docker Desktop with Kubernetes
  - Any remote cluster with `kubectl` configured

### 1. Clone the repository

```bash
git clone https://github.com/your-org/forensicsOperator.git
cd forensicsOperator
```

### 2. Deploy

```bash
python3 deploy.py
```

The deploy script will:
- Detect your Kubernetes environment
- Build Docker images for the API, processor, and frontend
- Apply all Kubernetes manifests in the correct order
- Wait for pods to be ready
- Create a default admin user

### 3. Access the UI

```bash
# Get the frontend URL
python3 deploy.py --status
```

Default credentials:
- **Username:** `admin`
- **Password:** `admin`

> Change the default password immediately after first login via Settings > Users.

### 4. Create your first case

1. Click **+ New Case** in the sidebar
2. Name your case (e.g., "Incident 2024-001")
3. Upload forensic artifacts (EVTX, prefetch, MFT, registry hives, etc.)
4. Wait for ingestion to complete
5. Browse the timeline or search for specific events

## Deployment Options

### Local development (k3d)

```bash
# Install k3d if not present
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# Create cluster and deploy
k3d cluster create tracex --port "8080:80@loadbalancer"
python3 deploy.py
```

### Production deployment

```bash
# Configure your kubeconfig to point to the production cluster
export KUBECONFIG=/path/to/kubeconfig

# Deploy with custom image registry
python3 deploy.py

# Check status
python3 deploy.py --status
```

### Environment variables

Configure via `k8s/configmaps/api-config.yaml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTICSEARCH_URL` | `http://elasticsearch-service:9200` | Elasticsearch endpoint |
| `REDIS_URL` | `redis://redis-service:6379/0` | Redis endpoint |
| `MINIO_ENDPOINT` | `minio-service:9000` | MinIO endpoint |
| `MINIO_BUCKET` | `forensics-cases` | Storage bucket name |
| `AUTH_ENABLED` | `true` | Enable JWT authentication |
| `JWT_SECRET` | `CHANGE_ME_IN_PRODUCTION` | JWT signing secret |
| `JWT_EXPIRE_HOURS` | `8` | Token lifetime |

## Usage Guide

### Ingesting Artifacts

Upload files directly or use ZIP archives containing multiple artifacts:

| Format | Plugin | Extensions |
|--------|--------|------------|
| Windows Event Logs | evtx | `.evtx` |
| Prefetch files | prefetch | `.pf` |
| Master File Table | mft | `$MFT` |
| Registry hives | registry | `NTUSER.DAT`, `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY` |
| Shortcut files | lnk | `.lnk` |
| Plaso/L2T output | plaso | `.plaso`, `.json`, `.jsonl` |
| Syslog | syslog | `.log` |
| Network captures | pcap | `.pcap`, `.pcapng` |
| Browser databases | browser | `History`, `Cookies`, `places.sqlite` |
| Android artifacts | android | `mmssms.db`, `contacts2.db`, `calllog.db` |
| iOS artifacts | ios | `sms.db`, `call_history.db`, `AddressBook.sqlitedb` |
| Suricata alerts | suricata | `eve.json` |
| Zeek logs | zeek | `conn.log`, `dns.log`, `http.log` |
| Web server logs | access_log | `access.log`, `access_log` |

### Detection Rules

1. Navigate to **Alert Rules** in the sidebar
2. Click **New Rule** to create a Sigma rule, or **Load Defaults** for built-in rules
3. Use **Generate with AI** to create rules from natural language descriptions
4. Click the play button on any rule to run it against a specific case

### Analysis Modules

Available modules (from the **Modules** section on any case):

| Module | Description | Status |
|--------|-------------|--------|
| Hayabusa | Sigma-based EVTX threat hunting | Available |
| YARA | Pattern matching with custom rules | Available |
| Strings Analysis | Extract strings from binaries | Available |
| PE Analysis | Windows executable analysis | Available |
| OLE Analysis | Office macro/VBA detection | Available |
| Pattern Search | Regex-based IOC search | Available |
| RegRipper | Registry forensic analysis | Available |
| CTI IOC Match | Match events against threat intel | Available |
| Cuckoo Sandbox | Dynamic malware analysis | Requires setup |
| Chainsaw | Sigma-based EVTX analysis | Coming soon |

### Threat Intelligence

1. Go to **Threat Intel** in the sidebar
2. Add a STIX/TAXII feed or import a STIX bundle manually
3. Pull IOCs from configured feeds
4. Run **IOC Match** against any case to find indicators

### Remote Collection

1. Navigate to **Collector**
2. Configure the collector endpoint
3. Download the collection script
4. Run the script on target endpoints
5. Artifacts are automatically uploaded and ingested

### S3 Integration

1. Go to **Settings** > **S3 Storage**
2. Configure your S3-compatible endpoint (AWS, MinIO, Wasabi, GCS)
3. Test the connection
4. Browse and import artifacts directly from S3 into cases

## Development

### Project Structure

```
forensicsOperator/
+-- api/                    # FastAPI backend
|   +-- routers/            # API endpoints
|   +-- services/           # Business logic
|   +-- auth/               # Authentication
|   +-- alert_rules/        # Built-in Sigma rules (YAML)
|   +-- modules_registry/   # Module definitions (YAML)
+-- processor/              # Celery worker
|   +-- tasks/              # Ingest + module tasks
|   +-- utils/              # Helpers
+-- plugins/                # Built-in artifact parsers
|   +-- base_plugin.py      # Plugin contract
|   +-- evtx/               # Windows Event Log parser
|   +-- prefetch/           # Prefetch parser
|   +-- ...                 # Other parsers
+-- frontend/               # React SPA
|   +-- src/pages/          # UI pages
|   +-- src/components/     # Shared components
|   +-- src/api/            # API client
+-- collector/              # Remote collection script
+-- k8s/                    # Kubernetes manifests
+-- deploy.py               # Deployment automation
+-- manage_users.py         # CLI user management
```

### Building a Custom Ingester

1. Create a file named `*_ingester.py` or `*_plugin.py`
2. Subclass `BasePlugin` from `plugins.base_plugin`
3. Implement `parse()` — yield dicts with `timestamp` and `message`
4. Upload via **Studio** or place in the plugins volume

```python
from plugins.base_plugin import BasePlugin

class MyIngester(BasePlugin):
    PLUGIN_NAME = "my_format"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "my_format"
    SUPPORTED_EXTENSIONS = [".myext"]

    def parse(self):
        with open(self.ctx.source_file_path) as f:
            for line in f:
                yield {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "message": line.strip(),
                }
```

### Managing Users via CLI

```bash
# Create admin user
python3 manage_users.py create admin --role admin --password changeme

# List users
python3 manage_users.py list

# Delete user
python3 manage_users.py delete username
```

## Troubleshooting

### Common Issues

**Pods not starting**
```bash
python3 deploy.py --status
kubectl -n forensics-operator get pods
kubectl -n forensics-operator describe pod <pod-name>
```

**Ingestion failures**
- Check processor logs: `python3 deploy.py --logs processor`
- Verify MinIO connectivity: `kubectl -n forensics-operator logs deploy/api-deployment | grep minio`
- Retry failed jobs from the case timeline UI

**Elasticsearch issues**
```bash
kubectl -n forensics-operator exec -it elasticsearch-0 -- curl localhost:9200/_cluster/health?pretty
```

**Reset admin password**
```bash
python3 manage_users.py create admin --role admin --password newpassword
```

## License

MIT
