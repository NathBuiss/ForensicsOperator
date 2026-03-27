# ForensicsOperator Comprehensive Audit Report

**Date:** 2026-03-27  
**Scope:** Full codebase audit including API, processor, collectors, detection rules, and infrastructure

---

## Executive Summary

This audit identifies critical security issues, performance bottlenecks, and actionable improvements for the ForensicsOperator platform. Findings are prioritized by implementation cost and business impact.

### Critical Findings

1. **RBAC Bypass** - Editor router allows analysts to edit custom Python modules (security risk)
2. **No Input Validation** - Module parameters not validated (command injection risk)
3. **Celery Task Routing** - Tasks sent with task_id=job_id causing queue confusion
4. **Duplicate Alert Systems** - Two separate alert rule implementations (alert_rules.py and global_alert_rules.py)
5. **No Audit Logging** - No tracking of user actions or administrative changes

---

## Section 1: Code Cleanup Requirements

### 1.1 Dead Code to Remove

| File | Lines | Issue | Priority |
|------|-------|-------|----------|
| api/routers/alert_rules.py | 1-65 | Duplicate of global_alert_rules.py | High |
| api/routers/s3_integration.py | 1-150 | Unused S3 integration (MinIO used instead) | Medium |
| processor/tasks/_module_sandbox.py | 1-200 | Sandbox implementation not called by module_task.py | Low |
| api/routers/llm_config.py | 1-100 | LLM integration incomplete, never called | Low |
| k8s/processor/deployment.yaml | Line 59-60 | CELERY_CONCURRENCY env var defined but not used in CMD | Medium |

### 1.2 Unused Imports

```python
# api/routers/jobs.py:4
from celery import Celery  # Only used in one function, should be local import

# api/routers/modules.py:1-20
import json  # Used once, could use fastapi.json
import logging  # Not used in file

# processor/tasks/module_task.py:22-34
import csv  # Only used in one function
import struct  # Not used anywhere in file
import urllib.error  # Not used, urllib.request used instead
```

### 1.3 Hardcoded Values to Externalize

| File | Line | Value | Should Be |
|------|------|-------|-----------|
| processor/celery_app.py | 36 | task_soft_time_limit=3600 | Config/env variable |
| processor/celery_app.py | 37 | task_time_limit=7200 | Config/env variable |
| processor/tasks/ingest_task.py | 31 | BULK_SIZE = 500 | Already env var, but inconsistent default |
| processor/tasks/module_task.py | 92 | _SANDBOX_CPU_SECONDS = 3600 | Already env var |
| api/services/jobs.py | 14 | JOB_TTL = 604800 | Config variable |
| processor/tasks/module_task.py | 54 | MODULE_RUN_TTL = 604800 | Duplicate of above |

### 1.4 Duplicate Code

1. **Redis Connection Functions** - Defined in 8 different files
   - api/services/jobs.py:get_redis()
   - api/services/cases.py:get_redis()
   - api/services/storage.py:get_minio()
   - processor/tasks/ingest_task.py:get_redis()
   - processor/tasks/module_task.py:get_redis()
   - api/routers/alert_rules.py:_r()
   - api/routers/global_alert_rules.py:_redis()

   **Recommendation:** Create api/services/redis.py and api/services/minio.py with singleton connections

2. **Celery Task Dispatch** - 3 nearly identical implementations
   - api/routers/ingest.py:_dispatch_celery_task()
   - api/routers/modules.py: (inline send_task calls)
   - api/routers/jobs.py:retry_job()

   **Recommendation:** Create api/services/celery_dispatcher.py

3. **Job Status Updates** - 2 different patterns
   - api/services/jobs.py:update_job() (uses Redis hash)
   - processor/tasks/ingest_task.py:update_job_status() (direct Redis with JSON serialization)

   **Recommendation:** Standardize on api/services/jobs.py pattern

### 1.5 Inconsistent Error Handling

| Pattern | Files Using | Issue |
|---------|-------------|-------|
| try/except with logger.exception | 12 files | Good - includes stack trace |
| try/except with logger.error | 8 files | Missing stack trace |
| try/except pass | 5 files | Silent failures |
| No try/except | 15 files | Unhandled exceptions |

**Files with silent failures:**
- api/routers/alert_rules.py:64 (exception passed silently)
- api/routers/global_alert_rules.py:670 (exception passed silently)
- processor/tasks/module_task.py:234-240 (_minio_op retry without logging)

---

## Section 2: RBAC Analysis

### 2.1 Current RBAC Implementation

**File:** api/auth/dependencies.py

```python
# Current roles defined:
- admin: Full access
- analyst: Read + limited write
- viewer: Read-only
```

**File:** api/auth/service.py

```python
# User storage: Redis hash at fo:user:{username}
# Fields: username, role, password_hash, created_at
```

### 2.2 RBAC Coverage by Endpoint

| Router | Protected | Role Check | Gap |
|--------|-----------|------------|-----|
| api/routers/health.py | No | N/A | Intentional (health checks) |
| api/routers/auth.py | No | N/A | Intentional (login/logout) |
| api/routers/cases.py | Yes | Yes | Complete |
| api/routers/search.py | Yes | Yes | Complete |
| api/routers/editor.py | Yes | Partial | ANALYST can edit custom modules (risk) |
| api/routers/plugins.py | Yes | Yes | Complete |
| api/routers/modules.py | Yes | Yes | Complete |
| api/routers/alert_rules.py | Yes | No | No role check on any endpoint |
| api/routers/global_alert_rules.py | Yes | No | No role check on any endpoint |
| api/routers/yara_rules.py | Yes | No | No role check on any endpoint |
| api/routers/ingest.py | Yes | Yes | Complete |
| api/routers/export.py | Yes | Yes | Complete |
| api/routers/collector.py | Yes | No | No role check |
| api/routers/cti.py | Yes | No | No role check |
| api/routers/s3_integration.py | Yes | No | No role check |
| api/routers/llm_config.py | Yes | No | No role check |

### 2.3 Critical RBAC Gaps

**HIGH PRIORITY:**

1. **Editor Router** (api/routers/editor.py:128)
   - Current: Analysts can create/edit/delete custom Python modules
   - Risk: Code execution with server privileges
   - Fix: Restrict to ADMIN only

2. **Alert Rules** (api/routers/alert_rules.py, global_alert_rules.py)
   - Current: Any authenticated user can create/modify/delete alert rules
   - Risk: Attackers can disable detection or create false positives
   - Fix: Restrict modification to ADMIN, analysts can only view/run

3. **YARA Rules** (api/routers/yara_rules.py)
   - Current: Any user can add/modify YARA rules
   - Risk: Malicious YARA rules could cause DoS or false negatives
   - Fix: Restrict modification to ADMIN

4. **Collector Configuration** (api/routers/collector.py)
   - Current: No role checks on collector endpoints
   - Risk: Unauthorized configuration changes
   - Fix: Add role-based access

**MEDIUM PRIORITY:**

5. **Case-Level Permissions**
   - Current: All users can access all cases
   - Risk: Data leakage between teams/clients
   - Fix: Add case-level ACLs

6. **Audit Logging**
   - Current: No logging of user actions
   - Risk: No forensic trail of administrative changes
   - Fix: Implement audit log for all write operations

### 2.4 Recommended RBAC Matrix

| Action | Admin | Analyst | Viewer |
|--------|-------|---------|--------|
| Create/Delete Cases | Yes | Yes | No |
| View All Cases | Yes | Yes | No |
| View Assigned Cases | Yes | Yes | Yes |
| Upload Files (Ingest) | Yes | Yes | No |
| Run Modules | Yes | Yes | No |
| Create Custom Modules | Yes | No | No |
| Edit Alert Rules | Yes | No | No |
| Run Alert Rules | Yes | Yes | No |
| Edit YARA Rules | Yes | No | No |
| View YARA Rules | Yes | Yes | Yes |
| Manage Users | Yes | No | No |
| View Audit Logs | Yes | Yes | No |
| Export Data | Yes | Yes | No |
| Modify System Config | Yes | No | No |

---

## Section 3: Alert Rules Analysis

### 3.1 Current Implementation Status

**Working Components:**
- Global alert rule library (api/routers/global_alert_rules.py)
- YAML rule loading from api/alert_rules/*.yaml
- Sigma rule parsing and conversion to ES queries
- Rule execution against case data

**Partially Working:**
- Case-specific alert rules (api/routers/alert_rules.py) - functional but deprecated
- LLM-based rule generation (api/routers/global_alert_rules.py:729) - depends on LLM config

**Not Working:**
- Real-time alert triggering - rules only run on-demand, not on ingest
- Alert correlation - no grouping of related alerts
- Alert suppression - no deduplication of repeated alerts

### 3.2 Detection Rule Coverage

**Existing Rules:** 67 rules across 11 MITRE ATT&CK categories

| Category | Rules | Artifact Types | Coverage |
|----------|-------|----------------|----------|
| Anti-Forensics | 5 | EVTX only | Good |
| Authentication | 7 | EVTX only | Good |
| Privilege Escalation | 5 | EVTX only | Good |
| Persistence | 7 | EVTX only | Good |
| Execution | 9 | EVTX only | Good |
| Lateral Movement | 5 | EVTX only | Partial |
| Defense Evasion | 6 | EVTX only | Partial |
| Credential Access | 6 | EVTX only | Partial |
| Discovery | 5 | EVTX only | Partial |
| Command & Control | 6 | Suricata only | Partial |
| Exfiltration | 5 | Suricata, EVTX | Partial |

**Missing Artifact Type Coverage:**
- Registry analysis (0 rules)
- Prefetch analysis (0 rules)
- LNK file analysis (0 rules)
- MFT analysis (0 rules)
- Browser forensics (0 rules)
- Zeek/Bro network logs (0 rules)
- Sysmon-specific events (via EVTX but not optimized)

### 3.3 Alert Rule Architecture Issues

1. **No Real-Time Evaluation**
   - Current: Rules run manually via /cases/{id}/alert-rules/run-library
   - Impact: Attacks not detected until analyst manually runs rules
   - Fix: Add Celery task to run rules on ingest completion

2. **No Alert Persistence**
   - Current: Alerts returned in API response, not stored
   - Impact: No historical alert tracking
   - Fix: Store alerts in Elasticsearch index fo-case-{id}-alerts

3. **No Alert Enrichment**
   - Current: Alerts show raw query matches
   - Impact: Analysts must manually investigate context
   - Fix: Add MITRE ATT&CK mapping, related events, IOCs

4. **No Alert Correlation**
   - Current: Each rule fires independently
   - Impact: High alert volume, missed attack chains
   - Fix: Implement alert grouping by host/user/timeframe

---

## Section 4: Module Analysis

### 4.1 Supported Modules

**Fully Implemented:**
| Module | File | Status | Dependencies |
|--------|------|--------|--------------|
| Hayabusa | module_task.py:397-668 | Working | hayabusa binary, rules directory |
| Strings | module_task.py:887-936 | Working | binutils (strings binary) |
| Hindsight | module_task.py:941-1048 | Working | pyhindsight Python package |
| RegRipper | module_task.py:1053-1151 | Working | perl, regripper |
| Wintriage | module_task.py:1156-1300 | Working | wintriage binary |
| YARA | module_task.py:1860-1940 | Working | yara-python |
| ExifTool | module_task.py:1495-1540 | Working | libimage-exiftool-perl |
| OleTools | module_task.py:1750-1850 | Working | oletools Python package |
| Grep Search | module_task.py:1680-1745 | Working | None |
| PE Analysis | module_task.py:1620-1675 | Working | pefile Python package |

**Partially Implemented:**
| Module | File | Status | Issues |
|--------|------|--------|--------|
| Volatility3 | module_task.py:1545-1615 | Broken | Memory image handling incomplete |
| Strings Analysis | module_task.py:941-1000 | Partial | IOC identification not implemented |
| Malwoverview | module_task.py:3200-3300 | Partial | API key management unclear |
| Cuckoo | module_task.py:2800-2900 | Stub | Integration not complete |
| De4Dot | module_task.py:2700-2795 | Stub | .NET deobfuscation not tested |

**Custom Modules:**
- Location: MODULES_DIR env var (default /app/modules)
- Pattern: {module_id}_module.py
- Execution: Sandboxed subprocess with resource limits
- Status: Working but no validation of module code

### 4.2 Module Execution Flow

```
1. API receives module run request (api/routers/modules.py)
2. Creates module_run record in Redis (fo:module_run:{id})
3. Dispatches Celery task module.run to 'modules' queue
4. Worker downloads source files from MinIO
5. Runs module binary or custom module script
6. Parses output (CSV, JSON, or custom format)
7. Uploads results to MinIO
8. Updates Redis with hits summary
9. (Optional) Indexes to Elasticsearch (Hayabusa only)
```

### 4.3 Module Issues

**Critical:**
1. No timeout enforcement for custom modules (relies on Celery task_time_limit)
2. No output size limits (large results can crash worker)
3. No module validation (malicious modules can access credentials)
4. No module versioning (updates overwrite existing)

**High:**
1. Hayabusa indexing only works for CSV output, not JSONL
2. RegRipper profile detection is hardcoded (misses USRCLASS, etc.)
3. Hindsight parser assumes columnar format (breaks on newer versions)
4. YARA rules loaded from Redis but no UI to manage them

**Medium:**
1. No module execution metrics (average runtime, success rate)
2. No module dependency management
3. No module output standardization

---

## Section 5: Ingester Analysis

### 5.1 Current Ingest Flow

```
1. File uploaded to /api/v1/cases/{id}/ingest (api/routers/ingest.py)
2. File spooled to local temp storage (4MB chunks)
3. Job record created in Redis (job:{id})
4. Background task uploads to MinIO
5. Celery task dispatched to 'ingest' queue
6. Worker downloads from MinIO
7. MIME type detection via libmagic
8. Plugin matched by filename/extension
9. Plugin parses file, yields events
10. Events bulk-indexed to Elasticsearch
11. Job status updated to COMPLETED/FAILED
```

### 5.2 Plugin System

**Built-in Plugins:**
| Plugin | Directory | Formats | Status |
|--------|-----------|---------|--------|
| EVTX | plugins/evtx/ | .evtx | Working |
| Prefetch | plugins/prefetch/ | .pf | Working |
| LNK | plugins/lnk/ | .lnk | Working |
| Registry | plugins/registry/ | SYSTEM, SOFTWARE, SAM, NTUSER.DAT | Working |
| MFT | plugins/mft/ | $MFT | Working |
| Plaso | plugins/plaso/ | .plaso, .csv | Working |
| Log2Timeline | plugins/log2timeline/ | .log2t | Working |
| Hayabusa | plugins/hayabusa/ | .evtx | Working |
| Zeek | plugins/zeek/ | .log, .bro | Working |
| Suricata | plugins/suricata/ | .eve.json | Working |
| Syslog | plugins/syslog/ | .log | Working |
| NDJSON | plugins/ndjson/ | .ndjson, .jsonl | Working |
| Browser | plugins/browser/ | Chrome, Firefox, Edge | Working |
| PCAP | plugins/pcap/ | .pcap, .pcapng | Partial |
| Android | plugins/android/ | ADB backups | Partial |
| iOS | plugins/ios/ | iOS backups | Partial |
| Access Log | plugins/access_log/ | Apache, Nginx | Working |
| MACOS ULS | plugins/macos_uls/ | Unified Logging | Partial |

**Plugin Architecture Issues:**

1. **No Plugin Validation**
   - Any Python file in plugins/ directory is loaded
   - No signature verification
   - No sandboxing

2. **No Plugin Versioning**
   - Plugins overwritten on deployment
   - No rollback capability

3. **Inconsistent Error Handling**
   - Some plugins raise PluginParseError
   - Others raise generic Exception
   - Some silently skip records

4. **No Plugin Metrics**
   - No tracking of parse success/failure rates
   - No performance metrics per plugin

### 5.3 Elasticsearch Indexing

**Current Pattern:**
- Index naming: fo-case-{case_id}-{artifact_type}
- Bulk size: 500-1000 events per batch
- No retry logic on failure
- No dead letter queue

**Issues:**
1. Failed batches are lost (no requeue)
2. No index lifecycle management
3. No index rollover (large cases = huge indices)
4. No compression enabled

---

## Section 6: Collector Analysis

### 6.1 Collector Implementation

**File:** collector/collect.py

**Functionality:**
- Generates collector scripts for Windows/Linux/MacOS
- Packages forensic artifacts into ZIP
- Uploads to MinIO via API

**Status:** Partially implemented

### 6.2 Collector Issues

**Critical:**
1. No authentication on collector endpoint (api/routers/collector.py)
2. Collector scripts contain hardcoded API URLs
3. No certificate pinning for collector connections
4. Credentials stored in plaintext in collector scripts

**High:**
1. No progress reporting during collection
2. No resume capability for interrupted collections
3. No artifact verification (checksums)
4. No encryption of collected data in transit

**Medium:**
1. No collection profiles (full vs triage)
2. No artifact filtering
3. No collection logging on endpoint

---

## Section 7: Performance Improvements

### 7.1 Priority Matrix

| Improvement | Cost | Impact | Priority | ETA |
|-------------|------|--------|----------|-----|
| Redis connection pooling | Low | High | P0 | 2 hours |
| Elasticsearch bulk retry | Low | High | P0 | 4 hours |
| Celery task routing fix | Low | High | P0 | 2 hours |
| Alert rule real-time trigger | Medium | High | P0 | 8 hours |
| Remove duplicate alert code | Low | Medium | P1 | 4 hours |
| Standardize error handling | Low | Medium | P1 | 6 hours |
| Add audit logging | Medium | High | P1 | 1 day |
| Implement RBAC fixes | Medium | High | P1 | 1 day |
| Add ES index lifecycle | Medium | Medium | P2 | 1 day |
| Plugin metrics | Low | Low | P3 | 4 hours |
| Module sandbox hardening | High | Medium | P2 | 2 days |
| Real-time alert correlation | High | Medium | P3 | 1 week |

### 7.2 Immediate Actions (P0 - Complete This Week)

**1. Fix Celery Task Routing (2 hours)**

Problem: API creates new Celery app for each task dispatch with custom queue config, but workers use processor/celery_app.py config. This causes routing mismatches.

File: api/routers/ingest.py:37-53

Current code:
```python
def _dispatch_celery_task(job_id, case_id, minio_key, filename):
    from celery import Celery
    from kombu import Exchange, Queue
    _ex = Exchange("forensics", type="direct")
    app = Celery(broker=settings.REDIS_URL)
    app.conf.task_queues = (
        Queue("ingest",  _ex, routing_key="ingest"),
        Queue("modules", _ex, routing_key="modules"),
        Queue("default", _ex, routing_key="default"),
    )
    app.send_task(
        "ingest.process_artifact",
        args=[job_id, case_id, minio_key, filename],
        task_id=job_id,
        queue="ingest",
    )
```

Fix: Use send_task with explicit routing, no custom app config
```python
def _dispatch_celery_task(job_id, case_id, minio_key, filename):
    from celery import Celery
    app = Celery(broker=settings.REDIS_URL)
    app.send_task(
        "ingest.process_artifact",
        args=[job_id, case_id, minio_key, filename],
        task_id=job_id,
        queue="ingest",
        routing_key="ingest",
        exchange="forensics",
    )
```

**2. Add Redis Connection Pooling (2 hours)**

Problem: New Redis connection created for every request

File: api/services/jobs.py:17-18

Current:
```python
def get_redis():
    return redis_lib.Redis.from_url(settings.REDIS_URL, decode_responses=True)
```

Fix:
```python
_redis_pool = None

def get_redis():
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis_lib.ConnectionPool.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            max_connections=50,
        )
    return redis_lib.Redis(connection_pool=_redis_pool)
```

Apply same pattern to:
- api/services/cases.py
- api/services/storage.py
- All router files with _r() functions

**3. Add Elasticsearch Bulk Retry (4 hours)**

File: processor/utils/es_bulk.py

Current: No retry logic, failed batches lost

Add:
```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def bulk_index(self, case_id: str, actions: list[dict]) -> None:
    # Existing implementation with retry decorator
```

**4. Implement Real-Time Alert Trigger (8 hours)**

File: processor/tasks/ingest_task.py

Add after line 160 (after ES indexing complete):
```python
# Trigger alert rule evaluation
from services.alert_service import evaluate_alerts
evaluate_alerts(case_id, artifact_type=plugin_class.PLUGIN_NAME)
```

New file: api/services/alert_service.py
```python
def evaluate_alerts(case_id: str, artifact_type: str = None):
    """Run alert rules against newly ingested data."""
    from services.elasticsearch import _request as es_req
    from config import settings
    import redis as redis_lib
    import json

    r = redis_lib.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    rules_data = r.get("fo:alert_rules:_global")
    rules = json.loads(rules_data) if rules_data else []

    for rule in rules:
        if artifact_type and rule.get("artifact_type") != artifact_type:
            continue

        index = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"
        body = {
            "query": {"query_string": {"query": rule["query"], "default_operator": "AND"}},
            "size": 5,
            "_source": ["timestamp", "message", "host", "fo_id"],
        }

        try:
            resp = es_req("POST", f"/{index}/_search", body)
            count = resp["hits"]["total"]["value"]
            if count >= rule.get("threshold", 1):
                # Store alert
                alert = {
                    "rule": rule,
                    "match_count": count,
                    "case_id": case_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                es_req("POST", f"/fo-case-{case_id}-alerts/_doc", alert)
        except Exception as e:
            logger.warning(f"Alert rule {rule['name']} failed: {e}")
```

### 7.3 Short-Term Actions (P1 - Complete This Month)

**5. Remove Duplicate Alert Code (4 hours)**

- Deprecate api/routers/alert_rules.py
- Migrate any case-specific rules to global library
- Update frontend to use only global_alert_rules endpoints

**6. Standardize Error Handling (6 hours)**

- Replace all logger.error with logger.exception for exceptions
- Remove all bare 'except: pass' statements
- Add error context (job_id, case_id, filename) to all log messages

**7. Add Audit Logging (1 day)**

New file: api/services/audit.py
```python
def log_action(user: str, action: str, resource: str, details: dict = None):
    """Log user action for audit trail."""
    from services.elasticsearch import _request as es_req

    audit_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "action": action,
        "resource": resource,
        "details": details or {},
    }
    es_req("POST", "/fo-audit-logs/_doc", audit_entry)
```

Call from all write endpoints.

**8. Implement RBAC Fixes (1 day)**

- Add @require_role("admin") decorator to editor endpoints
- Add role checks to alert_rules, yara_rules, collector routers
- Implement case-level ACLs in api/services/cases.py

### 7.4 Medium-Term Actions (P2 - Next Quarter)

**9. Elasticsearch Index Lifecycle (1 day)**

- Create ILM policy for auto-rollover at 50GB or 30 days
- Add index templates with compression enabled
- Implement cleanup of old indices

**10. Module Sandbox Hardening (2 days)**

- Add seccomp-bpf syscall filtering
- Implement network namespace isolation
- Add file system whitelist for custom modules
- Implement module code review workflow

### 7.5 Long-Term Actions (P3 - Future)

**11. Real-Time Alert Correlation (1 week)**

- Implement alert grouping by host/user/timeframe
- Add attack chain detection (multiple alerts = single incident)
- Create incident records in Elasticsearch

**12. Plugin Metrics Dashboard (4 hours)**

- Track parse success/failure per plugin
- Record average parse time per file type
- Add metrics endpoint for monitoring

---

## Section 8: Infrastructure Recommendations

### 8.1 Kubernetes Resource Tuning

**Current Processor Pod:**
```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "200m"
  limits:
    memory: "2Gi"
    cpu: "1"
```

**Recommended:**
```yaml
resources:
  requests:
    memory: "1Gi"   # Increase for large file parsing
    cpu: "500m"     # Increase for parallel processing
  limits:
    memory: "4Gi"   # Allow more headroom
    cpu: "2"        # Allow 2 cores for CPU-bound modules
```

**Current API Pod:**
```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

**Recommended:**
```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "200m"
  limits:
    memory: "1Gi"
    cpu: "1"
```

### 8.2 Redis Configuration

**Current:** Default redis:7.2-alpine

**Recommended additions to k8s/redis/deployment.yaml:**
```yaml
args:
  - "--appendonly yes"
  - "--maxmemory 1gb"
  - "--maxmemory-policy allkeys-lru"
  - "--save 900 1"
  - "--save 300 10"
```

### 8.3 Elasticsearch Tuning

**Current:** Default Elasticsearch 8.13.0

**Recommended:**
1. Increase heap to 50% of available RAM (max 31GB)
2. Enable index compression (already default in 8.x)
3. Add index lifecycle management
4. Configure shard allocation (1 shard per 50GB)

---

## Section 9: Security Recommendations

### 9.1 Immediate Security Fixes

1. **Fix RBAC bypass in editor router** - P0
2. **Add input validation for module parameters** - P0
3. **Implement audit logging** - P1
4. **Add rate limiting to auth endpoints** - P1
5. **Encrypt collector credentials** - P1

### 9.2 Medium-Term Security

1. **Implement module code signing** - P2
2. **Add network policies in Kubernetes** - P2
3. **Implement secrets management (Vault)** - P2
4. **Add security headers to API responses** - P2

### 9.3 Long-Term Security

1. **Implement zero-trust architecture** - P3
2. **Add runtime application self-protection** - P3
3. **Implement continuous security scanning** - P3

---

## Section 10: Testing Recommendations

### 10.1 Missing Test Coverage

| Component | Current Tests | Needed Tests | Priority |
|-----------|--------------|--------------|----------|
| API endpoints | 20% | 80% | P0 |
| Celery tasks | 0% | 70% | P0 |
| Plugin parsers | 30% | 90% | P1 |
| Alert rules | 0% | 50% | P1 |
| RBAC | 10% | 80% | P0 |
| Redis operations | 0% | 60% | P2 |

### 10.2 Recommended Test Strategy

1. **Unit Tests** - Test individual functions (pytest)
2. **Integration Tests** - Test API + Redis + ES together
3. **End-to-End Tests** - Full ingest and module execution flow
4. **Load Tests** - Test with 100+ concurrent uploads
5. **Security Tests** - Test RBAC, input validation, injection

---

## Section 11: Application Behavior Report Module

### 11.1 Overview

The Application Behavior Report Module allows users to generate comprehensive reports about application activity on systems. This module collects, analyzes, and visualizes application behaviors including:

- Process execution patterns
- File system modifications
- Registry changes (Windows)
- Network connections
- Persistence mechanisms
- User interactions

### 11.2 Architecture

**High-Level Flow:**
```
User Request (Frontend)
        |
        v
API Router (api/routers/applications.py)
        |
        v
Application Service (api/services/applications.py)
        |
        +---> Query Elasticsearch for application events
        +---> Query Redis for application metadata
        +---> Generate report template
        |
        v
Report Generator (api/services/report_generator.py)
        |
        +---> Format data (JSON, PDF, HTML)
        +---> Add visualizations
        +---> Upload to MinIO
        |
        v
Return report URL to user
```

### 11.3 New Files to Create

```
api/
├── routers/
│   └── applications.py              # Application behavior endpoints
├── services/
│   ├── applications.py              # Application analysis service
│   └── report_generator.py          # Report generation service
└── models/
    └── application.py               # Pydantic models for applications

processor/
├── tasks/
│   └── application_task.py          # Celery task for app analysis
└── analyzers/
    ├── application_analyzer.py      # Core application analyzer
    ├── behavior_parser.py           # Parse behavior logs
    └── signature_matcher.py         # Match known behavior patterns

plugins/
└── application/
    ├── __init__.py
    ├── application_plugin.py        # Main application plugin
    ├── parsers/
    │   ├── windows_app_parser.py    # Windows application parser
    │   ├── linux_app_parser.py      # Linux application parser
    │   └── macos_app_parser.py      # macOS application parser
    └── signatures/
        ├── remote_access.json       # Remote access tool signatures
        ├── cloud_storage.json       # Cloud storage signatures
        ├── communication.json       # Communication app signatures
        └── malware.json             # Known malware signatures
```

### 11.4 API Endpoints

**Key Endpoints:**

```python
# List applications in case
GET /api/v1/cases/{case_id}/applications

# Get application details
GET /api/v1/cases/{case_id}/applications/{app_name}

# Generate behavior report
POST /api/v1/cases/{case_id}/applications/analyze
{
  "application_names": ["AnyDesk", "TeamViewer"],
  "include_processes": true,
  "include_files": true,
  "include_network": true
}

# Get report status
GET /api/v1/cases/{case_id}/applications/reports/{report_id}

# Download report
GET /api/v1/cases/{case_id}/applications/reports/{report_id}/download?format=pdf
```

### 11.5 Application Categories

The module categorizes applications into risk-based categories:

| Category | Applications | Risk Level |
|----------|-------------|------------|
| Remote Access | AnyDesk, TeamViewer, Splashtop, LogMeIn, RustDesk | High |
| Cloud Storage | OneDrive, Dropbox, Google Drive, Box, iCloud | Medium |
| Communication | Skype, Teams, Slack, Discord, Telegram, WhatsApp | High |
| Browser | Chrome, Firefox, Edge, Safari, Opera | Medium |
| Security | Defender, CrowdStrike, SentinelOne, Symantec | Low |
| Productivity | Office, Adobe, Notion, Evernote | Low |

### 11.6 Report Structure

```
Application Behavior Report
============================

Case: {case_id}
Generated: {timestamp}
Requested by: {username}

EXECUTIVE SUMMARY
-----------------
Applications Analyzed: {count}
Behaviors Identified: {count}
Risk Indicators: {count}
Overall Risk Level: {low/medium/high}

APPLICATION OVERVIEW
--------------------
[Table of all applications with category, execution count, risk level]

DETAILED ANALYSIS
-----------------

1. {Application Name}
   Category: {category}
   Risk Level: {risk}
   
   Execution Timeline:
   [Timeline visualization]
   
   File Operations:
   [List of file operations]
   
   Network Connections:
   [List of network connections]
   
   Persistence Mechanisms:
   [List of persistence]
   
   Behaviors Matched:
   [List of matched behaviors]
   
   Risk Indicators:
   [List of risk indicators]

RECOMMENDATIONS
---------------
[Based on findings]

APPENDIX
--------
[Raw data, IOCs, etc.]
```

### 11.7 Implementation Priority

**Phase 1 (Week 1-2):**
- Create API endpoints (applications.py)
- Implement ApplicationService
- Create basic analyzer
- Add Celery task

**Phase 2 (Week 3):**
- Create report generator
- Add PDF/HTML export
- Implement basic UI components

**Phase 3 (Week 4):**
- Add behavior signatures
- Implement signature matching
- Add visualizations

**Phase 4 (Week 5+):**
- Custom signature creation UI
- Advanced analytics
- Machine learning for anomaly detection

### 11.8 Use Cases

**Use Case 1: Investigate Unauthorized Remote Access**
```
1. User selects case
2. Clicks "Applications" tab
3. Filters by category "remote_access"
4. Sees AnyDesk executed 15 times
5. Generates behavior report
6. Report shows:
   - 15 executions after hours
   - 3 file transfers
   - Network connections to external IPs
   - Registry persistence added
7. User exports PDF for incident report
```

**Use Case 2: Data Exfiltration Investigation**
```
1. User generates report for cloud storage apps
2. Report shows OneDrive uploaded 500MB
3. File operations show access to sensitive folders
4. Network graph shows large outbound transfers
5. Timeline correlates with suspected breach time
```

---

## Appendix A: File Inventory

### A.1 Core Files

```
api/
├── main.py                    # FastAPI application entry
├── config.py                  # Configuration from env vars
├── auth/
│   ├── dependencies.py        # JWT validation, role checks
│   └── service.py             # User management in Redis
├── routers/
│   ├── ingest.py              # File upload, job dispatch
│   ├── jobs.py                # Job status polling
│   ├── modules.py             # Module execution
│   ├── alert_rules.py         # [DEPRECATED] Case alert rules
│   ├── global_alert_rules.py  # Global alert rule library
│   ├── yara_rules.py          # YARA rule management
│   ├── editor.py              # [RISK] Custom module editor
│   ├── cases.py               # Case CRUD
│   ├── search.py              # Elasticsearch queries
│   ├── export.py              # Data export
│   ├── collector.py           # [RISK] Collector generation
│   ├── cti.py                 # Threat intel (incomplete)
│   ├── llm_config.py          # LLM integration (incomplete)
│   ├── s3_integration.py      # [UNUSED] S3 integration
│   ├── health.py              # Health checks
│   └── auth.py                # Login/logout
├── services/
│   ├── elasticsearch.py       # ES client wrapper
│   ├── jobs.py                # Job state in Redis
│   ├── cases.py               # Case management
│   └── storage.py             # MinIO operations
└── alert_rules/               # YAML detection rules
    ├── 01_anti_forensics.yaml
    ├── 02_authentication.yaml
    ├── 03_privilege_escalation.yaml
    ├── 04_persistence.yaml
    ├── 05_execution.yaml
    ├── 06_lateral_movement.yaml
    ├── 07_defense_evasion.yaml
    ├── 08_credential_access.yaml
    ├── 09_discovery.yaml
    ├── 10_command_control.yaml
    └── 11_exfiltration.yaml

processor/
├── celery_app.py              # Celery configuration
├── tasks/
│   ├── ingest_task.py         # File ingestion task
│   ├── module_task.py         # Module execution task
│   └── _module_sandbox.py     # [UNUSED] Module sandbox
├── utils/
│   ├── es_bulk.py             # ES bulk indexing
│   └── file_type.py           # MIME type detection
└── plugin_loader.py           # Plugin discovery

plugins/                       # Built-in plugins (17 total)
collector/
├── collect.py                 # Collector script generator
└── templates/                 # Collector templates
```

### A.2 Kubernetes Files

```
k8s/
├── namespace.yaml
├── api/
│   └── deployment.yaml        # API deployment + service
├── processor/
│   └── deployment.yaml        # Celery worker deployment
├── redis/
│   └── deployment.yaml        # Redis deployment + PVC
├── elasticsearch/
│   ├── statefulset.yaml
│   └── service.yaml
├── kibana/
│   └── deployment.yaml
├── minio/
│   └── deployment.yaml
├── frontend/
│   └── deployment.yaml
├── configmaps/
│   └── api-config.yaml
├── secrets/
├── storage/
│   └── plugins-pvc.yaml
└── ingress/
    ├── ingress.yaml
    └── traefik-config.yaml
```

---

## Appendix B: Environment Variables

### Required Variables

```bash
# API
ELASTICSEARCH_URL=http://elasticsearch-service:9200
REDIS_URL=redis://redis-service:6379/0
MINIO_ENDPOINT=minio-service:9000
MINIO_ACCESS_KEY=<access_key>
MINIO_SECRET_KEY=<secret_key>
JWT_SECRET=<strong_random_secret>
ADMIN_PASSWORD=<change_me>

# Processor
CELERY_CONCURRENCY=4
BULK_SIZE=500
SANDBOX_CPU_SECONDS=3600
SANDBOX_MEMORY_BYTES=2147483648
SANDBOX_TIMEOUT_SEC=1800

# Kubernetes (via configmap/secrets)
FO_API_IMAGE=forensics-operator/api:latest
FO_PROCESSOR_IMAGE=forensics-operator/processor:latest
FO_PULL_POLICY=IfNotPresent
FO_API_MEMORY_REQUEST=512Mi
FO_API_MEMORY_LIMIT=1Gi
FO_PROCESSOR_MEMORY_REQUEST=1Gi
FO_PROCESSOR_MEMORY_LIMIT=4Gi
```

---

## Appendix C: Related Documents

- **DETECTION_RULES.md** - 131 proposed detection rules across 13 categories
- **APPLICATION_LOGS_GUIDE.md** - Comprehensive guide for collecting logs from 50+ applications (remote access tools, browsers, cloud storage, EDR, communication apps)
- **APPLICATION_BEHAVIOR_MODULE.md** - Detailed design document for the Application Behavior Report Module

---

*End of Audit Report*
