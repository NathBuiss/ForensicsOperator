# Deployment Fixes Summary

## Issues Fixed

### 1. **Celery Tasks Stuck in PENDING** ✅
**Problem:** Ingestion jobs were created but never processed, staying in `PENDING` status indefinitely.

**Root Cause:** Celery tasks were being sent to the wrong queue (`celery` instead of `ingest` or `modules`).

**Files Modified:**
- `api/routers/ingest.py` - Added explicit `exchange` and `routing_key` to `send_task()`
- `api/routers/modules.py` - Added explicit `exchange` and `routing_key` to `send_task()`
- `api/routers/s3_integration.py` - Added explicit `exchange` and `routing_key` to `send_task()`
- `api/routers/jobs.py` - Added explicit `exchange` and `routing_key` to `send_task()`

**What Changed:**
```python
# Before (broken):
app.send_task("ingest.process_artifact", args=[...], task_id=job_id, queue="ingest")

# After (fixed):
app.send_task(
    "ingest.process_artifact", 
    args=[...], 
    task_id=job_id, 
    queue="ingest",
    exchange=Exchange("forensics", type="direct"),  # ← Added
    routing_key="ingest",  # ← Added
)
```

### 2. **Hardware-Adaptive Resource Configuration** ✅
**Problem:** Default resource limits were too low, especially for MinIO (512Mi), causing slow uploads.

**Files Modified:**
- `config.json` - Added configurable resources for all components
- `k8s/api/deployment.yaml` - Uses `__FO_API_*__` variables from config
- `k8s/processor/deployment.yaml` - Uses `__FO_PROCESSOR_*__` variables from config
- `k8s/minio/deployment.yaml` - Uses `__FO_MINIO_*__` variables from config
- `k8s/frontend/deployment.yaml` - Uses `__FO_FRONTEND_*__` variables from config
- `deploy.py` - Added resource substitutions

**New Default Resources:**
| Component | Memory Request | Memory Limit | CPU Request | CPU Limit |
|-----------|---------------|--------------|-------------|-----------|
| API | 512Mi | 2Gi | 100m | 1000m |
| Processor | 1Gi | 8Gi | 500m | 4000m |
| MinIO | 1Gi | 4Gi | 250m | 1000m |
| Frontend | 128Mi | 512Mi | 50m | 200m |

**Customize in `config.json`:**
```json
{
  "resources": {
    "api_memory_request": "512Mi",
    "api_memory_limit": "2Gi",
    "minio_memory_request": "2Gi",  // Increase for better upload performance
    "processor_cpu_limit": "8000m"  // Increase for faster analysis
  }
}
```

### 3. **Traefik HTTP/2 Timeout Errors** ✅
**Problem:** `ERR_HTTP2_PROTOCOL_ERROR` during large file uploads.

**Solution:** Applied on server (not in code):
```bash
kubectl patch deployment traefik -n kube-system --type='json' -p='[
  {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--entryPoints.websecure.transport.respondingTimeouts.readTimeout=600s"},
  {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--entryPoints.websecure.transport.respondingTimeouts.writeTimeout=600s"},
  {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--entryPoints.websecure.transport.respondingTimeouts.idleTimeout=600s"},
  {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--serversTransport.forwardingTimeouts.responseHeaderTimeout=600s"}
]'
```

### 4. **Deploy.py Enhancements** ✅
**Added automatic cleanup and verification:**

- `clear_stale_celery_tasks()` - Clears stuck tasks from Redis on deploy
- `verify_celery_queues()` - Verifies workers are consuming from correct queues
- Both run automatically after `rollout_restart_apps()`

**Deployment flow now:**
1. Build images
2. Load into cluster
3. Apply manifests
4. Restart pods
5. **Clear stale Celery tasks** ← NEW
6. **Verify queue consumption** ← NEW
7. Wait for Elasticsearch
8. Apply index template

---

## How to Deploy

### On Your Server:

```bash
# 1. Copy updated files
cd /path/to/forensicsOperator
git pull  # or copy files manually

# 2. Edit config.json for your hardware
# Adjust resources based on available RAM/CPU:
# - 16GB RAM server: keep defaults
# - 32GB+ RAM: increase minio_memory_limit to 8Gi
# - 8GB RAM: reduce elasticsearch_heap_mb to 256

# 3. Deploy
python3 deploy.py

# Or if images already built:
python3 deploy.py --no-build
```

### Verify Deployment:

```bash
# Check all pods are running
kubectl get pods -n forensics-operator

# Check resource allocation
kubectl get pod -n forensics-operator -l app=minio -o yaml | grep -A10 "resources:"

# Check Celery queues
kubectl exec -n forensics-operator deploy/redis -- redis-cli llen ingest
kubectl exec -n forensics-operator deploy/redis -- redis-cli llen modules
kubectl exec -n forensics-operator deploy/redis -- redis-cli llen celery
# ingest/modules should be 0 (or low), celery should be 0

# Watch logs during upload
kubectl logs -n forensics-operator -l app=api -f
kubectl logs -n forensics-operator -l app=processor -f
```

### Test Upload:

```bash
# Create test file
dd if=/dev/zero of=/tmp/test100mb.bin bs=1M count=100

# Get auth token first (if auth enabled)
TOKEN=$(curl -k -X POST https://forensics.local/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"TracexAdmin1!"}' | jq -r '.access_token')

# Upload
curl -k -X POST https://forensics.local/api/v1/cases/<case-id>/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -F "files=@/tmp/test100mb.bin" -v

# Check job status
curl -k https://forensics.local/api/v1/cases/<case-id>/jobs \
  -H "Authorization: Bearer $TOKEN"
```

Expected job status flow: `UPLOADING` → `PENDING` → `RUNNING` → `COMPLETED`

---

## Troubleshooting

### Jobs still stuck in PENDING?

```bash
# 1. Check queue lengths
kubectl exec -n forensics-operator deploy/redis -- redis-cli keys "celery*"

# 2. Check if workers are running
kubectl get pods -n forensics-operator -l app=processor

# 3. Check worker logs
kubectl logs -n forensics-operator -l app=processor --tail=100 | grep -i "task\|queue"

# 4. Clear stuck tasks and retry
kubectl exec -n forensics-operator deploy/redis -- redis-cli FLUSHDB

# 5. Restart API to pick up code changes
kubectl rollout restart deployment/api -n forensics-operator
```

### Uploads still slow?

```bash
# 1. Check MinIO resources
kubectl top pod -n forensics-operator -l app=minio

# 2. Increase MinIO memory in config.json
# Edit: minio_memory_limit: "8Gi"
python3 deploy.py --no-build

# 3. Check Traefik timeouts
kubectl get deployment traefik -n kube-system -o yaml | grep -i timeout

# 4. Test direct upload (bypass Tailscale)
kubectl port-forward -n forensics-operator svc/api-service 8000:8000
curl -X POST http://localhost:8000/api/v1/cases/<case-id>/ingest -F "files=@/tmp/test.bin"
```

### HTTP/2 errors?

```bash
# Verify Traefik patch was applied
kubectl get deployment traefik -n kube-system -o yaml | grep -A20 "args:"

# If not applied, re-run the patch command from section 3 above
```

---

## Architecture Notes

### Celery Queue Flow:
```
User Upload → API (receives file) → Redis Queue → Processor Worker → MinIO + Elasticsearch
                  ↓                      ↓              ↓
              UPLOADING              PENDING       RUNNING → COMPLETED
```

### Queue Routing:
- `ingest.process_artifact` → `ingest` queue (I/O bound: MinIO download, ES upload)
- `module.run` → `modules` queue (CPU bound: Hayabusa, YARA, etc.)
- Default exchange: `forensics` (direct type)

### Resource Tuning:
- **MinIO**: Most critical for upload performance. Increase memory first.
- **Processor**: Increase CPU for faster analysis, especially with multiple concurrent jobs.
- **API**: Moderate resources needed; bottleneck is usually MinIO or network.
- **Elasticsearch**: Heap size affects search performance, not uploads.

---

## Next Steps

1. **Deploy the fixes** on your server
2. **Test with a small file** (1-10MB) first
3. **Monitor queues** during upload
4. **Tune resources** based on your server's capacity
5. **Consider disabling Tailscale** for large uploads if still slow (use direct port-forward)
