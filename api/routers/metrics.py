"""
Performance Metrics API.

Provides real-time server consumption metrics including:
- CPU, memory, disk usage of the cluster
- Elasticsearch cluster health and index stats
- Redis memory usage and key counts
- MinIO disk usage
- Celery worker status and queue depths
"""
import json
import os
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

from fastapi import APIRouter

from config import settings

router = APIRouter(prefix="/metrics", tags=["metrics"])


# ── Helpers ──────────────────────────────────────────────────────────────────


def _get_system_metrics() -> dict:
    """CPU, memory, and disk usage from /proc (container-aware)."""
    result = {
        "cpu_percent": 0.0,
        "memory_used_mb": 0.0,
        "memory_total_mb": 0.0,
        "memory_percent": 0.0,
        "disk_used_gb": 0.0,
        "disk_total_gb": 0.0,
        "disk_percent": 0.0,
    }
    try:
        # CPU — read two snapshots of /proc/stat 100 ms apart
        def _read_cpu():
            with open("/proc/stat") as f:
                parts = f.readline().split()
            # user, nice, system, idle, iowait, irq, softirq, steal
            vals = list(map(int, parts[1:9]))
            idle = vals[3] + vals[4]
            total = sum(vals)
            return idle, total

        idle1, total1 = _read_cpu()
        time.sleep(0.1)
        idle2, total2 = _read_cpu()
        d_total = total2 - total1
        d_idle = idle2 - idle1
        result["cpu_percent"] = round((1 - d_idle / d_total) * 100, 1) if d_total else 0.0
    except Exception:
        # Fallback: try os.getloadavg as a rough indicator
        try:
            load1, _, _ = os.getloadavg()
            cpu_count = os.cpu_count() or 1
            result["cpu_percent"] = round(min(load1 / cpu_count * 100, 100), 1)
        except Exception:
            pass

    try:
        # Memory — prefer cgroup v2, fall back to cgroup v1, then /proc/meminfo
        mem_total = None
        mem_used = None

        # cgroup v2
        cg2_max = "/sys/fs/cgroup/memory.max"
        cg2_current = "/sys/fs/cgroup/memory.current"
        # cgroup v1
        cg1_limit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
        cg1_usage = "/sys/fs/cgroup/memory/memory.usage_in_bytes"

        if os.path.exists(cg2_current):
            with open(cg2_current) as f:
                mem_used = int(f.read().strip())
            with open(cg2_max) as f:
                val = f.read().strip()
                mem_total = int(val) if val != "max" else None
        elif os.path.exists(cg1_usage):
            with open(cg1_usage) as f:
                mem_used = int(f.read().strip())
            with open(cg1_limit) as f:
                mem_total = int(f.read().strip())

        # Fall back to /proc/meminfo when cgroup limits are absent
        if mem_total is None or mem_total > 2**60:
            with open("/proc/meminfo") as f:
                info = {}
                for line in f:
                    parts = line.split()
                    info[parts[0].rstrip(":")] = int(parts[1]) * 1024  # kB → bytes
                mem_total = info.get("MemTotal", 0)
                mem_used = mem_total - info.get("MemAvailable", 0)

        result["memory_total_mb"] = round(mem_total / (1024 * 1024), 1) if mem_total else 0.0
        result["memory_used_mb"] = round(mem_used / (1024 * 1024), 1) if mem_used else 0.0
        result["memory_percent"] = (
            round(mem_used / mem_total * 100, 1) if mem_total else 0.0
        )
    except Exception:
        pass

    try:
        st = os.statvfs("/")
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        used = total - free
        result["disk_total_gb"] = round(total / (1024**3), 2)
        result["disk_used_gb"] = round(used / (1024**3), 2)
        result["disk_percent"] = round(used / total * 100, 1) if total else 0.0
    except Exception:
        pass

    return result


def _get_elasticsearch_metrics() -> dict:
    """Cluster health + per-index stats from Elasticsearch."""
    result = {
        "status": "unavailable",
        "node_count": 0,
        "total_docs": 0,
        "total_size_mb": 0.0,
        "indices": [],
    }
    base = settings.ELASTICSEARCH_URL

    # Cluster health
    try:
        req = urllib.request.Request(f"{base}/_cluster/health", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            health = json.loads(resp.read())
        result["status"] = health.get("status", "unknown")
        result["node_count"] = health.get("number_of_nodes", 0)
    except Exception:
        return result

    # Index stats
    try:
        req = urllib.request.Request(f"{base}/_cat/indices?format=json", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            indices = json.loads(resp.read())
        total_docs = 0
        total_size = 0.0
        idx_list = []
        for idx in indices:
            name = idx.get("index", "")
            docs = int(idx.get("docs.count", 0) or 0)
            size_bytes = _parse_es_size(idx.get("store.size", "0"))
            size_mb = round(size_bytes / (1024 * 1024), 2)
            total_docs += docs
            total_size += size_mb
            idx_list.append({"name": name, "docs": docs, "size_mb": size_mb})
        result["total_docs"] = total_docs
        result["total_size_mb"] = round(total_size, 2)
        result["indices"] = idx_list
    except Exception:
        pass

    return result


def _parse_es_size(size_str: str) -> float:
    """Parse Elasticsearch human-readable sizes like '5.2gb', '120mb', '500kb'."""
    if not size_str:
        return 0.0
    size_str = str(size_str).strip().lower()
    multipliers = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(suffix):
            try:
                return float(size_str[: -len(suffix)]) * mult
            except ValueError:
                return 0.0
    try:
        return float(size_str)
    except ValueError:
        return 0.0


def _get_redis_metrics() -> dict:
    """Memory, client, and key stats from Redis."""
    result = {
        "used_memory_mb": 0.0,
        "connected_clients": 0,
        "total_keys": 0,
        "uptime_seconds": 0,
    }
    try:
        import redis as _redis

        r = _redis.Redis.from_url(settings.REDIS_URL, socket_timeout=5)
        info = r.info()
        result["used_memory_mb"] = round(info.get("used_memory", 0) / (1024 * 1024), 2)
        result["connected_clients"] = info.get("connected_clients", 0)
        result["uptime_seconds"] = info.get("uptime_in_seconds", 0)
        # Total keys across all dbs
        total_keys = 0
        for key, val in info.items():
            if isinstance(key, str) and key.startswith("db") and isinstance(val, dict):
                total_keys += val.get("keys", 0)
        result["total_keys"] = total_keys
    except Exception:
        pass
    return result


def _get_minio_metrics() -> dict:
    """Bucket count, object count, and total size from MinIO."""
    result = {
        "bucket_count": 0,
        "total_objects": 0,
        "total_size_mb": 0.0,
    }
    try:
        from minio import Minio

        client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=False,
        )
        buckets = client.list_buckets()
        result["bucket_count"] = len(buckets)
        total_objects = 0
        total_size = 0
        for bucket in buckets:
            for obj in client.list_objects(bucket.name, recursive=True):
                total_objects += 1
                total_size += obj.size or 0
        result["total_objects"] = total_objects
        result["total_size_mb"] = round(total_size / (1024 * 1024), 2)
    except Exception:
        pass
    return result


def _get_celery_metrics() -> dict:
    """Worker status and queue depths from Celery + Redis."""
    result = {
        "active_tasks": 0,
        "reserved_tasks": 0,
        "registered_workers": 0,
        "queue_lengths": {"ingest": 0, "modules": 0, "default": 0},
    }
    try:
        from celery import Celery

        app = Celery(broker=settings.REDIS_URL)
        inspector = app.control.inspect(timeout=3)

        active = inspector.active()
        if active:
            result["registered_workers"] = len(active)
            result["active_tasks"] = sum(len(tasks) for tasks in active.values())

        reserved = inspector.reserved()
        if reserved:
            result["reserved_tasks"] = sum(len(tasks) for tasks in reserved.values())
    except Exception:
        pass

    # Queue depths via Redis LLEN
    try:
        import redis as _redis

        r = _redis.Redis.from_url(settings.REDIS_URL, socket_timeout=5)
        for queue_name in ("ingest", "modules", "default"):
            try:
                length = r.llen(queue_name)
                result["queue_lengths"][queue_name] = length or 0
            except Exception:
                pass
    except Exception:
        pass

    return result


def _get_cases_metrics() -> dict:
    """Case and job counts from Redis."""
    result = {
        "total_cases": 0,
        "total_jobs": 0,
        "active_jobs": 0,
        "failed_jobs": 0,
    }
    try:
        import redis as _redis

        r = _redis.Redis.from_url(settings.REDIS_URL, socket_timeout=5)

        # Total cases from the cases:all set
        result["total_cases"] = r.scard("cases:all") or 0

        # Scan for job keys and tally statuses
        total_jobs = 0
        active_jobs = 0
        failed_jobs = 0
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="job:*", count=200)
            for key in keys:
                total_jobs += 1
                try:
                    raw = r.get(key)
                    if raw:
                        job = json.loads(raw)
                        status = job.get("status", "")
                        if status in ("running", "pending"):
                            active_jobs += 1
                        elif status == "failed":
                            failed_jobs += 1
                except Exception:
                    pass
            if cursor == 0:
                break

        result["total_jobs"] = total_jobs
        result["active_jobs"] = active_jobs
        result["failed_jobs"] = failed_jobs
    except Exception:
        pass
    return result


# ── Endpoint ─────────────────────────────────────────────────────────────────


@router.get("/dashboard")
def metrics_dashboard():
    """Return comprehensive real-time metrics from all services."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": _get_system_metrics(),
        "elasticsearch": _get_elasticsearch_metrics(),
        "redis": _get_redis_metrics(),
        "minio": _get_minio_metrics(),
        "celery": _get_celery_metrics(),
        "cases": _get_cases_metrics(),
    }
