"""
Module execution task: download source files, run module binary, store results.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import redis

from celery_app import app

logger = logging.getLogger(__name__)

REDIS_URL      = os.getenv("REDIS_URL",       "redis://redis-service:6379/0")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT",  "minio-service:9000")
MINIO_ACCESS   = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET   = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET   = os.getenv("MINIO_BUCKET",    "forensics-cases")

MODULE_RUN_TTL = 604800  # 7 days

LEVEL_INT = {
    "critical":      5,
    "high":          4,
    "medium":        3,
    "low":           2,
    "informational": 1,
    "info":          1,
}


def get_redis() -> redis.Redis:
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def get_minio():
    from minio import Minio
    return Minio(MINIO_ENDPOINT, access_key=MINIO_ACCESS, secret_key=MINIO_SECRET, secure=False)


def _update(r: redis.Redis, run_id: str, **fields) -> None:
    key = f"fo:module_run:{run_id}"
    r.hset(key, mapping={
        k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        for k, v in fields.items()
    })
    r.expire(key, MODULE_RUN_TTL)


# ── Celery task ────────────────────────────────────────────────────────────────

@app.task(bind=True, name="module.run")
def run_module(
    self,
    run_id: str,
    case_id: str,
    module_id: str,
    source_files: list,
) -> dict:
    """
    Execute a module against a set of source files already stored in MinIO.

    source_files: list of {job_id, filename, minio_key}
    """
    r = get_redis()
    work_dir = Path(tempfile.mkdtemp(prefix=f"fo_mod_{run_id}_"))

    try:
        _update(r, run_id,
                status="RUNNING",
                started_at=datetime.now(timezone.utc).isoformat())

        # ── 1. Download source files ──────────────────────────────────────────
        minio = get_minio()
        sources_dir = work_dir / "sources"
        sources_dir.mkdir()

        for sf in source_files:
            dest = sources_dir / sf["filename"]
            logger.info("[%s] Downloading %s", run_id, sf["minio_key"])
            minio.fget_object(MINIO_BUCKET, sf["minio_key"], str(dest))

        # ── 2. Run module ─────────────────────────────────────────────────────
        if module_id == "hayabusa":
            results = _run_hayabusa(run_id, work_dir, sources_dir)
        else:
            raise RuntimeError(f"Unknown module: {module_id}")

        # ── 3. Upload full results to MinIO ───────────────────────────────────
        results_json = work_dir / "results.json"
        results_json.write_text(json.dumps(results, ensure_ascii=False))

        output_key = f"cases/{case_id}/modules/{run_id}/results.json"
        minio.fput_object(MINIO_BUCKET, output_key, str(results_json),
                          content_type="application/json")
        logger.info("[%s] Uploaded %d hits to MinIO", run_id, len(results))

        # ── 4. Build level summary ────────────────────────────────────────────
        hits_by_level: dict[str, int] = {}
        for hit in results:
            lvl = hit.get("level", "informational")
            hits_by_level[lvl] = hits_by_level.get(lvl, 0) + 1

        preview = results[:200]

        # ── 5. Mark complete ──────────────────────────────────────────────────
        _update(r, run_id,
                status="COMPLETED",
                total_hits=str(len(results)),
                hits_by_level=json.dumps(hits_by_level),
                results_preview=json.dumps(preview),
                output_minio_key=output_key,
                completed_at=datetime.now(timezone.utc).isoformat())

        logger.info("[%s] Module run complete: %d hits", run_id, len(results))
        return {"status": "COMPLETED", "total_hits": len(results)}

    except Exception as exc:
        logger.exception("[%s] Module run failed: %s", run_id, exc)
        _update(r, run_id,
                status="FAILED",
                error=str(exc),
                completed_at=datetime.now(timezone.utc).isoformat())
        raise

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


# ── Hayabusa runner ───────────────────────────────────────────────────────────

def _run_hayabusa(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
    """Invoke the hayabusa binary and parse its JSONL output."""
    hayabusa_bin = shutil.which("hayabusa")
    if not hayabusa_bin:
        raise RuntimeError(
            "Hayabusa binary not found in PATH. "
            "Ensure the processor image was built with the Hayabusa download step."
        )

    output_jsonl = work_dir / "hayabusa_output.jsonl"

    cmd = [
        hayabusa_bin,
        "json-timeline",
        "-d", str(sources_dir),
        "-o", str(output_jsonl),
        "--no-wizard",
        "--no-color",
        "-q",
    ]

    logger.info("[%s] Running: %s", run_id, " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Hayabusa timed out after 1 hour")

    # Hayabusa exits 0 on success, non-zero on hard errors
    # (exit 1 sometimes means "no events found" in older versions — tolerate it)
    if proc.returncode not in (0, 1):
        stderr_snippet = proc.stderr[:500] if proc.stderr else "(no stderr)"
        raise RuntimeError(
            f"Hayabusa exited with code {proc.returncode}: {stderr_snippet}"
        )

    if not output_jsonl.exists():
        logger.info("[%s] Hayabusa produced no output (0 detections)", run_id)
        return []

    return _parse_hayabusa_jsonl(output_jsonl)


def _parse_hayabusa_jsonl(path: Path) -> list[dict]:
    """Parse hayabusa JSONL output into a list of hit dicts."""
    results: list[dict] = []
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                hit = _row_to_hit(row)
                if hit:
                    results.append(hit)
            except Exception as exc:
                logger.debug("Skipped JSONL line %d: %s", lineno, exc)
    return results


def _row_to_hit(row: dict) -> dict | None:
    timestamp_raw = row.get("Timestamp") or row.get("timestamp") or ""
    rule_title    = str(row.get("RuleTitle")   or row.get("ruleTitle")   or "")
    level         = str(row.get("Level")       or row.get("level")       or "informational").lower()
    computer      = str(row.get("Computer")    or row.get("computer")    or "")
    channel       = str(row.get("Channel")     or row.get("channel")     or "")
    event_id_raw  = str(row.get("EventID")     or row.get("eventId")     or "")
    details_raw   = str(row.get("Details")     or row.get("details")     or "")
    rule_file     = str(row.get("RuleFile")    or row.get("ruleFile")    or "")
    evtx_file     = str(row.get("EvtxFile")    or row.get("evtxFile")    or "")

    if not rule_title and not timestamp_raw:
        return None

    try:
        event_id: int | None = int(event_id_raw) if event_id_raw else None
    except (ValueError, TypeError):
        event_id = None

    return {
        "id":          str(uuid.uuid4()),
        "timestamp":   _normalize_timestamp(timestamp_raw),
        "level":       level,
        "level_int":   LEVEL_INT.get(level, 1),
        "rule_title":  rule_title,
        "computer":    computer,
        "channel":     channel,
        "event_id":    event_id,
        "details_raw": details_raw,
        "rule_file":   rule_file,
        "evtx_file":   evtx_file,
    }


def _normalize_timestamp(ts: str) -> str:
    """Normalize Hayabusa timestamp to ISO 8601 UTC (mirrors HayabusaPlugin)."""
    if not ts:
        return ""
    ts = ts.strip()
    if len(ts) > 10 and ts[10] == " ":
        ts = ts[:10] + "T" + ts[11:]
    ts = ts.replace(" +", "+").replace(" -", "-")
    dot = ts.find(".")
    if dot != -1:
        end = dot + 1
        while end < len(ts) and ts[end].isdigit():
            end += 1
        frac = (ts[dot + 1:end] + "000")[:3]
        ts = ts[:dot + 1] + frac + ts[end:]
    if ts.endswith("+00:00"):
        ts = ts[:-6] + "Z"
    elif not (ts.endswith("Z") or "+" in ts[10:] or (len(ts) > 19 and ts[-3] == ":")):
        ts += "Z"
    return ts
