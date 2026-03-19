"""
Module execution task: download source files, run module binary, store results.

Supported modules:
  hayabusa  — Sigma-based EVTX threat hunting
  strings   — Printable string extraction from any file
  hindsight — Browser forensics (Chrome/Firefox/Edge)
  regripper — Deep Windows registry analysis
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import redis

from celery_app import app

logger = logging.getLogger(__name__)

REDIS_URL      = os.getenv("REDIS_URL",        "redis://redis-service:6379/0")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT",   "minio-service:9000")
MINIO_ACCESS   = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET   = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET   = os.getenv("MINIO_BUCKET",     "forensics-cases")

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
        RUNNERS = {
            "hayabusa":  _run_hayabusa,
            "strings":   _run_strings,
            "hindsight": _run_hindsight,
            "regripper": _run_regripper,
        }
        runner = RUNNERS.get(module_id)
        if not runner:
            raise RuntimeError(f"Unknown module: {module_id}")

        results = runner(run_id, work_dir, sources_dir)

        # ── 3. Upload full results to MinIO ───────────────────────────────────
        results_json = work_dir / "results.json"
        results_json.write_text(json.dumps(results, ensure_ascii=False))
        output_key = f"cases/{case_id}/modules/{run_id}/results.json"
        minio.fput_object(MINIO_BUCKET, output_key, str(results_json),
                          content_type="application/json")
        logger.info("[%s] Uploaded %d hits to MinIO", run_id, len(results))

        # ── 4. Level summary ─────────────────────────────────────────────────
        hits_by_level: dict[str, int] = {}
        for hit in results:
            lvl = hit.get("level", "informational")
            hits_by_level[lvl] = hits_by_level.get(lvl, 0) + 1

        # ── 5. Complete ───────────────────────────────────────────────────────
        _update(r, run_id,
                status="COMPLETED",
                total_hits=str(len(results)),
                hits_by_level=json.dumps(hits_by_level),
                results_preview=json.dumps(results[:200]),
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


# ─────────────────────────────────────────────────────────────────────────────
# Hayabusa
# ─────────────────────────────────────────────────────────────────────────────

def _run_hayabusa(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
    hayabusa_bin = shutil.which("hayabusa")
    if not hayabusa_bin:
        raise RuntimeError(
            "Hayabusa binary not found. Ensure the processor image was built with the Hayabusa step."
        )

    output_jsonl = work_dir / "hayabusa_output.jsonl"
    cmd = [
        hayabusa_bin, "json-timeline",
        "-d", str(sources_dir),
        "-o", str(output_jsonl),
        "--no-wizard", "--no-color", "-q",
    ]

    logger.info("[%s] Running: %s", run_id, " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Hayabusa timed out after 1 hour")

    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"Hayabusa exited {proc.returncode}: {(proc.stderr or '')[:500]}"
        )

    if not output_jsonl.exists():
        return []

    return _parse_hayabusa_jsonl(output_jsonl)


def _parse_hayabusa_jsonl(path: Path) -> list[dict]:
    results: list[dict] = []
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                hit = _hayabusa_row_to_hit(row)
                if hit:
                    results.append(hit)
            except Exception as exc:
                logger.debug("Hayabusa: skipped line %d: %s", lineno, exc)
    return results


def _hayabusa_row_to_hit(row: dict) -> dict | None:
    timestamp_raw = row.get("Timestamp") or row.get("timestamp") or ""
    rule_title    = str(row.get("RuleTitle") or row.get("ruleTitle") or "")
    level         = str(row.get("Level")     or row.get("level")     or "informational").lower()
    computer      = str(row.get("Computer")  or row.get("computer")  or "")
    channel       = str(row.get("Channel")   or row.get("channel")   or "")
    event_id_raw  = str(row.get("EventID")   or row.get("eventId")   or "")
    details_raw   = str(row.get("Details")   or row.get("details")   or "")
    rule_file     = str(row.get("RuleFile")  or row.get("ruleFile")  or "")
    evtx_file     = str(row.get("EvtxFile")  or row.get("evtxFile")  or "")

    if not rule_title and not timestamp_raw:
        return None

    try:
        event_id: int | None = int(event_id_raw) if event_id_raw else None
    except (ValueError, TypeError):
        event_id = None

    return {
        "id":          str(uuid.uuid4()),
        "timestamp":   _normalize_ts(timestamp_raw),
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


def _normalize_ts(ts: str) -> str:
    """Normalize Hayabusa timestamp to ISO 8601 UTC."""
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


# ─────────────────────────────────────────────────────────────────────────────
# Strings
# ─────────────────────────────────────────────────────────────────────────────

MAX_STRINGS_HITS = 10_000


def _run_strings(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
    strings_bin = shutil.which("strings")
    if not strings_bin:
        raise RuntimeError(
            "'strings' binary not found. Ensure binutils is installed in the processor image."
        )

    results: list[dict] = []
    total = 0

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file() or total >= MAX_STRINGS_HITS:
            break

        logger.info("[%s] Extracting strings from %s", run_id, file_path.name)
        try:
            proc = subprocess.run(
                [strings_bin, "-n", "8", str(file_path)],
                capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.warning("[%s] strings timed out on %s", run_id, file_path.name)
            continue

        for line in proc.stdout.splitlines():
            s = line.strip()
            if not s or total >= MAX_STRINGS_HITS:
                break
            results.append({
                "id":           str(uuid.uuid4()),
                "timestamp":    "",
                "level":        "informational",
                "level_int":    1,
                "rule_title":   file_path.name,
                "computer":     "",
                "details_raw":  s,
                "filename":     file_path.name,
                "string_value": s,
            })
            total += 1

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Hindsight
# ─────────────────────────────────────────────────────────────────────────────

def _run_hindsight(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
    hindsight_bin = shutil.which("hindsight") or shutil.which("hindsight.py")
    if not hindsight_bin:
        raise RuntimeError(
            "hindsight binary not found. Ensure pyhindsight is installed in the processor image."
        )

    output_dir = work_dir / "hindsight_output"
    output_dir.mkdir()
    output_prefix = str(output_dir / "results")

    cmd = [hindsight_bin, "-i", str(sources_dir), "-o", output_prefix, "-f", "json"]
    logger.info("[%s] Running: %s", run_id, " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Hindsight timed out after 10 minutes")

    # Hindsight may exit non-zero but still produce output
    json_files = list(output_dir.glob("*.json"))
    if not json_files:
        if proc.returncode != 0:
            raise RuntimeError(
                f"Hindsight failed (code {proc.returncode}): {(proc.stderr or '')[:500]}"
            )
        return []

    return _parse_hindsight_json(json_files[0])


def _parse_hindsight_json(json_path: Path) -> list[dict]:
    try:
        with open(json_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list):
        data = [data]

    results: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        # Columnar format (older hindsight): {"col_types": [...], "data": [[...], ...]}
        if "col_types" in item and "data" in item:
            cols = item["col_types"]
            for row in item.get("data", []):
                if isinstance(row, list):
                    hit = _hindsight_item_to_hit(dict(zip(cols, row)))
                    if hit:
                        results.append(hit)
        else:
            hit = _hindsight_item_to_hit(item)
            if hit:
                results.append(hit)

    return results


def _hindsight_item_to_hit(item: dict) -> dict | None:
    url     = str(item.get("url",   item.get("value", ""))).strip()
    title   = str(item.get("title", "")).strip()
    ts_raw  = item.get("timestamp_UTC") or item.get("timestamp") or ""
    typ     = str(item.get("type",  "Browser Event")).strip()
    profile = str(item.get("profile", "")).strip()

    if not url and not title:
        return None

    details = url if not title or title == url else f"{url} — {title}"

    return {
        "id":          str(uuid.uuid4()),
        "timestamp":   _parse_hindsight_timestamp(ts_raw),
        "level":       "informational",
        "level_int":   1,
        "rule_title":  typ,
        "computer":    profile,
        "details_raw": details,
        "url":         url,
        "title":       title,
    }


def _parse_hindsight_timestamp(ts) -> str:
    if not ts:
        return ""
    ts_str = str(ts).strip()

    # Human-readable UTC: "2023-01-15 14:32:11.123456"
    if len(ts_str) >= 19 and ts_str[10] == " ":
        clean = ts_str[:19].replace(" ", "T") + "Z"
        return clean

    # Chrome/WebKit microsecond timestamp (since 1601-01-01)
    try:
        ts_int = int(ts_str)
        if ts_int > 10 ** 15:
            unix_ts = (ts_int / 1_000_000) - 11_644_473_600
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        pass

    return ts_str


# ─────────────────────────────────────────────────────────────────────────────
# RegRipper
# ─────────────────────────────────────────────────────────────────────────────

_RIP_PL = Path("/opt/regripper/rip.pl")


def _run_regripper(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
    if not _RIP_PL.exists():
        raise RuntimeError(
            "RegRipper not found at /opt/regripper/rip.pl. "
            "Ensure the processor image was built with the RegRipper step."
        )

    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue

        profile = _regripper_profile(file_path.name)
        logger.info("[%s] RegRipper: %s (profile: %s)", run_id, file_path.name, profile)

        try:
            proc = subprocess.run(
                ["perl", str(_RIP_PL), "-r", str(file_path), "-f", profile],
                capture_output=True, text=True, timeout=300,
                cwd="/opt/regripper",
            )
        except subprocess.TimeoutExpired:
            logger.warning("[%s] RegRipper timed out on %s", run_id, file_path.name)
            continue

        hits = _parse_regripper_output(proc.stdout, file_path.name)
        results.extend(hits)

        if not hits and proc.returncode not in (0, 1):
            logger.warning(
                "[%s] RegRipper code %d for %s: %s",
                run_id, proc.returncode, file_path.name, (proc.stderr or "")[:200],
            )

    return results


def _regripper_profile(filename: str) -> str:
    name = os.path.basename(filename).upper()
    if "NTUSER" in name or "USRCLASS" in name:
        return "ntuser"
    if name == "SYSTEM":
        return "system"
    if name == "SOFTWARE":
        return "software"
    if name == "SAM":
        return "sam"
    if name == "SECURITY":
        return "security"
    return "ntuser"


def _parse_regripper_output(output: str, filename: str) -> list[dict]:
    """Parse RegRipper text output (blocks separated by --- lines) into hit dicts."""
    results: list[dict] = []

    blocks = re.split(r"^-{10,}$", output, flags=re.MULTILINE)
    for block in blocks:
        block = block.strip()
        if not block or len(block) < 10:
            continue

        lines = block.splitlines()
        if not lines:
            continue

        # First line: "PluginName v.YYYYMMDD"
        first = lines[0].strip()
        plugin_name = first.split(" v.")[0].strip() if " v." in first else first[:60]

        # Skip the hive-path line "(HIVENAME)" if present
        body_lines = []
        for line in lines[1:]:
            stripped = line.strip()
            if stripped.startswith("(") and stripped.endswith(")"):
                continue
            body_lines.append(line)

        content = "\n".join(body_lines).strip()
        if not content or len(content) < 5:
            continue

        results.append({
            "id":          str(uuid.uuid4()),
            "timestamp":   "",
            "level":       "informational",
            "level_int":   1,
            "rule_title":  plugin_name,
            "computer":    filename,          # hive filename
            "details_raw": content[:2000],    # cap per hit
        })

    return results
