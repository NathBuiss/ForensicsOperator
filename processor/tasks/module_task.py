"""
Module execution task: download source files, run module binary, store results.

Supported modules:
  hayabusa         — Sigma-based EVTX threat hunting
  strings          — Printable string extraction from any file
  strings_analysis — Categorised string extraction with IOC identification
  hindsight        — Browser forensics (Chrome/Firefox/Edge)
  regripper        — Deep Windows registry analysis
  wintriage        — Windows triage collection analysis
  yara             — YARA rule scanning
  exiftool         — Metadata extraction
  volatility3      — Memory forensics
  oletools         — Office document macro / OLE analysis
  ole_analysis     — Alias for oletools
  pe_analysis      — PE executable deep inspection
  grep_search      — Regex-based IOC / keyword pattern search
  malwoverview     — VirusTotal / multi-TI hash lookup (malwoverview CLI or direct API)
"""
from __future__ import annotations

import csv
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

import redis

from celery_app import app

logger = logging.getLogger(__name__)

REDIS_URL           = os.getenv("REDIS_URL",            "redis://redis-service:6379/0")
MINIO_ENDPOINT      = os.getenv("MINIO_ENDPOINT",       "minio-service:9000")
MINIO_ACCESS        = os.getenv("MINIO_ACCESS_KEY",     "minioadmin")
MINIO_SECRET        = os.getenv("MINIO_SECRET_KEY",     "minioadmin")
MINIO_BUCKET        = os.getenv("MINIO_BUCKET",         "forensics-cases")
ELASTICSEARCH_URL   = os.getenv("ELASTICSEARCH_URL",    "http://elasticsearch-service:9200")

# Custom modules directory (shared volume, created via Studio UI)
CUSTOM_MODULES_DIR = Path(os.getenv("MODULES_DIR", "/app/modules"))

MODULE_RUN_TTL = 604800  # 7 days

LEVEL_INT = {
    "critical":      5,
    "high":          4,
    "medium":        3,
    "low":           2,
    "informational": 1,
    "info":          1,
}

# Strip ANSI terminal escape sequences before storing output in Redis / displaying in UI
_ANSI_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-9;]*[ -/]*[@-~])')

# Minimal subprocess environment — strips MINIO/Redis secrets from child processes
# so that a compromised binary cannot exfiltrate credentials via env inheritance.
_SAFE_ENV = {
    "PATH":   os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "HOME":   "/tmp",
    "LANG":   os.environ.get("LANG", "en_US.UTF-8"),
    "TMPDIR": "/tmp",
}

# Redis key for UI-configured Cuckoo integration settings
_CUCKOO_CONFIG_KEY = "fo:config:cuckoo"
# Redis key for UI-configured malwoverview / VirusTotal settings
_MALWOVERVIEW_CONFIG_KEY = "fo:config:malwoverview"


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)


_SANDBOX_SCRIPT = Path(__file__).parent / "_module_sandbox.py"

# Resource limits for custom module subprocess
_SANDBOX_CPU_SECONDS  = int(os.getenv("SANDBOX_CPU_SECONDS",  "3600"))
_SANDBOX_MEMORY_BYTES = int(os.getenv("SANDBOX_MEMORY_BYTES", str(2 * 1024**3)))
_SANDBOX_FSIZE_BYTES  = int(os.getenv("SANDBOX_FSIZE_BYTES",  str(500 * 1024**2)))
_SANDBOX_NPROC        = int(os.getenv("SANDBOX_NPROC",        "64"))
_SANDBOX_TIMEOUT      = int(os.getenv("SANDBOX_TIMEOUT_SEC",  "1800"))  # 30 min wall time


def _run_custom_module(
    run_id: str,
    case_id: str,
    module_id: str,
    work_dir: Path,
    source_files: list,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """
    Execute a custom *_module.py file in an isolated subprocess.

    The child process:
      • sets resource limits (CPU, memory, file size, nproc) before importing
        any module code — limits cascade to any subprocesses the module spawns
      • receives MinIO/Redis credentials via stdin (not visible in ps/env)
      • has HOME remapped to work_dir and sensitive env vars stripped
      • is killed by the parent after SANDBOX_TIMEOUT_SEC wall-clock seconds

    Returns the list of hit dicts produced by the module's run() function.
    """
    import sys as _sys

    module_file = CUSTOM_MODULES_DIR / f"{module_id}_module.py"
    if not module_file.exists():
        raise RuntimeError(
            f"Custom module file not found: {module_file}. "
            "Create it in the Studio editor."
        )

    args_payload = json.dumps({
        "run_id":        run_id,
        "case_id":       case_id,
        "module_file":   str(module_file),
        "source_files":  source_files,
        "params":        params,
        "work_dir":      str(work_dir),
        "minio_endpoint": MINIO_ENDPOINT,
        "minio_access":  MINIO_ACCESS,
        "minio_secret":  MINIO_SECRET,
        "minio_bucket":  MINIO_BUCKET,
        "redis_url":     REDIS_URL,
        # Propagate limit overrides so sandbox can log them
        "limit_cpu_seconds":  _SANDBOX_CPU_SECONDS,
        "limit_memory_bytes": _SANDBOX_MEMORY_BYTES,
        "limit_fsize_bytes":  _SANDBOX_FSIZE_BYTES,
        "limit_nproc":        _SANDBOX_NPROC,
    })

    logger.info("[%s] Launching custom module '%s' in sandbox (timeout=%ss)",
                run_id, module_id, _SANDBOX_TIMEOUT)
    tool_meta["log"] += (
        f"[sandbox] executing {module_file.name} in subprocess "
        f"(cpu={_SANDBOX_CPU_SECONDS}s mem={_SANDBOX_MEMORY_BYTES // 1024**2}MB "
        f"fsize={_SANDBOX_FSIZE_BYTES // 1024**2}MB nproc={_SANDBOX_NPROC})\n"
    )

    try:
        proc = subprocess.run(
            [_sys.executable, str(_SANDBOX_SCRIPT)],
            input=args_payload,
            capture_output=True,
            text=True,
            timeout=_SANDBOX_TIMEOUT,
            # Inherit only a minimal environment — no secrets in child env
            env={
                "PATH":       os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                "HOME":       str(work_dir),
            },
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Custom module '{module_id}' timed out after {_SANDBOX_TIMEOUT}s"
        )

    stderr_out = (proc.stderr or "").strip()
    if stderr_out:
        tool_meta["log"] += f"\n[sandbox stderr]\n{stderr_out[:8000]}\n"
        logger.info("[%s] Sandbox stderr:\n%s", run_id, stderr_out[:3000])

    stdout_out = (proc.stdout or "").strip()
    tool_meta["stdout"] = stdout_out[:4000] if stdout_out else ""

    if proc.returncode != 0:
        raise RuntimeError(
            f"Custom module '{module_id}' subprocess exited {proc.returncode}. "
            f"stderr: {stderr_out[:500]}"
        )

    try:
        result = json.loads(stdout_out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Custom module '{module_id}' produced invalid JSON output: {exc}. "
            f"stdout: {stdout_out[:300]}"
        ) from exc

    if "error" in result:
        raise RuntimeError(f"Custom module '{module_id}' failed: {result['error']}")

    hits = result.get("hits", [])
    logger.info("[%s] Custom module returned %d hits", run_id, len(hits))
    return hits


def get_redis() -> redis.Redis:
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def get_minio():
    from minio import Minio
    return Minio(MINIO_ENDPOINT, access_key=MINIO_ACCESS, secret_key=MINIO_SECRET, secure=False)


_CONN_ERRORS = ("connection refused", "max retries", "timeout", "connect", "reset by peer",
                "broken pipe", "connection reset", "econnrefused")


def _minio_op(fn, max_tries: int = 4, base_delay: float = 3.0):
    """Execute fn(), retrying on transient MinIO connectivity errors with exponential backoff."""
    last_exc = None
    for attempt in range(max_tries):
        try:
            return fn()
        except Exception as exc:
            msg = str(exc).lower()
            if any(k in msg for k in _CONN_ERRORS):
                last_exc = exc
                if attempt < max_tries - 1:
                    wait = base_delay * (2 ** attempt)
                    logger.warning("MinIO attempt %d/%d failed (%s). Retrying in %.0fs…",
                                   attempt + 1, max_tries, exc, wait)
                    time.sleep(wait)
                    continue
            raise
    raise last_exc  # type: ignore[misc]


def _update(r: redis.Redis, run_id: str, **fields) -> None:
    key = f"fo:module_run:{run_id}"
    r.hset(key, mapping={
        k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        for k, v in fields.items()
    })
    r.expire(key, MODULE_RUN_TTL)


# ── Celery task ────────────────────────────────────────────────────────────────

@app.task(bind=True, name="module.run", queue="modules")
def run_module(
    self,
    run_id: str,
    case_id: str,
    module_id: str,
    source_files: list,
    params: dict | None = None,
) -> dict:
    """
    Execute a module against a set of source files already stored in MinIO.

    source_files: list of {job_id, filename, minio_key}
    params: optional module-specific parameters (e.g. custom YARA rules)
    """
    r = get_redis()
    work_dir = Path(tempfile.mkdtemp(prefix=f"fo_mod_{run_id}_"))
    params = params or {}

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
            _minio_op(lambda d=dest, k=sf["minio_key"]: minio.fget_object(MINIO_BUCKET, k, str(d)))

        logger.info("[%s] Sources: %s", run_id,
                    [p.name for p in sorted(sources_dir.iterdir()) if p.is_file()])

        # ── 2. Run module ─────────────────────────────────────────────────────
        # tool_meta captures subprocess output for display in the UI
        tool_meta: dict[str, str] = {"stdout": "", "stderr": "", "log": ""}

        RUNNERS = {
            "hayabusa":            _run_hayabusa,
            "strings":             _run_strings,
            "hindsight":           _run_hindsight,
            "regripper":           _run_regripper,
            "wintriage":           _run_wintriage,
            "yara":                _run_yara,
            "exiftool":            _run_exiftool,
            "volatility3":         _run_volatility3,
            "oletools":            _run_oletools,
            "pe_analysis":         _run_pe_analysis,
            "strings_analysis":    _run_strings_analysis,
            "grep_search":         _run_grep_search,
            "ole_analysis":        _run_oletools,        # alias
            "access_log_analysis": _run_access_log_analysis,
            "cuckoo":              _run_cuckoo,
            "de4dot":              _run_de4dot,
            "malwoverview":        _run_malwoverview,
        }
        runner = RUNNERS.get(module_id)

        if runner is not None:
            # Built-in module — run directly in this process
            results = runner(run_id, work_dir, sources_dir, params, tool_meta)
        else:
            # Custom module — run in isolated sandboxed subprocess
            results = _run_custom_module(
                run_id, case_id, module_id, work_dir, source_files, params, tool_meta
            )

        # ── 3a. For Hayabusa: also index into Elasticsearch so hits appear in Timeline ──
        if module_id == "hayabusa" and results:
            ingested_at = datetime.now(timezone.utc).isoformat()
            try:
                indexed = _hayabusa_index_to_es(case_id, run_id, results, ingested_at)
                tool_meta["log"] += f"\nIndexed {indexed} events into Elasticsearch (artifact_type=hayabusa)\n"
                tool_meta["stdout"] += f"\n=== Indexed {indexed} events into Timeline (ES) ===\n"
            except Exception as _es_exc:
                logger.warning("[%s] ES indexing failed (non-fatal): %s", run_id, _es_exc)
                tool_meta["log"] += f"\n[ES index warning: {_es_exc}]\n"

        # ── 3. Upload full results to MinIO ───────────────────────────────────
        results_json = work_dir / "results.json"
        results_json.write_text(json.dumps(results, ensure_ascii=False))
        output_key = f"cases/{case_id}/modules/{run_id}/results.json"
        _minio_op(lambda: minio.fput_object(MINIO_BUCKET, output_key, str(results_json),
                                            content_type="application/json"))
        logger.info("[%s] Uploaded %d hits to MinIO", run_id, len(results))

        # ── 4. Level summary ─────────────────────────────────────────────────
        hits_by_level: dict[str, int] = {}
        for hit in results:
            lvl = hit.get("level", "informational")
            hits_by_level[lvl] = hits_by_level.get(lvl, 0) + 1

        # ── 5. Complete ───────────────────────────────────────────────────────
        # Sort by severity descending for the preview so the most critical
        # detections always appear first — not just the first 200 by timestamp.
        results_by_severity = sorted(
            results, key=lambda h: h.get("level_int", 1), reverse=True
        )
        _update(r, run_id,
                status="COMPLETED",
                total_hits=str(len(results)),
                hits_by_level=json.dumps(hits_by_level),
                results_preview=json.dumps(results_by_severity[:200]),
                output_minio_key=output_key,
                tool_stdout=tool_meta.get("stdout", "")[:16000],
                tool_stderr=tool_meta.get("stderr", "")[:4000],
                tool_log=tool_meta.get("log",    "")[:8000],
                completed_at=datetime.now(timezone.utc).isoformat())

        logger.info("[%s] Module run complete: %d hits", run_id, len(results))
        return {"status": "COMPLETED", "total_hits": len(results)}

    except Exception as exc:
        logger.exception("[%s] Module run failed: %s", run_id, exc)
        _update(r, run_id,
                status="FAILED",
                error=str(exc),
                tool_stdout=tool_meta.get("stdout", "")[:8000] if 'tool_meta' in dir() else "",
                tool_stderr=tool_meta.get("stderr", "")[:4000] if 'tool_meta' in dir() else "",
                completed_at=datetime.now(timezone.utc).isoformat())
        raise RuntimeError(str(exc)) from None

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Hayabusa
# ─────────────────────────────────────────────────────────────────────────────

def _find_hayabusa_rules() -> Path | None:
    """Locate the Hayabusa rules/ directory.

    Tries (in order):
    1. Sibling of the real binary (follows symlinks) — works when the full
       distribution is kept next to the binary (e.g. /opt/hayabusa/).
    2. Hardcoded fallback /opt/hayabusa/rules.
    """
    bin_path = shutil.which("hayabusa")
    if bin_path:
        real_bin = Path(bin_path).resolve()
        candidate = real_bin.parent / "rules"
        if candidate.is_dir():
            return candidate
    fallback = Path("/opt/hayabusa/rules")
    if fallback.is_dir():
        return fallback
    return None


def _run_hayabusa(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    hayabusa_bin = shutil.which("hayabusa")
    if not hayabusa_bin:
        raise RuntimeError(
            "Hayabusa binary not found. Ensure the processor image was built with the Hayabusa step."
        )

    rules_dir = _find_hayabusa_rules()
    if rules_dir is None:
        raise RuntimeError(
            "Hayabusa rules directory not found next to the binary or at /opt/hayabusa/rules. "
            "Rebuild the processor image — the full distribution (binary + rules/) must be kept together."
        )
    logger.info("[%s] Using Hayabusa rules: %s", run_id, rules_dir)

    # List EVTX files we are about to scan
    evtx_files = [p.name for p in sources_dir.iterdir()
                  if p.is_file() and p.suffix.lower() == ".evtx"]
    logger.info("[%s] EVTX files in sources_dir: %s", run_id, evtx_files)
    tool_meta["log"] = f"Rules: {rules_dir}\nEVTX files: {', '.join(evtx_files) or 'none'}\n"

    output_csv = work_dir / "hayabusa_output.csv"
    min_level  = params.get("min_level", "informational")

    # csv-timeline is the most reliable output format across all Hayabusa 3.x versions.
    # The JSONL writer has had format-shift bugs between minor releases; CSV is stable.
    cmd = [
        hayabusa_bin, "csv-timeline",
        "--no-wizard",           # required since 3.x: suppress interactive wizard
        "-d", str(sources_dir),
        "-r", str(rules_dir),
        "-o", str(output_csv),
        "--min-level", min_level,
    ]

    logger.info("[%s] Running: %s", run_id, " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,  # prevent any interactive prompts
            timeout=3600,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Hayabusa timed out after 1 hour")

    # Strip ANSI escape codes before storing in Redis / displaying in UI
    stdout_str = _strip_ansi((proc.stdout or "").strip())
    stderr_str = _strip_ansi((proc.stderr or "").strip())

    # Combine both streams into tool_meta for display in the UI
    combined = ""
    if stdout_str:
        combined += stdout_str
    if stderr_str:
        combined += ("\n" if combined else "") + "[stderr]\n" + stderr_str
    tool_meta["stdout"] = combined
    tool_meta["log"] += f"\nReturn code: {proc.returncode}\n"

    if stdout_str:
        logger.info("[%s] Hayabusa stdout:\n%s", run_id, stdout_str[:3000])
    if stderr_str:
        logger.info("[%s] Hayabusa stderr:\n%s", run_id, stderr_str[:1000])

    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"Hayabusa exited {proc.returncode}: {(stderr_str or stdout_str or '')[:500]}"
        )

    if not output_csv.exists() or output_csv.stat().st_size == 0:
        detail = f"\n\nHayabusa output:\n{combined[:1000]}" if combined else ""
        logger.warning("[%s] Hayabusa produced no output file (or empty)%s", run_id, detail)
        return []

    file_size = output_csv.stat().st_size
    logger.info("[%s] Hayabusa output file: %d bytes", run_id, file_size)

    # ── Diagnostic: raw bytes peek into tool_stdout so it's visible in UI ────
    try:
        with open(output_csv, "rb") as _bf:
            _raw_bytes = _bf.read(600)
        _raw_text = _raw_bytes.decode("utf-8", errors="replace")
        tool_meta["stdout"] += (
            f"\n\n=== CSV output: {file_size:,} bytes ==="
            f"\nFirst 600 bytes:\n{_raw_text}\n"
        )
    except Exception as _e:
        tool_meta["stdout"] += f"\n[file peek error: {_e}]\n"

    return _parse_hayabusa_csv(output_csv, tool_meta)


def _parse_hayabusa_csv(path: Path, tool_meta: dict | None = None) -> list[dict]:
    """Parse Hayabusa csv-timeline output into the hit list used by the module runner."""

    def _log(msg: str) -> None:
        if tool_meta is not None:
            tool_meta["log"] += msg

    _LEVEL_MAP = {
        "info": "informational", "information": "informational",
        "crit": "critical",
        "med":  "medium", "warn": "medium", "warning": "medium",
    }

    results: list[dict] = []
    skipped = 0
    first_skip_msg = ""

    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            _log(f"\nCSV columns: {reader.fieldnames}\n")
            if tool_meta:
                tool_meta["stdout"] += f"\nCSV columns: {reader.fieldnames}\n"

            for lineno, row in enumerate(reader, 2):
                try:
                    rule_title = str(row.get("RuleTitle") or row.get("ruleTitle") or "")
                    ts_raw     = str(row.get("Timestamp") or row.get("timestamp") or "")
                    if not rule_title and not ts_raw:
                        skipped += 1
                        if skipped == 1:
                            first_skip_msg = f"line {lineno}: missing RuleTitle+Timestamp"
                        continue

                    level = str(row.get("Level") or row.get("level") or "informational").lower()
                    level = _LEVEL_MAP.get(level, level)

                    details_raw = str(row.get("Details") or row.get("details") or "")
                    # CSV Details is always a string; may contain key: val | key: val
                    event_id_raw = str(row.get("EventID") or row.get("eventId") or "")
                    try:
                        event_id: int | None = int(event_id_raw) if event_id_raw else None
                    except ValueError:
                        event_id = None

                    # Tags column: comma-separated MITRE ATT&CK tags
                    # e.g. "attack.defense-evasion,attack.t1059.003"
                    tags_raw = str(row.get("Tags") or row.get("tags") or row.get("MitreTags") or "")
                    tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

                    results.append({
                        "id":          str(uuid.uuid4()),
                        "timestamp":   _normalize_ts(ts_raw),
                        "level":       level,
                        "level_int":   LEVEL_INT.get(level, 1),
                        "rule_title":  rule_title,
                        "computer":    str(row.get("Computer") or row.get("computer") or ""),
                        "channel":     str(row.get("Channel") or row.get("channel") or ""),
                        "event_id":    event_id,
                        "details_raw": details_raw[:2000],
                        "rule_file":   str(row.get("RuleFile") or row.get("ruleFile") or ""),
                        "evtx_file":   str(row.get("EvtxFile") or row.get("evtxFile") or ""),
                        "tags":        tags,
                    })
                except Exception as exc:
                    skipped += 1
                    if skipped <= 3:
                        logger.warning("Hayabusa CSV row %d error: %s", lineno, exc)
                    if skipped == 1:
                        first_skip_msg = f"line {lineno}: {exc}"

    except Exception as exc:
        _log(f"\n[CSV read error: {exc}]\n")
        return []

    summary = (
        f"\nParsed {len(results):,} CSV hits ({skipped:,} skipped)"
        + (f"\n{first_skip_msg}" if first_skip_msg else "")
        + "\n"
    )
    _log(summary)
    if tool_meta:
        tool_meta["stdout"] += f"\n=== Parser: {len(results):,} hits ({skipped:,} skipped) ===\n"
        if first_skip_msg:
            tool_meta["stdout"] += f"{first_skip_msg}\n"

    return results


def _hayabusa_index_to_es(
    case_id: str,
    run_id: str,
    hits: list[dict],
    ingested_at: str,
    bulk_size: int = 500,
) -> int:
    """Bulk-index Hayabusa hits into Elasticsearch as artifact_type=hayabusa events."""
    es_url = ELASTICSEARCH_URL.rstrip("/")
    indexed = 0

    def _flush(batch: list[dict]) -> None:
        nonlocal indexed
        lines = []
        for event in batch:
            index_name = f"fo-case-{case_id}-hayabusa"
            action = {"index": {"_index": index_name, "_id": event["fo_id"]}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(event))
        body = "\n".join(lines) + "\n"
        req = urllib.request.Request(
            f"{es_url}/_bulk",
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            if result.get("errors"):
                errs = [i for i in result.get("items", []) if i.get("index", {}).get("error")]
                logger.warning("Hayabusa ES bulk: %d errors in batch", len(errs))
        indexed += len(batch)

    batch: list[dict] = []
    for hit in hits:
        level = hit.get("level", "informational")
        computer = hit.get("computer", "")
        rule_title = hit.get("rule_title", "")
        message = f"[{level.upper()}] {rule_title}"
        if computer:
            message += f" on {computer}"

        event = {
            "fo_id":          str(uuid.uuid4()),
            "case_id":        case_id,
            "ingest_job_id":  run_id,
            "source_file":    f"module:hayabusa:{run_id}",
            "ingested_at":    ingested_at,
            "artifact_type":  "hayabusa",
            "timestamp":      hit.get("timestamp", ""),
            "timestamp_desc": "Hayabusa Detection",
            "message":        message,
            "host":           {"hostname": computer},
            "hayabusa": {
                "rule_title":  rule_title,
                "level":       level,
                "level_int":   hit.get("level_int", 1),
                "computer":    computer,
                "channel":     hit.get("channel", ""),
                "event_id":    hit.get("event_id"),
                "details_raw": hit.get("details_raw", ""),
                "rule_file":   hit.get("rule_file", ""),
                "evtx_file":   hit.get("evtx_file", ""),
            },
            "tags":          [],
            "analyst_note":  "",
            "is_flagged":    False,
            "mitre":         {},
            "raw":           {},
        }
        batch.append(event)
        if len(batch) >= bulk_size:
            _flush(batch)
            batch = []

    if batch:
        _flush(batch)

    return indexed


def _parse_hayabusa_jsonl(path: Path, tool_meta: dict | None = None) -> list[dict]:
    """
    Parse Hayabusa output.  Handles two formats:
      • JSONL  – one JSON object per line  (Hayabusa default with .jsonl extension)
      • JSON   – a single JSON array       (Hayabusa -o file.json, pretty-print mode)

    Streams line-by-line for JSONL to avoid loading the full file into memory.
    utf-8-sig encoding handles UTF-8 BOM headers automatically.
    """

    def _log(msg: str) -> None:
        if tool_meta is not None:
            tool_meta["log"] += msg

    rows: list[dict] = []
    results: list[dict] = []
    skipped = 0
    total   = 0
    first_skip_msg = ""

    # ── Peek at the first non-empty line to detect format ────────────────────
    first_line = ""
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            for raw_line in fh:
                stripped_line = raw_line.strip()
                if stripped_line:
                    first_line = stripped_line
                    break
    except Exception as exc:
        _log(f"\n[JSONL peek error: {exc}]\n")
        return []

    _log(f"\nFirst non-empty line (120 chars): {first_line[:120]}\n")

    if first_line.startswith("["):
        # ── JSON array format — full read required ────────────────────────
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                text = fh.read()
            data = json.loads(text)
            rows = data if isinstance(data, list) else [data]
            _log(f"\n[format: JSON array, {len(rows):,} entries]\n")
        except (json.JSONDecodeError, MemoryError) as exc:
            _log(f"\n[JSON array parse failed ({exc}); falling back to line-by-line]\n")
            rows = []
            try:
                with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                    for line in fh:
                        line = line.strip().rstrip(",")
                        if not line or line in ("[", "]"):
                            continue
                        try:
                            rows.append(json.loads(line))
                        except Exception:
                            pass
                _log(f"\n[format: JSON array (line fallback), {len(rows):,} entries]\n")
            except Exception as exc2:
                _log(f"\n[line fallback error: {exc2}]\n")
    else:
        # ── JSONL format — stream line-by-line ───────────────────────────
        parse_errors = 0
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                for lineno, raw_line in enumerate(fh, 1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Rare: some builds emit trailing commas
                        try:
                            rows.append(json.loads(line.rstrip(",")))
                        except Exception as exc:
                            parse_errors += 1
                            if parse_errors <= 3:
                                logger.warning(
                                    "Hayabusa: JSONL parse error line %d: %s | raw: %.120s",
                                    lineno, exc, line,
                                )
            _log(f"\n[format: JSONL, {len(rows):,} rows decoded, {parse_errors} parse errors]\n")
        except Exception as exc:
            _log(f"\n[JSONL streaming error: {exc}]\n")

    # ── Log first row for diagnostics ─────────────────────────────────────────
    if rows:
        first_row = rows[0]
        _log(f"\nFirst row keys: {list(first_row.keys())}\n")
        _log(f"First row sample: {str(first_row)[:400]}\n")
        # Also surface to tool_stdout so it's visible without scrolling to log
        if tool_meta is not None:
            tool_meta["stdout"] += f"\nFirst row keys: {list(first_row.keys())}\n"
    else:
        _log("\n[WARNING: 0 rows decoded from output file — check format above]\n")
        if tool_meta is not None:
            tool_meta["stdout"] += "\n[WARNING: 0 rows decoded from output file]\n"

    # ── Convert rows to hits ──────────────────────────────────────────────────
    for row in rows:
        if not isinstance(row, dict):
            skipped += 1
            continue
        total += 1
        try:
            hit = _hayabusa_row_to_hit(row)
            if hit:
                results.append(hit)
            else:
                skipped += 1
                if skipped == 1:
                    first_skip_msg = f"first skipped row keys: {list(row.keys())[:12]}"
        except Exception as exc:
            skipped += 1
            if skipped <= 3:
                logger.warning("Hayabusa: row conversion error: %s | keys: %s", exc, list(row.keys())[:8])
            if skipped == 1:
                first_skip_msg = f"row error: {exc} | keys: {list(row.keys())[:8]}"

    logger.info("Hayabusa: %d rows, %d hits, %d skipped", total, len(results), skipped)
    summary = (
        f"\nDecoded {total:,} rows → {len(results):,} hits ({skipped:,} skipped)"
        + (f"\n{first_skip_msg}" if first_skip_msg else "")
        + "\n"
    )
    _log(summary)
    # Also surface parse summary to tool_stdout
    if tool_meta is not None:
        tool_meta["stdout"] += f"\n=== Parser: {total:,} rows → {len(results):,} hits ({skipped:,} skipped) ==="
        if first_skip_msg:
            tool_meta["stdout"] += f"\n{first_skip_msg}"
        tool_meta["stdout"] += "\n"
    return results


def _hayabusa_row_to_hit(row: dict) -> dict | None:
    # Accept PascalCase (2.x / 3.x standard), camelCase, snake_case, and @-prefixed variants
    def _g(*keys):
        for k in keys:
            v = row.get(k)
            if v is not None and v != "":
                return v
        return ""

    timestamp_raw = _g("Timestamp", "timestamp", "@timestamp", "datetime", "time")
    rule_title    = str(_g("RuleTitle", "ruleTitle", "rule_title", "Title", "title", "RuleName", "rule_name") or "")
    level         = str(_g("Level", "level", "Severity", "severity") or "informational").lower()
    computer      = str(_g("Computer", "computer", "Hostname", "hostname", "host") or "")
    channel       = str(_g("Channel", "channel") or "")
    event_id_raw  = str(_g("EventID", "eventId", "event_id", "EventId") or "")
    rule_file     = str(_g("RuleFile", "ruleFile", "rule_file") or "")
    evtx_file     = str(_g("EvtxFile", "evtxFile", "evtx_file", "SrcFile", "src_file") or "")

    if not rule_title and not timestamp_raw:
        return None

    # Details can be a dict (Hayabusa 3.x) or a plain string (2.x)
    raw_details = row.get("Details") or row.get("details") or ""
    if isinstance(raw_details, dict):
        # Flatten key: value pairs into a readable string
        details_raw = " | ".join(f"{k}: {v}" for k, v in raw_details.items() if v not in (None, "", "-"))
    else:
        details_raw = str(raw_details)

    try:
        event_id: int | None = int(event_id_raw) if event_id_raw else None
    except (ValueError, TypeError):
        event_id = None

    # Normalise level names across Hayabusa versions
    # 3.x: "crit", "high", "med", "low", "info"
    # 2.x: "critical", "high", "medium", "low", "informational"
    level_map = {
        "info": "informational", "information": "informational",
        "crit": "critical",
        "med":  "medium", "warn": "medium", "warning": "medium",
    }
    level = level_map.get(level, level)

    return {
        "id":          str(uuid.uuid4()),
        "timestamp":   _normalize_ts(timestamp_raw),
        "level":       level,
        "level_int":   LEVEL_INT.get(level, 1),
        "rule_title":  rule_title,
        "computer":    computer,
        "channel":     channel,
        "event_id":    event_id,
        "details_raw": details_raw[:2000],
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


def _run_strings(run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict) -> list[dict]:
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

def _run_hindsight(run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict) -> list[dict]:
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


def _run_regripper(run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict) -> list[dict]:
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


# ─────────────────────────────────────────────────────────────────────────────
# Windows Artifact Triage
# Handles: .evtx · registry hives · .lnk · .pf (Prefetch)
# ─────────────────────────────────────────────────────────────────────────────

_EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Interesting Windows event IDs for forensic triage: {eid: (label, level)}
_INTERESTING_EIDS: dict[int, tuple[str, str]] = {
    # Authentication & Lateral Movement
    4624:  ("Logon",                        "medium"),
    4625:  ("Failed Logon",                 "high"),
    4648:  ("Explicit-Credential Logon",    "high"),
    4672:  ("Special Privileges Logon",     "medium"),
    4776:  ("NTLM Auth Attempt",            "medium"),
    4778:  ("RDP Session Reconnected",      "medium"),
    4779:  ("RDP Session Disconnected",     "low"),
    # Account Management
    4720:  ("User Account Created",         "high"),
    4722:  ("Account Enabled",              "medium"),
    4724:  ("Password Reset",               "high"),
    4732:  ("Added to Local Group",         "high"),
    4756:  ("Added to Universal Group",     "medium"),
    4728:  ("Added to Global Group",        "high"),
    # Process / Execution Evidence
    4688:  ("Process Created",              "medium"),
    4689:  ("Process Terminated",           "low"),
    # Service / Driver
    7045:  ("Service Installed",            "high"),
    7034:  ("Service Crashed",              "medium"),
    7036:  ("Service State Changed",        "low"),
    4697:  ("Service Installed (Security)", "high"),
    # Scheduled Tasks
    4698:  ("Scheduled Task Created",       "high"),
    4702:  ("Scheduled Task Updated",       "medium"),
    4699:  ("Scheduled Task Deleted",       "high"),
    # PowerShell
    4103:  ("PS Module Logging",            "medium"),
    4104:  ("PS Script Block",              "high"),
    # Audit Tampering
    1102:  ("Security Log Cleared",         "critical"),
    104:   ("System Log Cleared",           "critical"),
    4719:  ("System Audit Policy Changed",  "high"),
    # Policy / Object Access
    4670:  ("Permissions Changed",          "medium"),
    4663:  ("Object Access Attempted",      "low"),
    # Network (Windows Firewall)
    5156:  ("Network Connection Allowed",   "low"),
    5158:  ("Network Bind Allowed",         "low"),
    # BITS (common persistence / exfil channel)
    59:    ("BITS Job Created",             "medium"),
    60:    ("BITS Job Transferred",         "low"),
    # System lifecycle
    6005:  ("Event Log Started",            "low"),
    6006:  ("Event Log Stopped",            "low"),
    6009:  ("OS Version at Boot",           "low"),
}

MAX_EVTX_HITS = 3000  # per-file cap

# Registry paths to examine per hive type (paths relative to hive root)
_REG_TRIAGE_PATHS: dict[str, list[tuple[str, str]]] = {
    "ntuser": [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "HKCU Run (Persistence)"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKCU RunOnce (Persistence)"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
         "Recent Documents"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
         "Explorer Typed Paths"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
         "Run Dialog MRU"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps",
         "Recent Apps"),
        (r"SOFTWARE\Microsoft\Internet Explorer\TypedURLs",
         "IE Typed URLs"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
         "Open/Save Dialog MRU"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU",
         "Mapped Drives MRU"),
    ],
    "usrclass": [
        (r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
         "Shell Bags (folder navigation)"),
        (r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
         "Installed UWP Apps"),
    ],
    "software": [
        (r"Microsoft\Windows\CurrentVersion\Run",
         "HKLM Run (Persistence)"),
        (r"Microsoft\Windows\CurrentVersion\RunOnce",
         "HKLM RunOnce (Persistence)"),
        (r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
         "HKLM Run WOW64 (Persistence)"),
        (r"Microsoft\Windows NT\CurrentVersion",
         "OS Version / Install Date"),
        (r"Microsoft\Windows NT\CurrentVersion\ProfileList",
         "User Profile List"),
        (r"Microsoft\Windows NT\CurrentVersion\Winlogon",
         "Winlogon (possible persistence)"),
        (r"Microsoft\Windows\CurrentVersion\Policies\System",
         "UAC & Policy Settings"),
        (r"Clients\StartMenuInternet",
         "Default Browser"),
    ],
    "system": [
        (r"ControlSet001\Control\ComputerName\ComputerName",
         "Computer Name"),
        (r"ControlSet001\Control\TimeZoneInformation",
         "Timezone"),
        (r"ControlSet001\Services",
         "Services (persistence)"),
        (r"ControlSet001\Control\Session Manager\AppCompatCache",
         "AppCompatCache / ShimCache"),
        (r"MountedDevices",
         "Mounted Devices (USB evidence)"),
        (r"ControlSet001\Enum\USBSTOR",
         "USB Storage History"),
    ],
    "sam": [
        (r"SAM\Domains\Account\Users\Names",
         "Local User Accounts"),
        (r"SAM\Domains\Account",
         "Account Policy"),
    ],
    "security": [],   # binary-heavy; RegRipper handles it better
}

MAX_REG_VALUES = 60  # per key


def _hive_type(filename: str) -> str:
    n = os.path.basename(filename).upper()
    if "NTUSER" in n:    return "ntuser"
    if "USRCLASS" in n:  return "usrclass"
    if n == "SYSTEM":    return "system"
    if n == "SOFTWARE":  return "software"
    if n == "SAM":       return "sam"
    if n == "SECURITY":  return "security"
    return "ntuser"


# ── EVTX ─────────────────────────────────────────────────────────────────────

def _parse_evtx_triage(file_path: Path) -> list[dict]:
    try:
        import Evtx.Evtx as evtx_lib
    except ImportError:
        logger.warning("[wintriage] python-evtx not installed, skipping EVTX")
        return []

    ns = _EVTX_NS
    results: list[dict] = []

    try:
        with evtx_lib.Evtx(str(file_path)) as log:
            for record in log.records():
                if len(results) >= MAX_EVTX_HITS:
                    break
                try:
                    root   = record.lxml()
                    sys_el = root.find(f"{{{ns}}}System")
                    if sys_el is None:
                        continue

                    eid_el = sys_el.find(f"{{{ns}}}EventID")
                    if eid_el is None:
                        continue
                    try:
                        event_id = int(eid_el.text)
                    except (ValueError, TypeError):
                        continue

                    if event_id not in _INTERESTING_EIDS:
                        continue

                    label, level = _INTERESTING_EIDS[event_id]

                    tc_el   = sys_el.find(f"{{{ns}}}TimeCreated")
                    ts      = tc_el.get("SystemTime", "") if tc_el is not None else ""

                    comp_el = sys_el.find(f"{{{ns}}}Computer")
                    computer = (comp_el.text or "") if comp_el is not None else ""

                    chan_el = sys_el.find(f"{{{ns}}}Channel")
                    channel = (chan_el.text or "") if chan_el is not None else ""

                    # EventData key-value pairs
                    ed_el  = root.find(f"{{{ns}}}EventData")
                    parts: list[str] = []
                    if ed_el is not None:
                        for data_el in ed_el:
                            name = data_el.get("Name", "")
                            val  = (data_el.text or "").strip()
                            if name and val and val not in ("-", "%%1840", "%%1843", "%%1842"):
                                parts.append(f"{name}: {val}")
                    details = " | ".join(parts[:7])

                    results.append({
                        "id":          str(uuid.uuid4()),
                        "timestamp":   ts,
                        "level":       level,
                        "level_int":   LEVEL_INT.get(level, 1),
                        "rule_title":  f"EID {event_id}: {label}",
                        "computer":    computer,
                        "details_raw": f"[{channel}] {details}" if details else f"[{channel}]",
                    })
                except Exception:
                    continue
    except Exception as exc:
        logger.warning("[wintriage] EVTX error %s: %s", file_path.name, exc)

    return results


# ── Registry ──────────────────────────────────────────────────────────────────

def _parse_registry_triage(file_path: Path) -> list[dict]:
    try:
        from Registry import Registry as RegistryLib
    except ImportError:
        logger.warning("[wintriage] python-registry not installed, skipping registry")
        return []

    hive_type   = _hive_type(file_path.name)
    triage_paths = _REG_TRIAGE_PATHS.get(hive_type, [])
    if not triage_paths:
        return []

    try:
        reg = RegistryLib.Registry(str(file_path))
    except Exception as exc:
        logger.warning("[wintriage] Cannot open registry %s: %s", file_path.name, exc)
        return []

    results: list[dict] = []

    for key_path, label in triage_paths:
        try:
            key = reg.open(key_path)
        except Exception:
            continue  # key absent in this hive variant

        try:
            ts_dt = key.timestamp()
            ts = ts_dt.isoformat() + "Z" if ts_dt else ""
        except Exception:
            ts = ""

        values_found = 0
        for val in key.values():
            if values_found >= MAX_REG_VALUES:
                break
            try:
                name = val.name() or "(Default)"
                data = str(val.value())[:600]
                if not data.strip():
                    continue
            except Exception:
                continue
            results.append({
                "id":          str(uuid.uuid4()),
                "timestamp":   ts,
                "level":       "informational",
                "level_int":   1,
                "rule_title":  f"{label}: {name}",
                "computer":    file_path.name,
                "details_raw": data,
            })
            values_found += 1

        # No values → list subkey names as a single summary hit
        if values_found == 0:
            try:
                subkeys = [sk.name() for sk in list(key.subkeys())[:MAX_REG_VALUES]]
                if subkeys:
                    results.append({
                        "id":          str(uuid.uuid4()),
                        "timestamp":   ts,
                        "level":       "informational",
                        "level_int":   1,
                        "rule_title":  f"{label} (subkeys)",
                        "computer":    file_path.name,
                        "details_raw": " | ".join(subkeys),
                    })
            except Exception:
                pass

    return results


# ── LNK ──────────────────────────────────────────────────────────────────────

def _parse_lnk_triage(file_path: Path) -> list[dict]:
    try:
        import LnkParse3
    except ImportError:
        logger.warning("[wintriage] LnkParse3 not installed, skipping LNK")
        return []

    try:
        with open(file_path, "rb") as fh:
            lnk  = LnkParse3.lnk_file(fh)
            data = lnk.get_json()
    except Exception as exc:
        logger.debug("[wintriage] LNK parse failed %s: %s", file_path.name, exc)
        return []

    header      = data.get("header",      {}) or {}
    link_info   = data.get("link_info",   {}) or {}
    string_data = data.get("string_data", {}) or {}

    ts = header.get("creation_time") or header.get("write_time") or ""
    if ts and not ts.endswith("Z"):
        ts = ts.replace(" ", "T") + "Z"

    target_path = (
        link_info.get("local_base_path")
        or string_data.get("relative_path")
        or string_data.get("working_dir")
        or file_path.stem
    )

    vol_info  = link_info.get("volume_id_and_local_base_path") or {}
    vol_label = vol_info.get("volume_label", "") if isinstance(vol_info, dict) else ""
    machine   = string_data.get("machine_identifier", "")
    cmd_args  = string_data.get("command_line_arguments", "")

    details = target_path or file_path.stem
    if vol_label:  details += f"  [Vol: {vol_label}]"
    if cmd_args:   details += f"  Args: {cmd_args}"
    if machine:    details += f"  Machine: {machine}"

    return [{
        "id":          str(uuid.uuid4()),
        "timestamp":   ts,
        "level":       "informational",
        "level_int":   1,
        "rule_title":  f"LNK: {file_path.stem}",
        "computer":    machine or "",
        "details_raw": details,
    }]


# ── Prefetch ──────────────────────────────────────────────────────────────────

_PF_RUN_COUNT_OFFSET: dict[int, int] = {
    17: 0x90,   # Windows XP
    23: 0x98,   # Windows Vista / 7
    26: 0xD0,   # Windows 8 / 8.1
    30: 0xD0,   # Windows 10 (uncompressed only)
}


def _parse_prefetch_triage(file_path: Path) -> list[dict]:
    stem  = file_path.stem                     # e.g. NOTEPAD.EXE-AB1234CD
    parts = stem.rsplit("-", 1)
    exe_name = parts[0] if len(parts) == 2 else stem
    pf_hash  = parts[1] if len(parts) == 2 else ""

    try:
        mtime = datetime.fromtimestamp(
            file_path.stat().st_mtime, tz=timezone.utc
        ).isoformat()
    except Exception:
        mtime = ""

    run_count    = None
    version_note = ""

    try:
        with open(file_path, "rb") as fh:
            header = fh.read(512)

        if header[:3] == b"MAM":
            version_note = "Win10 (MAM-compressed)"
        elif header[4:8] == b"SCCA" and len(header) >= 8:
            ver    = struct.unpack_from("<I", header, 0)[0]
            offset = _PF_RUN_COUNT_OFFSET.get(ver)
            if offset and len(header) >= offset + 4:
                run_count = struct.unpack_from("<I", header, offset)[0]
            version_note = {17: "WinXP", 23: "Vista/7", 26: "Win8.x", 30: "Win10"}.get(ver, f"v{ver}")
        else:
            version_note = "unknown format"
    except Exception:
        pass

    details = exe_name
    if pf_hash:                   details += f"  hash={pf_hash}"
    if run_count is not None:     details += f"  run_count={run_count}"
    if version_note:              details += f"  [{version_note}]"

    return [{
        "id":          str(uuid.uuid4()),
        "timestamp":   mtime,
        "level":       "informational",
        "level_int":   1,
        "rule_title":  f"Prefetch: {exe_name}",
        "computer":    "",
        "details_raw": details,
    }]


# ── Main dispatcher ───────────────────────────────────────────────────────────

_REGISTRY_FILENAMES  = frozenset({"NTUSER.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "USRCLASS.DAT"})
_REGISTRY_EXTENSIONS = frozenset({".dat", ".hive"})


def _run_wintriage(run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict) -> list[dict]:
    """
    Auto-detect Windows artifact type and run the appropriate parser.

      .evtx              → EVTX triage (filtered to ~35 high-value event IDs)
      .dat / .hive /
      SYSTEM / SOFTWARE /
      SAM / SECURITY /
      NTUSER.DAT         → Registry triage (persistence + forensic key paths)
      .lnk               → LNK (target path, timestamps, machine ID)
      .pf                → Prefetch (execution evidence + run count)
    """
    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue

        name_upper = file_path.name.upper()
        ext        = file_path.suffix.lower()

        if ext == ".evtx":
            logger.info("[%s] wintriage EVTX: %s", run_id, file_path.name)
            hits = _parse_evtx_triage(file_path)

        elif name_upper in _REGISTRY_FILENAMES or ext in _REGISTRY_EXTENSIONS:
            logger.info("[%s] wintriage Registry: %s", run_id, file_path.name)
            hits = _parse_registry_triage(file_path)

        elif ext == ".lnk":
            logger.info("[%s] wintriage LNK: %s", run_id, file_path.name)
            hits = _parse_lnk_triage(file_path)

        elif ext == ".pf":
            logger.info("[%s] wintriage Prefetch: %s", run_id, file_path.name)
            hits = _parse_prefetch_triage(file_path)

        else:
            logger.debug("[%s] wintriage skip: %s", run_id, file_path.name)
            continue

        logger.info("[%s] %s → %d hits", run_id, file_path.name, len(hits))
        results.extend(hits)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# YARA Scanner
# ─────────────────────────────────────────────────────────────────────────────

# Built-in ruleset — 16 rules covering common malware patterns and threat-hunting
_YARA_RULES_SOURCE = r"""
rule SuspiciousPE_Packer {
    meta:
        description = "Detects common PE packer signatures"
        severity = "medium"
    strings:
        $upx0   = "UPX0"    ascii
        $upx1   = "UPX1"    ascii
        $upx2   = "UPX2"    ascii
        $aspack = "ASPack"  ascii
        $fsg    = ".ndata"  ascii
        $mpress = "MPRESS1" ascii
    condition:
        2 of them
}

rule SuspiciousScript_PowerShellEncoded {
    meta:
        description = "Detects base64-encoded or obfuscated PowerShell commands"
        severity = "high"
    strings:
        $enc1 = "-EncodedCommand"  ascii nocase
        $enc3 = "FromBase64String" ascii nocase
        $enc4 = "JABlAG4AYwBvAGQA" ascii
        $iex1 = "Invoke-Expression" ascii nocase
        $iex2 = "IEX("             ascii nocase
        $byp1 = "bypass"           ascii nocase
        $byp2 = "DownloadString"   ascii nocase
        $byp3 = "DownloadFile"     ascii nocase
    condition:
        2 of ($enc*) or any of ($iex*) or (any of ($byp*) and any of ($enc*))
}

rule SuspiciousShell_ReverseShell {
    meta:
        description = "Detects common reverse shell patterns"
        severity = "critical"
    strings:
        $nc1  = "nc -e /bin/bash"         ascii nocase
        $nc2  = "nc -e /bin/sh"           ascii nocase
        $nc3  = "/bin/bash -i >& /dev/tcp/" ascii
        $nc4  = "bash -i >& /dev/tcp/"    ascii
        $perl = "perl -e 'use Socket"     ascii nocase
        $py1  = "python -c 'import socket" ascii nocase
        $py2  = "python3 -c 'import socket" ascii nocase
    condition:
        any of them
}

rule SuspiciousStrings_Credentials {
    meta:
        description = "Detects hard-coded credential patterns"
        severity = "high"
    strings:
        $pass1 = "password="  ascii nocase
        $pass2 = "passwd="    ascii nocase
        $api1  = "api_key"    ascii nocase
        $api2  = "apikey"     ascii nocase
        $sec1  = "secret_key" ascii nocase
        $sec2  = "aws_secret" ascii nocase
        $tok1  = "bearer "    ascii nocase
    condition:
        2 of them
}

rule Mimikatz_Indicators {
    meta:
        description = "Detects Mimikatz credential dumping tool signatures"
        severity = "critical"
    strings:
        $s1 = "mimikatz"       ascii nocase
        $s2 = "sekurlsa::"     ascii nocase
        $s3 = "lsadump::"      ascii nocase
        $s4 = "kerberos::"     ascii nocase
        $s5 = "privilege::debug" ascii nocase
        $s6 = "SamSs"          ascii wide
        $s7 = "wdigest"        ascii wide
    condition:
        2 of them
}

rule Webshell_PHP {
    meta:
        description = "Detects common PHP webshell patterns"
        severity = "critical"
    strings:
        $p1 = "eval(base64_decode("  ascii nocase
        $p2 = "eval(gzinflate("      ascii nocase
        $p3 = "eval(str_rot13("      ascii nocase
        $p4 = "eval($_POST["         ascii nocase
        $p5 = "system($_GET["        ascii nocase
        $p6 = "exec($_REQUEST["      ascii nocase
        $p7 = "passthru($_"          ascii nocase
    condition:
        any of them
}

rule Ransomware_ExtensionTargets {
    meta:
        description = "Detects ransomware-like file extension targeting patterns"
        severity = "high"
    strings:
        $ext2 = "encrypt"                    ascii nocase
        $ext3 = "ransom"                     ascii nocase
        $ext4 = "YOUR_FILES_ARE_ENCRYPTED"   ascii nocase
        $ext5 = "HOW_TO_DECRYPT"             ascii nocase
        $ext6 = "RECOVERY_KEY"               ascii nocase
        $ext7 = "bitcoin"                    ascii nocase
    condition:
        2 of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Detects CobaltStrike beacon patterns and default strings"
        severity = "critical"
    strings:
        $s1 = "ReflectiveLoader"       ascii
        $s2 = "beacon.dll"             ascii nocase
        $s3 = "cobaltstrike"           ascii nocase
        $s4 = "sleep_mask"             ascii
        $s5 = "%s (admin)"             ascii
        $s6 = "post-ex"                ascii
        $b1 = { 68 74 74 70 73 3A 2F 2F }   // "https://" in shellcode context
        $w1 = "www6"                   ascii
        $w2 = "cdn."                   ascii
    condition:
        2 of ($s*) or ($b1 and 1 of ($w*))
}

rule Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit/Meterpreter staging and session strings"
        severity = "critical"
    strings:
        $m1 = "meterpreter"     ascii nocase
        $m2 = "metasploit"      ascii nocase
        $m3 = "Msf::"           ascii
        $m4 = "PAYLOAD_UUID"    ascii
        $m5 = "stageless"       ascii nocase
        $sh1 = "windows/meterpreter" ascii nocase
        $sh2 = "linux/x86/meterpreter" ascii nocase
    condition:
        any of them
}

rule Persistence_Registry_AppInit {
    meta:
        description = "Detects AppInit_DLLs and other covert registry persistence keys"
        severity = "high"
    strings:
        $k1 = "AppInit_DLLs"        ascii nocase wide
        $k2 = "AppCertDlls"         ascii nocase wide
        $k3 = "Notify\\"            ascii nocase wide
        $k4 = "SecurityProviders"   ascii nocase wide
        $k5 = "LSA\\Authentication" ascii nocase wide
        $k6 = "Print\\Providers"    ascii nocase wide
        $k7 = "Winsock2\\Parameters\\Protocol_Catalog9" ascii nocase wide
    condition:
        any of them
}

rule ProcessInjection_APIs {
    meta:
        description = "Detects common process injection API call sequences"
        severity = "high"
    strings:
        $va   = "VirtualAllocEx"     ascii wide
        $wpm  = "WriteProcessMemory" ascii wide
        $ct   = "CreateRemoteThread" ascii wide
        $nt1  = "NtCreateThreadEx"   ascii wide
        $nt2  = "NtMapViewOfSection" ascii wide
        $apc  = "QueueUserAPC"       ascii wide
        $sh   = "SetWindowsHookEx"   ascii wide
    condition:
        3 of them
}

rule LOLBIN_Abuse {
    meta:
        description = "Detects Living-off-the-Land Binary abuse patterns"
        severity = "high"
    strings:
        $c1 = "certutil" ascii nocase
        $c2 = "-decode"  ascii nocase
        $c3 = "-urlcache" ascii nocase
        $r1 = "regsvr32" ascii nocase
        $r2 = "scrobj.dll" ascii nocase
        $b1 = "bitsadmin"  ascii nocase
        $b2 = "/transfer"  ascii nocase
        $w1 = "wmic"       ascii nocase
        $w2 = "process call create" ascii nocase
        $m1 = "mshta"      ascii nocase
        $m2 = "vbscript"   ascii nocase
    condition:
        ($c1 and 1 of ($c2, $c3)) or
        ($r1 and $r2) or
        ($b1 and $b2) or
        ($w1 and $w2) or
        ($m1 and $m2)
}

rule LateralMovement_PsExec {
    meta:
        description = "Detects PsExec and common lateral movement tool artifacts"
        severity = "high"
    strings:
        $px1 = "PSEXESVC"      ascii wide nocase
        $px2 = "psexec"        ascii nocase
        $wm1 = "wmiexec"       ascii nocase
        $wm2 = "Win32_Process" ascii wide
        $sm1 = "smbexec"       ascii nocase
        $at1 = "atexec"        ascii nocase
        $dc  = "dcomexec"      ascii nocase
    condition:
        any of them
}

rule SuspiciousOfficeDoc_Macro {
    meta:
        description = "Detects suspicious VBA macro execution patterns in Office documents"
        severity = "high"
    strings:
        $v1 = "Auto_Open"     ascii nocase
        $v2 = "Document_Open" ascii nocase
        $v3 = "AutoOpen"      ascii nocase
        $v4 = "Shell("        ascii nocase
        $v5 = "CreateObject(" ascii nocase
        $v6 = "WScript.Shell" ascii nocase
        $v7 = "cmd.exe"       ascii nocase
    condition:
        2 of ($v1, $v2, $v3) or (1 of ($v1, $v2, $v3) and 1 of ($v4, $v5, $v6, $v7))
}

rule DataStaging_Exfil {
    meta:
        description = "Detects data staging and potential exfiltration indicators"
        severity = "medium"
    strings:
        $z1 = "7z.exe"        ascii nocase
        $z2 = "WinRAR"        ascii nocase
        $z3 = ".7z"           ascii nocase
        $n1 = "\\\\\\\\*"     ascii
        $f1 = "passwords"     ascii nocase
        $f2 = "credentials"   ascii nocase
        $f3 = "sensitive"     ascii nocase
        $u1 = "ftp://"        ascii nocase
        $u2 = "pastebin.com"  ascii nocase
        $u3 = "mega.nz"       ascii nocase
    condition:
        (1 of ($z*) and 1 of ($f*)) or
        (1 of ($f*) and 1 of ($u*))
}

rule CryptoMiner {
    meta:
        description = "Detects cryptocurrency miner strings and configuration"
        severity = "high"
    strings:
        $s1 = "xmrig"         ascii nocase
        $s2 = "stratum+tcp://" ascii nocase
        $s3 = "monero"        ascii nocase
        $s4 = "--donate-level" ascii nocase
        $s5 = "pool.minexmr"  ascii nocase
        $s6 = "cryptonight"   ascii nocase
        $s7 = "nicehash"      ascii nocase
        $s8 = "2miners.com"   ascii nocase
    condition:
        2 of them
}
"""


def _compile_yara_rules(custom_rules_source: str | None = None):
    """Compile YARA rules from the built-in set, optionally merging custom rules."""
    import yara
    source = _YARA_RULES_SOURCE
    if custom_rules_source and custom_rules_source.strip():
        source = source + "\n\n" + custom_rules_source.strip()
    return yara.compile(source=source)


def _load_yara_library_rules(run_id: str) -> str:
    """Fetch all YARA rules stored in the library (Redis) and return them as a single string."""
    try:
        r = get_redis()
        rule_ids = r.smembers("fo:yara_rules")
        if not rule_ids:
            return ""
        parts: list[str] = []
        for rid in rule_ids:
            key = f"fo:yara_rule:{rid.decode() if isinstance(rid, bytes) else rid}"
            content = r.hget(key, "content")
            if content:
                parts.append(content.decode() if isinstance(content, bytes) else content)
        if parts:
            logger.info("[%s] YARA: loaded %d library rule(s) from library", run_id, len(parts))
        return "\n\n".join(parts)
    except Exception as exc:
        logger.warning("[%s] YARA: could not load library rules: %s", run_id, exc)
        return ""


def _run_yara(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """Scan source files with YARA rules (built-in + library + optional custom rules)."""
    custom_rules     = params.get("custom_rules", "") or ""
    use_library      = params.get("use_library_rules", True)

    # Merge library rules (fetched from Redis) with any inline custom rules from the run params
    library_rules = _load_yara_library_rules(run_id) if use_library else ""
    all_extra = "\n\n".join(s for s in [custom_rules.strip(), library_rules.strip()] if s)

    try:
        import yara
    except ImportError:
        yara_bin = shutil.which("yara")
        if not yara_bin:
            raise RuntimeError(
                "yara-python is not installed and the yara CLI binary is not in PATH. "
                "Ensure yara-python is installed in the processor image (pip install yara-python)."
            )
        return _run_yara_cli(run_id, work_dir, sources_dir, yara_bin, params, tool_meta)

    # Compile built-in rules + library rules + any custom rules
    try:
        rules = _compile_yara_rules(all_extra if all_extra else None)
    except yara.SyntaxError as exc:
        raise RuntimeError(f"YARA rule compilation failed: {exc}") from exc

    n_custom  = custom_rules.strip().count("rule ") if custom_rules.strip() else 0
    n_library = library_rules.strip().count("rule ") if library_rules.strip() else 0
    tool_meta["log"] = f"Built-in rules + {n_library} library rule(s) + {n_custom} custom rule(s)\n"

    _SEVERITY_MAP = {
        "critical": ("critical", 5),
        "high":     ("high",     4),
        "medium":   ("medium",   3),
        "low":      ("low",      2),
    }

    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue
        logger.info("[%s] YARA scanning: %s", run_id, file_path.name)
        try:
            matches = rules.match(str(file_path), timeout=60)
        except yara.TimeoutError:
            logger.warning("[%s] YARA timeout on %s", run_id, file_path.name)
            continue
        except Exception as exc:
            logger.debug("[%s] YARA error on %s: %s", run_id, file_path.name, exc)
            continue

        for match in matches:
            sev_raw  = (match.meta.get("severity") or "medium").lower()
            level, lint = _SEVERITY_MAP.get(sev_raw, ("medium", 3))
            description = match.meta.get("description", "")
            strings_info = ", ".join(
                f"{s.identifier}@{s.instances[0].offset:#x}" if s.instances else s.identifier
                for s in match.strings[:5]
            )
            results.append({
                "id":           str(uuid.uuid4()),
                "timestamp":    "",
                "level":        level,
                "level_int":    lint,
                "rule_title":   match.rule,
                "computer":     file_path.name,
                "details_raw":  f"{description}  [{strings_info}]",
                "yara_rule":    match.rule,
                "yara_tags":    list(match.tags),
                "yara_strings": strings_info,
            })

    if not results:
        results.append({
            "id":          str(uuid.uuid4()),
            "timestamp":   "",
            "level":       "informational",
            "level_int":   1,
            "rule_title":  "YARA: No matches",
            "computer":    "",
            "details_raw": "No YARA rules matched the submitted files.",
        })

    return results


def _run_yara_cli(run_id: str, work_dir: Path, sources_dir: Path, yara_bin: str, params: dict, tool_meta: dict) -> list[dict]:
    """Fallback: use the yara CLI binary."""
    rules_file = work_dir / "rules.yar"
    rules_file.write_text(_YARA_RULES_SOURCE)

    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue
        try:
            proc = subprocess.run(
                [yara_bin, "-s", str(rules_file), str(file_path)],
                capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            continue

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            rule = parts[0]
            results.append({
                "id":          str(uuid.uuid4()),
                "timestamp":   "",
                "level":       "medium",
                "level_int":   3,
                "rule_title":  rule,
                "computer":    file_path.name,
                "details_raw": line,
            })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# ExifTool
# ─────────────────────────────────────────────────────────────────────────────

def _run_exiftool(run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict) -> list[dict]:
    """Extract metadata from files using ExifTool."""
    exiftool_bin = shutil.which("exiftool")
    if not exiftool_bin:
        raise RuntimeError(
            "exiftool not found in PATH. Ensure ExifTool is installed in the processor image "
            "(apt-get install libimage-exiftool-perl, or download from exiftool.org)."
        )

    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue

        logger.info("[%s] ExifTool: %s", run_id, file_path.name)
        try:
            proc = subprocess.run(
                [exiftool_bin, "-json", "-l", "-a", "-G1", str(file_path)],
                capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.warning("[%s] ExifTool timed out on %s", run_id, file_path.name)
            continue

        if not proc.stdout.strip():
            continue

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue

        if not data or not isinstance(data, list):
            continue

        meta: dict = data[0]

        # Try to extract a meaningful timestamp
        ts = (
            meta.get("EXIF:DateTimeOriginal", {}).get("val")
            or meta.get("XMP:CreateDate", {}).get("val")
            or meta.get("QuickTime:CreateDate", {}).get("val")
            or meta.get("PDF:CreateDate", {}).get("val")
            or meta.get("File:FileModifyDate", {}).get("val")
            or ""
        )

        # Author / creator
        author = (
            meta.get("EXIF:Artist", {}).get("val")
            or meta.get("XMP:Creator", {}).get("val")
            or meta.get("PDF:Author", {}).get("val")
            or meta.get("Office:Author", {}).get("val")
            or ""
        )

        # Software
        software = (
            meta.get("EXIF:Software", {}).get("val")
            or meta.get("XMP:CreatorTool", {}).get("val")
            or meta.get("PDF:Producer", {}).get("val")
            or ""
        )

        # GPS
        gps_lat = meta.get("EXIF:GPSLatitude", {}).get("val", "")
        gps_lon = meta.get("EXIF:GPSLongitude", {}).get("val", "")

        # Build details string from interesting fields
        interesting = []
        _INTERESTING_FIELDS = [
            "EXIF:Make", "EXIF:Model", "EXIF:GPSLatitude", "EXIF:GPSLongitude",
            "XMP:Subject", "XMP:Description", "PDF:Title", "PDF:Subject",
            "Office:LastModifiedBy", "Office:AppVersion",
            "File:MIMEType", "File:FileSize",
            "Composite:GPSPosition",
        ]
        for field in _INTERESTING_FIELDS:
            val_obj = meta.get(field, {})
            val = val_obj.get("val") if isinstance(val_obj, dict) else val_obj
            if val:
                interesting.append(f"{field.split(':')[1]}: {val}")

        details = " | ".join(interesting[:10]) if interesting else f"File: {file_path.name}"

        # Embed macros or suspicious fields
        has_macros = any(
            "macro" in k.lower() or "vba" in k.lower()
            for k in meta.keys()
        )
        level     = "medium" if has_macros else "informational"
        level_int = 3 if has_macros else 1

        results.append({
            "id":          str(uuid.uuid4()),
            "timestamp":   ts,
            "level":       level,
            "level_int":   level_int,
            "rule_title":  f"ExifTool: {file_path.name}",
            "computer":    author or "",
            "details_raw": details,
            "exiftool": {
                "author":    author,
                "software":  software,
                "gps":       f"{gps_lat}, {gps_lon}" if gps_lat and gps_lon else "",
                "has_macros": has_macros,
            },
        })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Volatility 3 — memory forensics
# ─────────────────────────────────────────────────────────────────────────────

# Supported memory dump extensions
_MEMORY_EXTS = frozenset({
    ".dmp", ".vmem", ".raw", ".mem", ".img",
    ".lime", ".dd", ".bin", ".elf", ".e01",
})

# Plugins: (plugin_name, display_label, base_level, max_rows)
_VOL_WIN_PLUGINS = [
    ("windows.pslist.PsList",               "Process List",           "informational", 500),
    ("windows.cmdline.CmdLine",             "Command Lines",          "informational", 500),
    ("windows.netscan.NetScan",             "Network Connections",    "informational", 500),
    ("windows.malfind.Malfind",             "Injected Code (Malfind)","high",          200),
    ("windows.svcscan.SvcScan",             "Services",               "informational", 400),
    ("windows.dlllist.DllList",             "Loaded DLLs",            "informational", 300),
    ("windows.registry.hivescan.HiveScan",  "Registry Hives",         "informational", 200),
]

_VOL_LINUX_PLUGINS = [
    ("linux.pslist.PsList",   "Process List",        "informational", 500),
    ("linux.bash.Bash",       "Bash History",        "informational", 300),
    ("linux.netstat.Netstat", "Network Connections", "informational", 500),
    ("linux.lsof.Lsof",      "Open Files",          "informational", 300),
]


def _find_vol_binary() -> tuple[str, str | None]:
    """
    Return (interpreter, vol_script_or_None).
    Tries: vol3, vol, then common install paths.
    Raises RuntimeError if not found.
    """
    for name in ("vol3", "vol"):
        found = shutil.which(name)
        if found:
            return (found, None)

    # Fallback: look for vol.py in known paths
    candidates = [
        "/opt/volatility3/vol.py",
        "/usr/local/lib/volatility3/vol.py",
        str(Path.home() / "volatility3" / "vol.py"),
    ]
    python3 = shutil.which("python3") or "python3"
    for c in candidates:
        if Path(c).exists():
            return (python3, c)

    raise RuntimeError(
        "Volatility 3 not found in PATH. Install with:\n"
        "  pip install volatility3\n"
        "or place vol3/vol in PATH."
    )


def _run_vol_plugin(
    vol_bin: str,
    vol_script: str | None,
    mem_file: Path,
    plugin: str,
    work_dir: Path,
    tool_meta: dict,
) -> tuple[list[str], list[list]]:
    """
    Run one Volatility 3 plugin with --renderer json.
    Returns (columns, rows) on success, or ([], []) on failure.
    """
    cmd = [vol_bin]
    if vol_script:
        cmd.append(vol_script)
    cmd += ["-f", str(mem_file), "--renderer", "json", plugin]

    tool_meta["log"] += f"  cmd: {' '.join(cmd)}\n"

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,    # 10 min per plugin
            cwd=str(work_dir),
        )
    except subprocess.TimeoutExpired:
        tool_meta["stdout"] += f"  → TIMEOUT (>10 min)\n"
        tool_meta["log"]    += f"  [{plugin}] timeout\n"
        return [], []

    stdout = _strip_ansi((proc.stdout or "").strip())
    stderr = _strip_ansi((proc.stderr or "").strip())

    if stderr:
        tool_meta["log"] += f"  stderr: {stderr[:600]}\n"

    if not stdout:
        tool_meta["stdout"] += f"  → no output (code={proc.returncode})\n"
        if stderr:
            tool_meta["stdout"] += f"  {stderr[:200]}\n"
        return [], []

    # Find the JSON object in stdout (Volatility may print progress lines first)
    json_start = stdout.find("{")
    if json_start == -1:
        tool_meta["stdout"] += f"  → no JSON found in output\n"
        return [], []

    try:
        data = json.loads(stdout[json_start:])
    except json.JSONDecodeError as exc:
        tool_meta["stdout"] += f"  → JSON decode error: {exc}\n"
        return [], []

    columns = data.get("columns", [])
    rows    = data.get("rows",    [])
    return columns, rows


def _volatility_rows_to_hits(
    plugin: str,
    label: str,
    base_level: str,
    columns: list[str],
    rows: list[list],
    source_file: str,
) -> list[dict]:
    """Convert Volatility 3 JSON rows into FO hit dicts."""
    col_lower = [c.lower() for c in columns]

    def _col(row: list, *names: str) -> str:
        for name in names:
            try:
                idx = col_lower.index(name.lower())
                v = row[idx]
                return str(v) if v not in (None, "", 0) else ""
            except (ValueError, IndexError):
                pass
        return ""

    results: list[dict] = []
    p_lower = plugin.lower()

    for row in rows:
        if not isinstance(row, list):
            continue

        # Build generic details from all non-empty columns
        parts = [f"{c}: {v}" for c, v in zip(columns, row)
                 if v is not None and v != "" and v != 0]
        details = " | ".join(parts[:15])

        pid      = _col(row, "PID", "pid")
        level    = base_level
        tags     = [f"volatility.{plugin.split('.')[0]}"]

        # Per-plugin rule_title and enrichment
        if "pslist" in p_lower or "pstree" in p_lower:
            name  = _col(row, "ImageFileName", "Name", "name")
            ppid  = _col(row, "PPID", "ppid")
            title = f"Process: {name or '?'}"
            if pid:  title += f" (PID {pid})"
            if ppid: title += f" ← {ppid}"

        elif "cmdline" in p_lower:
            name  = _col(row, "ImageFileName", "Name", "Process")
            args  = _col(row, "Args", "CommandLine", "cmdline", "Cmd")
            title = f"CmdLine: {name or '?'}"
            if pid:  title += f" (PID {pid})"
            details = args or details
            # Flag suspicious patterns
            for pattern in ("encodedcommand", "frombase64", "invoke-expression", "iex(", "bypass"):
                if pattern in (args or "").lower():
                    level = "high"
                    tags.append("suspicious.cmdline")
                    break

        elif "netscan" in p_lower or "netstat" in p_lower:
            proto  = _col(row, "Proto", "Type", "proto")
            local  = _col(row, "LocalAddr", "LocalIp", "local_addr")
            lport  = _col(row, "LocalPort", "lport")
            remote = _col(row, "ForeignAddr", "ForeignIp", "RemoteAddr", "remote_addr")
            rport  = _col(row, "ForeignPort", "rport", "RemotePort")
            state  = _col(row, "State", "state")
            owner  = _col(row, "Owner", "ImageFileName")
            laddr  = f"{local}:{lport}" if lport else local
            raddr  = f"{remote}:{rport}" if rport else remote
            title  = f"Network: {proto} {laddr} → {raddr}"
            if state:  title += f" [{state}]"
            if owner:  title += f" ({owner})"

        elif "malfind" in p_lower:
            name      = _col(row, "ImageFileName", "Process", "Name")
            protection= _col(row, "Protection", "Vad Tag", "VadTag")
            title     = f"Malfind: {name or '?'}"
            if pid:   title += f" (PID {pid})"
            if protection: title += f" [{protection}]"
            level = "high"
            tags.append("malware.injected-code")

        elif "svcscan" in p_lower or "services" in p_lower:
            svc   = _col(row, "ServiceName", "Name", "DisplayName")
            state = _col(row, "State", "state")
            start = _col(row, "Start", "StartType")
            title = f"Service: {svc or '?'}"
            if state: title += f" [{state}]"
            if start: title += f" ({start})"

        elif "dlllist" in p_lower:
            proc = _col(row, "ImageFileName", "Name", "Process")
            path = _col(row, "Path", "FullDllName", "Base")
            title = f"DLL: {proc or '?'} → {Path(path).name if path else '?'}"

        elif "bash" in p_lower:
            cmd   = _col(row, "Command", "command", "History")
            uname = _col(row, "Name", "Process", "pid")
            title = f"Bash: {(cmd or '?')[:80]}"
            details = cmd or details

        elif "hive" in p_lower:
            hive  = _col(row, "Name", "HiveName", "FileFullPath", "File")
            title = f"Registry Hive: {hive or '?'}"

        elif "lsof" in p_lower:
            proc  = _col(row, "Name", "ImageFileName", "pid")
            fpath = _col(row, "File", "Path", "FdType")
            title = f"Open File: {proc or '?'} → {fpath or '?'}"

        else:
            title = label

        try:
            pid_int = int(pid) if pid and str(pid).isdigit() else None
        except (ValueError, TypeError):
            pid_int = None

        results.append({
            "id":          str(uuid.uuid4()),
            "timestamp":   "",
            "level":       level,
            "level_int":   LEVEL_INT.get(level, 1),
            "rule_title":  title[:200],
            "computer":    source_file,
            "channel":     plugin,
            "event_id":    pid_int,
            "details_raw": details[:2000],
            "tags":        tags,
        })

    return results


def _run_volatility3(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """
    Run Volatility 3 memory forensics against an uploaded memory dump.

    Params:
      os:      "windows" (default) | "linux"
      plugins: comma-separated short plugin names to override the default set
               e.g. "pslist,cmdline,malfind"
    """
    vol_bin, vol_script = _find_vol_binary()

    # Find the memory dump — prefer files with known extensions, fall back to largest
    mem_files = [p for p in sources_dir.iterdir()
                 if p.is_file() and p.suffix.lower() in _MEMORY_EXTS]
    if not mem_files:
        all_files = [p for p in sources_dir.iterdir() if p.is_file()]
        if not all_files:
            raise RuntimeError("No source files found for Volatility analysis.")
        # Use the largest file as a heuristic for the memory image
        mem_files = sorted(all_files, key=lambda p: p.stat().st_size, reverse=True)[:1]

    mem_file = mem_files[0]
    size_mb  = mem_file.stat().st_size / (1024 * 1024)
    logger.info("[%s] Volatility: %s (%.0f MB)", run_id, mem_file.name, size_mb)
    tool_meta["log"]    += f"Memory file: {mem_file.name} ({size_mb:.0f} MB)\n"
    tool_meta["stdout"] += (
        f"=== Volatility 3 Memory Forensics ===\n"
        f"File : {mem_file.name}  ({size_mb:.0f} MB)\n"
        f"Tool : {vol_script or vol_bin}\n\n"
    )

    os_hint = (params.get("os") or "windows").lower()
    all_plugins = _VOL_WIN_PLUGINS if os_hint != "linux" else _VOL_LINUX_PLUGINS

    # Allow user to restrict plugins via params
    plugin_filter = [p.strip().lower() for p in (params.get("plugins") or "").split(",") if p.strip()]
    if plugin_filter:
        all_plugins = [
            (p, lbl, lvl, mr) for p, lbl, lvl, mr in all_plugins
            if any(f in p.lower() for f in plugin_filter)
        ]
        if not all_plugins:
            raise RuntimeError(
                f"No matching plugins for filter {plugin_filter}. "
                f"Available: {[p for p, *_ in (_VOL_WIN_PLUGINS if os_hint != 'linux' else _VOL_LINUX_PLUGINS)]}"
            )

    results: list[dict] = []

    for plugin, label, base_level, max_rows in all_plugins:
        tool_meta["stdout"] += f"\n--- {label} ({plugin}) ---\n"
        tool_meta["log"]    += f"\n[{plugin}]\n"

        columns, rows = _run_vol_plugin(vol_bin, vol_script, mem_file, plugin, work_dir, tool_meta)

        if not rows:
            tool_meta["stdout"] += "  0 rows\n"
            continue

        tool_meta["stdout"] += f"  {len(rows):,} rows\n"
        hits = _volatility_rows_to_hits(plugin, label, base_level, columns, rows[:max_rows], mem_file.name)
        results.extend(hits)
        logger.info("[%s] %s → %d hits", run_id, plugin, len(hits))

    tool_meta["stdout"] += f"\n=== Total: {len(results):,} hits across {len(all_plugins)} plugins ===\n"
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Oletools — Office macro / VBA / OLE analysis
# ─────────────────────────────────────────────────────────────────────────────

_OFFICE_EXTS = frozenset({
    '.doc', '.docx', '.docm', '.dot', '.dotm',
    '.xls', '.xlsx', '.xlsm', '.xla', '.xlam',
    '.ppt', '.pptx', '.pptm',
    '.rtf', '.mht',
})

# Oletools risk level → FO level
_OLE_RISK_MAP = {
    "HIGH":   "high",
    "MEDIUM": "medium",
    "LOW":    "low",
    "ERROR":  "medium",
}

# Keywords that escalate a hit to high
_VBA_SUSPICIOUS_KEYWORDS = {
    "shell", "createobject", "wscript", "powershell", "cmd.exe",
    "regwrite", "environ", "shlobj", "dde", "autoopen", "autoclose",
    "document_open", "workbook_open", "auto_open", "auto_close",
    "download", "urldownloadtofile", "winexec", "shellexecute",
}


def _run_oletools(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """Analyse Office documents with oletools (olevba + oleid)."""
    try:
        import oletools.olevba as _olevba  # type: ignore
        import oletools.oleid as _oleid    # type: ignore
        _OT_AVAILABLE = True
    except ImportError:
        _OT_AVAILABLE = False

    if not _OT_AVAILABLE:
        # Try CLI fallback
        olevba_bin = shutil.which("olevba") or shutil.which("olevba3")
        if not olevba_bin:
            raise RuntimeError(
                "oletools not installed. Run: pip install oletools  in the processor image."
            )
        return _run_oletools_cli(run_id, sources_dir, olevba_bin, tool_meta)

    results: list[dict] = []
    doc_files = [
        p for p in sorted(sources_dir.iterdir())
        if p.is_file() and p.suffix.lower() in _OFFICE_EXTS
    ]
    if not doc_files:
        tool_meta["log"] += "No Office files found in source set.\n"
        return []

    for doc in doc_files:
        tool_meta["stdout"] += f"\n=== {doc.name} ===\n"
        try:
            # ── olevba ───────────────────────────────────────────────────────
            vba_parser = _olevba.VBA_Parser(str(doc))
            if vba_parser.detect_vba_macros():
                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    if not vba_code:
                        continue
                    # Scan for IOCs
                    analysis = vba_parser.analyze_macros()
                    for kw_type, keyword, description in analysis:
                        level = "high" if keyword.lower() in _VBA_SUSPICIOUS_KEYWORDS else "medium"
                        results.append({
                            "id":          str(uuid.uuid4()),
                            "timestamp":   "",
                            "level":       level,
                            "level_int":   LEVEL_INT.get(level, 1),
                            "rule_title":  f"VBA Macro — {kw_type}: {keyword}",
                            "computer":    doc.name,
                            "details_raw": description[:1000],
                            "filename":    doc.name,
                            "vba_keyword": keyword,
                            "vba_type":    kw_type,
                        })
                    # Add summary hit for each macro module found
                    results.append({
                        "id":          str(uuid.uuid4()),
                        "timestamp":   "",
                        "level":       "medium",
                        "level_int":   LEVEL_INT.get("medium", 3),
                        "rule_title":  f"VBA Module: {vba_filename or stream_path}",
                        "computer":    doc.name,
                        "details_raw": vba_code[:2000],
                        "filename":    doc.name,
                        "stream_path": stream_path,
                    })
                tool_meta["stdout"] += f"  VBA macros detected in {doc.name}\n"
            else:
                tool_meta["stdout"] += f"  No VBA macros in {doc.name}\n"
                results.append({
                    "id":          str(uuid.uuid4()),
                    "timestamp":   "",
                    "level":       "informational",
                    "level_int":   1,
                    "rule_title":  "No Macros Detected",
                    "computer":    doc.name,
                    "details_raw": f"No VBA macros found in {doc.name}",
                    "filename":    doc.name,
                })
        except Exception as exc:
            logger.warning("[%s] oletools error on %s: %s", run_id, doc.name, exc)
            results.append({
                "id":          str(uuid.uuid4()),
                "timestamp":   "",
                "level":       "medium",
                "level_int":   3,
                "rule_title":  "Oletools Parse Error",
                "computer":    doc.name,
                "details_raw": str(exc)[:500],
                "filename":    doc.name,
            })

    tool_meta["log"] += f"\nProcessed {len(doc_files)} Office file(s), {len(results)} hits\n"
    return results


def _run_oletools_cli(
    run_id: str,
    sources_dir: Path,
    olevba_bin: str,
    tool_meta: dict,
) -> list[dict]:
    """CLI fallback for oletools when the Python library is not importable."""
    results: list[dict] = []
    doc_files = [
        p for p in sorted(sources_dir.iterdir())
        if p.is_file() and p.suffix.lower() in _OFFICE_EXTS
    ]
    for doc in doc_files:
        try:
            proc = subprocess.run(
                [olevba_bin, "--json", str(doc)],
                capture_output=True, text=True, timeout=120,
            )
            if proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    for item in (data if isinstance(data, list) else [data]):
                        for macro in item.get("macros", []):
                            keyword = macro.get("keyword", "")
                            level = "high" if keyword.lower() in _VBA_SUSPICIOUS_KEYWORDS else "medium"
                            results.append({
                                "id":          str(uuid.uuid4()),
                                "timestamp":   "",
                                "level":       level,
                                "level_int":   LEVEL_INT.get(level, 1),
                                "rule_title":  f"VBA Macro — {macro.get('type', 'unknown')}: {keyword}",
                                "computer":    doc.name,
                                "details_raw": macro.get("description", "")[:1000],
                                "filename":    doc.name,
                                "vba_keyword": keyword,
                            })
                except json.JSONDecodeError:
                    if "VBA" in proc.stdout or "macro" in proc.stdout.lower():
                        results.append({
                            "id":          str(uuid.uuid4()),
                            "timestamp":   "",
                            "level":       "medium",
                            "level_int":   3,
                            "rule_title":  "VBA Macros Detected",
                            "computer":    doc.name,
                            "details_raw": proc.stdout[:2000],
                            "filename":    doc.name,
                        })
        except subprocess.TimeoutExpired:
            logger.warning("[%s] olevba timed out on %s", run_id, doc.name)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# PE Analysis — pefile-based executable inspection
# ─────────────────────────────────────────────────────────────────────────────

_PE_EXTS = frozenset({'.exe', '.dll', '.sys', '.ocx', '.scr', '.drv', '.cpl', '.com'})

# Entropy thresholds
_ENTROPY_HIGH   = 7.0   # likely packed / encrypted section
_ENTROPY_MEDIUM = 6.0

# Suspicious imported functions
_SUSPICIOUS_IMPORTS = {
    "virtualalloc", "virtualallocex", "writeprocessmemory",
    "createremotethread", "openprocess", "ntunmapviewofsection",
    "rtldecompressbuffer", "rtlmovememory",
    "loadlibrarya", "loadlibraryexw", "getprocaddress",
    "createprocessw", "createprocessa", "shellexecutea", "shellexecutew",
    "winexec", "system", "isdebuggerpresent", "checkremotedebuggerpresent",
    "ntqueryinformationprocess", "gettickcount", "sleep",
    "regsetvalueexa", "regcreatekeyexa",
    "internetopena", "internetconnecta", "httpopenrequesta",
    "wsastartup", "socket", "connect", "send", "recv",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _run_pe_analysis(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """Analyse PE files with pefile."""
    try:
        import pefile as _pefile  # type: ignore
    except ImportError:
        raise RuntimeError(
            "pefile not installed. Run: pip install pefile  in the processor image."
        )

    results: list[dict] = []
    pe_files = [
        p for p in sorted(sources_dir.iterdir())
        if p.is_file() and p.suffix.lower() in _PE_EXTS
    ]
    if not pe_files:
        tool_meta["log"] += "No PE files (exe/dll/sys) found in source set.\n"
        return []

    for pe_path in pe_files:
        tool_meta["stdout"] += f"\n=== {pe_path.name} ===\n"
        try:
            pe = _pefile.PE(str(pe_path), fast_load=False)
        except Exception as exc:
            results.append({
                "id":          str(uuid.uuid4()),
                "timestamp":   "",
                "level":       "medium",
                "level_int":   3,
                "rule_title":  "PE Parse Error",
                "computer":    pe_path.name,
                "details_raw": str(exc)[:500],
                "filename":    pe_path.name,
            })
            continue

        # ── PE Header summary ─────────────────────────────────────────────
        try:
            machine     = pe.FILE_HEADER.Machine
            num_sects   = pe.FILE_HEADER.NumberOfSections
            ts          = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
            compile_ts  = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else ""
            subsystem   = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
            entry_point = hex(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0))
            arch        = "x86" if machine == 0x014c else ("x64" if machine == 0x8664 else hex(machine))
        except Exception:
            arch, num_sects, compile_ts, entry_point = "unknown", 0, "", ""

        results.append({
            "id":          str(uuid.uuid4()),
            "timestamp":   compile_ts,
            "level":       "informational",
            "level_int":   1,
            "rule_title":  f"PE Header — {pe_path.name}",
            "computer":    pe_path.name,
            "details_raw": (
                f"Architecture: {arch}  |  Sections: {num_sects}  |  "
                f"Compile time: {compile_ts or 'unknown'}  |  EntryPoint: {entry_point}"
            ),
            "filename":    pe_path.name,
            "pe_arch":     arch,
        })
        tool_meta["stdout"] += f"  Arch: {arch}, Sections: {num_sects}, Compile: {compile_ts or '?'}\n"

        # ── Section entropy ───────────────────────────────────────────────
        try:
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                data = section.get_data()
                ent  = _entropy(data)
                if ent >= _ENTROPY_HIGH:
                    level = "high"
                elif ent >= _ENTROPY_MEDIUM:
                    level = "medium"
                else:
                    level = "informational"
                results.append({
                    "id":          str(uuid.uuid4()),
                    "timestamp":   "",
                    "level":       level,
                    "level_int":   LEVEL_INT.get(level, 1),
                    "rule_title":  f"Section Entropy — {name.strip() or '(unnamed)'}",
                    "computer":    pe_path.name,
                    "details_raw": f"Entropy: {ent:.2f}  |  Size: {len(data):,} bytes",
                    "filename":    pe_path.name,
                    "entropy":     round(ent, 3),
                })
                if ent >= _ENTROPY_HIGH:
                    tool_meta["stdout"] += f"  HIGH ENTROPY section {name}: {ent:.2f}\n"
        except Exception:
            pass

        # ── Suspicious imports ────────────────────────────────────────────
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                    for imp in entry.imports:
                        fn_name = (imp.name or b"").decode("utf-8", errors="replace")
                        if fn_name.lower() in _SUSPICIOUS_IMPORTS:
                            results.append({
                                "id":          str(uuid.uuid4()),
                                "timestamp":   "",
                                "level":       "medium",
                                "level_int":   3,
                                "rule_title":  f"Suspicious Import — {fn_name}",
                                "computer":    pe_path.name,
                                "details_raw": f"{dll}::{fn_name}",
                                "filename":    pe_path.name,
                                "import_dll":  dll,
                                "import_fn":   fn_name,
                            })
        except Exception:
            pass

        pe.close()
        tool_meta["log"] += f"{pe_path.name}: {len(results)} hits\n"

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Strings Analysis — categorised string extraction with IOC identification
# ─────────────────────────────────────────────────────────────────────────────

_IOC_PATTERNS = {
    "urls":     re.compile(r'https?://'),
    "ips":      re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    "emails":   re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "paths":    re.compile(r'[A-Z]:\\|/usr/|/etc/|/var/'),
    "registry": re.compile(r'HKEY_|HKLM\\|HKCU\\'),
}


def _run_strings_analysis(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """Extract ASCII and Unicode strings, then categorise IOCs."""
    strings_bin = shutil.which("strings")
    if not strings_bin:
        raise RuntimeError(
            "'strings' binary not found. Ensure binutils is installed in the processor image."
        )

    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue

        logger.info("[%s] strings_analysis: extracting from %s", run_id, file_path.name)
        tool_meta["stdout"] += f"\n=== {file_path.name} ===\n"

        # ASCII strings (min length 6)
        try:
            proc_ascii = subprocess.run(
                [strings_bin, "-a", "-n", "6", str(file_path)],
                capture_output=True, text=True, timeout=120,
            )
            ascii_strings = proc_ascii.stdout.strip().split("\n") if proc_ascii.stdout.strip() else []
        except subprocess.TimeoutExpired:
            logger.warning("[%s] strings (ASCII) timed out on %s", run_id, file_path.name)
            ascii_strings = []

        # Unicode strings (min length 6)
        try:
            proc_unicode = subprocess.run(
                [strings_bin, "-a", "-n", "6", "-el", str(file_path)],
                capture_output=True, text=True, timeout=120,
            )
            unicode_strings = proc_unicode.stdout.strip().split("\n") if proc_unicode.stdout.strip() else []
        except subprocess.TimeoutExpired:
            logger.warning("[%s] strings (Unicode) timed out on %s", run_id, file_path.name)
            unicode_strings = []

        all_strings = list(set(ascii_strings + unicode_strings))

        # Categorise interesting strings
        iocs: dict[str, list[str]] = {cat: [] for cat in _IOC_PATTERNS}
        for s in all_strings:
            for cat, pat in _IOC_PATTERNS.items():
                if pat.search(s):
                    iocs[cat].append(s)

        # Emit one summary hit per file
        ioc_count = sum(len(v) for v in iocs.values())
        level = "high" if ioc_count > 20 else ("medium" if ioc_count > 5 else "informational")
        results.append({
            "id":             str(uuid.uuid4()),
            "timestamp":      "",
            "level":          level,
            "level_int":      LEVEL_INT.get(level, 1),
            "rule_title":     f"Strings Analysis — {file_path.name}",
            "computer":       file_path.name,
            "details_raw":    json.dumps({
                "total_strings": len(all_strings),
                "interesting_strings": {k: v[:50] for k, v in iocs.items()},
                "sample_strings": all_strings[:200],
            }),
            "filename":       file_path.name,
            "total_strings":  len(all_strings),
        })

        # Emit individual IOC hits so they show up in the results table
        for cat, matches in iocs.items():
            for m in matches[:50]:
                results.append({
                    "id":          str(uuid.uuid4()),
                    "timestamp":   "",
                    "level":       "medium",
                    "level_int":   LEVEL_INT.get("medium", 3),
                    "rule_title":  f"IOC String ({cat})",
                    "computer":    file_path.name,
                    "details_raw": m,
                    "filename":    file_path.name,
                    "ioc_type":    cat,
                })

        tool_meta["stdout"] += (
            f"  Total strings: {len(all_strings)}  |  IOCs: {ioc_count} "
            f"(urls={len(iocs['urls'])}, ips={len(iocs['ips'])}, emails={len(iocs['emails'])})\n"
        )

    tool_meta["log"] += f"\nProcessed {len(list(sources_dir.iterdir()))} file(s), {len(results)} hits\n"
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Pattern Search (grep) — regex-based IOC / keyword scanning
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_GREP_PATTERNS = [
    r'https?://[^\s<>"]+',
    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    r'[a-fA-F0-9]{32}',   # MD5
    r'[a-fA-F0-9]{40}',   # SHA1
    r'[a-fA-F0-9]{64}',   # SHA256
    r'(?:powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin)',
]


def _run_grep_search(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """Search files for regex patterns — IOCs, keywords, encoded payloads."""
    grep_bin = shutil.which("grep")
    if not grep_bin:
        raise RuntimeError(
            "'grep' binary not found. Ensure coreutils is installed in the processor image."
        )

    run_config = params or {}
    patterns = run_config.get("patterns", []) if isinstance(run_config, dict) else []
    if not patterns:
        patterns = list(_DEFAULT_GREP_PATTERNS)

    tool_meta["log"] += f"Patterns ({len(patterns)}): {patterns}\n"
    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue

        logger.info("[%s] grep_search: scanning %s with %d patterns", run_id, file_path.name, len(patterns))
        tool_meta["stdout"] += f"\n=== {file_path.name} ===\n"

        for pat in patterns:
            # Count matches
            try:
                proc_count = subprocess.run(
                    [grep_bin, "-oPc", pat, str(file_path)],
                    capture_output=True, text=True, timeout=60,
                )
                count = int(proc_count.stdout.strip()) if proc_count.stdout.strip().isdigit() else 0
            except (subprocess.TimeoutExpired, ValueError):
                count = 0

            if count > 0:
                # Extract actual matches (deduplicated, capped at 50)
                try:
                    proc_matches = subprocess.run(
                        [grep_bin, "-oP", pat, str(file_path)],
                        capture_output=True, text=True, timeout=60,
                    )
                    matches = list(set(proc_matches.stdout.strip().split("\n")))[:50]
                except subprocess.TimeoutExpired:
                    matches = []

                level = "high" if count > 10 else ("medium" if count > 2 else "low")
                results.append({
                    "id":            str(uuid.uuid4()),
                    "timestamp":     "",
                    "level":         level,
                    "level_int":     LEVEL_INT.get(level, 1),
                    "rule_title":    f"Pattern Match — {pat[:60]}",
                    "computer":      file_path.name,
                    "details_raw":   json.dumps({"count": count, "samples": matches}),
                    "filename":      file_path.name,
                    "pattern":       pat,
                    "match_count":   count,
                })

                tool_meta["stdout"] += f"  [{pat[:40]}…] → {count} match(es)\n"

    tool_meta["log"] += f"\nScanned {len(list(sources_dir.iterdir()))} file(s), {len(results)} pattern hits\n"
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Access Log Analysis
# ─────────────────────────────────────────────────────────────────────────────

_ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

_SCANNER_UAS = re.compile(
    r'sqlmap|nikto|nmap|masscan|dirbuster|wfuzz|gobuster|burpsuite|nessus|openvas'
    r'|acunetix|w3af|nuclei|metasploit|zgrab|shodan|censys|internetmeasurement',
    re.IGNORECASE,
)

_PATH_TRAVERSAL_RE = re.compile(
    r'(?:\.\./|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|/proc/self|/windows/system32)',
    re.IGNORECASE,
)

_ADMIN_PATHS_RE = re.compile(
    r'(?:/wp-admin|/wp-login|/admin|/administrator|/phpmyadmin|/\.env|/\.git/|/config\.php'
    r'|/shell\.php|/cmd\.php|/webshell)',
    re.IGNORECASE,
)

_CMD_INJECT_RE = re.compile(r'(?:;ls|;id|;cat|%7cid|%3bls|\$\(|`cmd|%7C|union\s+select)', re.IGNORECASE)


def _run_access_log_analysis(
    run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict
) -> list[dict]:
    """
    Parse Apache / Nginx access logs and detect suspicious patterns:
    path traversal, scanner user-agents, brute force, admin probing,
    command injection, high error rates per IP.
    """
    results: list[dict] = []
    files_processed = 0

    for log_path in sorted(sources_dir.rglob("*")):
        if not log_path.is_file():
            continue
        ext = log_path.suffix.lower()
        if ext not in (".log", ".txt", "") and log_path.name.lower() not in (
            "access.log", "access_log", "error.log"
        ):
            continue

        tool_meta["stdout"] += f"\n=== Analysing {log_path.name} ===\n"
        files_processed += 1

        # Per-IP counters  {ip: {"4xx": N, "5xx": N, "req": N}}
        ip_stats: dict[str, dict] = {}
        # Auth brute force: {ip: {path: count}}
        auth_attempts: dict[str, dict] = {}

        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    m = _ACCESS_LOG_RE.match(line)
                    if not m:
                        continue

                    ip       = m.group("ip")
                    ts_raw   = m.group("ts")
                    method   = m.group("method")
                    path     = m.group("path")
                    status   = int(m.group("status"))
                    size_raw = m.group("size")
                    ua       = m.group("ua") or ""
                    size     = int(size_raw) if size_raw.isdigit() else 0

                    # Parse timestamp (Apache format: 01/Jan/2024:12:00:00 +0000)
                    try:
                        ts = datetime.strptime(ts_raw[:20], "%d/%b/%Y:%H:%M:%S").isoformat() + "Z"
                    except ValueError:
                        ts = ""

                    # IP stats
                    stat = ip_stats.setdefault(ip, {"4xx": 0, "5xx": 0, "req": 0})
                    stat["req"] += 1
                    if 400 <= status < 500:
                        stat["4xx"] += 1
                    elif 500 <= status < 600:
                        stat["5xx"] += 1

                    # Auth brute force (401 responses)
                    if status == 401:
                        auth_attempts.setdefault(ip, {}).setdefault(path, 0)
                        auth_attempts[ip][path] += 1

                    details_extra = {"ip": ip, "method": method, "path": path[:256],
                                     "status": status, "ua": ua[:200]}

                    # 1. Path traversal
                    if _PATH_TRAVERSAL_RE.search(path):
                        results.append({
                            "id":          str(uuid.uuid4()),
                            "timestamp":   ts,
                            "level":       "high",
                            "level_int":   LEVEL_INT["high"],
                            "rule_title":  "Path Traversal Attempt",
                            "computer":    log_path.name,
                            "details_raw": json.dumps({**details_extra, "matched": path[:200]}),
                            "message":     f"{ip} → {method} {path[:200]} ({status})",
                        })

                    # 2. Scanner user-agent
                    if _SCANNER_UAS.search(ua):
                        results.append({
                            "id":          str(uuid.uuid4()),
                            "timestamp":   ts,
                            "level":       "high",
                            "level_int":   LEVEL_INT["high"],
                            "rule_title":  "Known Scanner User-Agent",
                            "computer":    log_path.name,
                            "details_raw": json.dumps({**details_extra, "ua": ua[:200]}),
                            "message":     f"{ip} → Scanner detected: {ua[:100]}",
                        })

                    # 3. Admin path probing
                    if _ADMIN_PATHS_RE.search(path) and status not in (200, 301, 302):
                        results.append({
                            "id":          str(uuid.uuid4()),
                            "timestamp":   ts,
                            "level":       "medium",
                            "level_int":   LEVEL_INT["medium"],
                            "rule_title":  "Admin/Sensitive Path Probe",
                            "computer":    log_path.name,
                            "details_raw": json.dumps(details_extra),
                            "message":     f"{ip} → Probed {path[:200]} ({status})",
                        })

                    # 4. Command injection in URL
                    if _CMD_INJECT_RE.search(path):
                        results.append({
                            "id":          str(uuid.uuid4()),
                            "timestamp":   ts,
                            "level":       "critical",
                            "level_int":   LEVEL_INT["critical"],
                            "rule_title":  "Command Injection Attempt in URL",
                            "computer":    log_path.name,
                            "details_raw": json.dumps(details_extra),
                            "message":     f"{ip} → Injection payload in {path[:200]}",
                        })

        except Exception as exc:
            tool_meta["stderr"] += f"\nError reading {log_path.name}: {exc}\n"
            continue

        # Post-scan: emit aggregate findings

        # 5. Brute force: IP with ≥10 auth failures on same path
        for ip, paths in auth_attempts.items():
            for path, count in paths.items():
                if count >= 10:
                    level = "critical" if count >= 50 else "high"
                    results.append({
                        "id":          str(uuid.uuid4()),
                        "timestamp":   "",
                        "level":       level,
                        "level_int":   LEVEL_INT[level],
                        "rule_title":  "Authentication Brute Force",
                        "computer":    log_path.name,
                        "details_raw": json.dumps({"ip": ip, "path": path[:200], "401_count": count}),
                        "message":     f"{ip} → {count} failed auth attempts on {path[:200]}",
                    })

        # 6. High error rate: IP with ≥20 4xx/5xx out of ≥30 total requests
        for ip, stat in ip_stats.items():
            errors = stat["4xx"] + stat["5xx"]
            total  = stat["req"]
            if total >= 30 and errors / total >= 0.5:
                level = "high" if errors >= 100 else "medium"
                results.append({
                    "id":          str(uuid.uuid4()),
                    "timestamp":   "",
                    "level":       level,
                    "level_int":   LEVEL_INT[level],
                    "rule_title":  "High Error Rate from Single IP",
                    "computer":    log_path.name,
                    "details_raw": json.dumps({"ip": ip, "requests": total, "errors": errors,
                                               "4xx": stat["4xx"], "5xx": stat["5xx"]}),
                    "message":     f"{ip} → {errors}/{total} error responses ({int(100*errors/total)}%)",
                })

        tool_meta["stdout"] += f"  {files_processed} log file(s) — {len(results)} finding(s) so far\n"

    tool_meta["log"] += f"\nAccess log analysis: {files_processed} file(s), {len(results)} findings\n"
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Cuckoo Sandbox
# ─────────────────────────────────────────────────────────────────────────────

def _run_cuckoo(
    run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict
) -> list[dict]:
    """
    Submit files to a Cuckoo Sandbox instance and collect behavioral reports.
    Requires CUCKOO_API_URL (and optionally CUCKOO_API_TOKEN) env vars.
    """
    import urllib.parse

    # Load config: Redis (UI-configured) first, then env-var fallback.
    # This lets admins set the Cuckoo URL via Settings without touching K8s env vars.
    _redis_cfg: dict = {}
    try:
        _redis_cfg = get_redis().hgetall(_CUCKOO_CONFIG_KEY) or {}
    except Exception:
        pass

    api_url   = (_redis_cfg.get("api_url") or os.getenv("CUCKOO_API_URL", "")).rstrip("/")
    api_token = _redis_cfg.get("api_token") or os.getenv("CUCKOO_API_TOKEN", "")

    if not api_url:
        raise RuntimeError(
            "Cuckoo not configured — go to Settings → Integrations → Cuckoo Sandbox "
            "to enter the API URL, or set CUCKOO_API_URL as an environment variable."
        )

    def _cuckoo_req(path: str, method: str = "GET", data=None, files=None):
        """Simple urllib-based Cuckoo API request."""
        url     = f"{api_url}{path}"
        headers = {}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"

        if files:
            # Multipart form — build manually
            boundary  = f"----FormBoundary{uuid.uuid4().hex}"
            body_parts: list[bytes] = []
            for field_name, (fname, fdata, ctype) in files.items():
                body_parts.append(
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; "
                    f"filename=\"{fname}\"\r\nContent-Type: {ctype}\r\n\r\n".encode()
                )
                body_parts.append(fdata if isinstance(fdata, bytes) else fdata.read())
                body_parts.append(b"\r\n")
            body_parts.append(f"--{boundary}--\r\n".encode())
            body = b"".join(body_parts)
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        elif data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
        else:
            req = urllib.request.Request(url, headers=headers, method=method)

        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    results: list[dict] = []

    for file_path in sorted(sources_dir.rglob("*")):
        if not file_path.is_file():
            continue

        tool_meta["stdout"] += f"\n=== Submitting {file_path.name} to Cuckoo ===\n"

        try:
            # Submit file
            with open(file_path, "rb") as fh:
                resp = _cuckoo_req(
                    "/tasks/create/file",
                    method="POST",
                    files={"file": (file_path.name, fh, "application/octet-stream")},
                )
            task_id = resp.get("task_id")
            if not task_id:
                tool_meta["stderr"] += f"No task_id returned for {file_path.name}\n"
                continue

            tool_meta["stdout"] += f"  Task ID: {task_id} — polling for completion…\n"

            # Poll for completion (max 10 min)
            max_wait = 600
            waited   = 0
            while waited < max_wait:
                time.sleep(15)
                waited += 15
                status_resp = _cuckoo_req(f"/tasks/view/{task_id}")
                status = (status_resp.get("task") or {}).get("status", "")
                if status == "reported":
                    break
                if status in ("failed_analysis", "failed_processing"):
                    raise RuntimeError(f"Cuckoo task {task_id} failed: {status}")

            # Fetch report
            report = _cuckoo_req(f"/tasks/report/{task_id}")

            # Parse behavioral indicators
            info      = report.get("info", {})
            behavior  = report.get("behavior", {})
            network   = report.get("network", {})
            signatures = report.get("signatures", [])
            score     = info.get("score", 0)

            level = "critical" if score >= 8 else ("high" if score >= 5 else
                    "medium" if score >= 3 else "low")

            # One hit per signature detected
            for sig in signatures:
                sig_name = sig.get("name", "Unknown")
                sig_desc = sig.get("description", "")
                sig_severity = sig.get("severity", 1)
                sig_level = "critical" if sig_severity >= 3 else ("high" if sig_severity == 2 else "medium")
                results.append({
                    "id":          str(uuid.uuid4()),
                    "timestamp":   "",
                    "level":       sig_level,
                    "level_int":   LEVEL_INT.get(sig_level, 2),
                    "rule_title":  f"Cuckoo: {sig_name}",
                    "computer":    file_path.name,
                    "details_raw": json.dumps({"description": sig_desc, "file": file_path.name,
                                               "task_id": task_id, "score": score}),
                    "message":     f"{file_path.name} — {sig_desc[:200]}",
                })

            # Network indicators
            domains  = [d.get("domain", "") for d in network.get("domains", [])][:20]
            hosts    = [h.get("ip", "") for h in network.get("hosts", [])][:20]
            if domains or hosts:
                results.append({
                    "id":          str(uuid.uuid4()),
                    "timestamp":   "",
                    "level":       "medium",
                    "level_int":   LEVEL_INT["medium"],
                    "rule_title":  "Cuckoo: Network Activity",
                    "computer":    file_path.name,
                    "details_raw": json.dumps({"domains": domains, "hosts": hosts,
                                               "task_id": task_id}),
                    "message":     f"{file_path.name} — contacted {len(domains)} domain(s), {len(hosts)} host(s)",
                })

            # Summary hit
            results.append({
                "id":          str(uuid.uuid4()),
                "timestamp":   "",
                "level":       level,
                "level_int":   LEVEL_INT.get(level, 1),
                "rule_title":  f"Cuckoo: Analysis Score {score}/10",
                "computer":    file_path.name,
                "details_raw": json.dumps({"score": score, "task_id": task_id,
                                           "file": file_path.name}),
                "message":     f"{file_path.name} — Cuckoo score {score}/10",
            })

            tool_meta["stdout"] += f"  Score: {score}/10 — {len(signatures)} signature(s)\n"

        except Exception as exc:
            tool_meta["stderr"] += f"Cuckoo error for {file_path.name}: {exc}\n"
            results.append({
                "id":          str(uuid.uuid4()),
                "timestamp":   "",
                "level":       "low",
                "level_int":   LEVEL_INT["low"],
                "rule_title":  "Cuckoo: Submission Error",
                "computer":    file_path.name,
                "details_raw": json.dumps({"error": str(exc), "file": file_path.name}),
                "message":     f"{file_path.name} — {exc}",
            })

    tool_meta["log"] += f"\nCuckoo analysis: {len(results)} findings\n"
    return results


# ─────────────────────────────────────────────────────────────────────────────
# de4dot — .NET Deobfuscator
# ─────────────────────────────────────────────────────────────────────────────

def _run_de4dot(
    run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict
) -> list[dict]:
    """
    Deobfuscate .NET assemblies using de4dot.
    Looks for de4dot binary (native Linux build) or de4dot.exe via mono.
    Reports the detected obfuscator type and deobfuscated output filename.
    """
    # Locate binary — native Linux build first, then Mono fallback
    de4dot_bin  = shutil.which("de4dot")
    mono_bin    = shutil.which("mono")
    de4dot_exe  = shutil.which("de4dot.exe") or "/usr/local/bin/de4dot.exe"

    if de4dot_bin:
        cmd_prefix = [de4dot_bin]
    elif mono_bin and Path(de4dot_exe).exists():
        cmd_prefix = [mono_bin, de4dot_exe]
    else:
        raise RuntimeError(
            "de4dot binary not found. Install de4dot (Linux build) or Mono + de4dot.exe. "
            "See the Studio docs for setup instructions."
        )

    results: list[dict] = []

    for file_path in sorted(sources_dir.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in (".exe", ".dll"):
            continue

        out_path = work_dir / f"{file_path.stem}_deob{file_path.suffix}"
        cmd = cmd_prefix + [str(file_path), "-o", str(out_path)]
        tool_meta["stdout"] += f"\n=== de4dot: {file_path.name} ===\n"

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                env=_SAFE_ENV,  # strip MINIO/Redis secrets from subprocess env
            )
            stdout = _strip_ansi(proc.stdout)
            stderr = _strip_ansi(proc.stderr)
            tool_meta["stdout"] += stdout
            tool_meta["stderr"] += stderr

            # Parse detected obfuscator from output
            # de4dot prints: "Detected: Dotfuscator v4.x (7a8b...)"
            obf_match = re.search(r'Detected:\s*(.+)', stdout, re.IGNORECASE)
            obfuscator = obf_match.group(1).strip() if obf_match else "Unknown"

            level     = "high" if obfuscator != "Unknown" else "medium"
            success   = out_path.exists()

            results.append({
                "id":          str(uuid.uuid4()),
                "timestamp":   "",
                "level":       level,
                "level_int":   LEVEL_INT.get(level, 2),
                "rule_title":  f"Obfuscated .NET Assembly — {obfuscator}",
                "computer":    file_path.name,
                "details_raw": json.dumps({
                    "file":         file_path.name,
                    "obfuscator":   obfuscator,
                    "deobfuscated": out_path.name if success else None,
                    "exit_code":    proc.returncode,
                }),
                "message": (
                    f"{file_path.name} — obfuscated with {obfuscator}; "
                    f"{'deobfuscated OK' if success else 'deobfuscation failed'}"
                ),
            })

            if success:
                tool_meta["stdout"] += f"  → Deobfuscated output: {out_path.name}\n"
            else:
                tool_meta["stderr"] += f"  Deobfuscation may have failed (exit {proc.returncode})\n"

        except subprocess.TimeoutExpired:
            tool_meta["stderr"] += f"de4dot timed out for {file_path.name}\n"
        except Exception as exc:
            tool_meta["stderr"] += f"de4dot error for {file_path.name}: {exc}\n"

    tool_meta["log"] += f"\nde4dot: {len(results)} file(s) processed\n"
    return results


# ── malwoverview — VirusTotal / multi-source TI hash lookup ───────────────────

def _vt_file_report(sha256: str, api_key: str, filename: str, tool_meta: dict) -> list[dict]:
    """
    Query VirusTotal v3 for a file hash.
    Returns a list of standardised result dicts (one entry per file).
    """
    import hashlib as _hl  # already in stdlib; reimport locally for clarity

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            tool_meta["stdout"] += f"  {sha256[:16]}… not found in VirusTotal — file may be new or private.\n"
            return [{
                "id":          str(uuid.uuid4()),
                "timestamp":   "",
                "level":       "info",
                "level_int":   LEVEL_INT["info"],
                "rule_title":  "Not in VirusTotal",
                "computer":    filename,
                "details_raw": json.dumps({"sha256": sha256, "status": "not_found", "file": filename}),
                "message":     f"{filename} — hash not found in VirusTotal (may be new or unknown sample)",
            }]
        raise

    attrs  = data.get("data", {}).get("attributes", {})
    stats  = attrs.get("last_analysis_stats", {})

    malicious  = int(stats.get("malicious",  0))
    suspicious = int(stats.get("suspicious", 0))
    total      = sum(stats.values())

    # Map detection count to severity level
    if   malicious >= 10:                   level = "critical"
    elif malicious >= 5:                    level = "high"
    elif malicious >= 2 or suspicious >= 5: level = "medium"
    elif malicious >= 1 or suspicious >= 1: level = "low"
    else:                                   level = "info"

    # Collect engine verdicts for detected engines only
    engine_verdicts: dict[str, str] = {}
    for engine, result in (attrs.get("last_analysis_results") or {}).items():
        if result.get("category") in ("malicious", "suspicious"):
            engine_verdicts[engine] = result.get("result") or result.get("category", "")

    names = attrs.get("names", [])
    tags  = attrs.get("tags",  [])

    tool_meta["stdout"] += (
        f"  VirusTotal: {malicious}/{total} engines flagged as malicious\n"
        + (f"  Known names: {', '.join(names[:5])}\n" if names else "")
        + (f"  Tags: {', '.join(tags[:5])}\n"         if tags  else "")
    )

    return [{
        "id":          str(uuid.uuid4()),
        "timestamp":   "",
        "level":       level,
        "level_int":   LEVEL_INT.get(level, 1),
        "rule_title":  f"VirusTotal: {malicious}/{total} detections",
        "computer":    filename,
        "details_raw": json.dumps({
            "sha256":          sha256,
            "malicious":       malicious,
            "suspicious":      suspicious,
            "total_engines":   total,
            "names":           names[:10],
            "tags":            tags,
            "engine_verdicts": dict(list(engine_verdicts.items())[:20]),
        }),
        "message": (
            f"{filename} — {malicious}/{total} AV engines detected malware"
            + (f" | {', '.join(names[:2])}"   if names else "")
            + (f" [{', '.join(tags[:3])}]"    if tags  else "")
        ),
    }]


def _run_malwoverview(
    run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict
) -> list[dict]:
    """
    Threat intelligence lookup using malwoverview / VirusTotal v3.

    For each uploaded file:
      1. Computes SHA-256, MD5, SHA-1 hashes.
      2. Queries VirusTotal v3 REST API directly (primary).
      3. Optionally enriches via the malwoverview CLI if it is present.

    Requires a VirusTotal API key — configure via Settings → Integrations
    or set the VT_API_KEY environment variable.

    References: https://github.com/alexandreborges/malwoverview
    """
    import hashlib

    # ── Load config (Redis UI settings → env var fallback) ────────────────────
    _redis_cfg: dict = {}
    try:
        _redis_cfg = get_redis().hgetall(_MALWOVERVIEW_CONFIG_KEY) or {}
    except Exception:
        pass

    vt_api_key = (_redis_cfg.get("vt_api_key") or os.getenv("VT_API_KEY", "")).strip()

    if not vt_api_key:
        raise RuntimeError(
            "malwoverview not configured — go to Settings → Integrations → malwoverview "
            "and enter your VirusTotal API key, or set VT_API_KEY as an environment variable."
        )

    # Check if the malwoverview CLI is available for extra output
    mwo_bin = shutil.which("malwoverview") or shutil.which("malwoverview.py")

    results: list[dict] = []

    for file_path in sorted(sources_dir.rglob("*")):
        if not file_path.is_file():
            continue

        tool_meta["stdout"] += f"\n=== malwoverview: {file_path.name} ===\n"

        try:
            # ── 1. Hash the file ───────────────────────────────────────────────
            sha256_h = hashlib.sha256()
            md5_h    = hashlib.md5()
            sha1_h   = hashlib.sha1()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    sha256_h.update(chunk)
                    md5_h.update(chunk)
                    sha1_h.update(chunk)

            file_sha256 = sha256_h.hexdigest()
            file_md5    = md5_h.hexdigest()
            file_sha1   = sha1_h.hexdigest()

            tool_meta["stdout"] += (
                f"  SHA256: {file_sha256}\n"
                f"  MD5:    {file_md5}\n"
                f"  SHA1:   {file_sha1}\n"
            )

            # ── 2. VirusTotal v3 lookup (direct API) ──────────────────────────
            hits = _vt_file_report(file_sha256, vt_api_key, file_path.name, tool_meta)
            results.extend(hits)

            # ── 3. malwoverview CLI (optional enrichment) ─────────────────────
            if mwo_bin:
                # Write a minimal config file so malwoverview can authenticate
                config_dir  = work_dir / ".malwoverview"
                config_dir.mkdir(exist_ok=True)
                config_file = config_dir / ".malwoverview"
                config_file.write_text(f"[VIRUSTOTAL]\nvtapi = {vt_api_key}\n")

                env = {**_SAFE_ENV, "HOME": str(work_dir)}
                try:
                    proc = subprocess.run(
                        [mwo_bin, "-x", file_sha256, "-V", "3"],
                        capture_output=True, text=True, timeout=60,
                        env=env,
                    )
                    mwo_out = _strip_ansi(proc.stdout or "")
                    mwo_err = _strip_ansi(proc.stderr or "")
                    if mwo_out:
                        tool_meta["stdout"] += "\n[malwoverview CLI output]\n" + mwo_out
                    if mwo_err:
                        tool_meta["stderr"] += mwo_err
                except Exception as mwo_exc:
                    tool_meta["stderr"] += f"  malwoverview CLI skipped: {mwo_exc}\n"

        except urllib.error.URLError as exc:
            tool_meta["stderr"] += f"  Network error querying VirusTotal: {exc}\n"
        except Exception as exc:
            tool_meta["stderr"] += f"  Error processing {file_path.name}: {exc}\n"

    tool_meta["log"] += f"\nmalwoverview: {len(results)} file(s) queried\n"
    return results
