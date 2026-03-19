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
import struct
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
            "hayabusa":    _run_hayabusa,
            "strings":     _run_strings,
            "hindsight":   _run_hindsight,
            "regripper":   _run_regripper,
            "wintriage":   _run_wintriage,
            "yara":        _run_yara,
            "exiftool":    _run_exiftool,
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


def _run_hayabusa(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
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

    output_jsonl = work_dir / "hayabusa_output.jsonl"
    cmd = [
        hayabusa_bin, "json-timeline",
        "--no-wizard",           # required: suppress interactive prompts
        "-d", str(sources_dir),
        "-r", str(rules_dir),
        "-o", str(output_jsonl),
        "--no-color",
        "--quiet",
        "--min-level", "informational",  # capture ALL severity levels
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

    # Log output for diagnosability (visible in Celery worker logs)
    if proc.stdout:
        logger.info("[%s] Hayabusa stdout: %s", run_id, proc.stdout[:1000])
    if proc.stderr:
        logger.info("[%s] Hayabusa stderr: %s", run_id, proc.stderr[:1000])

    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"Hayabusa exited {proc.returncode}: {(proc.stderr or proc.stdout or '')[:500]}"
        )

    if not output_jsonl.exists() or output_jsonl.stat().st_size == 0:
        logger.warning("[%s] Hayabusa produced no output file (or empty)", run_id)
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
    rule_title    = str(row.get("RuleTitle") or row.get("RuleTitle") or row.get("ruleTitle") or "")
    level         = str(row.get("Level")     or row.get("level")     or "informational").lower()
    computer      = str(row.get("Computer")  or row.get("computer")  or "")
    channel       = str(row.get("Channel")   or row.get("channel")   or "")
    event_id_raw  = str(row.get("EventID")   or row.get("eventId")   or "")
    rule_file     = str(row.get("RuleFile")  or row.get("ruleFile")  or "")
    evtx_file     = str(row.get("EvtxFile")  or row.get("evtxFile")  or "")

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

    # Normalise level names: Hayabusa 3.x uses "info" instead of "informational"
    level_map = {"info": "informational", "crit": "critical", "warn": "medium"}
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


def _run_wintriage(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
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

# Inline ruleset — common malware patterns and suspicious indicators
_YARA_RULES_SOURCE = r"""
rule SuspiciousPE_Packer {
    meta:
        description = "Detects common PE packer signatures"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $aspack = "ASPack" ascii
        $fsg = ".ndata" ascii
        $mpress = "MPRESS1" ascii
    condition:
        2 of them
}

rule SuspiciousScript_PowerShellEncoded {
    meta:
        description = "Detects base64-encoded PowerShell commands"
        severity = "high"
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-encodedcommand" ascii nocase
        $enc3 = "FromBase64String" ascii nocase
        $enc4 = "JABlAG4AYwBvAGQA" ascii   // base64 of "$encod"
        $iex1 = "Invoke-Expression" ascii nocase
        $iex2 = "IEX(" ascii nocase
    condition:
        any of ($enc*) or any of ($iex*)
}

rule SuspiciousShell_ReverseShell {
    meta:
        description = "Detects common reverse shell patterns"
        severity = "critical"
    strings:
        $nc1  = "nc -e /bin/bash" ascii nocase
        $nc2  = "nc -e /bin/sh" ascii nocase
        $nc3  = "/bin/bash -i >& /dev/tcp/" ascii
        $nc4  = "bash -i >& /dev/tcp/" ascii
        $perl = "perl -e 'use Socket" ascii nocase
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
        $pass1 = "password=" ascii nocase
        $pass2 = "passwd=" ascii nocase
        $pass3 = "pwd=" ascii nocase
        $api1  = "api_key" ascii nocase
        $api2  = "apikey" ascii nocase
        $sec1  = "secret_key" ascii nocase
        $sec2  = "aws_secret" ascii nocase
        $tok1  = "bearer " ascii nocase
    condition:
        2 of them
}

rule Mimikatz_Indicators {
    meta:
        description = "Detects Mimikatz credential dumping tool signatures"
        severity = "critical"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "sekurlsa::" ascii nocase
        $s3 = "lsadump::" ascii nocase
        $s4 = "kerberos::" ascii nocase
        $s5 = "privilege::debug" ascii nocase
        $s6 = "SamSs" ascii wide
        $s7 = "wdigest" ascii wide
    condition:
        2 of them
}

rule Webshell_PHP {
    meta:
        description = "Detects common PHP webshell patterns"
        severity = "critical"
    strings:
        $p1 = "eval(base64_decode(" ascii nocase
        $p2 = "eval(gzinflate(" ascii nocase
        $p3 = "eval(str_rot13(" ascii nocase
        $p4 = "eval($_POST[" ascii nocase
        $p5 = "system($_GET[" ascii nocase
        $p6 = "exec($_REQUEST[" ascii nocase
        $p7 = "passthru($_" ascii nocase
    condition:
        any of them
}

rule Ransomware_ExtensionTargets {
    meta:
        description = "Detects ransomware-like file extension targeting patterns"
        severity = "high"
    strings:
        $ext1 = ".docx,.xlsx,.pptx" ascii nocase
        $ext2 = "encrypt" ascii nocase
        $ext3 = "ransom" ascii nocase
        $ext4 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase
        $ext5 = "HOW_TO_DECRYPT" ascii nocase
        $ext6 = "RECOVERY_KEY" ascii nocase
    condition:
        2 of them
}
"""


def _run_yara(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
    """Scan source files with YARA rules."""
    try:
        import yara
    except ImportError:
        # Try system binary as fallback
        yara_bin = shutil.which("yara")
        if not yara_bin:
            raise RuntimeError(
                "yara-python is not installed and the yara CLI binary is not in PATH. "
                "Ensure yara-python is installed in the processor image (pip install yara-python)."
            )
        return _run_yara_cli(run_id, work_dir, sources_dir, yara_bin)

    # Compile inline rules
    try:
        rules = yara.compile(source=_YARA_RULES_SOURCE)
    except yara.SyntaxError as exc:
        raise RuntimeError(f"YARA rule compilation failed: {exc}") from exc

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


def _run_yara_cli(run_id: str, work_dir: Path, sources_dir: Path, yara_bin: str) -> list[dict]:
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

def _run_exiftool(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
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
