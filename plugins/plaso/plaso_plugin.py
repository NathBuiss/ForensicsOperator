"""
Plaso Plugin — parses Plaso storage files (.plaso).
Plaso files are SQLite databases produced by log2timeline.
Events are fanned out to the appropriate artifact_type index based on the
Plaso parser that generated them.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

# Maps Plaso parser name prefix → artifact_type for routing
PLASO_PARSER_TO_ARTIFACT = {
    "winevt": "evtx",
    "winevtx": "evtx",
    "winprefetch": "prefetch",
    "mft": "mft",
    "msiecf": "lnk",
    "lnk": "lnk",
    "winreg": "registry",
    "filestat": "filesystem",
    "sqlite": "browser",
    "chrome_history": "browser",
    "firefox_history": "browser",
}


def _sanitize_for_json(obj: Any) -> Any:
    """Recursively convert an object to be JSON-serializable."""
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(v) for v in obj]
    if isinstance(obj, (int, float, str, type(None), bool)):
        return obj
    return str(obj)


class PlasoPlugin(BasePlugin):

    PLUGIN_NAME = "plaso"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "timeline"
    SUPPORTED_EXTENSIONS = [".plaso"]
    SUPPORTED_MIME_TYPES = ["application/x-sqlite3"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        """Try psort first, then fall back to direct SQLite reading."""
        if self._psort_available():
            yield from self._parse_with_psort()
        else:
            self.log.warning("psort not found, falling back to direct SQLite parsing")
            yield from self._parse_sqlite_direct()

    def _psort_available(self) -> bool:
        try:
            result = subprocess.run(
                ["psort.py", "--version"],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _parse_with_psort(self) -> Generator[dict[str, Any], None, None]:
        """Export via psort to JSON Lines, then parse."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=True) as tmp:
            tmp_path = tmp.name

        cmd = [
            "psort.py",
            "--output-time-zone", "UTC",
            "-o", "json_line",
            "-w", tmp_path,
            str(self.ctx.source_file_path),
        ]
        self.log.info("Running: %s", " ".join(cmd))

        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=3600)
        except subprocess.CalledProcessError as exc:
            raise PluginFatalError(
                f"psort failed (exit {exc.returncode}): {exc.stderr.decode()[:500]}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PluginFatalError("psort timed out after 1 hour") from exc

        output_file = Path(tmp_path)
        if not output_file.exists():
            raise PluginFatalError("psort produced no output file")

        with output_file.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = self._psort_event_to_fo(data)
                    self._records_read += 1
                    yield event
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped line: %s", exc)

        output_file.unlink(missing_ok=True)

    def _psort_event_to_fo(self, data: dict) -> dict[str, Any]:
        """Convert a psort JSON Line event to a TraceX event dict."""
        parser = data.get("parser", "unknown")
        artifact_type = self._resolve_artifact_type(parser)
        timestamp = data.get("datetime", "")
        hostname = data.get("hostname", "")
        username = data.get("username", "")
        message = data.get("message", data.get("description", ""))
        source_short = data.get("source_short", "")
        source_long = data.get("source_long", "")

        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp,
            "timestamp_desc": data.get("timestamp_desc", "Event Time"),
            "message": message or f"{source_short}: {source_long}",
            "host": {"hostname": hostname},
            "user": {"name": username},
            "plaso": {
                "parser": parser,
                "source_short": source_short,
                "source_long": source_long,
                "store_number": data.get("store_number"),
                "inode": data.get("inode"),
                "filename": data.get("filename", ""),
                "display_name": data.get("display_name", ""),
            },
            "raw": _sanitize_for_json(data),
        }

    def _parse_sqlite_direct(self) -> Generator[dict[str, Any], None, None]:
        """
        Directly query the Plaso SQLite storage file.
        Plaso >= 20200227 uses a single SQLite file with event tables.
        """
        db_path = str(self.ctx.source_file_path)

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        except sqlite3.DatabaseError as exc:
            raise PluginFatalError(f"Cannot open as SQLite: {exc}") from exc

        try:
            # Check if this looks like a plaso storage file
            cursor = conn.cursor()
            tables = {row[0] for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}

            if "event_data" not in tables and "events" not in tables:
                raise PluginFatalError(
                    "Not a recognized Plaso storage file "
                    "(missing event_data/events tables)"
                )

            # Try the newer schema first (plaso >= 20200227)
            if "event_data" in tables:
                yield from self._read_new_schema(conn)
            else:
                yield from self._read_legacy_schema(conn)
        finally:
            conn.close()

    def _read_new_schema(self, conn: sqlite3.Connection) -> Generator[dict[str, Any], None, None]:
        cursor = conn.cursor()
        # Get actual column names from the table
        cursor.execute("PRAGMA table_info(event_data)")
        columns = [row[1] for row in cursor.fetchall()]
        self.log.info("event_data columns: %s", columns)
        
        # Build SELECT based on available columns
        select_cols = []
        for col in ["timestamp", "timestamp_desc", "parser", "message", "hostname", 
                    "username", "data_type", "_identifier", "display_name", "filename"]:
            if col in columns:
                select_cols.append(col)
        
        if not select_cols:
            select_cols = ["*"]
        
        query = f"SELECT {', '.join(select_cols)} FROM event_data ORDER BY timestamp ASC LIMIT 500000"
        self.log.info("Executing: %s", query)
        rows = cursor.execute(query)

        for row in rows:
            try:
                d = dict(row)
                parser = d.get("parser", "") or ""
                artifact_type = self._resolve_artifact_type(parser)
                # Plaso timestamps are in microseconds since epoch
                ts_micro = d.get("timestamp", 0) or 0
                timestamp = ""
                if ts_micro:
                    try:
                        from datetime import datetime, timezone
                        dt = datetime.fromtimestamp(ts_micro / 1_000_000, tz=timezone.utc)
                        timestamp = dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
                    except (OSError, OverflowError, ValueError) as ts_exc:
                        self.log.debug("Invalid timestamp %s: %s", ts_micro, ts_exc)
                        timestamp = ""

                # Build message from available fields
                message = d.get("message", "") or ""
                if not message:
                    display_name = d.get("display_name", "") or ""
                    filename = d.get("filename", "") or ""
                    if display_name:
                        message = display_name
                    elif filename:
                        message = f"File: {filename}"
                    else:
                        message = f"[{parser}] Event"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": artifact_type,
                    "timestamp": timestamp,
                    "timestamp_desc": d.get("timestamp_desc", "") or "Event Time",
                    "message": message,
                    "host": {"hostname": d.get("hostname", "") or ""},
                    "user": {"name": d.get("username", "") or ""},
                    "plaso": {
                        "parser": parser,
                        "data_type": d.get("data_type", "") or "",
                        "display_name": d.get("display_name", "") or "",
                        "filename": d.get("filename", "") or "",
                    },
                    "raw": _sanitize_for_json(d),
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.error("Skipped row: %s", exc)

    def _read_legacy_schema(self, conn: sqlite3.Connection) -> Generator[dict[str, Any], None, None]:
        """Fallback for older plaso schemas."""
        cursor = conn.cursor()
        try:
            for row in cursor.execute("SELECT * FROM events ORDER BY timestamp ASC"):
                d = dict(row)
                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "timeline",
                    "timestamp": None,
                    "timestamp_desc": "Unknown",
                    "message": str(d),
                    "plaso": _sanitize_for_json(d),
                    "raw": _sanitize_for_json(d),
                }
        except sqlite3.OperationalError as exc:
            raise PluginFatalError(f"Cannot query legacy events table: {exc}") from exc

    def _resolve_artifact_type(self, parser: str) -> str:
        parser_lower = parser.lower()
        for prefix, artifact_type in PLASO_PARSER_TO_ARTIFACT.items():
            if parser_lower.startswith(prefix):
                return artifact_type
        return self.DEFAULT_ARTIFACT_TYPE

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }

    # ── log2timeline fallback ─────────────────────────────────────────────────

    @classmethod
    def create_from_source(cls, source_file: Path, work_dir: Path, ctx: PluginContext) -> "PlasoPlugin":
        """
        Run log2timeline on an arbitrary source file, produce a .plaso storage,
        and return a PlasoPlugin instance pointing at it.

        This is the fallback path used when the primary plugin fails — log2timeline
        supports hundreds of file formats and will extract whatever it can.

        Raises PluginFatalError if log2timeline is unavailable or fails.
        """
        plaso_path = work_dir / f"{source_file.name}.plaso"
        cmd = [
            "log2timeline.py",
            "--status_view", "none",
            "--logfile", "/dev/null",
            str(plaso_path),
            str(source_file),
        ]
        ctx.logger.info("[%s] log2timeline fallback: processing %s", ctx.job_id, source_file.name)
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=7200)
        except FileNotFoundError as exc:
            raise PluginFatalError("log2timeline.py not found in PATH") from exc
        except subprocess.CalledProcessError as exc:
            raise PluginFatalError(
                f"log2timeline failed (exit {exc.returncode}): {exc.stderr.decode()[:500]}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PluginFatalError("log2timeline timed out after 2 hours") from exc

        if not plaso_path.exists() or plaso_path.stat().st_size == 0:
            raise PluginFatalError("log2timeline produced no output")

        new_ctx = PluginContext(
            case_id=ctx.case_id,
            job_id=ctx.job_id,
            source_file_path=plaso_path,
            source_minio_url=ctx.source_minio_url,
            logger=ctx.logger,
        )
        return cls(new_ctx)
