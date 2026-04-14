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
from datetime import datetime, timezone
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


def _format_timestamp(ts_micro: int) -> str:
    """Convert Plaso microsecond timestamp to ISO8601."""
    if not ts_micro:
        return ""
    try:
        dt = datetime.fromtimestamp(ts_micro / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OSError, OverflowError, ValueError):
        return ""


class PlasoPlugin(BasePlugin):

    PLUGIN_NAME = "plaso"
    PLUGIN_VERSION = "2.0.0"
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
        parser = data.get("parser", "unknown") or "unknown"
        artifact_type = self._resolve_artifact_type(parser)
        timestamp = data.get("datetime", "") or ""
        hostname = data.get("hostname", "") or ""
        username = data.get("username", "") or ""
        message = data.get("message", "") or data.get("description", "") or ""
        source_short = data.get("source_short", "") or ""
        source_long = data.get("source_long", "") or ""
        filename = data.get("filename", "") or ""
        display_name = data.get("display_name", "") or ""

        if not message:
            message = display_name or filename or f"{source_short}: {source_long}" or f"[{parser}] Event"

        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp,
            "timestamp_desc": data.get("timestamp_desc", "") or "Event Time",
            "message": message,
            "host": {"hostname": hostname},
            "user": {"name": username},
            "plaso": {
                "parser": parser,
                "source_short": source_short,
                "source_long": source_long,
                "store_number": data.get("store_number"),
                "inode": data.get("inode"),
                "filename": filename,
                "display_name": display_name,
            },
            "raw": _sanitize_for_json(data),
        }

    def _parse_sqlite_direct(self) -> Generator[dict[str, Any], None, None]:
        """
        Directly query the Plaso SQLite storage file.
        Handles multiple schema versions dynamically.
        """
        db_path = str(self.ctx.source_file_path)

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        except sqlite3.DatabaseError as exc:
            raise PluginFatalError(f"Cannot open as SQLite: {exc}") from exc

        try:
            cursor = conn.cursor()
            
            # Get all tables
            tables = {row[0] for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            self.log.info("Tables in plaso file: %s", tables)

            if "event_data" not in tables and "events" not in tables:
                raise PluginFatalError(
                    "Not a recognized Plaso storage file "
                    "(missing event_data/events tables)"
                )

            # Try event_data first (newer schema), then events (legacy)
            if "event_data" in tables:
                yield from self._read_event_data(conn)
            elif "events" in tables:
                yield from self._read_events(conn)
        finally:
            conn.close()

    def _read_event_data(self, conn: sqlite3.Connection) -> Generator[dict[str, Any], None, None]:
        """Read from event_data table with dynamic column detection."""
        cursor = conn.cursor()
        
        # Get column info
        cursor.execute("PRAGMA table_info(event_data)")
        columns = {row[1]: {"cid": row[0], "type": row[2]} for row in cursor.fetchall()}
        column_names = list(columns.keys())
        
        self.log.info("event_data columns (%d): %s", len(column_names), column_names)
        
        # Log first 3 rows as debug
        cursor.execute("SELECT * FROM event_data LIMIT 3")
        sample_rows = cursor.fetchall()
        for i, row in enumerate(sample_rows):
            row_dict = dict(row)
            self.log.info("Sample row %d: %s", i, {k: repr(v)[:100] for k, v in row_dict.items()})
        
        # Identify timestamp column (could be _timestamp, timestamp, or event_timestamp)
        timestamp_col = None
        for candidate in ["_timestamp", "timestamp", "event_timestamp"]:
            if candidate in column_names:
                timestamp_col = candidate
                break
        
        # Build column list for SELECT
        important_cols = ["parser", "message", "description", "hostname", "username", 
                         "data_type", "display_name", "filename", "timestamp_desc", 
                         "pathspec", "source_short", "source_long", "store_number", 
                         "inode", "unicode_string", "string"]
        
        select_cols = []
        if timestamp_col:
            select_cols.append(timestamp_col)
        for col in important_cols:
            if col in column_names:
                select_cols.append(col)
        
        # If no important columns found, select all
        if not select_cols:
            select_cols = ["*"]
        
        order_by = timestamp_col if timestamp_col else "rowid"
        query = f"SELECT {', '.join(select_cols)} FROM event_data ORDER BY {order_by} ASC LIMIT 500000"
        self.log.info("Executing: %s", query)
        
        rows = cursor.execute(query)
        for row in rows:
            try:
                d = dict(row)
                event = self._row_to_event(d, timestamp_col)
                if event:
                    self._records_read += 1
                    yield event
            except Exception as exc:
                self._records_skipped += 1
                self.log.error("Skipped row: %s", exc)

    def _read_events(self, conn: sqlite3.Connection) -> Generator[dict[str, Any], None, None]:
        """Read from legacy events table."""
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(events)")
        column_names = [row[1] for row in cursor.fetchall()]
        self.log.info("events table columns: %s", column_names)
        
        # Log sample
        cursor.execute("SELECT * FROM events LIMIT 3")
        for i, row in enumerate(cursor.fetchall()):
            self.log.info("Sample events row %d: %s", i, dict(row))
        
        timestamp_col = "_timestamp" if "_timestamp" in column_names else "timestamp" if "timestamp" in column_names else None
        
        select_cols = [timestamp_col] if timestamp_col else []
        for col in ["timestamp_desc", "source_short", "source_long", "parser", 
                   "display_name", "pathspec", "inode", "filename", "unicode_string", 
                   "message", "string", "data"]:
            if col in column_names:
                select_cols.append(col)
        
        if not select_cols:
            select_cols = ["*"]
        
        order_by = timestamp_col if timestamp_col else "rowid"
        query = f"SELECT {', '.join(select_cols)} FROM events ORDER BY {order_by} ASC LIMIT 500000"
        self.log.info("Executing: %s", query)
        
        rows = cursor.execute(query)
        for row in rows:
            try:
                d = dict(row)
                event = self._row_to_event_legacy(d, timestamp_col)
                if event:
                    self._records_read += 1
                    yield event
            except Exception as exc:
                self._records_skipped += 1
                self.log.error("Skipped events row: %s", exc)

    def _row_to_event(self, d: dict, timestamp_col: str | None) -> dict[str, Any] | None:
        """Convert a row from event_data table to ForensicEvent."""
        # Extract fields with multiple possible names
        parser = d.get("parser", "") or d.get("data_type", "") or ""
        artifact_type = self._resolve_artifact_type(parser) if parser else "timeline"
        
        # Timestamp
        ts_val = d.get(timestamp_col, 0) if timestamp_col else 0
        timestamp = _format_timestamp(ts_val) if ts_val else ""
        
        # Message - try multiple fields
        message = (
            d.get("message", "") or 
            d.get("description", "") or 
            d.get("unicode_string", "") or 
            d.get("string", "") or 
            d.get("display_name", "") or 
            d.get("filename", "") or 
            ""
        ).strip()
        
        if not message:
            # Build from available context
            display_name = d.get("display_name", "") or ""
            filename = d.get("filename", "") or ""
            pathspec = d.get("pathspec", "") or ""
            
            if display_name:
                message = display_name
            elif filename:
                message = f"File: {filename}"
            elif pathspec:
                message = f"Path: {pathspec}"
            elif parser:
                message = f"[{parser}] Event"
            else:
                message = "Plaso event"
        
        # Hostname and username
        hostname = d.get("hostname", "") or ""
        username = d.get("username", "") or ""
        
        # Timestamp description
        timestamp_desc = d.get("timestamp_desc", "") or "Event Time"
        
        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp if timestamp else None,
            "timestamp_desc": timestamp_desc,
            "message": message,
            "host": {"hostname": hostname},
            "user": {"name": username},
            "plaso": {
                "parser": parser,
                "data_type": d.get("data_type", "") or "",
                "display_name": d.get("display_name", "") or "",
                "filename": d.get("filename", "") or "",
                "pathspec": d.get("pathspec", "") or "",
                "source_short": d.get("source_short", "") or "",
                "source_long": d.get("source_long", "") or "",
            },
            "raw": _sanitize_for_json(d),
        }

    def _row_to_event_legacy(self, d: dict, timestamp_col: str | None) -> dict[str, Any] | None:
        """Convert a row from legacy events table to ForensicEvent."""
        parser = d.get("parser", "") or ""
        artifact_type = self._resolve_artifact_type(parser) if parser else "timeline"
        
        ts_val = d.get(timestamp_col, 0) if timestamp_col else 0
        timestamp = _format_timestamp(ts_val) if ts_val else ""
        
        # Legacy plaso uses different field names
        message = (
            d.get("unicode_string", "") or 
            d.get("string", "") or 
            d.get("message", "") or 
            d.get("display_name", "") or 
            d.get("filename", "") or 
            ""
        ).strip()
        
        if not message:
            source_short = d.get("source_short", "") or ""
            source_long = d.get("source_long", "") or ""
            if source_short or source_long:
                message = f"{source_short}: {source_long}"
            elif parser:
                message = f"[{parser}] Event"
            else:
                message = "Plaso event"
        
        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp if timestamp else None,
            "timestamp_desc": d.get("timestamp_desc", "") or "Event Time",
            "message": message,
            "host": {"hostname": ""},
            "user": {"name": ""},
            "plaso": {
                "parser": parser,
                "source_short": d.get("source_short", "") or "",
                "source_long": d.get("source_long", "") or "",
                "display_name": d.get("display_name", "") or "",
                "filename": d.get("filename", "") or "",
                "pathspec": d.get("pathspec", "") or "",
            },
            "raw": _sanitize_for_json(d),
        }

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

    @classmethod
    def create_from_source(cls, source_file: Path, work_dir: Path, ctx: PluginContext) -> "PlasoPlugin":
        """
        Run log2timeline on an arbitrary source file, produce a .plaso storage,
        and return a PlasoPlugin instance pointing at it.
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
