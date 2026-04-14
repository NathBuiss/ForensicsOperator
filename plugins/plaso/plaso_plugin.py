"""
Plaso Plugin — parses Plaso storage files (.plaso).
Plaso files are SQLite databases. This plugin dynamically detects the schema
and extracts all events with proper field mapping.

Supports:
- Modern schema (20200227+): event_data table with _timestamp, data_type, attributes
- Legacy schema: events table with timestamp, parser, unicode_string
"""
from __future__ import annotations

import json
import pickle
import sqlite3
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

# Maps Plaso data_type/parser name → artifact_type for routing
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
    "macos_keychain": "browser",
    "macos_security": "filesystem",
}


def _sanitize_for_json(obj: Any) -> Any:
    """Recursively convert an object to be JSON-serializable."""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)
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


def _deserialize_blob(blob: bytes | None) -> Any:
    """Deserialize a Plaso pathspec or attributes blob."""
    if not blob:
        return None
    try:
        # Plaso uses pickle for pathspec and attributes
        return pickle.loads(blob)
    except Exception:
        try:
            # Fallback: try UTF-8 decode
            return blob.decode("utf-8", errors="replace")
        except Exception:
            return str(blob)


class PlasoPlugin(BasePlugin):

    PLUGIN_NAME = "plaso"
    PLUGIN_VERSION = "2.1.0"
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
            self.log.info("Using psort for parsing")
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
            result = subprocess.run(cmd, check=True, capture_output=True, timeout=3600)
            if result.stdout:
                self.log.info("psort stdout: %s", result.stdout.decode()[:500])
            if result.stderr:
                self.log.warning("psort stderr: %s", result.stderr.decode()[:500])
        except subprocess.CalledProcessError as exc:
            raise PluginFatalError(
                f"psort failed (exit {exc.returncode}): {exc.stderr.decode()[:500] if exc.stderr else 'no output'}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PluginFatalError("psort timed out after 1 hour") from exc

        output_file = Path(tmp_path)
        if not output_file.exists():
            raise PluginFatalError("psort produced no output file")

        self.log.info("Reading psort output: %s (%d bytes)", tmp_path, output_file.stat().st_size)
        
        with output_file.open() as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = self._psort_event_to_fo(data)
                    self._records_read += 1
                    yield event
                    if i > 0 and i % 100000 == 0:
                        self.log.info("Processed %d events", i)
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped line %d: %s", i, exc)

        output_file.unlink(missing_ok=True)

    def _psort_event_to_fo(self, data: dict) -> dict[str, Any]:
        """Convert a psort JSON Line event to a ForensicEvent dict."""
        # Modern plaso uses data_type, older uses parser
        parser = data.get("data_type", "") or data.get("parser", "") or "unknown"
        artifact_type = self._resolve_artifact_type(parser)
        
        timestamp = data.get("datetime", "") or data.get("timestamp", "") or ""
        hostname = data.get("hostname", "") or ""
        username = data.get("username", "") or ""
        
        # Message can be in multiple fields
        message = (
            data.get("message", "") or 
            data.get("description", "") or 
            data.get("display_name", "") or 
            data.get("filename", "") or 
            ""
        )
        
        source_short = data.get("source_short", "") or ""
        source_long = data.get("source_long", "") or ""
        
        if not message and (source_short or source_long):
            message = f"{source_short}: {source_long}"
        if not message:
            message = f"[{parser}] Event"

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
                "data_type": parser,
                "source_short": source_short,
                "source_long": source_long,
                "filename": data.get("filename", "") or "",
                "display_name": data.get("display_name", "") or "",
                "pathspec": data.get("pathspec", ""),
            },
            "raw": _sanitize_for_json(data),
        }

    def _parse_sqlite_direct(self) -> Generator[dict[str, Any], None, None]:
        """Directly query the Plaso SQLite storage file with dynamic schema detection."""
        db_path = str(self.ctx.source_file_path)
        self.log.info("Opening plaso file: %s", db_path)

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        except sqlite3.DatabaseError as exc:
            raise PluginFatalError(f"Cannot open as SQLite: {exc}") from exc

        try:
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            self.log.info("Tables in plaso file: %s", tables)

            # Find the event table (could be event_data or events)
            event_table = None
            if "event_data" in tables:
                event_table = "event_data"
            elif "events" in tables:
                event_table = "events"
            
            if not event_table:
                raise PluginFatalError(
                    f"No event table found. Available tables: {tables}"
                )

            self.log.info("Using event table: %s", event_table)
            
            # Get column info
            cursor.execute(f"PRAGMA table_info({event_table})")
            columns = {row[1]: {"cid": row[0], "type": row[2], "notnull": row[3]} for row in cursor.fetchall()}
            column_names = list(columns.keys())
            
            self.log.info("Columns in %s (%d): %s", event_table, len(column_names), column_names)
            
            # Log row count
            cursor.execute(f"SELECT COUNT(*) FROM {event_table}")
            row_count = cursor.fetchone()[0]
            self.log.info("Total rows in %s: %d", event_table, row_count)
            
            # Log sample rows to understand the data
            cursor.execute(f"SELECT * FROM {event_table} LIMIT 5")
            for i, row in enumerate(cursor.fetchall()):
                row_dict = dict(row)
                sample = {}
                for k, v in row_dict.items():
                    if isinstance(v, bytes):
                        sample[k] = f"<bytes:{len(v)}>"
                    elif v is None:
                        sample[k] = None
                    else:
                        sample[k] = repr(v)[:100]
                self.log.info("Sample row %d: %s", i, sample)
            
            # Identify timestamp column
            timestamp_col = None
            for candidate in ["_timestamp", "timestamp", "event_timestamp"]:
                if candidate in column_names:
                    timestamp_col = candidate
                    self.log.info("Using timestamp column: %s", timestamp_col)
                    break
            
            if not timestamp_col:
                self.log.warning("No timestamp column found!")
            
            # Yield events
            if event_table == "event_data":
                yield from self._read_event_data(conn, column_names, timestamp_col)
            else:
                yield from self._read_events(conn, column_names, timestamp_col)
                
        finally:
            conn.close()

    def _read_event_data(self, conn: sqlite3.Connection, columns: list[str], timestamp_col: str | None) -> Generator[dict[str, Any], None, None]:
        """Read from modern event_data table."""
        cursor = conn.cursor()
        
        # Build SELECT with all available important columns
        important_cols = [
            "_timestamp", "timestamp", "timestamp_desc", "data_type", "parser",
            "message", "description", "display_name", "filename", "hostname", 
            "username", "pathspec", "attributes", "source_short", "source_long",
            "store_number", "inode", "unicode_string", "string"
        ]
        
        select_cols = [c for c in important_cols if c in columns]
        if not select_cols:
            select_cols = ["*"]
        
        order_by = timestamp_col if timestamp_col else "rowid"
        limit = 500000
        query = f"SELECT {', '.join(select_cols)} FROM event_data ORDER BY {order_by} ASC LIMIT {limit}"
        self.log.info("Executing: %s", query)
        
        cursor.execute(query)
        
        while True:
            rows = cursor.fetchmany(10000)
            if not rows:
                break
                
            for row in rows:
                try:
                    d = dict(row)
                    event = self._row_to_event_modern(d, timestamp_col)
                    if event:
                        self._records_read += 1
                        yield event
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.error("Skipped row: %s", exc)
                    
            if self._records_read % 50000 == 0 and self._records_read > 0:
                self.log.info("Processed %d events...", self._records_read)

    def _read_events(self, conn: sqlite3.Connection, columns: list[str], timestamp_col: str | None) -> Generator[dict[str, Any], None, None]:
        """Read from legacy events table."""
        cursor = conn.cursor()
        
        important_cols = [
            "_timestamp", "timestamp", "timestamp_desc", "parser", "data_type",
            "source_short", "source_long", "display_name", "pathspec", "inode",
            "filename", "unicode_string", "string", "message", "data"
        ]
        
        select_cols = [c for c in important_cols if c in columns]
        if not select_cols:
            select_cols = ["*"]
        
        order_by = timestamp_col if timestamp_col else "rowid"
        query = f"SELECT {', '.join(select_cols)} FROM events ORDER BY {order_by} ASC LIMIT 500000"
        self.log.info("Executing: %s", query)
        
        cursor.execute(query)
        
        while True:
            rows = cursor.fetchmany(10000)
            if not rows:
                break
                
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
                    
            if self._records_read % 50000 == 0 and self._records_read > 0:
                self.log.info("Processed %d events...", self._records_read)

    def _row_to_event_modern(self, d: dict, timestamp_col: str | None) -> dict[str, Any]:
        """Convert a row from modern event_data table to ForensicEvent."""
        # Parser is in data_type (modern) or parser (older)
        parser = d.get("data_type", "") or d.get("parser", "") or ""
        parser_str = str(parser) if parser else ""
        artifact_type = self._resolve_artifact_type(parser_str) if parser_str else "timeline"
        
        # Timestamp
        ts_val = d.get(timestamp_col, 0) if timestamp_col else 0
        if isinstance(ts_val, bytes):
            try:
                ts_val = int.from_bytes(ts_val, 'little')
            except Exception:
                ts_val = 0
        timestamp = _format_timestamp(ts_val) if ts_val else ""
        
        # Message - try many fields in order of preference
        message = ""
        for field in ["message", "description", "unicode_string", "string", "display_name"]:
            val = d.get(field, "")
            if val:
                if isinstance(val, bytes):
                    val = val.decode("utf-8", errors="replace")
                message = str(val).strip()
                if message:
                    break
        
        # If still no message, build from filename/pathspec
        if not message:
            filename = d.get("filename", "")
            if filename:
                if isinstance(filename, bytes):
                    filename = filename.decode("utf-8", errors="replace")
                message = f"File: {filename}"
            
            if not message:
                pathspec_blob = d.get("pathspec")
                if pathspec_blob:
                    pathspec = _deserialize_blob(pathspec_blob if isinstance(pathspec_blob, bytes) else None)
                    if pathspec:
                        if isinstance(pathspec, dict):
                            location = pathspec.get("location", "") or pathspec.get("filename", "")
                            if location:
                                message = f"Path: {location}"
                        elif isinstance(pathspec, str):
                            message = f"Path: {pathspec}"
        
        # Final fallback
        if not message:
            message = f"[{parser_str}] Event" if parser_str else "Plaso event"
        
        # Hostname and username
        hostname = d.get("hostname", "") or ""
        if isinstance(hostname, bytes):
            hostname = hostname.decode("utf-8", errors="replace")
            
        username = d.get("username", "") or ""
        if isinstance(username, bytes):
            username = username.decode("utf-8", errors="replace")
        
        # Timestamp description
        timestamp_desc = d.get("timestamp_desc", "") or "Event Time"
        if isinstance(timestamp_desc, bytes):
            timestamp_desc = timestamp_desc.decode("utf-8", errors="replace")
        
        # Build plaso metadata
        filename = d.get("filename", "") or ""
        if isinstance(filename, bytes):
            filename = filename.decode("utf-8", errors="replace")
            
        display_name = d.get("display_name", "") or ""
        if isinstance(display_name, bytes):
            display_name = display_name.decode("utf-8", errors="replace")
        
        pathspec_blob = d.get("pathspec")
        pathspec_str = ""
        if pathspec_blob:
            pathspec = _deserialize_blob(pathspec_blob if isinstance(pathspec_blob, bytes) else None)
            if pathspec:
                pathspec_str = str(pathspec)
        
        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp if timestamp else None,
            "timestamp_desc": str(timestamp_desc),
            "message": message,
            "host": {"hostname": str(hostname)},
            "user": {"name": str(username)},
            "plaso": {
                "parser": parser_str,
                "data_type": parser_str,
                "display_name": display_name,
                "filename": filename,
                "pathspec": pathspec_str[:2000] if pathspec_str else "",
                "source_short": str(d.get("source_short", "") or ""),
                "source_long": str(d.get("source_long", "") or ""),
            },
            "raw": _sanitize_for_json(d),
        }

    def _row_to_event_legacy(self, d: dict, timestamp_col: str | None) -> dict[str, Any]:
        """Convert a row from legacy events table to ForensicEvent."""
        parser = d.get("parser", "") or d.get("data_type", "") or ""
        parser_str = str(parser) if parser else ""
        artifact_type = self._resolve_artifact_type(parser_str) if parser_str else "timeline"
        
        ts_val = d.get(timestamp_col, 0) if timestamp_col else 0
        if isinstance(ts_val, bytes):
            try:
                ts_val = int.from_bytes(ts_val, 'little')
            except Exception:
                ts_val = 0
        timestamp = _format_timestamp(ts_val) if ts_val else ""
        
        # Legacy uses unicode_string primarily
        message = ""
        for field in ["unicode_string", "string", "message", "display_name"]:
            val = d.get(field, "")
            if val:
                if isinstance(val, bytes):
                    val = val.decode("utf-8", errors="replace")
                message = str(val).strip()
                if message:
                    break
        
        if not message:
            source_short = d.get("source_short", "") or ""
            source_long = d.get("source_long", "") or ""
            if isinstance(source_short, bytes):
                source_short = source_short.decode("utf-8", errors="replace")
            if isinstance(source_long, bytes):
                source_long = source_long.decode("utf-8", errors="replace")
            if source_short or source_long:
                message = f"{source_short}: {source_long}"
            elif parser_str:
                message = f"[{parser_str}] Event"
            else:
                message = "Plaso event"
        
        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp if timestamp else None,
            "timestamp_desc": str(d.get("timestamp_desc", "") or "Event Time"),
            "message": message,
            "host": {"hostname": ""},
            "user": {"name": ""},
            "plaso": {
                "parser": parser_str,
                "data_type": parser_str,
                "source_short": str(d.get("source_short", "") or ""),
                "source_long": str(d.get("source_long", "") or ""),
                "display_name": str(d.get("display_name", "") or ""),
                "filename": str(d.get("filename", "") or ""),
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
        """Run log2timeline on source file to create plaso storage."""
        plaso_path = work_dir / f"{source_file.name}.plaso"
        cmd = [
            "log2timeline.py",
            "--status_view", "none",
            "--logfile", "/dev/null",
            str(plaso_path),
            str(source_file),
        ]
        ctx.logger.info("[%s] log2timeline: processing %s", ctx.job_id, source_file.name)
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, timeout=7200)
            if result.stderr:
                ctx.logger.info("log2timeline stderr: %s", result.stderr.decode()[:500])
        except FileNotFoundError as exc:
            raise PluginFatalError("log2timeline.py not found in PATH") from exc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode()[:500] if exc.stderr else "no output"
            raise PluginFatalError(f"log2timeline failed (exit {exc.returncode}): {stderr}") from exc
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
