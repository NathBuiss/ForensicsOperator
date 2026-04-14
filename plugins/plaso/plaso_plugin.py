"""
Plaso Plugin — parses Plaso storage files (.plaso).
Dynamically detects schema and extracts ALL available fields.
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

PLASO_PARSER_TO_ARTIFACT = {
    "winevt": "evtx", "winevtx": "evtx", "winprefetch": "prefetch",
    "mft": "mft", "msiecf": "lnk", "lnk": "lnk", "winreg": "registry",
    "filestat": "filesystem", "sqlite": "browser", "chrome_history": "browser",
    "firefox_history": "browser",
}


def _sanitize_for_json(obj: Any) -> Any:
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
    if not ts_micro:
        return ""
    try:
        dt = datetime.fromtimestamp(ts_micro / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OSError, OverflowError, ValueError):
        return ""


class PlasoPlugin(BasePlugin):

    PLUGIN_NAME = "plaso"
    PLUGIN_VERSION = "3.0.0"
    DEFAULT_ARTIFACT_TYPE = "timeline"
    SUPPORTED_EXTENSIONS = [".plaso"]
    SUPPORTED_MIME_TYPES = ["application/x-sqlite3"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        if self._psort_available():
            yield from self._parse_with_psort()
        else:
            self.log.warning("psort not found, using direct SQLite parsing")
            yield from self._parse_sqlite_direct()

    def _psort_available(self) -> bool:
        try:
            result = subprocess.run(["psort.py", "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _parse_with_psort(self) -> Generator[dict[str, Any], None, None]:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=True) as tmp:
            tmp_path = tmp.name

        cmd = ["psort.py", "--output-time-zone", "UTC", "-o", "json_line", "-w", tmp_path, str(self.ctx.source_file_path)]
        self.log.info("Running: %s", " ".join(cmd))

        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=3600)
        except subprocess.CalledProcessError as exc:
            raise PluginFatalError(f"psort failed: {exc.stderr.decode()[:500] if exc.stderr else 'no output'}") from exc
        except subprocess.TimeoutExpired:
            raise PluginFatalError("psort timed out") from exc

        output_file = Path(tmp_path)
        if not output_file.exists():
            raise PluginFatalError("psort produced no output")

        with output_file.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = self._event_to_fo(data)
                    self._records_read += 1
                    yield event
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped: %s", exc)

        output_file.unlink(missing_ok=True)

    def _parse_sqlite_direct(self) -> Generator[dict[str, Any], None, None]:
        db_path = str(self.ctx.source_file_path)
        self.log.info("Opening: %s", db_path)

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        except sqlite3.DatabaseError as exc:
            raise PluginFatalError(f"Cannot open SQLite: {exc}") from exc

        try:
            cursor = conn.cursor()
            
            # Get ALL tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            self.log.info("ALL TABLES: %s", tables)
            
            # Find event table
            event_table = None
            for t in ["event_data", "events", "event", "timeline"]:
                if t in tables:
                    event_table = t
                    break
            
            if not event_table:
                # Use first table that looks like it has events
                for t in tables:
                    if "event" in t.lower() or "timeline" in t.lower():
                        event_table = t
                        break
            
            if not event_table:
                raise PluginFatalError(f"No event table found. Tables: {tables}")
            
            self.log.info("Using table: %s", event_table)
            
            # Get ALL columns with detailed info
            cursor.execute(f"PRAGMA table_info({event_table})")
            columns_info = cursor.fetchall()
            
            self.log.info("=" * 80)
            self.log.info("COLUMN SCHEMA for %s:", event_table)
            for col in columns_info:
                # cid, name, type, notnull, default_value, pk
                self.log.info("  %s: %s (notnull=%s, pk=%s)", col[1], col[2], col[3], col[5])
            self.log.info("=" * 80)
            
            column_names = [col[1] for col in columns_info]
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {event_table}")
            count = cursor.fetchone()[0]
            self.log.info("Total rows: %d", count)
            
            # Get FIRST 10 rows with ALL data
            cursor.execute(f"SELECT * FROM {event_table} LIMIT 10")
            rows = cursor.fetchall()
            
            self.log.info("=" * 80)
            self.log.info("SAMPLE DATA (first 10 rows):")
            self.log.info("=" * 80)
            
            for i, row in enumerate(rows):
                self.log.info("--- ROW %d ---", i)
                d = dict(row)
                for key, value in d.items():
                    if value is None:
                        self.log.info("  %s: NULL", key)
                    elif isinstance(value, bytes):
                        # Try to show what kind of bytes
                        if len(value) < 200:
                            try:
                                decoded = value.decode("utf-8", errors="replace")
                                self.log.info("  %s: <bytes:%d> '%s'", key, len(value), decoded[:100])
                            except Exception:
                                self.log.info("  %s: <bytes:%d> (binary)", key, len(value))
                        else:
                            self.log.info("  %s: <bytes:%d> (large blob)", key, len(value))
                    elif isinstance(value, (int, float)):
                        # Check if it looks like a timestamp
                        if value > 1000000000000000 and value < 2000000000000000:
                            # Likely microseconds timestamp
                            try:
                                dt = datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
                                self.log.info("  %s: %d (%s) <- TIMESTAMP?", key, value, dt.isoformat())
                            except Exception:
                                self.log.info("  %s: %d", key, value)
                        else:
                            self.log.info("  %s: %d", key, value)
                    else:
                        val_str = str(value)[:200]
                        self.log.info("  %s: %s", key, val_str)
            
            self.log.info("=" * 80)
            self.log.info("END SAMPLE DATA")
            self.log.info("=" * 80)
            
            # Now find the actual columns we need by inspecting the data
            timestamp_col = None
            parser_col = None
            message_cols = []
            
            # Common timestamp column names
            for candidate in ["_timestamp", "timestamp", "event_timestamp", "time", "ts"]:
                if candidate in column_names:
                    timestamp_col = candidate
                    self.log.info("Found timestamp column: %s", timestamp_col)
                    break
            
            # Common parser/data_type column names
            for candidate in ["data_type", "parser", "type", "event_type", "source"]:
                if candidate in column_names:
                    parser_col = candidate
                    self.log.info("Found parser column: %s", parser_col)
                    break
            
            # Common message column names
            for candidate in ["message", "description", "text", "string", "unicode_string", "content", "body"]:
                if candidate in column_names:
                    message_cols.append(candidate)
            
            # Common filename/path columns
            filename_cols = []
            for candidate in ["filename", "display_name", "path", "filepath", "location", "pathspec"]:
                if candidate in column_names:
                    filename_cols.append(candidate)
            
            self.log.info("Message columns found: %s", message_cols)
            self.log.info("Filename columns found: %s", filename_cols)
            
            # Yield all events
            cursor.execute(f"SELECT * FROM {event_table} ORDER BY {timestamp_col or 'rowid'} ASC LIMIT 500000")
            
            while True:
                rows = cursor.fetchmany(10000)
                if not rows:
                    break
                
                for row in rows:
                    try:
                        d = dict(row)
                        event = self._sqlite_row_to_event(
                            d, column_names, timestamp_col, parser_col, message_cols, filename_cols
                        )
                        if event:
                            self._records_read += 1
                            yield event
                    except Exception as exc:
                        self._records_skipped += 1
                        self.log.error("Skipped row: %s", exc)
                
                if self._records_read % 50000 == 0 and self._records_read > 0:
                    self.log.info("Processed %d events...", self._records_read)
                    
        finally:
            conn.close()

    def _sqlite_row_to_event(self, d: dict, all_cols: list, timestamp_col: str | None, 
                             parser_col: str | None, message_cols: list, filename_cols: list) -> dict[str, Any]:
        """Convert any sqlite row to event, using discovered columns."""
        
        # Get parser/data_type
        parser = ""
        if parser_col and parser_col in d:
            val = d[parser_col]
            if val:
                parser = str(val)
        
        # If no parser column found, try to find one in the data
        if not parser:
            for col in ["data_type", "parser", "type", "source_short"]:
                if col in d and d[col]:
                    parser = str(d[col])
                    break
        
        artifact_type = self._resolve_artifact_type(parser) if parser else "timeline"
        
        # Get timestamp
        timestamp = ""
        if timestamp_col and timestamp_col in d:
            ts_val = d[timestamp_col]
            if isinstance(ts_val, bytes):
                try:
                    ts_val = int.from_bytes(ts_val, 'little')
                except Exception:
                    ts_val = 0
            if ts_val:
                timestamp = _format_timestamp(ts_val)
        
        # Get message - try all discovered message columns
        message = ""
        for col in message_cols:
            if col in d:
                val = d[col]
                if val:
                    if isinstance(val, bytes):
                        val = val.decode("utf-8", errors="replace")
                    message = str(val).strip()
                    if message:
                        break
        
        # If still no message, try filename columns
        if not message:
            for col in filename_cols:
                if col in d:
                    val = d[col]
                    if val:
                        if isinstance(val, bytes):
                            val = val.decode("utf-8", errors="replace")
                        message = f"{col}: {val}"
                        break
        
        # If still nothing, scan ALL columns for something useful
        if not message:
            for col, val in d.items():
                if val is None:
                    continue
                if col in ["_identifier", "rowid", "store_number", "store_index", "inode"]:
                    continue  # Skip ID fields
                if isinstance(val, (int, float)) and val > 1000000000000000:
                    continue  # Skip timestamps
                if isinstance(val, bytes):
                    if len(val) < 500:
                        try:
                            decoded = val.decode("utf-8", errors="replace").strip()
                            if decoded and len(decoded) > 3:
                                message = f"{col}: {decoded[:200]}"
                                break
                        except Exception:
                            pass
                    continue
                val_str = str(val).strip()
                if val_str and len(val_str) > 2:
                    message = f"{col}: {val_str[:200]}"
                    break
        
        # Final fallback
        if not message:
            message = f"[{parser}] Event" if parser else "Plaso event"
        
        # Get hostname/username if available
        hostname = ""
        username = ""
        for col in ["hostname", "computer_name", "machine"]:
            if col in d and d[col]:
                hostname = str(d[col]) if not isinstance(d[col], bytes) else d[col].decode("utf-8", errors="replace")
                break
        for col in ["username", "user", "sid"]:
            if col in d and d[col]:
                username = str(d[col]) if not isinstance(d[col], bytes) else d[col].decode("utf-8", errors="replace")
                break
        
        # Build plaso metadata from ALL columns
        plaso_meta = {"parser": parser, "data_type": parser}
        for col in all_cols:
            if col in ["_identifier", "rowid"] or col.startswith("_"):
                continue  # Skip internal IDs
            if col in d:
                val = d[col]
                if isinstance(val, bytes):
                    if len(val) > 1000:
                        val = f"<blob:{len(val)}>"
                    else:
                        try:
                            val = val.decode("utf-8", errors="replace")
                        except Exception:
                            val = f"<bytes:{len(val)}>"
                plaso_meta[col] = val
        
        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp if timestamp else None,
            "timestamp_desc": "Event Time",
            "message": message[:2000],
            "host": {"hostname": str(hostname)},
            "user": {"name": str(username)},
            "plaso": plaso_meta,
            "raw": _sanitize_for_json(d),
        }

    def _event_to_fo(self, data: dict) -> dict[str, Any]:
        parser = data.get("data_type", "") or data.get("parser", "") or "unknown"
        artifact_type = self._resolve_artifact_type(parser)
        timestamp = data.get("datetime", "") or data.get("timestamp", "") or ""
        message = data.get("message", "") or data.get("description", "") or data.get("display_name", "") or ""
        if not message:
            message = f"[{parser}] Event"
        
        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp,
            "timestamp_desc": data.get("timestamp_desc", "") or "Event Time",
            "message": message,
            "host": {"hostname": data.get("hostname", "") or ""},
            "user": {"name": data.get("username", "") or ""},
            "plaso": {"parser": parser, "data_type": parser},
            "raw": _sanitize_for_json(data),
        }

    def _resolve_artifact_type(self, parser: str) -> str:
        parser_lower = parser.lower()
        for prefix, artifact_type in PLASO_PARSER_TO_ARTIFACT.items():
            if parser_lower.startswith(prefix):
                return artifact_type
        return self.DEFAULT_ARTIFACT_TYPE

    def get_stats(self) -> dict[str, Any]:
        return {"records_read": self._records_read, "records_skipped": self._records_skipped}

    @classmethod
    def create_from_source(cls, source_file: Path, work_dir: Path, ctx: PluginContext) -> "PlasoPlugin":
        plaso_path = work_dir / f"{source_file.name}.plaso"
        cmd = ["log2timeline.py", "--status_view", "none", "--logfile", "/dev/null", str(plaso_path), str(source_file)]
        ctx.logger.info("[%s] log2timeline: %s", ctx.job_id, source_file.name)
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=7200)
        except FileNotFoundError as exc:
            raise PluginFatalError("log2timeline.py not found") from exc
        except subprocess.CalledProcessError as exc:
            raise PluginFatalError(f"log2timeline failed: {exc.stderr.decode()[:500] if exc.stderr else 'no output'}") from exc
        except subprocess.TimeoutExpired:
            raise PluginFatalError("log2timeline timed out") from exc
        if not plaso_path.exists() or plaso_path.stat().st_size == 0:
            raise PluginFatalError("log2timeline produced no output")
        return cls(PluginContext(ctx.case_id, ctx.job_id, plaso_path, ctx.source_minio_url, ctx.logger))
