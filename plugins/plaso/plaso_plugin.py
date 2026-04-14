"""
Plaso Plugin — parses Plaso storage files (.plaso).

NOTE: Modern Plaso files serialize all event data into BLOBs.
This plugin extracts timestamps from the event table, but for full
parsing you MUST install psort or plaso libraries.
"""
from __future__ import annotations

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
    PLUGIN_VERSION = "4.0.0"
    DEFAULT_ARTIFACT_TYPE = "timeline"
    SUPPORTED_EXTENSIONS = [".plaso"]
    SUPPORTED_MIME_TYPES = ["application/x-sqlite3"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        # ALWAYS try psort first - it's REQUIRED for modern plaso files
        if self._psort_available():
            self.log.info("Using psort for parsing (required for modern plaso files)")
            yield from self._parse_with_psort()
        else:
            # Fallback: extract what we can from SQLite directly
            self.log.error(
                "psort.py NOT FOUND! Modern plaso files require psort for full parsing. "
                "Install plaso-tools or use: apt-get install plaso-tools / pip install plaso"
            )
            yield from self._parse_sqlite_fallback()

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
            result = subprocess.run(cmd, check=True, capture_output=True, timeout=3600)
            if result.stdout:
                self.log.info("psort: %s", result.stdout.decode()[:300])
            if result.stderr:
                self.log.warning("psort: %s", result.stderr.decode()[:300])
        except subprocess.CalledProcessError as exc:
            raise PluginFatalError(f"psort failed: {exc.stderr.decode()[:500] if exc.stderr else 'no output'}") from exc
        except subprocess.TimeoutExpired:
            raise PluginFatalError("psort timed out") from exc

        output_file = Path(tmp_path)
        if not output_file.exists():
            raise PluginFatalError("psort produced no output")

        self.log.info("Reading psort output: %s (%d bytes)", tmp_path, output_file.stat().st_size)
        
        with output_file.open() as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = self._json_loads(line)
                    event = self._event_to_fo(data)
                    self._records_read += 1
                    yield event
                    if i > 0 and i % 100000 == 0:
                        self.log.info("Processed %d events", i)
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped line %d: %s", i, exc)

        output_file.unlink(missing_ok=True)

    def _json_loads(self, line: str) -> dict:
        import json
        return json.loads(line)

    def _event_to_fo(self, data: dict) -> dict[str, Any]:
        parser = data.get("data_type", "") or data.get("parser", "") or "unknown"
        artifact_type = self._resolve_artifact_type(parser) if parser else "timeline"
        
        timestamp = data.get("datetime", "") or data.get("timestamp", "") or ""
        hostname = data.get("hostname", "") or ""
        username = data.get("username", "") or ""
        
        message = (
            data.get("message", "") or 
            data.get("description", "") or 
            data.get("display_name", "") or 
            data.get("filename", "") or 
            ""
        )
        
        if not message:
            source_short = data.get("source_short", "") or ""
            source_long = data.get("source_long", "") or ""
            if source_short or source_long:
                message = f"{source_short}: {source_long}"
            else:
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
                "filename": data.get("filename", "") or "",
                "display_name": data.get("display_name", "") or "",
            },
            "raw": data,
        }

    def _parse_sqlite_fallback(self) -> Generator[dict[str, Any], None, None]:
        """
        Fallback when psort is not available.
        Extracts timestamps from the event table, but data is limited.
        """
        db_path = str(self.ctx.source_file_path)
        self.log.info("Opening: %s", db_path)

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        except sqlite3.DatabaseError as exc:
            raise PluginFatalError(f"Cannot open SQLite: {exc}") from exc

        try:
            cursor = conn.cursor()
            
            # Check for event table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            self.log.info("Tables: %s", tables)
            
            # Use event table if available (has _timestamp column)
            if "event" not in tables:
                raise PluginFatalError(
                    "No 'event' table found. This plaso file format is not supported without psort. "
                    "Install plaso-tools: apt-get install plaso-tools"
                )
            
            # Get timestamp from event table
            self.log.info("Extracting timestamps from 'event' table")
            cursor.execute("SELECT COUNT(*) FROM event")
            count = cursor.fetchone()[0]
            self.log.info("Total events: %d", count)
            
            # Sample first timestamp
            cursor.execute("SELECT _timestamp FROM event LIMIT 1")
            sample = cursor.fetchone()
            if sample:
                ts = sample[0]
                self.log.info("Sample timestamp: %d (%s)", ts, _format_timestamp(ts) if ts else "NULL")
            
            # Extract all events with timestamps only
            cursor.execute("SELECT _identifier, _timestamp FROM event ORDER BY _timestamp ASC LIMIT 500000")
            
            while True:
                rows = cursor.fetchmany(10000)
                if not rows:
                    break
                
                for row in rows:
                    try:
                        event_id = row[0]
                        ts_micro = row[1]
                        
                        timestamp = _format_timestamp(ts_micro) if ts_micro else ""
                        
                        self._records_read += 1
                        yield {
                            "fo_id": str(uuid.uuid4()),
                            "artifact_type": "timeline",
                            "timestamp": timestamp if timestamp else None,
                            "timestamp_desc": "Event Time",
                            "message": f"[Plaso Event #{event_id}] Data requires psort for extraction",
                            "host": {"hostname": ""},
                            "user": {"name": ""},
                            "plaso": {
                                "parser": "unknown",
                                "data_type": "unknown",
                                "note": "Full event data is serialized - install psort.py to extract",
                                "event_id": event_id,
                            },
                            "raw": {"_identifier": event_id, "_timestamp": ts_micro},
                        }
                    except Exception as exc:
                        self._records_skipped += 1
                        self.log.error("Skipped: %s", exc)
                
                if self._records_read % 50000 == 0 and self._records_read > 0:
                    self.log.info("Processed %d events...", self._records_read)
            
            self.log.warning(
                "Extracted %d events with TIMESTAMPS ONLY. "
                "For full event data (messages, filenames, etc.), install psort: "
                "apt-get install plaso-tools  OR  pip install plaso",
                self._records_read
            )
                    
        finally:
            conn.close()

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
        return cls(PluginContext(ctx.case_id, ctx.job_id, plaso_path, ctx.source_minio_url, logger=ctx.logger))
