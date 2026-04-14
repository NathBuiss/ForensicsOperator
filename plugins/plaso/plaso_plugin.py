"""
Plaso Plugin — parses Plaso storage files (.plaso) using psort.
"""
from __future__ import annotations

import json
import os
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
    PLUGIN_VERSION = "5.0.0"
    DEFAULT_ARTIFACT_TYPE = "timeline"
    SUPPORTED_EXTENSIONS = [".plaso"]
    SUPPORTED_MIME_TYPES = ["application/x-sqlite3"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        if self._psort_available():
            self.log.info("psort found, attempting parsing")
            try:
                yield from self._parse_with_psort()
                return
            except Exception as exc:
                self.log.error("psort parsing failed: %s", exc)
                self.log.info("Falling back to SQLite direct reading")
        
        # Fallback to SQLite
        yield from self._parse_sqlite_direct()

    def _psort_available(self) -> bool:
        try:
            result = subprocess.run(["psort.py", "--version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                self.log.info("psort version: %s", result.stdout.decode().strip() or result.stderr.decode().strip())
                return True
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _parse_with_psort(self) -> Generator[dict[str, Any], None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output.jsonl"
            
            # Try with explicit dynamic_output module
            cmd = [
                "psort.py",
                "--output-time-zone", "UTC",
                "-o", "dynamic_output",
                "--dynamic_output", "json_line",
                "-w", str(output_file),
                str(self.ctx.source_file_path),
            ]
            self.log.info("Running: %s", " ".join(cmd))
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=3600,
                    env={**os.environ, "PYTHONUNBUFFERED": "1", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
                )
                
                self.log.info("psort exit code: %d", result.returncode)
                if result.stdout:
                    self.log.info("psort stdout: %s", result.stdout.decode()[:1000])
                if result.stderr:
                    self.log.warning("psort stderr: %s", result.stderr.decode()[:1000])
                
                if result.returncode == 0 and output_file.exists() and output_file.stat().st_size > 0:
                    self.log.info("Success! Output: %d bytes", output_file.stat().st_size)
                    yield from self._read_psort_output(output_file)
                    return
                elif result.returncode == 0:
                    self.log.warning("psort succeeded but output file is empty or missing")
                    raise PluginFatalError("psort produced no output")
                else:
                    stderr_msg = result.stderr.decode()[:500] if result.stderr else "no error output"
                    raise PluginFatalError(f"psort failed (exit {result.returncode}): {stderr_msg}")
                        
            except subprocess.TimeoutExpired:
                self.log.error("psort timed out after 1 hour")
                raise PluginFatalError("psort timed out")

    def _read_psort_output(self, output_file: Path) -> Generator[dict[str, Any], None, None]:
        self.log.info("Reading psort output: %s", output_file)
        
        with output_file.open() as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = self._event_to_fo(data)
                    self._records_read += 1
                    yield event
                    if i > 0 and i % 100000 == 0:
                        self.log.info("Processed %d events", i)
                except json.JSONDecodeError as exc:
                    self._records_skipped += 1
                    self.log.debug("JSON decode error line %d: %s", i, exc)
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped line %d: %s", i, exc)
        
        self.log.info("Finished reading psort output: %d events, %d skipped", 
                     self._records_read, self._records_skipped)

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

    def _parse_sqlite_direct(self) -> Generator[dict[str, Any], None, None]:
        """Extract timestamps from SQLite when psort fails."""
        db_path = str(self.ctx.source_file_path)
        self.log.info("Direct SQLite parse: %s", db_path)

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        except sqlite3.DatabaseError as exc:
            raise PluginFatalError(f"Cannot open SQLite: {exc}") from exc

        try:
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            self.log.info("Tables: %s", tables)
            
            if "event" not in tables:
                raise PluginFatalError("No 'event' table found")
            
            cursor.execute("SELECT COUNT(*) FROM event")
            count = cursor.fetchone()[0]
            self.log.info("Total events: %d", count)
            
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
                            "message": f"[Plaso Event #{event_id}]",
                            "host": {"hostname": ""},
                            "user": {"name": ""},
                            "plaso": {
                                "parser": "unknown",
                                "data_type": "unknown",
                                "note": "Full data requires psort",
                                "event_id": event_id,
                            },
                            "raw": {"_identifier": event_id, "_timestamp": ts_micro},
                        }
                    except Exception as exc:
                        self._records_skipped += 1
                        self.log.error("Skipped: %s", exc)
                
                if self._records_read % 50000 == 0 and self._records_read > 0:
                    self.log.info("Processed %d events...", self._records_read)
                    
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
