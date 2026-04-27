"""
JSON file plugin — indexes JSON/config/text files as searchable events.

Handles:
  .json  — single object → 1 event; array → one event per element
  .yaml/.yml — parsed to dict → one event per top-level key
  .txt/.log/.conf/.cfg/.ini/.toml/.xml — raw text, one event per 200-line chunk
  .csv — each row as an event (up to 5000 rows)

Priority 15 — fallback for readable structured files not claimed by specific
parsers (e.g. hayabusa, ndjson, plaso). Files are stored verbatim in the
`file.content` field so they can be viewed in full in the EventDetail panel.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

# Max file size to read (5 MB)
MAX_BYTES = 5 * 1024 * 1024
# Lines per chunk for raw text files
CHUNK_LINES = 200
# Max CSV rows
MAX_CSV_ROWS = 5000


def _try_yaml(text: str) -> Any:
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:
        return None


class JsonFilePlugin(BasePlugin):

    PLUGIN_NAME = "json_file"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "file"
    SUPPORTED_EXTENSIONS = [
        ".json",
        ".yaml", ".yml",
        ".txt", ".log", ".conf", ".cfg", ".ini", ".toml", ".xml",
        ".csv",
        ".ps1", ".sh", ".bat", ".py",
    ]
    SUPPORTED_MIME_TYPES = [
        "text/plain", "text/html", "text/xml", "text/csv",
        "application/json", "application/yaml",
    ]
    PLUGIN_PRIORITY = 15

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        ext = fp.suffix.lower()
        filename = fp.name

        try:
            raw = fp.read_bytes()
        except Exception as exc:
            raise PluginFatalError(f"Cannot read file: {exc}")

        if len(raw) > MAX_BYTES:
            raw = raw[:MAX_BYTES]

        text = raw.decode("utf-8", errors="replace")

        if ext == ".json" or (not ext and text.lstrip().startswith(('{', '['))):
            yield from self._parse_json(filename, text)
        elif ext in (".yaml", ".yml"):
            yield from self._parse_yaml(filename, text)
        elif ext == ".csv" or (not ext and self._looks_like_csv(text)):
            yield from self._parse_csv(filename, text)
        else:
            yield from self._parse_text(filename, text)

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _parse_json(self, filename: str, text: str) -> Generator[dict, None, None]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Fall back to text chunking
            yield from self._parse_text(filename, text)
            return

        if isinstance(data, list):
            for i, item in enumerate(data):
                content = json.dumps(item, indent=2, ensure_ascii=False) if isinstance(item, (dict, list)) else str(item)
                msg = f"{filename}[{i}]"
                if isinstance(item, dict):
                    # Use first string value as preview
                    first_val = next((str(v)[:80] for v in item.values() if isinstance(v, str)), "")
                    if first_val:
                        msg += f": {first_val}"
                yield self._file_event(filename, msg, content)
        elif isinstance(data, dict):
            content = json.dumps(data, indent=2, ensure_ascii=False)
            # One event for the whole object; use first string value as preview
            first_val = next((str(v)[:80] for v in data.values() if isinstance(v, str)), "")
            msg = f"{filename}: {first_val}" if first_val else filename
            yield self._file_event(filename, msg, content)
        else:
            yield self._file_event(filename, f"{filename}: {str(data)[:200]}", text)

    # ── YAML ──────────────────────────────────────────────────────────────────

    def _parse_yaml(self, filename: str, text: str) -> Generator[dict, None, None]:
        data = _try_yaml(text)
        if data is None:
            yield from self._parse_text(filename, text)
            return
        if isinstance(data, dict):
            for key, value in data.items():
                val_str = json.dumps(value, default=str) if isinstance(value, (dict, list)) else str(value)
                yield self._file_event(filename, f"{filename} | {key}: {val_str[:200]}", val_str)
        else:
            yield self._file_event(filename, filename, text)

    # ── CSV ───────────────────────────────────────────────────────────────────

    def _parse_csv(self, filename: str, text: str) -> Generator[dict, None, None]:
        reader = csv.DictReader(io.StringIO(text))
        for i, row in enumerate(reader):
            if i >= MAX_CSV_ROWS:
                break
            content = json.dumps(dict(row), ensure_ascii=False)
            first_val = next((str(v)[:80] for v in row.values() if v), "")
            yield self._file_event(filename, f"{filename}[{i}]: {first_val}", content)

    # ── Raw text ──────────────────────────────────────────────────────────────

    def _parse_text(self, filename: str, text: str) -> Generator[dict, None, None]:
        lines = text.splitlines()
        for chunk_idx in range(0, max(1, len(lines)), CHUNK_LINES):
            chunk = "\n".join(lines[chunk_idx:chunk_idx + CHUNK_LINES])
            first_line = lines[chunk_idx].strip()[:120] if lines else ""
            yield self._file_event(
                filename,
                f"{filename} (lines {chunk_idx + 1}–{chunk_idx + CHUNK_LINES}): {first_line}",
                chunk,
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _looks_like_csv(self, text: str) -> bool:
        """Return True if the content looks like a CSV file (consistent comma-delimited rows)."""
        lines = [l for l in text.splitlines()[:6] if l.strip()]
        if len(lines) < 2:
            return False
        if ',' not in lines[0]:
            return False
        try:
            reader = csv.reader(lines)
            counts = [len(row) for row in reader]
            return len(counts) >= 2 and counts[0] > 1 and all(c == counts[0] for c in counts)
        except Exception:
            return False

    def _file_event(self, filename: str, message: str, content: str) -> dict:
        return {
            # No meaningful timestamp for raw file content — ingest_task falls
            # back to ingested_at so ES never receives an invalid date value.
            "timestamp":     None,
            "message":       message,
            "artifact_type": "file",
            "file": {
                "filename": filename,
                "content":  content,
            },
        }
