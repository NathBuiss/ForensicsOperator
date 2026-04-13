"""
Strings fallback plugin — last-resort handler for any file not matched by
a specific plugin. Extracts printable ASCII strings (≥6 chars) from the
raw bytes using a pure-Python regex scan.

Priority 1 — absolute lowest. Only selected when no other plugin claims the file.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

MIN_LEN   = 6
MAX_BYTES = 50 * 1024 * 1024   # 50 MB scan cap
MAX_STRINGS = 50_000            # safety cap on number of strings kept

_RE = re.compile(rb'[\x20-\x7e]{' + str(MIN_LEN).encode() + rb',}')


class StringsFallbackPlugin(BasePlugin):

    PLUGIN_NAME = "strings"
    PLUGIN_VERSION = "1.1.0"
    DEFAULT_ARTIFACT_TYPE = "strings"
    SUPPORTED_EXTENSIONS = []
    SUPPORTED_MIME_TYPES = []
    PLUGIN_PRIORITY = 1

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        return True   # catch-all — handles anything not claimed by another plugin

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        filename = fp.name

        try:
            data = fp.read_bytes()
        except Exception as exc:
            raise PluginFatalError(f"Cannot read file: {exc}")

        if len(data) > MAX_BYTES:
            data = data[:MAX_BYTES]

        strings = [
            m.group(0).decode("ascii", errors="replace")
            for m in _RE.finditer(data)
        ][:MAX_STRINGS]

        if not strings:
            return

        # All strings go into ONE event — keeps the file as a single timeline entry
        # and makes it unambiguous when feeding the file to analysis modules.
        content = "\n".join(strings)
        yield {
            "timestamp":     None,   # ingest_task falls back to ingested_at
            "message":       f"[{filename}] {strings[0][:120]}",
            "artifact_type": "strings",
            "strings": {
                "filename": filename,
                "content":  content,
                "count":    len(strings),
            },
        }
