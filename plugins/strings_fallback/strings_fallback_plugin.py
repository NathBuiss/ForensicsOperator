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
MAX_BYTES = 10 * 1024 * 1024   # 10 MB cap
BATCH     = 150                 # strings per event

_RE = re.compile(rb'[\x20-\x7e]{' + str(MIN_LEN).encode() + rb',}')


class StringsFallbackPlugin(BasePlugin):

    PLUGIN_NAME = "strings"
    PLUGIN_VERSION = "1.0.0"
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

        strings = [m.group(0).decode("ascii", errors="replace") for m in _RE.finditer(data)]

        if not strings:
            return

        for i in range(0, len(strings), BATCH):
            batch = strings[i:i + BATCH]
            content = "\n".join(batch)
            yield {
                "timestamp":     None,   # ingest_task falls back to ingested_at
                "message":       f"[{filename}] {batch[0][:120]}",
                "artifact_type": "strings",
                "strings": {
                    "filename":     filename,
                    "content":      content,
                    "count":        len(batch),
                    "batch_offset": i // BATCH,
                },
            }
