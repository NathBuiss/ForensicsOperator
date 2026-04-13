"""
Generic plist plugin — parses any Apple Property List (.plist) file.
Handles both XML and binary (bplist) formats using stdlib plistlib.

Each top-level key becomes a searchable event. Nested dicts/lists are
JSON-serialised into the value field so they remain searchable as text.

Priority 20 — runs after iOS plugin (default 50) so iOS-specific files
like Info.plist and WiFi plists are already claimed before this plugin
sees them.
"""
from __future__ import annotations

import json
import plistlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError


def _to_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, bytes):
        return f"<binary {len(val)} bytes>"
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.isoformat()
    if isinstance(val, (dict, list)):
        try:
            return json.dumps(val, default=str)
        except Exception:
            return str(val)
    return str(val)


class PlistPlugin(BasePlugin):

    PLUGIN_NAME = "plist"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "plist"
    SUPPORTED_EXTENSIONS = [".plist"]
    SUPPORTED_MIME_TYPES = []
    PLUGIN_PRIORITY = 20

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        try:
            with open(fp, "rb") as f:
                data = plistlib.load(f)
        except Exception as exc:
            raise PluginFatalError(f"Cannot parse plist: {exc}")

        filename = fp.name

        if isinstance(data, dict):
            for key, value in data.items():
                val_str = _to_str(value)
                yield {
                    "timestamp":      "",
                    "message":        f"{filename} | {key}: {val_str[:300]}",
                    "artifact_type":  "plist",
                    "plist": {
                        "filename": filename,
                        "key":      key,
                        "value":    val_str,
                    },
                }
        elif isinstance(data, list):
            for i, item in enumerate(data):
                val_str = _to_str(item)
                yield {
                    "timestamp":     "",
                    "message":       f"{filename}[{i}]: {val_str[:300]}",
                    "artifact_type": "plist",
                    "plist": {
                        "filename": filename,
                        "index":    i,
                        "value":    val_str,
                    },
                }
        else:
            val_str = _to_str(data)
            yield {
                "timestamp":     "",
                "message":       f"{filename}: {val_str[:300]}",
                "artifact_type": "plist",
                "plist": {
                    "filename": filename,
                    "value":    val_str,
                },
            }
