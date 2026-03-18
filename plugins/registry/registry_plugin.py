"""
Registry Plugin — parses Windows Registry hive files (NTUSER.DAT, SYSTEM, SAM, etc.).
Requires: python-registry (pip install python-registry)
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

try:
    from Registry import Registry
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False

HIVE_FILENAMES = {
    "NTUSER.DAT", "USRCLASS.DAT", "SYSTEM", "SOFTWARE",
    "SAM", "SECURITY", "DEFAULT", "COMPONENTS",
}


class RegistryPlugin(BasePlugin):

    PLUGIN_NAME = "registry"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "registry"
    SUPPORTED_EXTENSIONS = [".dat", ".hive"]
    SUPPORTED_MIME_TYPES = ["application/octet-stream"]

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(HIVE_FILENAMES)

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def setup(self) -> None:
        if not REGISTRY_AVAILABLE:
            raise PluginFatalError(
                "python-registry is not installed. Run: pip install python-registry"
            )

    def parse(self) -> Generator[dict[str, Any], None, None]:
        try:
            reg = Registry.Registry(str(self.ctx.source_file_path))
        except Exception as exc:
            raise PluginFatalError(f"Cannot open registry hive: {exc}") from exc

        yield from self._walk_key(reg.root(), "")

    def _walk_key(
        self, key: Any, path: str
    ) -> Generator[dict[str, Any], None, None]:
        full_path = f"{path}\\{key.name()}" if path else key.name()

        try:
            timestamp = key.timestamp().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        except Exception:
            timestamp = ""

        values = {}
        for val in key.values():
            try:
                values[val.name() or "(Default)"] = {
                    "type": val.value_type_str(),
                    "data": str(val.value())[:4096],
                }
            except Exception:
                pass

        if values:
            self._records_read += 1
            yield {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "registry",
                "timestamp": timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message": f"Registry key: {full_path}",
                "registry": {
                    "key_path": full_path,
                    "key_name": key.name(),
                    "last_write_time": timestamp,
                    "subkey_count": key.number_of_subkeys(),
                    "value_count": key.number_of_values(),
                    "values": values,
                },
                "raw": {},
            }

        for subkey in key.subkeys():
            try:
                yield from self._walk_key(subkey, full_path)
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipped subkey %s: %s", full_path, exc)

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }
