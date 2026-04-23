"""
MFT Plugin — parses NTFS Master File Table ($MFT) files.
Requires: dissect.ntfs or mft (pip install mft)
Falls back to calling 'analyzeMFT.py' if available.
"""
from __future__ import annotations

import csv
import io
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

try:
    from mft import PyMftParser
    MFT_LIB_AVAILABLE = True
except ImportError:
    MFT_LIB_AVAILABLE = False


class MftPlugin(BasePlugin):

    PLUGIN_NAME = "mft"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "mft"
    SUPPORTED_EXTENSIONS = []
    SUPPORTED_MIME_TYPES = []

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return ["$MFT", "MFT"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        if MFT_LIB_AVAILABLE:
            yield from self._parse_with_lib()
        elif self._analyze_mft_available():
            yield from self._parse_with_analyzeMFT()
        else:
            raise PluginFatalError(
                "No MFT parser available. "
                "Install 'mft' (pip install mft) or 'analyzeMFT.py'."
            )

    def _parse_with_lib(self) -> Generator[dict[str, Any], None, None]:
        try:
            parser = PyMftParser(str(self.ctx.source_file_path))
        except Exception as exc:
            raise PluginFatalError(f"Cannot open MFT: {exc}") from exc

        for entry in parser:
            try:
                if entry is None:
                    continue

                is_dir = entry.is_dir()
                is_deleted = not entry.is_allocated()
                record_num = entry.entry_id

                filename = ""
                filepath = ""
                created = ""
                modified = ""
                accessed = ""
                mft_modified = ""
                file_size = 0

                for attr in entry.attributes():
                    if hasattr(attr, "filename"):
                        fn = attr.filename
                        if fn:
                            filename = str(fn.name) if hasattr(fn, "name") else str(fn)
                    if hasattr(attr, "si_timestamps"):
                        si = attr.si_timestamps
                        if si:
                            created = self._ts(si.created)
                            modified = self._ts(si.modified)
                            accessed = self._ts(si.accessed)
                            mft_modified = self._ts(si.mft_modified)
                    if hasattr(attr, "data_size"):
                        file_size = attr.data_size or 0

                timestamp = modified or created or ""
                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "mft",
                    "timestamp": timestamp,
                    "timestamp_desc": "MFT Modified",
                    "message": f"{'[DIR]' if is_dir else '[FILE]'} "
                               f"{'[DELETED]' if is_deleted else ''} "
                               f"{filename}",
                    "mft": {
                        "mft_record_number": record_num,
                        "filename": filename,
                        "filepath": filepath,
                        "file_size": file_size,
                        "is_directory": is_dir,
                        "is_deleted": is_deleted,
                        "created_at": created,
                        "modified_at": modified,
                        "accessed_at": accessed,
                        "mft_modified_at": mft_modified,
                    },
                    "raw": {},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipped MFT entry: %s", exc)

    def _analyze_mft_available(self) -> bool:
        try:
            r = subprocess.run(["analyzeMFT.py", "--help"], capture_output=True, timeout=5)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _parse_with_analyzeMFT(self) -> Generator[dict[str, Any], None, None]:
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            subprocess.run(
                ["analyzeMFT.py", "-f", str(self.ctx.source_file_path), "-o", tmp_path],
                check=True, capture_output=True, timeout=600
            )
        except subprocess.CalledProcessError as exc:
            raise PluginFatalError(f"analyzeMFT.py failed: {exc}") from exc

        with open(tmp_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    self._records_read += 1
                    is_deleted = "deleted" in row.get("Active/Deleted", "").lower()
                    is_dir = row.get("Type", "") == "Directory"
                    fname = row.get("Filename", "")
                    fpath = row.get("Full Path", fname)
                    created = row.get("$SI [M]", "")
                    modified = row.get("$SI [A]", "")
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "mft",
                        "timestamp": modified or created or None,
                        "timestamp_desc": "MFT Modified",
                        "message": f"{'[DIR]' if is_dir else '[FILE]'} "
                                   f"{'[DELETED]' if is_deleted else ''} {fname}",
                        "mft": {
                            "mft_record_number": int(row.get("Record Number", 0) or 0),
                            "filename": fname,
                            "filepath": fpath,
                            "is_directory": is_dir,
                            "is_deleted": is_deleted,
                            "created_at": created,
                            "modified_at": modified,
                        },
                        "raw": dict(row),
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped CSV row: %s", exc)

        Path(tmp_path).unlink(missing_ok=True)

    def _ts(self, val: Any) -> str:
        if val is None:
            return ""
        try:
            return str(val)
        except Exception:
            return ""

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }
