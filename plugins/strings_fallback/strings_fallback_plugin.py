"""
Strings fallback plugin — last-resort handler for any file not matched by
a specific plugin. Extracts printable ASCII strings (≥6 chars) from the
raw bytes using a pure-Python regex scan.

Priority 1 — absolute lowest. Only selected when no other plugin claims the file.
Sets artifact_type based on the file extension for better classification in the
timeline UI (e.g. "pe_binary", "pdf_document", "memory_dump") rather than the
generic "strings".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

MIN_LEN     = 6
MAX_BYTES   = 50 * 1024 * 1024   # 50 MB scan cap
MAX_STRINGS = 50_000             # safety cap

_RE = re.compile(rb'[\x20-\x7e]{' + str(MIN_LEN).encode() + rb',}')

# Extension → artifact_type for informative classification
_EXT_TYPE: dict[str, str] = {
    # PE / executables
    ".exe":  "pe_binary",
    ".dll":  "pe_binary",
    ".sys":  "pe_binary",
    ".drv":  "pe_binary",
    ".ocx":  "pe_binary",
    ".scr":  "pe_binary",
    ".cpl":  "pe_binary",
    # ELF / scripts
    ".elf":  "elf_binary",
    ".so":   "elf_binary",
    ".sh":   "shell_script",
    ".py":   "script",
    ".ps1":  "powershell_script",
    ".psm1": "powershell_script",
    ".bat":  "batch_script",
    ".cmd":  "batch_script",
    ".vbs":  "vbscript",
    ".js":   "script",
    # Office / documents
    ".docx": "office_document",
    ".xlsx": "office_document",
    ".pptx": "office_document",
    ".doc":  "office_document",
    ".xls":  "office_document",
    ".ppt":  "office_document",
    ".odt":  "office_document",
    ".pdf":  "pdf_document",
    # Memory / crash
    ".dmp":  "memory_dump",
    ".mdmp": "memory_dump",
    ".raw":  "memory_dump",
    # Disk images
    ".vmdk": "disk_image",
    ".vhd":  "disk_image",
    ".vhdx": "disk_image",
    ".iso":  "disk_image",
    # Archives
    ".zip":  "archive",
    ".7z":   "archive",
    ".rar":  "archive",
    ".tar":  "archive",
    ".gz":   "archive",
    # Databases / mailboxes
    ".db":   "database",
    ".sqlite": "database",
    ".pst":  "outlook_mailbox",
    ".ost":  "outlook_mailbox",
    ".kdbx": "keepass_db",
    ".mdb":  "database",
    ".ldb":  "database",
    # Network
    ".pcap": "pcap",
    ".pcapng": "pcap",
    # Config / VPN
    ".ovpn": "vpn_config",
    ".conf": "config_file",
    ".cfg":  "config_file",
    ".ini":  "config_file",
    ".xml":  "config_file",
    # Traces / ETW
    ".etl":  "etw_trace",
    ".log":  "log_file",
    ".txt":  "text_file",
    # Certificates
    ".cer":  "certificate",
    ".crt":  "certificate",
    ".pem":  "certificate",
    ".pfx":  "certificate",
    ".p12":  "certificate",
}


def _artifact_type(path: Path) -> str:
    return _EXT_TYPE.get(path.suffix.lower(), "binary_file")


class StringsFallbackPlugin(BasePlugin):

    PLUGIN_NAME = "strings"
    PLUGIN_VERSION = "1.2.0"
    DEFAULT_ARTIFACT_TYPE = "binary_file"
    SUPPORTED_EXTENSIONS = []
    SUPPORTED_MIME_TYPES = []
    PLUGIN_PRIORITY = 1

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        return True   # catch-all

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        filename = fp.name
        atype = _artifact_type(fp)

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

        content = "\n".join(strings)
        yield {
            "timestamp":     None,   # ingest_task falls back to ingested_at
            "message":       f"[{filename}] {strings[0][:120]}",
            "artifact_type": atype,
            "strings": {
                "filename": filename,
                "content":  content,
                "count":    len(strings),
                "ext_type": atype,
            },
        }
