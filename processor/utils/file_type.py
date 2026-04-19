"""File type detection using python-magic with extension fallback."""
from __future__ import annotations

from pathlib import Path

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

EXTENSION_MIME_MAP = {
    ".evtx": "application/x-winevt",
    ".plaso": "application/x-sqlite3",
    ".pf": "application/x-prefetch",
    ".lnk": "application/x-ms-shortcut",
    ".dat": "application/octet-stream",
    ".hive": "application/octet-stream",
    ".reg": "text/plain",
    # fo-harvester specific
    ".wer":   "application/x-windows-wer",
    ".trace": "text/plain",             # AnyDesk/TeamViewer trace logs → syslog
    ".etl":   "application/octet-stream",  # ETW binary traces — strings fallback
}

FILENAME_MIME_MAP = {
    "$MFT": "application/x-ntfs-mft",
    "MFT": "application/x-ntfs-mft",
    "NTUSER.DAT": "application/x-registry",
    "SYSTEM": "application/x-registry",
    "SOFTWARE": "application/x-registry",
    "SAM": "application/x-registry",
    "SECURITY": "application/x-registry",
    # fo-harvester: well-known text files that would otherwise hit strings fallback
    "CONSOLEHOST_HISTORY.TXT": "text/plain",     # PowerShell command history → syslog
    "SETUPAPI.DEV.LOG":        "text/plain",     # USB device install log → syslog
    "SETUPAPI.SETUP.LOG":      "text/plain",     # USB setup log → syslog
    # fo-harvester: execution evidence + system logs
    "AMCACHE.HVE":        "application/x-registry",  # Execution evidence → registry plugin
    "SRUDB.DAT":          "application/x-sqlite3",   # SRUM database → browser/SQLite plugin
    "SRTTRAIL.TXT":       "text/plain",              # SFC scan log → syslog
    "CBS.LOG":            "text/plain",              # Component store log → syslog
    "WINDOWSUPDATE.LOG":  "text/plain",              # Windows Update log → syslog
}

# Artifact path-part → synthetic MIME type.
# Applied when a file's full path contains a specific directory component.
# This lets plugins identify artifact types that have no extension and no
# canonical MIME, relying solely on where they were collected from.
# Keys are lowercase directory names; values are the MIME assigned to any
# file whose path includes that directory component.
_PATH_PART_MIME_MAP: dict[str, str] = {
    "tasks":         "application/x-windows-task",   # persistence/tasks/... (Scheduled Task XML)
    "wifi_profiles": "application/x-wlan-profile",   # network_cfg/wifi_profiles/...
    "win_logs":      "text/plain",   # CBS.log, DISM.log, Panther logs → syslog
    "remote_access": "text/plain",   # AnyDesk traces, TeamViewer logs → syslog
    "antivirus":     "text/plain",   # Defender logs (non-evtx) → syslog
    # OneDrive sync-engine SQLite databases — bypass log2timeline (which exits 2 on these)
    "cloud_onedrive": "application/x-sqlite3",
}


def detect_mime(path: Path) -> str:
    """Detect MIME type using python-magic, falling back to extension/name lookup."""
    # 1. Check known filenames (highest priority — unambiguous mapping)
    upper_name = path.name.upper()
    if upper_name in FILENAME_MIME_MAP:
        return FILENAME_MIME_MAP[upper_name]

    # 2. Path-part based detection — for fo-harvester artifacts that carry no
    #    extension but whose directory context identifies them unambiguously.
    #    Only applied when the path has more than one component (i.e. the file
    #    arrived with directory context from a ZIP expansion).
    if len(path.parts) > 1:
        parts_lower = {p.lower() for p in path.parts}
        for part_key, part_mime in _PATH_PART_MIME_MAP.items():
            if part_key in parts_lower:
                return part_mime

    # 3. Use python-magic if available
    if MAGIC_AVAILABLE:
        try:
            mime = magic.from_file(str(path), mime=True)
            if mime and mime != "application/octet-stream":
                return mime
        except Exception:
            pass

    # 4. Fall back to extension lookup
    ext = path.suffix.lower()
    return EXTENSION_MIME_MAP.get(ext, "application/octet-stream")
