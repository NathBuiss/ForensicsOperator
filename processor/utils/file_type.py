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
}

FILENAME_MIME_MAP = {
    "$MFT": "application/x-ntfs-mft",
    "MFT": "application/x-ntfs-mft",
    "NTUSER.DAT": "application/x-registry",
    "SYSTEM": "application/x-registry",
    "SOFTWARE": "application/x-registry",
    "SAM": "application/x-registry",
    "SECURITY": "application/x-registry",
}


def detect_mime(path: Path) -> str:
    """Detect MIME type using python-magic, falling back to extension/name lookup."""
    # Check known filenames first
    upper_name = path.name.upper()
    if upper_name in FILENAME_MIME_MAP:
        return FILENAME_MIME_MAP[upper_name]

    # Use python-magic if available
    if MAGIC_AVAILABLE:
        try:
            mime = magic.from_file(str(path), mime=True)
            if mime and mime != "application/octet-stream":
                return mime
        except Exception:
            pass

    # Fall back to extension lookup
    ext = path.suffix.lower()
    return EXTENSION_MIME_MAP.get(ext, "application/octet-stream")
