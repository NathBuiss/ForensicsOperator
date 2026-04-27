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
    "C_MFT": "application/x-ntfs-mft",
    "C_MFT.BAK": "application/x-ntfs-mft",
    # CSV scanner logs without extension (fo-harvester output)
    "BASICINFOSCANNERLOGS": "text/csv",
    "SHELLBAGSSCANNERLOGS": "text/csv",
    "NTUSER.DAT": "application/x-registry",
    "SYSTEM": "application/x-registry",
    "SOFTWARE": "application/x-registry",
    "SAM": "application/x-registry",
    "SECURITY": "application/x-registry",
    # Shell command history — claimed by shell_history_plugin (priority 110)
    ".BASH_HISTORY":           "text/x-shell-history",
    ".ZSH_HISTORY":            "text/x-shell-history",
    ".HISTORY":                "text/x-shell-history",
    "FISH_HISTORY":            "text/x-shell-history",
    "CONSOLEHOST_HISTORY.TXT": "text/x-shell-history",  # PowerShell history
    # USB device install logs → syslog
    "SETUPAPI.DEV.LOG":        "text/plain",
    "SETUPAPI.SETUP.LOG":      "text/plain",
    # Execution evidence + system logs
    "AMCACHE.HVE":        "application/x-registry",  # registry plugin
    "SRUDB.DAT":          "application/x-sqlite3",   # browser/SQLite plugin
    "SRTTRAIL.TXT":       "text/plain",              # syslog
    "CBS.LOG":            "text/plain",              # syslog
    "WINDOWSUPDATE.LOG":  "text/plain",              # syslog
    # Windows triage output files → windows_triage plugin (priority 115)
    "SYSTEMINFO.TXT":         "text/x-windows-triage",
    "NETSTAT.TXT":            "text/x-windows-triage",
    "TASKLIST.TXT":           "text/x-windows-triage",
    "SERVICES.TXT":           "text/x-windows-triage",
    "INSTALLED_SOFTWARE.TXT": "text/x-windows-triage",
    "STARTUP_ITEMS.TXT":      "text/x-windows-triage",
    "PFIREWALL.LOG":          "text/x-windows-triage",
    # Linux/macOS system config files → linux_config plugin (priority 120)
    "PASSWD":           "text/x-unix-config",
    "SHADOW":           "text/x-unix-config",
    "GROUP":            "text/x-unix-config",
    "GSHADOW":          "text/x-unix-config",
    "HOSTS":            "text/x-unix-config",
    "SUDOERS":          "text/x-unix-config",
    "AUTHORIZED_KEYS":  "text/x-unix-config",
    "AUTHORIZED_KEYS2": "text/x-unix-config",
    "KNOWN_HOSTS":      "text/x-unix-config",
    "SSHD_CONFIG":      "text/x-unix-config",
    "SSH_CONFIG":       "text/x-unix-config",
    "CRONTAB":          "text/x-crontab",
}

# Artifact path-part → synthetic MIME type.
# Applied when a file's full path contains a specific directory component.
# This lets plugins identify artifact types that have no extension and no
# canonical MIME, relying solely on where they were collected from.
# Keys are lowercase directory names; values are the MIME assigned to any
# file whose path includes that directory component.
_PATH_PART_MIME_MAP: dict[str, str] = {
    "tasks":            "application/x-windows-task",   # persistence/tasks/... → scheduled_task plugin
    "scheduled_tasks":  "application/x-windows-task",   # fo-harvester uses scheduled_tasks/ as dir name
    "wifi_profiles": "application/x-wlan-profile",   # network_cfg/wifi_profiles/ → wlan_profile plugin
    "win_logs":      "text/plain",   # CBS.log, DISM.log, Panther logs → syslog
    "remote_access": "text/plain",   # AnyDesk traces, TeamViewer logs → syslog
    "antivirus":     "text/plain",   # Defender logs (non-evtx) → syslog
    # Shell history directories — force shell_history MIME so syslog_plugin doesn't claim them
    "shell_history": "text/x-shell-history",
    # OneDrive SQLite — bypass log2timeline (which exits 2 on these)
    "cloud_onedrive": "application/x-sqlite3",
    # Windows triage output directory → windows_triage plugin (priority 115)
    "triage":     "text/x-windows-triage",  # fo-harvester triage/ output folder
    # Linux/macOS config directories → linux_config plugin (priority 120)
    "cron.d":     "text/x-crontab",   # /etc/cron.d/* system cron jobs
    "crontabs":   "text/x-crontab",   # /var/spool/cron/crontabs/* user crontabs
    # SSH artifacts directory — force unix-config MIME so syslog doesn't eat them
    "ssh":        "text/x-unix-config",  # .ssh/authorized_keys, known_hosts, config
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
