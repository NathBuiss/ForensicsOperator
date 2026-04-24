#!/usr/bin/env python3
"""
TraceX Artifact Collector
==========================
Collect forensic artifacts from a live Windows or Linux system and package
them as a timestamped ZIP archive, then optionally upload directly to a case.

Usage
-----
  tracex-collector                                               # collect everything (live OS)
  tracex-collector --collect evtx,registry,prefetch              # selective collection
  tracex-collector --path /mnt/evidence                          # dead-box: mounted directory
  tracex-collector --disk /dev/sdb1 --bitlocker-key 123456-...  # dead-box: raw device (Linux)
  tracex-collector --api-url http://TRACEX/api/v1 --case-id XYZ # upload to case
  tracex-collector --output /tmp/evidence.zip                    # custom output path
  tracex-collector --dry-run --verbose                           # preview only

Build
-----
  Linux ELF:   ./build.sh        → dist/tracex-collector
  Windows EXE: build.bat         → dist\\tracex-collector.exe
"""
from __future__ import annotations

# ── Embedded configuration (injected by TraceX at download time) ─────────────
# When non-empty, these values are used as defaults and can still be overridden
# by CLI arguments.
EMBEDDED_CONFIG: dict = {}

# ─────────────────────────────────────────────────────────────────────────────

import argparse
import datetime
import json
import io
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

# ── Load config.json when EMBEDDED_CONFIG was not injected ───────────────────
# ForensicsOperator package mode: config.json ships next to this script.
# Format: {artifact_key: true/false, output_dir: "path"}
# Mode, input source, and BitLocker key are CLI arguments — not stored here.
if not EMBEDDED_CONFIG:
    _cfg_path = Path(__file__).with_name("config.json")
    if _cfg_path.exists():
        try:
            _raw = json.loads(_cfg_path.read_text("utf-8"))
            # Accept only known category keys with boolean True — safe against
            # old-format config files that have string/list values.
            _known_cats = {
                "evtx", "registry", "prefetch", "mft", "execution", "persistence",
                "filesystem", "network_cfg", "usb_devices", "credentials", "antivirus",
                "wer_crashes", "win_logs", "boot_uefi", "encryption", "etw_diagnostics",
                "browser", "browser_chrome", "browser_edge", "browser_ie",
                "email_outlook", "email_thunderbird", "teams", "slack", "discord",
                "signal", "whatsapp", "telegram", "cloud_onedrive", "cloud_google_drive",
                "cloud_dropbox", "remote_access", "rdp", "ssh_ftp", "lnk", "tasks",
                "office", "dev_tools", "password_managers", "database_clients", "gaming",
                "windows_apps", "wsl", "vpn", "iis_web", "active_directory",
                "virtualization", "recovery", "printing", "pe", "documents", "memory_artifacts",
            }
            EMBEDDED_CONFIG = {
                "collect":    [k for k, v in _raw.items() if k in _known_cats and v is True],
                "output_dir": _raw.get("output_dir", "./output"),
                "case_name":  _raw.get("case_name", ""),
            }
        except Exception as _cfg_err:
            print(f"  [!] Warning: could not read config.json: {_cfg_err}", file=sys.stderr)

VERSION  = "1.1.0"
HOSTNAME = socket.gethostname()
TS_NOW   = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MACOS   = platform.system() == "Darwin"

BANNER = f"""
╔══════════════════════════════════════════════════════════════╗
║         ForensicsOperator Harvester  v{VERSION}                    ║
╚══════════════════════════════════════════════════════════════╝"""

_HR = "  " + "─" * 62  # section separator line

# Default collection sets — all enabled when nothing is specified
DEFAULT_WINDOWS = {"evtx", "registry", "prefetch", "lnk", "browser", "tasks", "mft", "triage"}
DEFAULT_LINUX   = {"logs", "history", "config", "cron", "ssh", "triage", "network", "suricata", "zeek"}
DEFAULT_MACOS   = {"logs", "history", "config", "launchagents", "browser", "plist", "triage", "network"}
# "pe" and "documents" are opt-in — they can be large and broad in scope.
# Add explicitly: --collect pe,documents,evtx
# "memory" is intentionally NOT in the defaults — dumps are multi-GB.
# Add explicitly with --collect memory or --collect memory,evtx,...

# Human-readable names (used in the header printout)
ARTIFACT_LABELS = {
    # ── Live Windows ──────────────────────────────────────────────────────────
    "evtx":              "Event Logs (EVTX)",
    "registry":          "Registry Hives",
    "prefetch":          "Prefetch Files",
    "lnk":               "LNK / Recent Items",
    "browser":           "Browser Artifacts (all)",
    "tasks":             "Scheduled Tasks",
    "mft":               "Master File Table ($MFT)",
    "pe":                "PE / Executable Binaries",
    "documents":         "Office Documents & PDFs",
    "triage":            "System Triage (live)",
    # ── Dead-box / ForensicHarvester categories ───────────────────────────────
    "execution":         "Execution Evidence (SRUM, Amcache, Prefetch)",
    "persistence":       "Persistence (Tasks, WMI)",
    "network_cfg":       "Network Config (Hosts, WLAN, Firewall)",
    "usb_devices":       "USB Device History",
    "credentials":       "Credentials (DPAPI, Credential Manager)",
    "antivirus":         "Antivirus / Windows Defender",
    "wer_crashes":       "WER Crash Dumps & Reports",
    "filesystem":        "NTFS Metadata ($MFT, $LogFile, $Boot)",
    "browser_chrome":    "Chrome Browser Artifacts",
    "browser_firefox":   "Firefox Browser Artifacts",
    "browser_edge":      "Edge Browser Artifacts",
    "browser_ie":        "Internet Explorer WebCache",
    "email_outlook":     "Outlook Email (.pst / .ost)",
    "email_thunderbird":  "Thunderbird Email",
    "teams":             "Microsoft Teams",
    "slack":             "Slack",
    "discord":           "Discord",
    "signal":            "Signal Desktop",
    "whatsapp":          "WhatsApp Desktop",
    "telegram":          "Telegram Desktop",
    "cloud_onedrive":    "OneDrive Sync Artifacts",
    "cloud_google_drive":"Google Drive Sync Artifacts",
    "cloud_dropbox":     "Dropbox Sync Artifacts",
    "remote_access":     "Remote Access (AnyDesk, TeamViewer)",
    "rdp":               "RDP / Terminal Services",
    "ssh_ftp":           "SSH / FTP Clients (PuTTY, WinSCP)",
    "office":            "Office MRU / Trusted Documents",
    "iis_web":           "IIS Web Server Logs",
    "active_directory":  "Active Directory (NTDS.dit, SYSVOL)",
    "dev_tools":         "Dev Tools (.gitconfig, PS history, .aws)",
    "password_managers": "Password Managers (KeePass)",
    "vpn":               "VPN Config (OpenVPN, WireGuard)",
    "encryption":        "Encryption Metadata (BitLocker / EFS)",
    "boot_uefi":         "Boot Config (BCD, EFI)",
    "win_logs":          "Windows Logs (CBS, DISM, WU)",
    "memory_artifacts":  "Memory Artifacts (pagefile, hiberfil)",
    "etw_diagnostics":   "ETW Diagnostic Traces",
    "windows_apps":      "Windows UWP / Modern Apps",
    "wsl":               "WSL Filesystem & Config",
    "virtualization":    "Virtualization (Hyper-V, Docker)",
    "recovery":          "Recovery (VSS, Windows.old)",
    "database_clients":  "Database Clients (SSMS, DBeaver)",
    "gaming":            "Gaming Platforms (Steam, Epic)",
    "printing":          "Print Spool Files",
    # ── Linux / macOS ────────────────────────────────────────────────────────
    "logs":         "System Logs",
    "history":      "Shell Histories",
    "config":       "System Configuration",
    "cron":         "Cron Jobs",
    "ssh":          "SSH Artifacts",
    "launchagents": "Launch Agents / Daemons",
    "plist":        "macOS Preference Plists",
    "network":      "PCAP / Network Captures",
    "suricata":     "Suricata IDS Logs (EVE JSON)",
    "zeek":         "Zeek / Bro Network Logs",
    "memory":       "Physical Memory Dump (live acquisition)",
    "external_disk": "External / BitLocker Disk Triage",
}


# ─────────────────────────────────────────────────────────────────────────────
# Base Collector
# ─────────────────────────────────────────────────────────────────────────────

class Collector:
    def __init__(
        self,
        output: Path,
        collect: set[str],
        verbose: bool = False,
        dry_run: bool = False,
        skip_problematic: bool = False,
    ):
        self.output   = output
        self.collect  = collect
        self.verbose  = verbose
        self.dry_run  = dry_run
        self.skip_problematic = skip_problematic
        self.staging  = Path(tempfile.mkdtemp(prefix="fo_collect_"))
        self._items: list[tuple[str, Path]] = []
        self._errors: list[str] = []
        self._seen_arcnames: set[str] = set()   # duplicate path guard
        # Progress / results tracking
        self._results: list[dict]  = []
        self._total_cats: int      = 0
        self._current_cat: int     = 0

    def _want(self, key: str) -> bool:
        return key in self.collect

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"      {msg}")

    def _warn(self, msg: str) -> None:
        self._errors.append(msg)
        # Buffered during _timed(); written directly otherwise.
        print(f"  [!] {msg}", file=sys.stderr)

    def _check_deadbox_mode(self) -> dict:
        """
        Check if running in dead-box directory mode and warn about limitations.
        Returns a dict of problematic categories and reasons.
        """
        warnings = {}
        
        # Check if we're accessing a mounted filesystem (not live OS)
        is_deadbox = False
        if hasattr(self, 'disk') and getattr(self, 'disk', None):
            is_deadbox = True
        elif IS_WINDOWS:
            # Check if SystemDrive is different from C: or path looks like mount
            sys_drive = os.environ.get("SystemDrive", "C:")
            if sys_drive != "C:" or (hasattr(self, '_ntfs_dir') and getattr(self, '_ntfs_dir', None)):
                is_deadbox = True
        
        if not is_deadbox:
            return warnings
        
        # Categories that typically fail in dead-box directory mode
        DEADBOX_LIMITATIONS = {
            "mft": "$MFT requires raw volume access (\\\\.\\C:) - not available in directory mount mode",
            "filesystem": "NTFS metadata ($MFT, $Boot, $LogFile) requires raw volume handle",
            "prefetch": "Prefetch files may be WOF-compressed (Win10+) or have reparse points",
            "tasks": "C:\\Windows\\System32\\Tasks often contains reparse points",
            "browser_ie": "WebCache directories frequently use reparse points",
            "memory_artifacts": "pagefile.sys and hiberfil.sys are locked by the OS",
        }
        
        for cat, reason in DEADBOX_LIMITATIONS.items():
            if cat in self.collect:
                warnings[cat] = reason
        
        return warnings

    def _add(self, src: Path, arcname: str) -> bool:
        arcname = arcname.replace("\\", "/")
        if not src.exists() or not src.is_file():
            self._log(f"missing  {src}")
            return False
        try:
            size = src.stat().st_size
        except OSError as exc:
            self._warn(f"stat failed {src.name}: {exc}")
            return False
        if size == 0:
            self._log(f"empty    {src.name}")
            return False
        # Deduplicate arcnames — same relative path can appear for multiple users
        if arcname in self._seen_arcnames:
            if "." in arcname.split("/")[-1]:
                stem, ext = arcname.rsplit(".", 1)
            else:
                stem, ext = arcname, ""
            n = 2
            while True:
                candidate = f"{stem}_{n}.{ext}" if ext else f"{stem}_{n}"
                if candidate not in self._seen_arcnames:
                    arcname = candidate
                    break
                n += 1
        self._seen_arcnames.add(arcname)
        self._items.append((arcname, src))
        self._log(f"ok  ({size:>11,} B)  {arcname}")
        return True

    # ── Per-category progress tracking ───────────────────────────────────────

    @contextmanager
    def _timed(self, key: str, label: str):
        """
        Context manager that wraps a single artifact-category collection call.
        • Prints a live 'collecting…' placeholder on stdout.
        • Suppresses the [*] section-header that _from() methods print.
        • Buffers stderr (warnings) so they don't interleave with the status line.
        • On exit: overwrites the placeholder with a result line (files / time / ✓✗).
        • Appends a result dict to self._results for the final summary.
        """
        self._current_cat += 1
        idx   = self._current_cat
        total = self._total_cats or "?"
        pad   = f"{label:<44}"
        pfx   = f"  [{idx:>2}/{total}]  {pad}"

        items_before  = len(self._items)
        errors_before = len(self._errors)
        t0 = time.monotonic()

        # Live placeholder — overwritten by the result line on exit
        sys.stdout.write(f"{pfx}  collecting…\r")
        sys.stdout.flush()

        # ── stdout filter: swallow "  [*] …" lines emitted by _from() methods ──
        class _FilterOut:
            def __init__(self, w):
                self._w = w
                self._skip_nl = False
            def write(self, txt):
                if "  [*]" in txt:
                    self._skip_nl = True
                    return
                if self._skip_nl and txt in ("\n", "\r\n", "\r"):
                    self._skip_nl = False
                    return
                self._skip_nl = False
                self._w.write(txt)
            def flush(self):        self._w.flush()
            def __getattr__(self, n): return getattr(self._w, n)

        # ── stderr capture: keep warnings from interleaving with status lines ──
        class _BufErr:
            def __init__(self):
                self._buf = io.StringIO()
            def write(self, txt):   self._buf.write(txt)
            def flush(self):        pass
            def getvalue(self):     return self._buf.getvalue()
            def __getattr__(self, n): return getattr(sys.__stderr__, n)

        orig_out = sys.stdout
        orig_err = sys.stderr
        ferr = _BufErr()
        sys.stdout = _FilterOut(orig_out)
        sys.stderr = ferr
        try:
            yield
        finally:
            sys.stdout = orig_out
            sys.stderr = orig_err

            elapsed = time.monotonic() - t0
            added   = len(self._items) - items_before
            new_errs = self._errors[errors_before:]
            ok   = added > 0
            mark = "✓" if ok else "✗"
            stat = f"  {added:>5} files  {elapsed:>5.1f}s  {mark}"
            if not ok and new_errs:
                stat += f"  ({new_errs[0][:36]})"
            print(f"{pfx}{stat}")

            # Flush captured warnings in verbose mode only
            if self.verbose:
                captured = ferr.getvalue()
                if captured:
                    sys.stderr.write(captured)

            self._results.append({
                "label":    label,
                "files":    added,
                "duration": elapsed,
                "ok":       ok,
                "errors":   list(new_errs),
            })

    def _run_cat(self, key: str, fn, *args) -> None:
        """Run fn(*args) inside a _timed() context if the category is wanted."""
        if self._want(key):
            label = ARTIFACT_LABELS.get(key, key)
            with self._timed(key, label):
                try:
                    fn(*args)
                except Exception as exc:
                    self._warn(f"Collection error in '{key}': {exc}")

    def _copy_locked(self, src: Path, dest: Path) -> bool:
        """
        Copy a file that may be locked (browser databases, Event Logs).
        
        Cross-platform: works on Windows, Linux, macOS.
        On live Windows: uses robocopy for WOF compression.
        On mounted drives: uses binary I/O to avoid timeouts.
        """
        if not src.exists() or not src.is_file():
            return False
        
        dest.parent.mkdir(parents=True, exist_ok=True)
        
        # Method 1: Binary read/write (most reliable, cross-platform)
        try:
            with open(src, 'rb') as fsrc:
                with open(dest, 'wb') as fdst:
                    shutil.copyfileobj(fsrc, fdst, length=1024*1024)
            if dest.exists() and dest.stat().st_size > 0:
                return True
        except Exception:
            pass
        
        # Clean up
        try:
            if dest.exists() and dest.stat().st_size == 0:
                dest.unlink()
        except Exception:
            pass
        
        # Windows: try robocopy for WOF (live Windows only, not mounted)
        if IS_WINDOWS and not self._is_mounted_drive(src):
            if self._copy_with_robocopy(src, dest):
                return True
            try:
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()
            except Exception:
                pass
        
        # Windows: cmd copy fallback
        if IS_WINDOWS:
            try:
                r = subprocess.run(
                    ["cmd", "/c", "copy", "/B", "/Y", str(src), str(dest)],
                    capture_output=True, timeout=10,
                )
                if r.returncode == 0 and dest.exists() and dest.stat().st_size > 0:
                    return True
            except Exception:
                pass
            
            try:
                dest.unlink(missing_ok=True)
            except Exception:
                pass
        
        return False
        
        dest.parent.mkdir(parents=True, exist_ok=True)
        
        # Try direct copy first
        try:
            shutil.copy2(str(src), str(dest))
            if dest.exists() and dest.stat().st_size > 0:
                return True
        except Exception:
            pass
        
        # Clean up partial copy
        try:
            if dest.exists() and dest.stat().st_size == 0:
                dest.unlink()
        except Exception:
            pass
        
        if not IS_WINDOWS:
            return False
        
        # Try cmd copy (handles some locked files) - don't capture to avoid deadlock
        try:
            r = subprocess.run(
                ["cmd", "/c", "copy", "/B", "/Y", str(src), str(dest)],
                timeout=30,
            )
            if r.returncode == 0 and dest.exists() and dest.stat().st_size > 0:
                return True
        except Exception:
            pass
        
        # Clean up
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        
        return False

    def _is_mounted_drive(self, path: Path) -> bool:
        """
        Detect if path is a mounted drive (dead-box) vs live Windows.
        Returns True for mounted drives where robocopy causes timeouts.
        """
        if not IS_WINDOWS:
            return True  # Non-Windows is always mounted
        
        # Extract drive letter
        drive = str(path)[:2].upper()
        if len(drive) != 2 or drive[1] != ':':
            return True  # Not a drive letter path
        
        # C: is always live (system drive)
        if drive == "C:":
            return False
        
        # Check drive type - NETWORK/UNKNOWN = mounted
        try:
            import ctypes
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\")
            # DRIVE_REMOTE = 4 (network), DRIVE_NO_ROOT_DIR = 0 (invalid)
            # DRIVE_FIXED = 3 (local hard drive)
            if drive_type in (0, 4):
                return True  # Network/invalid = mounted
        except Exception:
            # If we can't check, assume non-C: drives are mounted
            return True
        
        # For fixed drives other than C:, check if it's the system drive
        sys_drive = os.environ.get("SystemDrive", "C:").upper()
        return drive != sys_drive

    def _copy_with_robocopy(self, src: Path, dest: Path) -> bool:
        """
        Use robocopy for WOF-compressed files (Windows 10+ Prefetch).
        ONLY used on live Windows - skipped for mounted drives (causes timeouts).
        """
        if not IS_WINDOWS or not src.exists():
            return False
        
        # Skip robocopy for mounted drives (causes semaphore timeouts)
        if self._is_mounted_drive(src):
            self._log(f"Skipping robocopy for mounted drive: {src.name}")
            return False
        
        try:
            r = subprocess.run(
                ["robocopy", str(src.parent), str(dest.parent), str(src.name), 
                 "/NJH", "/NJS", "/NDL", "/NFL", "/BYTES", "/R:0", "/W:0"],
                capture_output=True, timeout=30,
            )
            # robocopy returns 0-7 for success, 8+ for errors
            return r.returncode <= 7 and dest.exists() and dest.stat().st_size > 0
        except Exception:
            return False

    def _stage_file(self, src: Path, dest: Path) -> bool:
        """
        Copy src to dest for staging with smart fallback strategy.
        
        Cross-platform: works on Windows, Linux, macOS.
        Handles WOF compression on live Windows, avoids timeouts on mounted drives.
        """
        if not src.exists() or not src.is_file():
            return False
        
        try:
            src_size = src.stat().st_size
            if src_size == 0:
                return False
        except OSError:
            return False
        
        dest.parent.mkdir(parents=True, exist_ok=True)
        
        # Method 1: Simple binary read/write (cross-platform, most reliable)
        try:
            with open(src, 'rb') as fsrc:
                with open(dest, 'wb') as fdst:
                    shutil.copyfileobj(fsrc, fdst, length=1024*1024)  # 1MB chunks
            if dest.exists() and dest.stat().st_size > 0:
                return True
        except (PermissionError, OSError) as exc:
            self._log(f"read/write failed: {src.name} - {exc.errno if hasattr(exc, 'errno') else exc}")
        except Exception as exc:
            self._log(f"read/write failed: {src.name} - {exc}")
        
        # Clean up partial copy
        try:
            if dest.exists() and dest.stat().st_size == 0:
                dest.unlink()
        except Exception:
            pass
        
        # Windows-only: try robocopy for WOF compression (live Windows only)
        if IS_WINDOWS and not self._is_mounted_drive(src):
            if self._copy_with_robocopy(src, dest):
                return True
            # Clean up failed robocopy attempt
            try:
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()
            except Exception:
                pass
        
        # Windows-only: cmd /c copy fallback for locked files
        if IS_WINDOWS:
            try:
                r = subprocess.run(
                    ["cmd", "/c", "copy", "/B", "/Y", str(src), str(dest)],
                    capture_output=True, timeout=10,
                )
                if r.returncode == 0 and dest.exists() and dest.stat().st_size > 0:
                    return True
            except Exception:
                pass
            
            # Clean up
            try:
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()
            except Exception:
                pass
        
        return False

    def _run_cmd(self, cmd: list[str], timeout: int = 30) -> str:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, errors="replace",
            )
            return r.stdout
        except Exception as exc:
            self._log(f"cmd failed {cmd[0]}: {exc}")
            return ""

    def _write_text(self, filename: str, content: str, arcname: str) -> None:
        dest = self.staging / filename
        try:
            dest.write_text(content, encoding="utf-8", errors="replace")
            self._add(dest, arcname)
        except Exception as exc:
            self._warn(f"Could not write {filename}: {exc}")

    def collect_all(self) -> None:
        raise NotImplementedError

    def package(self) -> None:
        n = len(self._items)
        BAR_W = 44
        t0 = time.monotonic()

        print(f"\n{_HR}")
        print(f"  Packaging")
        print(_HR)
        print(f"\n  {n} file{'s' if n != 1 else ''} → {self.output.name}\n")

        self.output.parent.mkdir(parents=True, exist_ok=True)
        last_bar = ""
        with zipfile.ZipFile(str(self.output), "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for i, (arcname, path) in enumerate(self._items, 1):
                try:
                    zf.write(str(path), arcname)
                except Exception as exc:
                    self._warn(f"Archive failed for {arcname}: {exc}")
                filled = int(BAR_W * i / n) if n else BAR_W
                last_bar = "█" * filled + "░" * (BAR_W - filled)
                sys.stdout.write(f"\r  [{last_bar}] {i}/{n}  ")
                sys.stdout.flush()

        elapsed = time.monotonic() - t0
        size_mb = self.output.stat().st_size / (1024 * 1024)
        print(f"\r  [{'█' * BAR_W}] {n}/{n}  done          ")
        print(f"\n  Archive  : {self.output}")
        print(f"  Size     : {size_mb:.1f} MB")
        print(f"  Packed   : {elapsed:.1f}s")

    def cleanup(self) -> None:
        shutil.rmtree(self.staging, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Windows Collector
# ─────────────────────────────────────────────────────────────────────────────

class WindowsCollector(Collector):

    def collect_all(self) -> None:
        self._total_cats = len(self.collect)
        self._run_cat("evtx",      self._evtx)
        self._run_cat("registry",  self._registry)
        self._run_cat("prefetch",  self._prefetch)
        self._run_cat("lnk",       self._lnk)
        self._run_cat("browser",   self._browser)
        self._run_cat("tasks",     self._scheduled_tasks)
        self._run_cat("mft",       self._mft)
        self._run_cat("pe",        self._pe_binaries)
        self._run_cat("documents", self._documents)
        self._run_cat("triage",    self._system_triage)
        # "memory" removed: winpmem requires elevation; System Volume Information
        # access is denied on live systems. Use --collect memory explicitly.

    def _evtx(self) -> None:
        print("  [*] Event Logs (EVTX)")
        evtx_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "winevt" / "Logs"
        if not evtx_dir.exists():
            self._warn(f"EVTX directory not found: {evtx_dir}")
            return
        priority = [
            "Security.evtx", "System.evtx", "Application.evtx",
            "Microsoft-Windows-PowerShell%4Operational.evtx",
            "Microsoft-Windows-Sysmon%4Operational.evtx",
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            "Microsoft-Windows-TaskScheduler%4Operational.evtx",
            "Microsoft-Windows-WinRM%4Operational.evtx",
            "Microsoft-Windows-WindowsDefender%4Operational.evtx",
            "Microsoft-Windows-Bits-Client%4Operational.evtx",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
        ]
        seen: set[str] = set()
        for name in priority:
            src = evtx_dir / name
            try:
                if not src.is_file() or src.stat().st_size == 0:
                    continue
                tmp = self.staging / f"evtx_{name}"
                if self._stage_file(src, tmp) and self._add(tmp, f"evtx/{name}"):
                    seen.add(name)
            except Exception as exc:
                self._warn(f"EVTX {name}: {exc}")
        count = 0
        try:
            all_evtx = sorted(evtx_dir.glob("*.evtx"))
        except Exception as exc:
            self._warn(f"EVTX glob error: {exc}")
            return
        for p in all_evtx:
            if count >= 100:
                break
            if p.name in seen:
                continue
            try:
                if p.stat().st_size == 0:
                    continue
                tmp = self.staging / f"evtx_{p.name}"
                if self._stage_file(p, tmp) and self._add(tmp, f"evtx/{p.name}"):
                    count += 1
            except Exception as exc:
                self._warn(f"EVTX {p.name}: {exc}")

    def _registry(self) -> None:
        print("  [*] Registry Hives")
        staging_reg = self.staging / "registry"
        staging_reg.mkdir(exist_ok=True)
        hklm_hives = {
            "SYSTEM": "HKLM\\SYSTEM",
            "SOFTWARE": "HKLM\\SOFTWARE",
            "SAM": "HKLM\\SAM",
            "SECURITY": "HKLM\\SECURITY",
        }
        for name, hive_path in hklm_hives.items():
            dest = staging_reg / name
            try:
                r = subprocess.run(
                    ["reg.exe", "SAVE", hive_path, str(dest), "/y"],
                    capture_output=True, timeout=60,
                )
                if r.returncode == 0:
                    self._add(dest, f"registry/{name}")
                else:
                    self._warn(f"reg.exe SAVE {name} failed (run as Administrator?)")
            except Exception as exc:
                self._warn(f"reg.exe SAVE {name}: {exc}")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        try:
            user_dirs = sorted(users_dir.iterdir()) if users_dir.exists() else []
        except Exception as exc:
            self._warn(f"Registry users scan error: {exc}")
            user_dirs = []
        for user_dir in user_dirs:
            if not user_dir.is_dir():
                continue
            for rel, suffix in [
                ("NTUSER.DAT", "NTUSER.DAT"),
                (r"AppData\Local\Microsoft\Windows\UsrClass.dat", "USRCLASS.DAT"),
            ]:
                try:
                    src = user_dir / rel
                    tmp = staging_reg / f"{user_dir.name}_{suffix}"
                    if self._stage_file(src, tmp):
                        self._add(tmp, f"registry/users/{user_dir.name}/{suffix}")
                except Exception as exc:
                    self._warn(f"Registry {user_dir.name}/{suffix}: {exc}")

    def _prefetch(self) -> None:
        print("  [*] Prefetch Files")
        pf_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
        if not pf_dir.exists():
            self._warn("Prefetch directory not found (may be disabled)")
            return
        count = 0
        try:
            pf_files = sorted(pf_dir.glob("*.pf"))
        except Exception as exc:
            self._warn(f"Prefetch glob error: {exc}")
            return
        for p in pf_files:
            if count >= 500:
                break
            try:
                if p.stat().st_size == 0:
                    continue
                tmp = self.staging / f"pf_{p.name}"
                if self._stage_file(p, tmp) and self._add(tmp, f"prefetch/{p.name}"):
                    count += 1
            except Exception as exc:
                self._warn(f"Prefetch {p.name}: {exc}")

    def _lnk(self) -> None:
        print("  [*] LNK / Recent Items")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        count = 0
        try:
            user_dirs = sorted(users_dir.iterdir()) if users_dir.exists() else []
        except Exception as exc:
            self._warn(f"LNK users scan error: {exc}")
            return
        for user_dir in user_dirs:
            if not user_dir.is_dir():
                continue
            recent = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            try:
                lnk_files = list(recent.rglob("*.lnk")) if recent.exists() else []
            except Exception:
                lnk_files = []
            for p in lnk_files:
                if count >= 2000:
                    break
                try:
                    if self._add(p, f"lnk/{user_dir.name}/{p.name}"):
                        count += 1
                except Exception:
                    pass

    def _browser(self) -> None:
        print("  [*] Browser Artifacts")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        PROFILES = [
            # Chrome
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\History"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Web Data"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Cookies"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Login Data"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Bookmarks"),
            # Edge
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\History"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\Cookies"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\Web Data"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\Login Data"),
            # Brave
            ("brave",  r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History"),
            ("brave",  r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cookies"),
            ("brave",  r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Web Data"),
            ("brave",  r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data"),
            # Opera
            ("opera",  r"AppData\Roaming\Opera Software\Opera Stable\History"),
            ("opera",  r"AppData\Roaming\Opera Software\Opera Stable\Cookies"),
            ("opera",  r"AppData\Roaming\Opera Software\Opera Stable\Web Data"),
            ("opera",  r"AppData\Roaming\Opera Software\Opera Stable\Login Data"),
            # Vivaldi
            ("vivaldi", r"AppData\Local\Vivaldi\User Data\Default\History"),
            ("vivaldi", r"AppData\Local\Vivaldi\User Data\Default\Cookies"),
            ("vivaldi", r"AppData\Local\Vivaldi\User Data\Default\Login Data"),
        ]
        try:
            user_dirs = sorted(users_dir.iterdir()) if users_dir.exists() else []
        except Exception as exc:
            self._warn(f"Browser users scan error: {exc}")
            return
        for user_dir in user_dirs:
            if not user_dir.is_dir():
                continue
            for browser, rel in PROFILES:
                try:
                    src = user_dir / rel
                    tmp = self.staging / f"{user_dir.name}_{browser}_{Path(rel).name}"
                    if self._copy_locked(src, tmp):
                        self._add(tmp, f"browser/{browser}/{user_dir.name}/{Path(rel).name}")
                except Exception:
                    pass
            ff_base = user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
            try:
                ff_profiles = list(ff_base.iterdir()) if ff_base.exists() else []
            except Exception:
                ff_profiles = []
            for profile_dir in ff_profiles:
                if not profile_dir.is_dir():
                    continue
                for db in ("places.sqlite", "cookies.sqlite", "logins.json", "formhistory.sqlite"):
                    try:
                        src = profile_dir / db
                        tmp = self.staging / f"{user_dir.name}_ff_{profile_dir.name}_{db}"
                        if self._copy_locked(src, tmp):
                            self._add(tmp, f"browser/firefox/{user_dir.name}/{profile_dir.name}/{db}")
                    except Exception:
                        pass

    def _scheduled_tasks(self) -> None:
        print("  [*] Scheduled Tasks")
        tasks_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        if not tasks_dir.exists():
            self._warn("Tasks directory not found")
            return
        count = 0
        try:
            task_files = list(tasks_dir.rglob("*"))
        except Exception as exc:
            self._warn(f"Scheduled tasks scan error: {exc}")
            return
        for p in task_files:
            if count >= 500:
                break
            try:
                if p.is_file() and not p.suffix:
                    rel = str(p.relative_to(tasks_dir)).replace("\\", "/")
                    if self._add(p, f"scheduled_tasks/{rel}"):
                        count += 1
            except Exception as exc:
                self._warn(f"Task {p.name}: {exc}")

    def _mft(self) -> None:
        """Raw-copy $MFT from all NTFS volumes via Windows kernel API (requires Admin)."""
        print("  [*] Master File Table ($MFT)")
        try:
            import ctypes, ctypes.wintypes, struct
        except ImportError:
            self._warn("$MFT: ctypes not available")
            return

        # Detect lettered NTFS drives
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        drives = [chr(65 + i) for i in range(26) if bitmask & (1 << i)]

        for drive in drives:
            dest = self.staging / f"{drive}_MFT"
            try:
                h = ctypes.windll.kernel32.CreateFileW(
                    f"\\\\.\\{drive}:",
                    0x80000000,           # GENERIC_READ
                    0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
                    None, 3, 0, None,     # OPEN_EXISTING, no flags
                )
                INVALID = ctypes.c_void_p(-1).value
                if h == INVALID or h == 0:
                    self._warn(f"$MFT ({drive}:): cannot open volume — run as Administrator")
                    continue

                try:
                    # ── Read NTFS boot sector ────────────────────────────────
                    buf = ctypes.create_string_buffer(512)
                    n   = ctypes.wintypes.DWORD(0)
                    ctypes.windll.kernel32.ReadFile(h, buf, 512, ctypes.byref(n), None)
                    bs  = buf.raw

                    if bs[3:7] != b'NTFS':
                        self._log(f"{drive}: not NTFS — skipping")
                        continue

                    bps      = struct.unpack_from('<H', bs, 11)[0]   # bytes/sector
                    spc      = struct.unpack_from('<B', bs, 13)[0]   # sectors/cluster
                    mft_lcn  = struct.unpack_from('<Q', bs, 48)[0]   # MFT first LCN
                    cls_sz   = bps * spc

                    # MFT record size (boot sector offset 64)
                    rs_raw   = struct.unpack_from('<b', bs, 64)[0]
                    mft_rs   = cls_sz * (2 ** rs_raw) if rs_raw >= 0 else 2 ** (-rs_raw)
                    mft_rs   = max(512, min(int(mft_rs), 65536))

                    # ── Seek to MFT start, read first FILE record ────────────
                    mft_off  = mft_lcn * cls_sz
                    ctypes.windll.kernel32.SetFilePointerEx(
                        h, ctypes.c_longlong(mft_off), None, 0,  # FILE_BEGIN
                    )
                    rec0 = ctypes.create_string_buffer(mft_rs)
                    ctypes.windll.kernel32.ReadFile(h, rec0, mft_rs, ctypes.byref(n), None)

                    if rec0.raw[:4] != b'FILE':
                        self._warn(f"$MFT ({drive}:): first record has no FILE signature")
                        continue

                    # ── Parse attributes to find $DATA total size ────────────
                    attr_p     = struct.unpack_from('<H', rec0.raw, 20)[0]
                    total_size = 0
                    while attr_p + 8 < mft_rs:
                        at = struct.unpack_from('<I', rec0.raw, attr_p)[0]
                        al = struct.unpack_from('<I', rec0.raw, attr_p + 4)[0]
                        if at == 0xFFFFFFFF or al == 0:
                            break
                        if at == 0x80 and rec0.raw[attr_p + 8]:  # non-resident $DATA
                            total_size = struct.unpack_from('<Q', rec0.raw, attr_p + 0x30)[0]
                            break
                        attr_p += al

                    if total_size == 0 or total_size > 30 * 1024 ** 3:
                        total_size = 512 * 1024 * 1024  # 512 MB safety cap
                        self._log(f"$MFT ({drive}:): size unknown, capping at 512 MB")

                    # ── Re-seek and stream out the full MFT ──────────────────
                    ctypes.windll.kernel32.SetFilePointerEx(
                        h, ctypes.c_longlong(mft_off), None, 0,
                    )
                    CHUNK     = 4 * 1024 * 1024  # 4 MB
                    remaining = total_size
                    with open(dest, "wb") as out_f:
                        while remaining > 0:
                            to_read   = min(CHUNK, remaining)
                            cbuf      = ctypes.create_string_buffer(to_read)
                            ok        = ctypes.windll.kernel32.ReadFile(
                                h, cbuf, to_read, ctypes.byref(n), None,
                            )
                            if not ok or n.value == 0:
                                break
                            out_f.write(cbuf.raw[:n.value])
                            remaining -= n.value

                    self._add(dest, f"mft/{drive}_$MFT")
                    sz_mb = dest.stat().st_size / 1024 / 1024
                    print(f"      {drive}:\\$MFT  ({sz_mb:.1f} MB)")

                finally:
                    ctypes.windll.kernel32.CloseHandle(h)

            except Exception as exc:
                self._warn(f"$MFT ({drive}:): {exc}")

    def _pe_binaries(self) -> None:
        """Collect PE executables from high-risk staging locations."""
        print("  [*] PE / Executable Binaries")
        users_dir  = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        system_tmp = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"
        PE_EXTS    = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".msi", ".hta"}
        MAX_FILE   = 200 * 1024 * 1024   # 200 MB
        MAX_TOTAL  = 2 * 1024 ** 3       # 2 GB total
        MAX_FILES  = 1000

        dirs: list[Path] = [system_tmp]
        if users_dir.exists():
            for ud in sorted(users_dir.iterdir()):
                if not ud.is_dir():
                    continue
                for rel in [
                    r"AppData\Local\Temp",
                    r"AppData\Roaming",
                    r"Downloads",
                    r"Desktop",
                    r"AppData\Local\Microsoft\Windows\INetCache",
                ]:
                    dirs.append(ud / rel)

        count = 0
        total = 0
        for d in dirs:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*")):
                if count >= MAX_FILES or total >= MAX_TOTAL:
                    break
                if not p.is_file() or p.suffix.lower() not in PE_EXTS:
                    continue
                sz = p.stat().st_size
                if sz == 0 or sz > MAX_FILE:
                    continue
                rel = p.relative_to(d.parent) if d.parent in p.parents else Path(d.name) / p.name
                if self._add(p, f"pe/{rel}"):
                    count += 1
                    total += sz

    def _documents(self) -> None:
        """Collect Office documents and PDFs from user directories."""
        print("  [*] Office Documents & PDFs")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        DOC_EXTS  = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
                     ".ppt", ".pptx", ".pptm", ".rtf", ".pdf", ".odt", ".ods"}
        MAX_FILE  = 100 * 1024 * 1024  # 100 MB
        MAX_FILES = 500

        count = 0
        for ud in (sorted(users_dir.iterdir()) if users_dir.exists() else []):
            if not ud.is_dir():
                continue
            for rel in ["Documents", "Downloads", "Desktop"]:
                d = ud / rel
                if not d.exists():
                    continue
                for p in sorted(d.rglob("*")):
                    if count >= MAX_FILES:
                        break
                    if not p.is_file() or p.suffix.lower() not in DOC_EXTS:
                        continue
                    if p.stat().st_size == 0 or p.stat().st_size > MAX_FILE:
                        continue
                    if self._add(p, f"documents/{ud.name}/{rel}/{p.name}"):
                        count += 1

    def _system_triage(self) -> None:
        print("  [*] System Triage (live commands)")
        lines: list[str] = []
        for header, cmd in [
            ("SYSTEM INFO",         ["systeminfo"]),
            ("NETWORK CONFIG",      ["ipconfig", "/all"]),
            ("NETWORK CONNECTIONS", ["netstat", "-ano"]),
            ("ARP CACHE",           ["arp", "-a"]),
            ("DNS CACHE",           ["ipconfig", "/displaydns"]),
            ("RUNNING PROCESSES",   ["tasklist", "/v", "/fo", "list"]),
            ("LOCAL USERS",         ["net", "user"]),
            ("ADMINISTRATORS",      ["net", "localgroup", "administrators"]),
            ("SERVICES",            ["sc", "query", "state=", "all"]),
            ("STARTUP ITEMS",       ["wmic", "startup", "list", "full"]),
            ("SCHEDULED TASKS",     ["schtasks", "/query", "/fo", "list", "/v"]),
            ("SHARES",              ["net", "share"]),
            ("INSTALLED SOFTWARE",  ["wmic", "product", "get", "Name,Version,InstallDate", "/format:list"]),
            ("ENVIRONMENT",         ["set"]),
        ]:
            lines.append(f"\n{'='*60}\n{header}\n{'='*60}")
            lines.append(self._run_cmd(cmd, timeout=45))
        self._write_text("system_triage.txt", "\n".join(lines), "system_triage.txt")

    def _memory(self) -> None:
        print("  [*] Physical Memory Dump (live acquisition)")
        print("  [!] Note: Memory dumps are typically 4–64 GB — this may take a while")

        dump_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.dmp"

        # Locate WinPmem — check PATH, then script directory, then CWD
        winpmem: str | None = (
            shutil.which("winpmem")
            or shutil.which("winpmem_mini_x64_rc2")
        )
        if not winpmem:
            script_dir = Path(sys.argv[0]).resolve().parent
            for name in [
                "winpmem_mini_x64_rc2.exe", "winpmem.exe",
                "winpmem_x64.exe", "winpmem_mini_x64.exe",
            ]:
                for search_dir in (script_dir, Path.cwd()):
                    candidate = search_dir / name
                    if candidate.exists():
                        winpmem = str(candidate)
                        break
                if winpmem:
                    break

        if not winpmem:
            self._warn(
                "winpmem not found. Download the latest release from:\n"
                "      https://github.com/Velocidex/WinPmem/releases\n"
                "      Then place winpmem_mini_x64_rc2.exe next to this collector and re-run."
            )
            return

        self._log(f"Using: {winpmem}")
        print(f"      winpmem: {winpmem}")
        print(f"      Output : {dump_path}")

        try:
            r = subprocess.run(
                [winpmem, str(dump_path)],
                capture_output=True,
                timeout=7200,   # 2 hours
            )
            if r.returncode == 0:
                self._add(dump_path, f"memory/{dump_path.name}")
                size_gb = dump_path.stat().st_size / (1024 ** 3)
                print(f"  [+] Memory dump complete ({size_gb:.1f} GB)")
            else:
                err = (r.stderr or r.stdout or b"").decode(errors="replace")[:400]
                self._warn(f"winpmem failed (code {r.returncode}) — run as Administrator?\n      {err}")
        except subprocess.TimeoutExpired:
            self._warn("Memory acquisition timed out (>2 hours)")
        except FileNotFoundError:
            self._warn(f"winpmem binary not executable: {winpmem}")
        except Exception as exc:
            self._warn(f"Memory acquisition error: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Linux Collector
# ─────────────────────────────────────────────────────────────────────────────

class LinuxCollector(Collector):

    def collect_all(self) -> None:
        self._total_cats = len(self.collect)
        self._run_cat("logs",      self._logs)
        self._run_cat("history",   self._shell_history)
        self._run_cat("config",    self._system_config)
        self._run_cat("cron",      self._cron)
        self._run_cat("ssh",       self._ssh_artifacts)
        self._run_cat("network",   self._network_captures)
        self._run_cat("suricata",  self._suricata_logs)
        self._run_cat("zeek",      self._zeek_logs)
        self._run_cat("pe",        self._pe_binaries)
        self._run_cat("documents", self._documents)
        self._run_cat("triage",    self._system_triage)
        self._run_cat("memory",    self._memory)

    def _logs(self) -> None:
        print("  [*] System Logs")
        log_dir = Path("/var/log")
        for name in ["auth.log", "syslog", "messages", "secure", "kern.log",
                     "daemon.log", "audit/audit.log", "apache2/access.log",
                     "nginx/access.log", "dpkg.log", "apt/history.log"]:
            self._add(log_dir / name, f"logs/{name}")
        for p in sorted(log_dir.rglob("*.gz"))[:80]:
            self._add(p, f"logs/{p.relative_to(log_dir)}")
        out = self._run_cmd(["journalctl", "--no-pager", "-o", "short-iso", "-n", "100000"], timeout=120)
        if out:
            tmp = self.staging / "journal.log"
            tmp.write_text(out, encoding="utf-8", errors="replace")
            self._add(tmp, "logs/journal.log")

    def _shell_history(self) -> None:
        print("  [*] Shell Histories")
        HIST = [".bash_history", ".zsh_history", ".sh_history", ".python_history", ".mysql_history"]
        candidates = [Path("/root")]
        if Path("/home").exists():
            candidates += sorted(Path("/home").iterdir())
        for user_dir in candidates:
            if user_dir.is_dir():
                for h in HIST:
                    self._add(user_dir / h, f"history/{user_dir.name}/{h}")

    def _system_config(self) -> None:
        print("  [*] System Configuration")
        for p in ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers",
                  "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/crontab",
                  "/etc/ssh/sshd_config", "/etc/os-release", "/proc/version"]:
            self._add(Path(p), f"config/{Path(p).name}")
        if Path("/etc/sudoers.d").exists():
            for f in sorted(Path("/etc/sudoers.d").iterdir()):
                if f.is_file():
                    self._add(f, f"config/sudoers.d/{f.name}")

    def _cron(self) -> None:
        print("  [*] Cron Jobs")
        for d in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
                  "/etc/cron.weekly", "/etc/cron.monthly"]:
            if Path(d).exists():
                for f in sorted(Path(d).iterdir()):
                    if f.is_file():
                        self._add(f, f"cron/{Path(d).name}/{f.name}")
        spool = Path("/var/spool/cron/crontabs")
        if spool.exists():
            for ct in sorted(spool.iterdir()):
                self._add(ct, f"cron/crontabs/{ct.name}")
        out = self._run_cmd(["systemctl", "list-timers", "--all", "--no-pager"])
        if out:
            self._write_text("systemd_timers.txt", out, "cron/systemd_timers.txt")

    def _ssh_artifacts(self) -> None:
        print("  [*] SSH Artifacts")
        PRIVATE = {"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}
        candidates = [Path("/root")]
        if Path("/home").exists():
            candidates += sorted(Path("/home").iterdir())
        for user_dir in candidates:
            ssh = user_dir / ".ssh"
            if ssh.exists():
                for f in sorted(ssh.iterdir()):
                    if f.is_file() and f.name not in PRIVATE:
                        self._add(f, f"ssh/{user_dir.name}/{f.name}")

    def _network_captures(self) -> None:
        """Collect PCAP/PCAPNG files from common locations (max 10 files, 500 MB each)."""
        print("  [*] PCAP / Network Captures")
        SEARCH_DIRS = [
            Path("/var/log"),
            Path("/tmp"),
            Path("/var/capture"),
            Path("/opt/pcap"),
            Path("/data"),
            Path("/captures"),
        ]
        MAX_SIZE = 500 * 1024 * 1024  # 500 MB per file
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*.pcap")) + sorted(d.rglob("*.pcapng")) + sorted(d.rglob("*.cap")):
                if count >= 10:
                    break
                if p.stat().st_size <= MAX_SIZE:
                    if self._add(p, f"network/{p.name}"):
                        count += 1
            if count >= 10:
                break
        # Live capture — only if tcpdump is available and no pcaps found
        if count == 0 and shutil.which("tcpdump"):
            cap_path = self.staging / f"live-{HOSTNAME}-{TS_NOW}.pcap"
            print("      Live capture: 30 s via tcpdump")
            try:
                subprocess.run(
                    ["tcpdump", "-i", "any", "-w", str(cap_path), "-G", "30", "-W", "1"],
                    timeout=35, capture_output=True,
                )
                self._add(cap_path, f"network/{cap_path.name}")
            except Exception as exc:
                self._log(f"tcpdump: {exc}")

    def _suricata_logs(self) -> None:
        """Collect Suricata EVE JSON logs."""
        print("  [*] Suricata IDS Logs (EVE JSON)")
        SEARCH_DIRS = [
            Path("/var/log/suricata"),
            Path("/var/log/suricata/"),
            Path("/opt/suricata/log"),
            Path("/etc/suricata"),
        ]
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.glob("eve*.json")) + sorted(d.glob("*.json")):
                if count >= 20:
                    break
                if self._add(p, f"suricata/{p.name}"):
                    count += 1
            for p in sorted(d.glob("*.log")):
                if count >= 20:
                    break
                if self._add(p, f"suricata/{p.name}"):
                    count += 1

    def _zeek_logs(self) -> None:
        """Collect Zeek (formerly Bro) network analysis logs."""
        print("  [*] Zeek Network Logs")
        SEARCH_DIRS = [
            Path("/var/log/zeek"),
            Path("/var/log/bro"),
            Path("/opt/zeek/logs"),
            Path("/opt/bro/logs"),
            Path("/nsm/zeek/logs"),
        ]
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            # Priority logs
            for name in ["conn.log", "dns.log", "http.log", "ssl.log", "x509.log",
                         "files.log", "weird.log", "notice.log", "alarm.log"]:
                p = d / name
                if self._add(p, f"zeek/{p.name}"):
                    count += 1
            # Remaining logs (up to 50 total)
            for p in sorted(d.rglob("*.log")):
                if count >= 50:
                    break
                if self._add(p, f"zeek/{p.relative_to(d)}"):
                    count += 1
            if count > 0:
                break  # Found logs in this dir, no need to check others

    def _pe_binaries(self) -> None:
        """Collect suspicious ELF/PE binaries dropped in volatile locations."""
        print("  [*] PE / Executable Binaries")
        SEARCH_DIRS = [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"),
                       Path("/var/www"), Path("/opt"), Path("/root")]
        ELF_MAGIC   = b'\x7fELF'
        PE_MAGIC    = b'MZ'
        MAX_FILE    = 50 * 1024 * 1024   # 50 MB
        MAX_FILES   = 500

        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*")):
                if count >= MAX_FILES:
                    break
                if not p.is_file():
                    continue
                sz = p.stat().st_size
                if sz < 4 or sz > MAX_FILE:
                    continue
                try:
                    magic = p.read_bytes()[:4]
                except (PermissionError, OSError):
                    continue
                if not (magic[:4] == ELF_MAGIC or magic[:2] == PE_MAGIC):
                    continue
                rel = p.relative_to(d.parent) if d.parent in p.parents else Path(d.name) / p.name
                if self._add(p, f"pe/{rel}"):
                    count += 1

    def _documents(self) -> None:
        """Collect Office documents and PDFs from home directories."""
        print("  [*] Office Documents & PDFs")
        DOC_EXTS  = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
                     ".ppt", ".pptx", ".pptm", ".rtf", ".pdf", ".odt", ".ods"}
        MAX_FILE  = 100 * 1024 * 1024
        MAX_FILES = 500
        candidates = [Path("/root")]
        if Path("/home").exists():
            candidates += sorted(Path("/home").iterdir())

        count = 0
        for user_dir in candidates:
            if not user_dir.is_dir():
                continue
            for rel in ["Documents", "Downloads", "Desktop"]:
                d = user_dir / rel
                if not d.exists():
                    continue
                for p in sorted(d.rglob("*")):
                    if count >= MAX_FILES:
                        break
                    if not p.is_file() or p.suffix.lower() not in DOC_EXTS:
                        continue
                    if p.stat().st_size == 0 or p.stat().st_size > MAX_FILE:
                        continue
                    if self._add(p, f"documents/{user_dir.name}/{rel}/{p.name}"):
                        count += 1

    def _system_triage(self) -> None:
        print("  [*] System Triage (live commands)")
        lines: list[str] = []
        for header, cmd in [
            ("UNAME",            ["uname", "-a"]),
            ("PROCESSES",        ["ps", "auxf"]),
            ("NETWORK SOCKETS",  ["ss", "-tulpan"]),
            ("NETWORK IFACEs",   ["ip", "addr"]),
            ("ROUTING TABLE",    ["ip", "route"]),
            ("CURRENT USERS",    ["who"]),
            ("LAST LOGINS",      ["last", "-F", "-n", "200"]),
            ("FAILED LOGINS",    ["lastb", "-n", "100"]),
            ("MOUNTS",           ["mount"]),
            ("DISK USAGE",       ["df", "-h"]),
            ("LOADED MODULES",   ["lsmod"]),
            ("SERVICES",         ["systemctl", "list-units", "--type=service", "--all", "--no-pager"]),
            ("INSTALLED PKGS",   ["dpkg", "-l"]),
            ("INSTALLED RPM",    ["rpm", "-qa"]),
            ("SUID FILES",       ["find", "/", "-perm", "-4000", "-type", "f", "-ls"]),
            ("ENVIRONMENT",      ["env"]),
        ]:
            lines.append(f"\n{'='*60}\n{header}\n{'='*60}")
            lines.append(self._run_cmd(cmd, timeout=30))
        self._write_text("system_triage.txt", "\n".join(lines), "system_triage.txt")

    def _memory(self) -> None:
        print("  [*] Physical Memory Dump (live acquisition)")
        print("  [!] Note: Memory dumps are typically 4–64 GB — this may take a while")
        print("  [!] Root privileges are required for memory acquisition")

        dump_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.lime"

        # 1. Try avml (Microsoft's user-space memory acquisition tool)
        avml = shutil.which("avml")
        if avml:
            self._log(f"Using avml: {avml}")
            print(f"      avml : {avml}")
            print(f"      Output: {dump_path}")
            try:
                r = subprocess.run(
                    [avml, str(dump_path)],
                    capture_output=True,
                    timeout=7200,
                )
                if r.returncode == 0 and dump_path.exists() and dump_path.stat().st_size > 0:
                    self._add(dump_path, f"memory/{dump_path.name}")
                    size_gb = dump_path.stat().st_size / (1024 ** 3)
                    print(f"  [+] Memory dump complete ({size_gb:.1f} GB)")
                    return
                err = (r.stderr or r.stdout or b"").decode(errors="replace")[:400]
                self._warn(f"avml failed (code {r.returncode}): {err}")
            except subprocess.TimeoutExpired:
                self._warn("avml timed out (>2 hours)")
            except Exception as exc:
                self._warn(f"avml error: {exc}")

        # 2. Try fmem / dd /dev/fmem
        for mem_dev in ("/dev/fmem", "/dev/mem"):
            if Path(mem_dev).exists():
                raw_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.raw"
                print(f"      Trying {mem_dev} → {raw_path}")
                try:
                    r = subprocess.run(
                        ["dd", f"if={mem_dev}", f"of={raw_path}", "bs=1M"],
                        capture_output=True, timeout=7200,
                    )
                    if r.returncode == 0 and raw_path.stat().st_size > 0:
                        self._add(raw_path, f"memory/{raw_path.name}")
                        size_gb = raw_path.stat().st_size / (1024 ** 3)
                        print(f"  [+] Memory image via {mem_dev} ({size_gb:.1f} GB)")
                        return
                except Exception as exc:
                    self._log(f"{mem_dev} dd error: {exc}")

        self._warn(
            "No memory acquisition tool found.\n"
            "      Install avml for user-space acquisition:\n"
            "        https://github.com/microsoft/avml/releases\n"
            "      Or load the LiME kernel module for full physical memory."
        )


# ─────────────────────────────────────────────────────────────────────────────
# macOS Collector
# ─────────────────────────────────────────────────────────────────────────────

class MacOSCollector(Collector):

    def collect_all(self) -> None:
        self._total_cats = len(self.collect)
        self._run_cat("logs",         self._logs)
        self._run_cat("history",      self._shell_history)
        self._run_cat("config",       self._system_config)
        self._run_cat("launchagents", self._launch_agents)
        self._run_cat("browser",      self._browser)
        self._run_cat("plist",        self._plist_preferences)
        self._run_cat("network",      self._network_captures)
        self._run_cat("pe",           self._pe_binaries)
        self._run_cat("documents",    self._documents)
        self._run_cat("triage",       self._system_triage)
        self._run_cat("memory",       self._memory)

    # ── Logs ──────────────────────────────────────────────────────────────────

    def _logs(self) -> None:
        print("  [*] System Logs")
        # Traditional syslog-style files
        for name in ["system.log", "install.log", "fsck_apfs.log", "wifi.log"]:
            self._add(Path("/var/log") / name, f"logs/{name}")
        # Compress rotated logs
        for p in sorted(Path("/var/log").glob("*.gz"))[:30]:
            self._add(p, f"logs/{p.name}")
        # Unified Logging System — export last 7 days as JSON
        out = self._run_cmd(
            ["log", "show", "--style", "json", "--last", "7d", "--info"],
            timeout=120,
        )
        if out:
            tmp = self.staging / "unified_logs.ndjson"
            # 'log show --style json' returns a JSON array; save as-is
            tmp.write_text(out, encoding="utf-8", errors="replace")
            self._add(tmp, "logs/unified_logs.ndjson")
        else:
            # Fallback: human-readable text
            out_text = self._run_cmd(
                ["log", "show", "--last", "7d", "--info"], timeout=120,
            )
            if out_text:
                tmp = self.staging / "unified_logs.log"
                tmp.write_text(out_text, encoding="utf-8", errors="replace")
                self._add(tmp, "logs/unified_logs.log")

    # ── Shell history (same as Linux) ─────────────────────────────────────────

    def _shell_history(self) -> None:
        print("  [*] Shell Histories")
        HIST = [".bash_history", ".zsh_history", ".sh_history", ".python_history"]
        home = Path.home().parent  # /Users
        candidates = [Path("/var/root")]
        if home.exists():
            candidates += sorted(home.iterdir())
        for user_dir in candidates:
            if user_dir.is_dir():
                for h in HIST:
                    self._add(user_dir / h, f"history/{user_dir.name}/{h}")

    # ── System config ─────────────────────────────────────────────────────────

    def _system_config(self) -> None:
        print("  [*] System Configuration")
        for p in [
            "/etc/passwd", "/etc/group", "/etc/hosts",
            "/etc/resolv.conf", "/etc/ssh/sshd_config",
            "/private/etc/sudoers",
            "/System/Library/CoreServices/SystemVersion.plist",
        ]:
            self._add(Path(p), f"config/{Path(p).name}")
        # sudoers.d
        for d in ["/etc/sudoers.d", "/private/etc/sudoers.d"]:
            if Path(d).exists():
                for f in sorted(Path(d).iterdir()):
                    if f.is_file():
                        self._add(f, f"config/sudoers.d/{f.name}")

    # ── LaunchAgents / LaunchDaemons (macOS persistence) ─────────────────────

    def _launch_agents(self) -> None:
        print("  [*] Launch Agents / Daemons")
        dirs = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
        ]
        # Per-user LaunchAgents
        home = Path.home().parent
        if home.exists():
            for user_dir in sorted(home.iterdir()):
                dirs.append(str(user_dir / "Library" / "LaunchAgents"))

        for d in dirs:
            dp = Path(d)
            if dp.exists():
                for f in sorted(dp.glob("*.plist"))[:200]:
                    rel = f.relative_to(dp.parent)
                    self._add(f, f"launchagents/{dp.name}/{f.name}")

    # ── Browser artifacts ─────────────────────────────────────────────────────

    def _browser(self) -> None:
        print("  [*] Browser Artifacts")
        home = Path.home().parent
        candidates = sorted(home.iterdir()) if home.exists() else []
        for user_dir in candidates:
            if not user_dir.is_dir():
                continue
            lib = user_dir / "Library"
            # Chromium-based browsers (Chrome, Brave, Edge, Opera, Vivaldi)
            chromium_browsers = [
                ("chrome",  "Google/Chrome"),
                ("brave",   "BraveSoftware/Brave-Browser"),
                ("edge",    "Microsoft Edge"),
                ("opera",   "com.operasoftware.Opera"),
                ("vivaldi", "Vivaldi"),
            ]
            for bname, subpath in chromium_browsers:
                profile = lib / "Application Support" / subpath / "Default"
                for db in ["History", "Cookies", "Web Data", "Login Data", "Bookmarks"]:
                    self._add(profile / db, f"browser/{user_dir.name}/{bname}/{db}")
            # Safari
            safari_dir = lib / "Safari"
            for sf in ["History.db", "Downloads.plist", "Bookmarks.plist",
                       "RecentlyClosedTabs.plist", "LastSession.plist"]:
                self._add(safari_dir / sf, f"browser/{user_dir.name}/safari/{sf}")
            # Firefox
            ff_profiles = lib / "Application Support" / "Firefox" / "Profiles"
            if ff_profiles.exists():
                for profile in sorted(ff_profiles.iterdir()):
                    for db in ["places.sqlite", "cookies.sqlite", "logins.json", "formhistory.sqlite"]:
                        self._add(profile / db, f"browser/{user_dir.name}/firefox/{profile.name}/{db}")
            # Quarantine database (file download history)
            quarantine = lib / "Preferences" / "com.apple.LaunchServices.QuarantineEventsV2"
            self._add(quarantine, f"browser/{user_dir.name}/quarantine_events.sqlite")

    # ── Plist preferences ─────────────────────────────────────────────────────

    def _plist_preferences(self) -> None:
        """Collect plist files from system and per-user preference directories."""
        print("  [*] macOS Preference Plists")
        PREF_DIRS = [
            Path("/Library/Preferences"),
            Path("/Library/Application Support"),
            Path("/System/Library/Preferences"),
        ]
        home = Path.home().parent  # /Users
        if home.exists():
            for user_dir in sorted(home.iterdir()):
                if user_dir.is_dir():
                    PREF_DIRS.append(user_dir / "Library" / "Preferences")
                    PREF_DIRS.append(user_dir / "Library" / "Application Support")

        MAX_FILES = 5000
        count = 0
        for d in PREF_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*.plist"))[:MAX_FILES - count]:
                if count >= MAX_FILES:
                    break
                try:
                    rel = p.relative_to(d.parent)
                except ValueError:
                    rel = Path(d.name) / p.name
                if self._add(p, f"plist/{rel}"):
                    count += 1

    # ── Network captures ──────────────────────────────────────────────────────

    def _network_captures(self) -> None:
        """Collect PCAP/PCAPNG files or run a short live capture via tcpdump."""
        print("  [*] PCAP / Network Captures")
        SEARCH_DIRS = [
            Path("/var/log"), Path("/tmp"), Path.home().parent,
            Path("/Library/Logs"), Path("/var/capture"),
        ]
        MAX_SIZE = 500 * 1024 * 1024  # 500 MB per file
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*.pcap")) + sorted(d.rglob("*.pcapng")) + sorted(d.rglob("*.cap")):
                if count >= 10:
                    break
                if p.stat().st_size <= MAX_SIZE:
                    if self._add(p, f"network/{p.name}"):
                        count += 1
            if count >= 10:
                break

        if count == 0 and shutil.which("tcpdump"):
            cap_path = self.staging / f"live-{HOSTNAME}-{TS_NOW}.pcap"
            print("      Live capture: 30 s via tcpdump (requires sudo)")
            try:
                subprocess.run(
                    ["tcpdump", "-i", "any", "-w", str(cap_path), "-G", "30", "-W", "1"],
                    timeout=35, capture_output=True,
                )
                self._add(cap_path, f"network/{cap_path.name}")
            except Exception as exc:
                self._log(f"tcpdump: {exc}")

    # ── PE binaries ───────────────────────────────────────────────────────────

    def _pe_binaries(self) -> None:
        """Collect suspicious binaries from temp/download locations."""
        print("  [*] PE / Executable Binaries")
        home = Path.home().parent
        SEARCH_DIRS = [Path("/tmp"), Path("/var/tmp")]
        if home.exists():
            for user_dir in sorted(home.iterdir()):
                if user_dir.is_dir():
                    SEARCH_DIRS += [
                        user_dir / "Downloads",
                        user_dir / "Desktop",
                    ]

        ELF_MAGIC = b'\x7fELF'
        PE_MAGIC  = b'MZ'
        MAX_FILE  = 50 * 1024 * 1024
        MAX_FILES = 500
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*")):
                if count >= MAX_FILES:
                    break
                if not p.is_file():
                    continue
                sz = p.stat().st_size
                if sz < 4 or sz > MAX_FILE:
                    continue
                try:
                    magic = p.read_bytes()[:4]
                except (PermissionError, OSError):
                    continue
                if not (magic[:4] == ELF_MAGIC or magic[:2] == PE_MAGIC):
                    continue
                if self._add(p, f"pe/{d.name}/{p.name}"):
                    count += 1

    # ── Office documents ──────────────────────────────────────────────────────

    def _documents(self) -> None:
        """Collect Office documents and PDFs from user directories."""
        print("  [*] Office Documents & PDFs")
        DOC_EXTS  = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
                     ".ppt", ".pptx", ".pptm", ".rtf", ".pdf", ".odt", ".ods",
                     ".pages", ".numbers", ".key"}
        MAX_FILE  = 100 * 1024 * 1024
        MAX_FILES = 500
        home = Path.home().parent
        count = 0
        for user_dir in (sorted(home.iterdir()) if home.exists() else []):
            if not user_dir.is_dir():
                continue
            for rel in ["Documents", "Downloads", "Desktop"]:
                d = user_dir / rel
                if not d.exists():
                    continue
                for p in sorted(d.rglob("*")):
                    if count >= MAX_FILES:
                        break
                    if not p.is_file() or p.suffix.lower() not in DOC_EXTS:
                        continue
                    if p.stat().st_size == 0 or p.stat().st_size > MAX_FILE:
                        continue
                    if self._add(p, f"documents/{user_dir.name}/{rel}/{p.name}"):
                        count += 1

    # ── System triage ─────────────────────────────────────────────────────────

    def _system_triage(self) -> None:
        print("  [*] System Triage (live commands)")
        lines: list[str] = []
        for header, cmd in [
            ("OS VERSION",       ["sw_vers"]),
            ("UNAME",            ["uname", "-a"]),
            ("PROCESSES",        ["ps", "auxww"]),
            ("NETWORK SOCKETS",  ["netstat", "-anv"]),
            ("NETWORK IFACEs",   ["ifconfig"]),
            ("ROUTING TABLE",    ["netstat", "-rn"]),
            ("ARP CACHE",        ["arp", "-an"]),
            ("CURRENT USERS",    ["who"]),
            ("LAST LOGINS",      ["last", "-n", "200"]),
            ("MOUNTS",           ["mount"]),
            ("DISK USAGE",       ["df", "-h"]),
            ("LOADED KEXTS",     ["kextstat"]),
            ("LAUNCH DAEMONS",   ["launchctl", "list"]),
            ("INSTALLED APPS",   ["system_profiler", "SPApplicationsDataType"]),
            ("NETWORK SERVICES", ["networksetup", "-listallnetworkservices"]),
            ("FIREWALL",         ["socketfilterfw", "--getglobalstate"]),
            ("SUID FILES",       ["find", "/", "-perm", "-4000", "-type", "f", "-ls"]),
            ("ENVIRONMENT",      ["env"]),
        ]:
            lines.append(f"\n{'='*60}\n{header}\n{'='*60}")
            lines.append(self._run_cmd(cmd, timeout=60))
        self._write_text("system_triage.txt", "\n".join(lines), "system_triage.txt")

    # ── Memory acquisition ────────────────────────────────────────────────────

    def _memory(self) -> None:
        print("  [*] Physical Memory Dump (live acquisition)")
        print("  [!] Note: Memory dumps are typically 4–64 GB — this may take a while")
        print("  [!] Root privileges are required for memory acquisition")

        dump_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.raw"

        # osxpmem (most reliable tool for macOS)
        osxpmem = shutil.which("osxpmem")
        if not osxpmem:
            # Check common locations
            for loc in ["/usr/local/bin/osxpmem", Path.cwd() / "osxpmem",
                        Path(__file__).parent / "osxpmem"]:
                if Path(loc).exists():
                    osxpmem = str(loc)
                    break

        if osxpmem:
            self._log(f"Using osxpmem: {osxpmem}")
            print(f"      Output: {dump_path}")
            try:
                r = subprocess.run(
                    [osxpmem, str(dump_path)],
                    capture_output=True, timeout=7200,
                )
                if r.returncode == 0 and dump_path.exists() and dump_path.stat().st_size > 0:
                    self._add(dump_path, f"memory/{dump_path.name}")
                    size_gb = dump_path.stat().st_size / (1024 ** 3)
                    print(f"  [+] Memory dump complete ({size_gb:.1f} GB)")
                    return
                err = (r.stderr or r.stdout or b"").decode(errors="replace")[:400]
                self._warn(f"osxpmem failed (code {r.returncode}): {err}")
            except subprocess.TimeoutExpired:
                self._warn("osxpmem timed out (>2 hours)")
            except Exception as exc:
                self._warn(f"osxpmem error: {exc}")

        self._warn(
            "No memory acquisition tool found.\n"
            "      Download osxpmem for macOS memory acquisition:\n"
            "        https://github.com/google/rekall/releases\n"
            "      Run: sudo osxpmem memory.raw"
        )


# ─────────────────────────────────────────────────────────────────────────────
# External Disk Collector (BitLocker support via dislocker-fuse)
# ─────────────────────────────────────────────────────────────────────────────

class ExternalDiskCollector(Collector):
    """
    Collect forensic artifacts from an external Windows disk (NTFS).

    Works on Linux with dislocker-fuse for BitLocker-encrypted partitions,
    or with a plain ntfs-3g/mount for unencrypted NTFS disks.
    Also accepts a path to an already-mounted directory.

    Usage
    -----
      # Unencrypted NTFS partition:
      tracex-collector --disk /dev/sdb1

      # BitLocker-encrypted partition (recovery key):
      tracex-collector --disk /dev/sdb1 --bitlocker-key "123456-789012-345678-901234-567890-123456-789012-345678"

      # Already-mounted directory (no root needed):
      tracex-collector --disk /mnt/external

    Requirements (Linux)
    --------------------
      apt-get install dislocker ntfs-3g
    """

    # Mirrors harvest_task LEVEL_CATEGORIES["small"] — safe defaults for dead-box triage.
    # Heavy categories (memory_artifacts, pe, documents, printing) are opt-in only.
    DEFAULT_COLLECT = {
        "evtx", "registry", "prefetch", "mft",
        "execution", "persistence", "network_cfg",
        "usb_devices", "credentials", "antivirus", "wer_crashes", "win_logs",
    }

    def __init__(self, disk: str, bitlocker_key: str = "", **kwargs):
        super().__init__(**kwargs)
        self.disk          = disk
        self.bitlocker_key = bitlocker_key.strip()
        self._dislocker_dir: Path | None = None
        self._ntfs_dir: Path | None = None

    # ── Mount lifecycle ───────────────────────────────────────────────────────

    def _run_privileged(self, cmd: list, timeout: int = 60) -> bool:
        """Run a command, prepending sudo when not already root."""
        if IS_LINUX and os.getuid() != 0:
            cmd = ["sudo"] + cmd
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
            if r.returncode != 0:
                err = (r.stderr or r.stdout or b"").decode(errors="replace")[:300]
                self._warn(f"{cmd[0]} failed: {err}")
                return False
            return True
        except subprocess.TimeoutExpired:
            self._warn(f"{cmd[0]} timed out")
            return False
        except Exception as exc:
            self._warn(f"{cmd[0]} error: {exc}")
            return False

    def _detect_bitlocker(self, device: str) -> bool:
        """Check for BitLocker volume signature at sector offset 3."""
        try:
            with open(device, "rb") as fh:
                header = fh.read(16)
            return header[3:11] == b"-FVE-FS-"
        except (PermissionError, OSError):
            # Cannot read raw device — assume it may be BitLocker if key provided
            return bool(self.bitlocker_key)

    def _unlock_bitlocker(self, device: str, mount_point: Path) -> str | None:
        """
        Unlock a BitLocker partition using dislocker-fuse.

        Creates a virtual NTFS image (dislocker-file) inside mount_point.
        Returns the path to that file on success, None on failure.
        """
        mount_point.mkdir(parents=True, exist_ok=True)

        dl_bin = shutil.which("dislocker-fuse") or shutil.which("dislocker")
        if not dl_bin:
            self._warn(
                "dislocker-fuse not found. Install with: apt-get install dislocker"
            )
            return None

        cmd = [dl_bin, device]
        if self.bitlocker_key:
            # 48-digit recovery key (digits + hyphens) → -p flag
            # Passphrase → -u flag
            if re.match(r"^[\d\-]+$", self.bitlocker_key):
                cmd += ["-p", self.bitlocker_key]
            else:
                cmd += ["-u", self.bitlocker_key]
        else:
            self._warn(
                "No BitLocker key supplied — attempting unauthenticated unlock "
                "(only works on volumes with clear-key protector)."
            )

        cmd += ["--", str(mount_point)]
        print(f"      dislocker-fuse: unlocking {device} → {mount_point}")

        if not self._run_privileged(cmd, timeout=120):
            return None

        dl_file = mount_point / "dislocker-file"
        if not dl_file.exists():
            self._warn(f"dislocker-fuse succeeded but dislocker-file is absent in {mount_point}")
            return None

        return str(dl_file)

    def _mount_ntfs(self, source: str, mount_point: Path) -> bool:
        """Mount an NTFS image or partition read-only at mount_point."""
        mount_point.mkdir(parents=True, exist_ok=True)

        # Prefer ntfs-3g (handles advanced NTFS features and compressed files)
        ntfs3g = shutil.which("ntfs-3g") or shutil.which("mount.ntfs-3g")
        if ntfs3g:
            ok = self._run_privileged(
                [ntfs3g, source, str(mount_point),
                 "-o", "ro,noatime,streams_interface=none,nodev,nosuid"],
                timeout=30,
            )
            if ok:
                return True

        # Generic mount fallback (kernel NTFS module)
        ok = self._run_privileged(
            ["mount", "-t", "ntfs", "-o", "ro,noatime", source, str(mount_point)],
            timeout=30,
        )
        return ok

    def _umount(self, path: Path) -> None:
        self._run_privileged(["umount", "-l", str(path)], timeout=30)

    def unlock_and_mount(self) -> Path | None:
        """
        Full pipeline: detect → BitLocker unlock → NTFS mount.
        Returns the filesystem root Path, or None on any failure.
        """
        disk_path = Path(self.disk)

        # Normalize bare drive letter: Path("E:") on Windows is a *relative* path
        # (it refers to the CWD of drive E:), so "E:" / "Windows" → "E:Windows".
        # Appending os.sep makes it absolute: "E:\" / "Windows" → "E:\Windows".
        if IS_WINDOWS:
            s = str(disk_path)
            if len(s) == 2 and s[1] == ':':
                disk_path = Path(s + os.sep)

        # Already a mounted directory
        if disk_path.is_dir():
            print(f"      Using existing mount: {disk_path}")
            return disk_path

        device = str(disk_path)

        # ── BitLocker unlock ───────────────────────────────────────────────────
        is_bitlocker = self.bitlocker_key or self._detect_bitlocker(device)
        if is_bitlocker:
            print(f"  [*] BitLocker volume detected — unlocking {device}")
            self._dislocker_dir = Path(tempfile.mkdtemp(prefix="fo_dislocker_"))
            dl_file = self._unlock_bitlocker(device, self._dislocker_dir)
            if dl_file is None:
                return None
            ntfs_source = dl_file
        else:
            ntfs_source = device

        # ── NTFS mount ─────────────────────────────────────────────────────────
        self._ntfs_dir = Path(tempfile.mkdtemp(prefix="fo_ntfs_"))
        print(f"  [*] Mounting NTFS → {self._ntfs_dir}")
        if not self._mount_ntfs(ntfs_source, self._ntfs_dir):
            self._warn(f"Failed to mount NTFS from {ntfs_source}")
            return None

        return self._ntfs_dir

    def cleanup(self) -> None:
        """Unmount filesystems before removing the staging directory."""
        if self._ntfs_dir and self._ntfs_dir.exists():
            self._umount(self._ntfs_dir)
            try:
                self._ntfs_dir.rmdir()
            except OSError:
                pass

        if self._dislocker_dir and self._dislocker_dir.exists():
            self._umount(self._dislocker_dir)
            try:
                self._dislocker_dir.rmdir()
            except OSError:
                pass

        super().cleanup()

    # ── Artifact collection from filesystem root ──────────────────────────────

    def collect_all(self) -> None:
        root = self.unlock_and_mount()
        if root is None:
            self._warn("Could not access the disk — no artifacts collected")
            return

        win_dir   = root / "Windows"
        users_dir = root / "Users"

        print(f"  Filesystem root : {root}")
        print(f"  Windows dir     : {'found' if win_dir.exists() else 'not found'}")
        print(f"  Users dir       : {'found' if users_dir.exists() else 'not found'}")
        print()

        self._total_cats = len(self.collect)

        # ── Core ─────────────────────────────────────────────────────────────
        self._run_cat("evtx",            self._evtx_from,            win_dir)
        self._run_cat("registry",        self._registry_from,        win_dir, users_dir)
        self._run_cat("prefetch",        self._prefetch_from,        win_dir)
        self._run_cat("mft",             self._mft_from,             root)
        self._run_cat("execution",       self._execution_from,       win_dir)
        self._run_cat("persistence",     self._persistence_from,     win_dir)
        self._run_cat("filesystem",      self._filesystem_from,      root)
        # ── Network & USB ────────────────────────────────────────────────────
        self._run_cat("network_cfg",     self._network_cfg_from,     root, win_dir)
        self._run_cat("usb_devices",     self._usb_devices_from,     win_dir)
        # ── Credentials & Security ───────────────────────────────────────────
        self._run_cat("credentials",     self._credentials_from,     win_dir, users_dir)
        self._run_cat("antivirus",       self._antivirus_from,       root)
        self._run_cat("wer_crashes",     self._wer_crashes_from,     root)
        self._run_cat("win_logs",        self._win_logs_from,        win_dir)
        self._run_cat("boot_uefi",       self._boot_uefi_from,       win_dir)
        self._run_cat("encryption",      self._encryption_from,      win_dir)
        self._run_cat("etw_diagnostics", self._etw_diagnostics_from, win_dir)
        # ── Browsers ─────────────────────────────────────────────────────────
        self._run_cat("browser",         self._browser_from,         users_dir)
        self._run_cat("browser_chrome",  self._browser_chrome_from,  users_dir)
        self._run_cat("browser_edge",    self._browser_edge_from,    users_dir)
        self._run_cat("browser_ie",      self._browser_ie_from,      users_dir)
        # ── Email ────────────────────────────────────────────────────────────
        self._run_cat("email_outlook",    self._email_outlook_from,    users_dir)
        self._run_cat("email_thunderbird",self._email_thunderbird_from,users_dir)
        # ── Messaging ────────────────────────────────────────────────────────
        self._run_cat("teams",           self._teams_from,            users_dir)
        self._run_cat("slack",           self._slack_from,            users_dir)
        self._run_cat("discord",         self._discord_from,          users_dir)
        self._run_cat("signal",          self._signal_from,           users_dir)
        self._run_cat("whatsapp",        self._whatsapp_from,         users_dir)
        self._run_cat("telegram",        self._telegram_from,         users_dir)
        # ── Cloud ────────────────────────────────────────────────────────────
        self._run_cat("cloud_onedrive",    self._cloud_onedrive_from,    users_dir)
        self._run_cat("cloud_google_drive",self._cloud_google_drive_from,users_dir)
        self._run_cat("cloud_dropbox",     self._cloud_dropbox_from,     users_dir)
        # ── Remote access ────────────────────────────────────────────────────
        self._run_cat("remote_access",   self._remote_access_from,   root, users_dir)
        self._run_cat("rdp",             self._rdp_from,             users_dir)
        self._run_cat("ssh_ftp",         self._ssh_ftp_from,         users_dir)
        # ── Apps & user data ─────────────────────────────────────────────────
        self._run_cat("lnk",             self._lnk_from,             users_dir)
        self._run_cat("tasks",           self._tasks_from,           win_dir)
        self._run_cat("office",          self._office_from,          users_dir)
        self._run_cat("dev_tools",       self._dev_tools_from,       users_dir)
        self._run_cat("password_managers",self._password_managers_from,users_dir)
        self._run_cat("database_clients",self._database_clients_from,users_dir)
        self._run_cat("gaming",          self._gaming_from,          root, users_dir)
        self._run_cat("windows_apps",    self._windows_apps_from,    users_dir)
        self._run_cat("wsl",             self._wsl_from,             users_dir)
        # ── Infrastructure ───────────────────────────────────────────────────
        self._run_cat("vpn",             self._vpn_from,             root)
        self._run_cat("iis_web",         self._iis_web_from,         root)
        self._run_cat("active_directory",self._active_directory_from,win_dir)
        self._run_cat("virtualization",  self._virtualization_from,  root)
        self._run_cat("recovery",        self._recovery_from,        root)
        self._run_cat("printing",        self._printing_from,        win_dir)
        # ── Heavy / opt-in ───────────────────────────────────────────────────
        self._run_cat("pe",              self._pe_from,              win_dir, users_dir)
        self._run_cat("documents",       self._documents_from,       users_dir)
        self._run_cat("memory_artifacts",self._memory_artifacts_from,root)

    def _evtx_from(self, win_dir: Path) -> None:
        print("  [*] Event Logs (EVTX)")
        evtx_dir = win_dir / "System32" / "winevt" / "Logs"
        if not evtx_dir.exists():
            self._warn(f"EVTX directory not found: {evtx_dir}")
            return
        priority = [
            "Security.evtx", "System.evtx", "Application.evtx",
            "Microsoft-Windows-PowerShell%4Operational.evtx",
            "Microsoft-Windows-Sysmon%4Operational.evtx",
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            "Microsoft-Windows-TaskScheduler%4Operational.evtx",
            "Microsoft-Windows-WinRM%4Operational.evtx",
            "Microsoft-Windows-WindowsDefender%4Operational.evtx",
            "Microsoft-Windows-Bits-Client%4Operational.evtx",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
        ]
        seen: set = set()
        for name in priority:
            src = evtx_dir / name
            try:
                if not src.is_file() or src.stat().st_size == 0:
                    continue
                tmp = self.staging / f"evtx_{name}"
                if self._stage_file(src, tmp) and self._add(tmp, f"evtx/{name}"):
                    seen.add(name)
            except Exception as exc:
                self._warn(f"EVTX {name}: {exc}")
        count = 0
        try:
            all_evtx = sorted(evtx_dir.glob("*.evtx"))
        except Exception as exc:
            self._warn(f"EVTX glob error: {exc}")
            return
        for p in all_evtx:
            if count >= 100:
                break
            try:
                if p.name in seen:
                    continue
                if p.stat().st_size == 0:
                    continue
                tmp = self.staging / f"evtx_{p.name}"
                if self._stage_file(p, tmp) and self._add(tmp, f"evtx/{p.name}"):
                    count += 1
            except Exception as exc:
                self._warn(f"EVTX {p.name}: {exc}")

    def _registry_from(self, win_dir: Path, users_dir: Path) -> None:
        print("  [*] Registry Hives")
        config_dir = win_dir / "System32" / "config"
        for name in ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]:
            src = config_dir / name
            try:
                if not src.is_file():
                    continue
                tmp = self.staging / f"reg_{name}"
                if self._stage_file(src, tmp):
                    self._add(tmp, f"registry/{name}")
            except Exception as exc:
                self._warn(f"Registry {name}: {exc}")
        if users_dir.exists():
            for user_dir in sorted(users_dir.iterdir()):
                if not user_dir.is_dir():
                    continue
                safe = user_dir.name.replace(" ", "_")
                for src_rel, arcname in [
                    ("NTUSER.DAT", f"registry/users/{user_dir.name}/NTUSER.DAT"),
                    (
                        str(Path("AppData") / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"),
                        f"registry/users/{user_dir.name}/USRCLASS.DAT",
                    ),
                ]:
                    src = user_dir / src_rel
                    try:
                        if not src.is_file():
                            continue
                        tmp = self.staging / f"reg_{safe}_{Path(src_rel).name}"
                        if self._stage_file(src, tmp):
                            self._add(tmp, arcname)
                    except Exception as exc:
                        self._warn(f"Registry {user_dir.name}/{Path(src_rel).name}: {exc}")

    def _prefetch_from(self, win_dir: Path) -> None:
        print("  [*] Prefetch Files")
        pf_dir = win_dir / "Prefetch"
        count = 0
        success_count = 0
        error_count = 0
        try:
            pf_files = sorted(pf_dir.glob("*.pf")) if pf_dir.exists() else []
        except Exception as exc:
            self._warn(f"Prefetch glob error: {exc}")
            return
        for p in pf_files:
            if count >= 500:
                break
            count += 1
            try:
                if p.stat().st_size == 0:
                    continue
                tmp = self.staging / f"pf_{p.name}"
                if self._stage_file(p, tmp) and self._add(tmp, f"prefetch/{p.name}"):
                    success_count += 1
                else:
                    error_count += 1
                    if self.verbose and error_count <= 5:
                        self._log(f"Prefetch copy failed: {p.name} (may be WOF-compressed)")
            except PermissionError:
                error_count += 1
                if error_count <= 3:
                    self._warn(f"Prefetch {p.name}: Permission denied")
            except OSError as exc:
                error_count += 1
                if exc.errno == 22 and error_count <= 3:
                    self._log(f"Prefetch {p.name}: Invalid argument (WOF compression)")
            except Exception as exc:
                error_count += 1
                if error_count <= 3:
                    self._warn(f"Prefetch {p.name}: {exc}")
        
        if error_count > 0 and success_count == 0:
            self._warn(f"Prefetch: {error_count} files failed - may be WOF-compressed (Windows 10+)")
        elif error_count > success_count * 2:
            self._log(f"Prefetch: {success_count}/{count} succeeded, {error_count} failed (WOF compression likely)")

    def _lnk_from(self, users_dir: Path) -> None:
        print("  [*] LNK / Recent Items")
        count = 0
        for user_dir in (sorted(users_dir.iterdir()) if users_dir.exists() else []):
            if not user_dir.is_dir():
                continue
            recent = (
                user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            )
            for p in (recent.rglob("*.lnk") if recent.exists() else []):
                if count >= 2000:
                    break
                if self._add(p, f"lnk/{user_dir.name}/{p.name}"):
                    count += 1

    def _browser_from(self, users_dir: Path) -> None:
        print("  [*] Browser Artifacts")
        PROFILES = [
            ("chrome",  "AppData/Local/Google/Chrome/User Data/Default"),
            ("edge",    "AppData/Local/Microsoft/Edge/User Data/Default"),
            ("brave",   "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default"),
            ("opera",   "AppData/Roaming/Opera Software/Opera Stable"),
            ("vivaldi", "AppData/Local/Vivaldi/User Data/Default"),
        ]
        DB_FILES = ["History", "Web Data", "Cookies", "Login Data", "Bookmarks"]
        error_count = 0

        for user_dir in (sorted(users_dir.iterdir()) if users_dir.exists() else []):
            if not user_dir.is_dir():
                continue
            for browser, rel in PROFILES:
                profile_dir = user_dir / Path(rel.replace("/", os.sep))
                for db in DB_FILES:
                    src = profile_dir / db
                    try:
                        if not src.exists() or not src.is_file():
                            continue
                        if src.stat().st_size == 0:
                            continue
                        tmp = self.staging / f"browser_{user_dir.name}_{browser}_{db}"
                        if self._copy_locked(src, tmp):
                            self._add(tmp, f"browser/{browser}/{user_dir.name}/{db}")
                        else:
                            error_count += 1
                            if self.verbose and error_count <= 3:
                                self._log(f"Browser {browser}/{db}: copy failed (file locked?)")
                    except Exception:
                        error_count += 1
            # Firefox
            ff_profiles = (
                user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
            )
            if ff_profiles.exists():
                for prof in ff_profiles.iterdir():
                    if not prof.is_dir():
                        continue
                    for db in ("places.sqlite", "cookies.sqlite", "logins.json", "formhistory.sqlite"):
                        src = prof / db
                        try:
                            if not src.exists() or not src.is_file():
                                continue
                            tmp = self.staging / f"ff_{user_dir.name}_{prof.name}_{db}"
                            if self._copy_locked(src, tmp):
                                self._add(tmp, f"browser/firefox/{user_dir.name}/{prof.name}/{db}")
                        except Exception:
                            pass

    def _tasks_from(self, win_dir: Path) -> None:
        print("  [*] Scheduled Tasks")
        tasks_dir = win_dir / "System32" / "Tasks"
        count = 0
        error_count = 0
        try:
            task_files = list(tasks_dir.rglob("*")) if tasks_dir.exists() else []
        except Exception as exc:
            self._warn(f"Tasks scan error: {exc}")
            return
        for p in task_files:
            if count >= 500:
                break
            try:
                if p.is_file() and not p.suffix:
                    rel = str(p.relative_to(tasks_dir)).replace("\\", "/")
                    if self._add(p, f"scheduled_tasks/{rel}"):
                        count += 1
            except PermissionError:
                error_count += 1
                if error_count <= 3:
                    self._log(f"Task {p.name}: Permission denied (reparse point?)")
            except OSError as exc:
                error_count += 1
                if exc.errno == 22 and error_count <= 3:
                    self._log(f"Task {p.name}: Invalid argument (reparse point/junction)")
            except Exception as exc:
                error_count += 1
                if error_count <= 3:
                    self._warn(f"Task {p.name}: {exc}")
        
        if error_count > 0:
            self._log(f"Scheduled tasks: {error_count} files inaccessible (reparse points common in System32\\Tasks)")

    def _mft_from(self, root: Path) -> None:
        """Copy $MFT directly from the NTFS mount point root."""
        print("  [*] Master File Table ($MFT)")
        mft = root / "$MFT"
        if not mft.exists():
            self._warn("$MFT not found - requires raw volume access (\\\\.\\C:) in dead-box mode")
            return
        try:
            if mft.stat().st_size == 0:
                return
            tmp = self.staging / "mft_$MFT"
            if self._stage_file(mft, tmp):
                self._add(tmp, "mft/C_$MFT")
            else:
                self._warn("$MFT copy failed - file may be locked or requires raw volume handle")
        except PermissionError:
            self._warn("$MFT: Permission denied - run as Administrator or use raw device mode (--disk)")
        except OSError as exc:
            if exc.errno == 22:
                self._warn("$MFT: Invalid argument - NTFS metadata inaccessible in directory mount mode")
            else:
                self._warn(f"$MFT: OSError - {exc}")
        except Exception as exc:
            self._warn(f"$MFT: Error - {exc}")

    def _pe_from(self, win_dir: Path, users_dir: Path) -> None:
        print("  [*] PE / Executable Binaries")
        PE_EXTS  = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".msi", ".hta"}
        MAX_FILE = 200 * 1024 * 1024
        MAX_FILES = 1000
        dirs: list = [win_dir / "Temp"]
        if users_dir.exists():
            for ud in sorted(users_dir.iterdir()):
                if not ud.is_dir():
                    continue
                for rel in [
                    "AppData/Local/Temp", "AppData/Roaming",
                    "Downloads", "Desktop",
                    "AppData/Local/Microsoft/Windows/INetCache",
                ]:
                    dirs.append(ud / Path(rel.replace("/", os.sep)))
        count = 0
        total = 0
        for d in dirs:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*")):
                if count >= MAX_FILES or total >= 2 * 1024 ** 3:
                    break
                if not p.is_file() or p.suffix.lower() not in PE_EXTS:
                    continue
                sz = p.stat().st_size
                if sz == 0 or sz > MAX_FILE:
                    continue
                if self._add(p, f"pe/{d.name}/{p.name}"):
                    count += 1
                    total += sz

    def _documents_from(self, users_dir: Path) -> None:
        print("  [*] Office Documents & PDFs")
        DOC_EXTS = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
                    ".ppt", ".pptx", ".pptm", ".rtf", ".pdf", ".odt", ".ods"}
        MAX_FILE  = 100 * 1024 * 1024
        MAX_FILES = 500
        count = 0
        for ud in (sorted(users_dir.iterdir()) if users_dir.exists() else []):
            if not ud.is_dir():
                continue
            for rel in ["Documents", "Downloads", "Desktop"]:
                d = ud / rel
                if not d.exists():
                    continue
                for p in sorted(d.rglob("*")):
                    if count >= MAX_FILES:
                        break
                    if not p.is_file() or p.suffix.lower() not in DOC_EXTS:
                        continue
                    if p.stat().st_size == 0 or p.stat().st_size > MAX_FILE:
                        continue
                    if self._add(p, f"documents/{ud.name}/{rel}/{p.name}"):
                        count += 1

    # ── ForensicHarvester category methods ────────────────────────────────────

    _USER_SKIP = {"Default", "Default User", "Public", "All Users"}

    def _iter_users(self, users_dir: Path):
        """Yield user subdirectories, skipping built-in system accounts."""
        if not users_dir.exists():
            return
        for d in sorted(users_dir.iterdir()):
            if d.is_dir() and d.name not in self._USER_SKIP:
                yield d

    def _execution_from(self, win_dir: Path) -> None:
        print("  [*] Execution Evidence (SRUM, Amcache, Prefetch)")
        self._add(win_dir / "System32" / "sru" / "SRUDB.dat",    "execution/SRUDB.dat")
        self._add(win_dir / "AppCompat" / "Programs" / "Amcache.hve", "execution/Amcache.hve")
        self._add(win_dir / "System32" / "Amcache.hve",           "execution/Amcache.hve")
        pf = win_dir / "Prefetch"
        count = 0
        for p in (sorted(pf.glob("*.pf")) if pf.exists() else []):
            if count >= 500:
                break
            if self._add(p, f"execution/prefetch/{p.name}"):
                count += 1

    def _persistence_from(self, win_dir: Path) -> None:
        print("  [*] Persistence (Tasks, WMI)")
        for tasks_dir in [win_dir / "System32" / "Tasks", win_dir / "SysWOW64" / "Tasks"]:
            count = 0
            try:
                task_files = list(tasks_dir.rglob("*")) if tasks_dir.exists() else []
            except Exception as exc:
                self._warn(f"Persistence tasks scan ({tasks_dir.name}): {exc}")
                continue
            for p in task_files:
                if count >= 500:
                    break
                try:
                    if p.is_file() and not p.suffix:
                        rel = str(p.relative_to(tasks_dir)).replace("\\", "/")
                        if self._add(p, f"persistence/tasks/{tasks_dir.name}/{rel}"):
                            count += 1
                except Exception as exc:
                    self._warn(f"Persistence task {p.name}: {exc}")
        wmi_repo = win_dir / "System32" / "wbem" / "Repository"
        try:
            self._add(wmi_repo / "OBJECTS.DATA", "persistence/wmi/OBJECTS.DATA")
            self._add(wmi_repo / "INDEX.BTR",    "persistence/wmi/INDEX.BTR")
        except Exception as exc:
            self._warn(f"WMI repo: {exc}")

    def _network_cfg_from(self, root: Path, win_dir: Path) -> None:
        print("  [*] Network Config (Hosts, WLAN, Firewall)")
        self._add(win_dir / "System32" / "drivers" / "etc" / "hosts",
                  "network_cfg/hosts")
        self._add(win_dir / "System32" / "LogFiles" / "Firewall" / "pfirewall.log",
                  "network_cfg/pfirewall.log")
        wlan = root / "ProgramData" / "Microsoft" / "Wlansvc" / "Profiles" / "Interfaces"
        if wlan.exists():
            for p in wlan.rglob("*.xml"):
                self._add(p, f"network_cfg/wlan/{p.parent.name}/{p.name}")

    def _usb_devices_from(self, win_dir: Path) -> None:
        print("  [*] USB Device History")
        inf = win_dir / "INF"
        self._add(inf / "setupapi.dev.log",   "usb_devices/setupapi.dev.log")
        self._add(inf / "setupapi.setup.log",  "usb_devices/setupapi.setup.log")

    def _credentials_from(self, win_dir: Path, users_dir: Path) -> None:
        print("  [*] Credentials (DPAPI, Credential Manager)")
        cfg = win_dir / "System32" / "config"
        try:
            self._add(cfg / "SAM",      "credentials/SAM")
            self._add(cfg / "SECURITY", "credentials/SECURITY")
        except Exception as exc:
            self._warn(f"Credentials hives: {exc}")
        for ud in self._iter_users(users_dir):
            for rel in ["AppData/Local/Microsoft/Credentials",
                        "AppData/Roaming/Microsoft/Credentials",
                        "AppData/Local/Microsoft/Protect"]:
                d = ud / Path(rel.replace("/", os.sep))
                try:
                    items = list(d.rglob("*")) if d.exists() else []
                except Exception:
                    continue
                for p in items:
                    try:
                        if p.is_file():
                            self._add(p, f"credentials/{ud.name}/{rel.split('/')[-1]}/{p.name}")
                    except Exception:
                        pass

    def _antivirus_from(self, root: Path) -> None:
        print("  [*] Antivirus / Windows Defender")
        base = root / "ProgramData" / "Microsoft" / "Windows Defender"
        for sub in ["Quarantine", "Support"]:
            d = base / sub
            try:
                items = list(d.rglob("*")) if d.exists() else []
            except Exception as exc:
                self._warn(f"Antivirus {sub}: {exc}")
                continue
            for p in items:
                try:
                    if p.is_file():
                        self._add(p, f"antivirus/{sub}/{p.name}")
                except Exception:
                    pass

    def _wer_crashes_from(self, root: Path) -> None:
        print("  [*] WER Crash Dumps & Reports")
        base = root / "ProgramData" / "Microsoft" / "Windows" / "WER"
        count = 0
        for sub in ["ReportQueue", "ReportArchive"]:
            d = base / sub
            try:
                items = list(d.rglob("*")) if d.exists() else []
            except Exception as exc:
                self._warn(f"WER {sub}: {exc}")
                continue
            for p in items:
                if count >= 200:
                    break
                try:
                    if p.is_file():
                        if self._add(p, f"wer_crashes/{sub}/{p.name}"):
                            count += 1
                except Exception:
                    pass

    def _win_logs_from(self, win_dir: Path) -> None:
        print("  [*] Windows Logs (CBS, DISM, WU)")
        self._add(win_dir / "Logs" / "CBS" / "CBS.log",   "win_logs/CBS.log")
        self._add(win_dir / "Logs" / "DISM" / "dism.log", "win_logs/dism.log")
        self._add(win_dir / "WindowsUpdate.log",           "win_logs/WindowsUpdate.log")
        panther = win_dir / "Panther"
        if panther.exists():
            for p in panther.glob("*.log"):
                self._add(p, f"win_logs/panther/{p.name}")

    def _filesystem_from(self, root: Path) -> None:
        print("  [*] NTFS Metadata ($MFT, $LogFile, $Boot)")
        for name in ["$MFT", "$LogFile", "$Boot"]:
            src = root / name
            if not src.exists():
                self._warn(f"NTFS metadata {name} not accessible in directory mount mode - requires raw volume handle (\\\\.\\C:)")
                continue
            try:
                if src.stat().st_size == 0:
                    continue
                tmp = self.staging / f"fs_{name.replace('$', '')}"
                if self._stage_file(src, tmp):
                    self._add(tmp, f"filesystem/{name}")
            except PermissionError:
                self._warn(f"Permission denied reading {name} - requires Administrator or raw volume access")
            except OSError as exc:
                if exc.errno == 22:
                    self._warn(f"Invalid argument reading {name} - file system limitation in directory mount mode")
                else:
                    self._warn(f"Error reading {name}: {exc}")
            except Exception as exc:
                self._warn(f"Error reading {name}: {exc}")

    def _boot_uefi_from(self, win_dir: Path) -> None:
        print("  [*] Boot Config (BCD, EFI)")
        cfg = win_dir / "System32" / "config"
        self._add(cfg / "BCD",              "boot_uefi/BCD")
        self._add(win_dir / "bootstat.dat", "boot_uefi/bootstat.dat")

    def _encryption_from(self, win_dir: Path) -> None:
        print("  [*] Encryption Metadata (BitLocker / EFS)")
        self._add(win_dir / "System32" / "FVE" / "BDE-Recovery.txt",
                  "encryption/BDE-Recovery.txt")

    def _etw_diagnostics_from(self, win_dir: Path) -> None:
        print("  [*] ETW Diagnostic Traces")
        d = win_dir / "System32" / "LogFiles" / "WMI"
        count = 0
        for p in (d.glob("*.etl") if d.exists() else []):
            if count >= 50:
                break
            if self._add(p, f"etw_diagnostics/{p.name}"):
                count += 1

    def _browser_chrome_from(self, users_dir: Path) -> None:
        print("  [*] Chrome Browser Artifacts")
        FILES = ["History", "Cookies", "Web Data", "Login Data", "Bookmarks"]
        for ud in self._iter_users(users_dir):
            profile = ud / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
            for f in FILES:
                self._add(profile / f, f"browser_chrome/{ud.name}/{f}")

    def _browser_edge_from(self, users_dir: Path) -> None:
        print("  [*] Edge Browser Artifacts")
        FILES = ["History", "Cookies", "Web Data", "Login Data"]
        for ud in self._iter_users(users_dir):
            profile = ud / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default"
            for f in FILES:
                self._add(profile / f, f"browser_edge/{ud.name}/{f}")

    def _browser_ie_from(self, users_dir: Path) -> None:
        print("  [*] Internet Explorer WebCache")
        FILES = ["WebCacheV01.dat", "WebCacheV24.dat"]
        for ud in self._iter_users(users_dir):
            wc = ud / "AppData" / "Local" / "Microsoft" / "Windows" / "WebCache"
            for f in FILES:
                self._add(wc / f, f"browser_ie/{ud.name}/{f}")

    def _email_outlook_from(self, users_dir: Path) -> None:
        print("  [*] Outlook Email (.pst / .ost)")
        count = 0
        for ud in self._iter_users(users_dir):
            for rel in ["Documents/Outlook Files",
                        "AppData/Local/Microsoft/Outlook"]:
                d = ud / Path(rel.replace("/", os.sep))
                for p in (d.rglob("*.pst") if d.exists() else []):
                    if self._add(p, f"email_outlook/{ud.name}/{p.name}"):
                        count += 1
                for p in (d.rglob("*.ost") if d.exists() else []):
                    if self._add(p, f"email_outlook/{ud.name}/{p.name}"):
                        count += 1

    def _email_thunderbird_from(self, users_dir: Path) -> None:
        print("  [*] Thunderbird Email")
        for ud in self._iter_users(users_dir):
            tb = ud / "AppData" / "Roaming" / "Thunderbird" / "Profiles"
            if tb.exists():
                for prof in tb.iterdir():
                    if prof.is_dir():
                        for p in prof.rglob("*.sqlite"):
                            self._add(p, f"email_thunderbird/{ud.name}/{prof.name}/{p.name}")
                        for p in prof.rglob("*.msf"):
                            self._add(p, f"email_thunderbird/{ud.name}/{prof.name}/{p.name}")

    def _teams_from(self, users_dir: Path) -> None:
        print("  [*] Microsoft Teams")
        PATHS = ["AppData/Roaming/Microsoft/Teams/logs.txt",
                 "AppData/Roaming/Microsoft/Teams/IndexedDB",
                 "AppData/Roaming/Microsoft/Teams/Local Storage"]
        for ud in self._iter_users(users_dir):
            for rel in PATHS:
                p = ud / Path(rel.replace("/", os.sep))
                if p.is_file():
                    self._add(p, f"teams/{ud.name}/{p.name}")
                elif p.is_dir():
                    for f in p.rglob("*"):
                        if f.is_file():
                            self._add(f, f"teams/{ud.name}/{p.name}/{f.name}")

    def _slack_from(self, users_dir: Path) -> None:
        print("  [*] Slack")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Roaming" / "Slack" / "logs"
            if d.exists():
                for p in d.rglob("*.log"):
                    self._add(p, f"slack/{ud.name}/{p.name}")

    def _discord_from(self, users_dir: Path) -> None:
        print("  [*] Discord")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Roaming" / "discord" / "Local Storage"
            if d.exists():
                for p in d.rglob("*"):
                    if p.is_file():
                        self._add(p, f"discord/{ud.name}/{p.name}")

    def _signal_from(self, users_dir: Path) -> None:
        print("  [*] Signal Desktop")
        for ud in self._iter_users(users_dir):
            db = ud / "AppData" / "Roaming" / "Signal" / "databases" / "db.sqlite"
            self._add(db, f"signal/{ud.name}/db.sqlite")

    def _whatsapp_from(self, users_dir: Path) -> None:
        print("  [*] WhatsApp Desktop")
        for ud in self._iter_users(users_dir):
            base = ud / "AppData" / "Local" / "Packages"
            if base.exists():
                for pkg in base.iterdir():
                    if pkg.is_dir() and "WhatsApp" in pkg.name:
                        for p in pkg.rglob("*.db"):
                            self._add(p, f"whatsapp/{ud.name}/{p.name}")

    def _telegram_from(self, users_dir: Path) -> None:
        print("  [*] Telegram Desktop")
        for ud in self._iter_users(users_dir):
            tdata = ud / "AppData" / "Roaming" / "Telegram Desktop" / "tdata"
            if tdata.exists():
                for p in tdata.iterdir():
                    if p.is_file() and p.suffix not in {".db"}:
                        self._add(p, f"telegram/{ud.name}/{p.name}")

    def _cloud_onedrive_from(self, users_dir: Path) -> None:
        print("  [*] OneDrive Sync Artifacts")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Local" / "Microsoft" / "OneDrive"
            if d.exists():
                for p in d.rglob("*.db"):
                    self._add(p, f"cloud_onedrive/{ud.name}/{p.name}")
                for p in d.rglob("*.log"):
                    self._add(p, f"cloud_onedrive/{ud.name}/{p.name}")

    def _cloud_google_drive_from(self, users_dir: Path) -> None:
        print("  [*] Google Drive Sync Artifacts")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Local" / "Google" / "DriveFS"
            if d.exists():
                for p in d.rglob("*.db"):
                    self._add(p, f"cloud_google_drive/{ud.name}/{p.name}")

    def _cloud_dropbox_from(self, users_dir: Path) -> None:
        print("  [*] Dropbox Sync Artifacts")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Local" / "Dropbox"
            if d.exists():
                for p in d.rglob("*.db"):
                    self._add(p, f"cloud_dropbox/{ud.name}/{p.name}")
                for p in d.rglob("*.json"):
                    self._add(p, f"cloud_dropbox/{ud.name}/{p.name}")

    def _remote_access_from(self, root: Path, users_dir: Path) -> None:
        print("  [*] Remote Access (AnyDesk, TeamViewer)")
        tv_logs = root / "ProgramData" / "TeamViewer" / "Logs"
        if tv_logs.exists():
            for p in tv_logs.glob("*.log"):
                self._add(p, f"remote_access/teamviewer/{p.name}")
        for ud in self._iter_users(users_dir):
            ad = ud / "AppData" / "Roaming" / "AnyDesk"
            if ad.exists():
                for p in ad.rglob("*.trace"):
                    self._add(p, f"remote_access/anydesk/{ud.name}/{p.name}")
                for p in ad.rglob("*.conf"):
                    self._add(p, f"remote_access/anydesk/{ud.name}/{p.name}")

    def _rdp_from(self, users_dir: Path) -> None:
        print("  [*] RDP / Terminal Services")
        for ud in self._iter_users(users_dir):
            cache = (ud / "AppData" / "Local" / "Microsoft" /
                     "Terminal Server Client" / "Cache")
            if cache.exists():
                for p in cache.rglob("*"):
                    if p.is_file():
                        self._add(p, f"rdp/{ud.name}/{p.name}")

    def _ssh_ftp_from(self, users_dir: Path) -> None:
        print("  [*] SSH / FTP Clients (PuTTY, WinSCP)")
        for ud in self._iter_users(users_dir):
            ssh = ud / ".ssh"
            if ssh.exists():
                for p in ssh.iterdir():
                    if p.is_file() and "id_" not in p.name:  # skip private keys
                        self._add(p, f"ssh_ftp/{ud.name}/ssh/{p.name}")
            putty = ud / "AppData" / "Roaming" / "PuTTY"
            if putty.exists():
                for p in putty.rglob("*"):
                    if p.is_file():
                        self._add(p, f"ssh_ftp/{ud.name}/putty/{p.name}")
            winscp = ud / "AppData" / "Roaming" / "WinSCP.ini"
            self._add(winscp, f"ssh_ftp/{ud.name}/WinSCP.ini")

    def _office_from(self, users_dir: Path) -> None:
        print("  [*] Office MRU / Trusted Documents")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Roaming" / "Microsoft" / "Office"
            if d.exists():
                for p in d.rglob("*.json"):
                    self._add(p, f"office/{ud.name}/{p.name}")
                for p in d.rglob("Recent"):
                    if p.is_dir():
                        for f in p.iterdir():
                            if f.is_file():
                                self._add(f, f"office/{ud.name}/Recent/{f.name}")

    def _iis_web_from(self, root: Path) -> None:
        print("  [*] IIS Web Server Logs")
        d = root / "inetpub" / "logs" / "LogFiles"
        count = 0
        for p in (d.rglob("*.log") if d.exists() else []):
            if count >= 200:
                break
            if self._add(p, f"iis_web/{p.parent.name}/{p.name}"):
                count += 1
        self._add(root / "Windows" / "System32" / "inetsrv" / "config" / "applicationHost.config",
                  "iis_web/applicationHost.config")

    def _active_directory_from(self, win_dir: Path) -> None:
        print("  [*] Active Directory (NTDS.dit, SYSVOL)")
        ntds = win_dir / "NTDS"
        self._add(ntds / "ntds.dit", "active_directory/ntds.dit")
        self._add(ntds / "edb.log",  "active_directory/edb.log")

    def _dev_tools_from(self, users_dir: Path) -> None:
        print("  [*] Dev Tools (.gitconfig, PS history, .aws)")
        for ud in self._iter_users(users_dir):
            self._add(ud / ".gitconfig",
                      f"dev_tools/{ud.name}/.gitconfig")
            self._add(ud / ".git-credentials",
                      f"dev_tools/{ud.name}/.git-credentials")
            ps_hist = (ud / "AppData" / "Roaming" / "Microsoft" / "Windows" /
                       "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt")
            self._add(ps_hist, f"dev_tools/{ud.name}/ConsoleHost_history.txt")
            aws = ud / ".aws" / "credentials"
            self._add(aws, f"dev_tools/{ud.name}/aws_credentials")
            azure = ud / ".azure" / "accessTokens.json"
            self._add(azure, f"dev_tools/{ud.name}/azure_accessTokens.json")

    def _password_managers_from(self, users_dir: Path) -> None:
        print("  [*] Password Managers (KeePass)")
        count = 0
        for ud in self._iter_users(users_dir):
            for p in ud.rglob("*.kdbx"):
                if count >= 20:
                    break
                if self._add(p, f"password_managers/{ud.name}/{p.name}"):
                    count += 1

    def _vpn_from(self, root: Path) -> None:
        print("  [*] VPN Config (OpenVPN, WireGuard)")
        openvpn = root / "ProgramData" / "OpenVPN" / "config"
        if openvpn.exists():
            for p in openvpn.rglob("*.ovpn"):
                self._add(p, f"vpn/openvpn/{p.name}")
        wg = root / "ProgramData" / "WireGuard"
        if wg.exists():
            for p in wg.rglob("*.conf"):
                self._add(p, f"vpn/wireguard/{p.name}")

    def _windows_apps_from(self, users_dir: Path) -> None:
        print("  [*] Windows UWP / Modern Apps")
        APPS = ["Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe"]
        for ud in self._iter_users(users_dir):
            pkg_base = ud / "AppData" / "Local" / "Packages"
            for app in APPS:
                d = pkg_base / app
                if d.exists():
                    for p in d.rglob("*.sqlite"):
                        self._add(p, f"windows_apps/{ud.name}/{app}/{p.name}")

    def _wsl_from(self, users_dir: Path) -> None:
        print("  [*] WSL Filesystem & Config")
        for ud in self._iter_users(users_dir):
            pkg_base = ud / "AppData" / "Local" / "Packages"
            if pkg_base.exists():
                for pkg in pkg_base.iterdir():
                    if pkg.is_dir() and "CanonicalGroupLimited" in pkg.name:
                        cfg = pkg / "LocalState" / "rootfs" / "etc"
                        if cfg.exists():
                            for p in ["passwd", "shadow", "bash.bashrc"]:
                                self._add(cfg / p, f"wsl/{ud.name}/{p}")

    def _virtualization_from(self, root: Path) -> None:
        print("  [*] Virtualization (Hyper-V, Docker)")
        hv = root / "ProgramData" / "Microsoft" / "Windows" / "Hyper-V"
        if hv.exists():
            for p in hv.rglob("*.vhd"):
                self._add(p, f"virtualization/hyperv/{p.name}")
            for p in hv.rglob("*.vhdx"):
                self._add(p, f"virtualization/hyperv/{p.name}")

    def _recovery_from(self, root: Path) -> None:
        print("  [*] Recovery (VSS, Windows.old)")
        svi = root / "System Volume Information"
        if svi.exists():
            for p in svi.iterdir():
                if p.is_file():
                    self._add(p, f"recovery/svi/{p.name}")

    def _database_clients_from(self, users_dir: Path) -> None:
        print("  [*] Database Clients (SSMS, DBeaver)")
        for ud in self._iter_users(users_dir):
            for rel in ["AppData/Roaming/Microsoft SQL Server Management Studio",
                        "AppData/Roaming/DBeaverData"]:
                d = ud / Path(rel.replace("/", os.sep))
                if d.exists():
                    for p in d.rglob("*.xml"):
                        self._add(p, f"database_clients/{ud.name}/{rel.split('/')[-1]}/{p.name}")
                    for p in d.rglob("*.ini"):
                        self._add(p, f"database_clients/{ud.name}/{rel.split('/')[-1]}/{p.name}")

    def _gaming_from(self, root: Path, users_dir: Path) -> None:
        print("  [*] Gaming Platforms (Steam, Epic)")
        epic = root / "ProgramData" / "Epic" / "EpicGamesLauncher" / "Data" / "Logs"
        if epic.exists():
            for p in epic.glob("*.log"):
                self._add(p, f"gaming/epic/{p.name}")
        for ud in self._iter_users(users_dir):
            steam = ud / "AppData" / "Local" / "Steam"
            if steam.exists():
                for p in steam.rglob("*.vdf"):
                    self._add(p, f"gaming/steam/{ud.name}/{p.name}")

    def _printing_from(self, win_dir: Path) -> None:
        print("  [*] Print Spool Files")
        spool = win_dir / "System32" / "spool" / "PRINTERS"
        count = 0
        for p in (spool.iterdir() if spool.exists() else []):
            if count >= 100:
                break
            if p.is_file() and self._add(p, f"printing/{p.name}"):
                count += 1

    def _memory_artifacts_from(self, root: Path) -> None:
        print("  [*] Memory Artifacts (pagefile, hiberfil)")
        for name in ["pagefile.sys", "hiberfil.sys", "swapfile.sys"]:
            self._add(root / name, f"memory_artifacts/{name}")


# ─────────────────────────────────────────────────────────────────────────────
# Upload helper
# ─────────────────────────────────────────────────────────────────────────────

def upload_to_fo(zip_path: Path, api_url: str, case_id: str, api_token: str = "") -> None:
    import urllib.request
    import urllib.error

    url      = f"{api_url.rstrip('/')}/cases/{case_id}/ingest"
    boundary = f"fo_boundary_{TS_NOW}"

    print(f"\n  [*] Uploading {zip_path.name} → {url}")

    with open(zip_path, "rb") as fh:
        file_data = fh.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files"; filename="{zip_path.name}"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            print(f"  [+] Upload successful  (HTTP {resp.status})")
    except urllib.error.HTTPError as exc:
        body_preview = exc.read(256).decode(errors="replace")
        if exc.code == 401:
            print(
                f"  [!] Upload failed: HTTP 401 Unauthorized — "
                f"pass --api-token <your JWT token> or embed it at download time.",
                file=sys.stderr,
            )
        else:
            print(f"  [!] Upload failed: HTTP {exc.code} — {body_preview}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"  [!] Upload error: {exc}", file=sys.stderr)
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fo-harvester",
        description="ForensicsOperator Harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output",    "-o", type=Path, default=None,
                        help="Full path for the output ZIP (overrides config.json output_dir)")
    parser.add_argument("--api-url",   type=str, default=None)
    parser.add_argument("--case-id",   type=str, default=None)
    parser.add_argument("--api-token", type=str, default=None)
    parser.add_argument("--collect",   type=str, default=None,
                        help="Override categories: comma-separated keys (e.g. evtx,registry)")
    parser.add_argument("--dry-run",   action="store_true")
    parser.add_argument("--verbose",   "-v", action="store_true")
    parser.add_argument(
        "--skip-problematic", action="store_true",
        help="Skip artifact categories known to fail in dead-box directory mode",
    )
    parser.add_argument(
        "--path", type=str, default=None,
        help="Already-mounted Windows filesystem root (e.g. /mnt/evidence or E:\\)",
    )
    parser.add_argument(
        "--disk", type=str, default=None,
        help="Raw block device to mount — Linux only (requires ntfs-3g / dislocker)",
    )
    parser.add_argument(
        "--bitlocker-key", type=str, default=None, dest="bitlocker_key",
        help="BitLocker recovery key — stays local, never stored in config.json",
    )
    args = parser.parse_args()

    t_start = time.monotonic()

    # Merge: config.json (EMBEDDED_CONFIG) < CLI args (CLI always wins)
    cfg = {**EMBEDDED_CONFIG}
    if args.api_url:   cfg["api_url"]   = args.api_url
    if args.case_id:   cfg["case_id"]   = args.case_id
    if args.api_token: cfg["api_token"] = args.api_token
    if args.collect:   cfg["collect"]   = args.collect.split(",")

    api_url   = cfg.get("api_url",   "")
    case_id   = cfg.get("case_id",   "")
    api_token = cfg.get("api_token", "")
    case_name = cfg.get("case_name", "") or ""

    # Build output path — case_name goes in the filename if provided
    if args.output:
        output = Path(args.output)
    else:
        out_dir   = Path(cfg.get("output_dir", "./output"))
        name_parts = ["fo-artifacts"]
        if case_name:
            name_parts.append(case_name.replace(" ", "_"))
        name_parts += [HOSTNAME, TS_NOW]
        filename = "-".join(name_parts) + ".zip"
        output   = out_dir / filename

    # Input source — CLI only (never stored in config.json)
    path_arg      = args.path or ""
    disk          = args.disk or ""
    bitlocker_key = args.bitlocker_key or ""
    skip_problematic = args.skip_problematic

    # Live Windows: use ExternalDiskCollector(C:\) to get all 52 _from() methods
    _live_windows = IS_WINDOWS and not path_arg and not disk
    if _live_windows:
        path_arg = os.environ.get("SystemDrive", "C:") + "\\"

    # Collect set
    raw_collect = cfg.get("collect", [])
    if raw_collect:
        collect_set = set(raw_collect)
    elif path_arg or disk:
        collect_set = ExternalDiskCollector.DEFAULT_COLLECT
    elif IS_WINDOWS:
        collect_set = DEFAULT_WINDOWS
    elif IS_MACOS:
        collect_set = DEFAULT_MACOS
    else:
        collect_set = DEFAULT_LINUX

    # ── Header ───────────────────────────────────────────────────────────────
    print(BANNER)
    print(f"  Host      : {HOSTNAME}")
    print(f"  OS        : {platform.system()} {platform.release()} {platform.machine()}")
    if case_name:
        print(f"  Case      : {case_name}")
    print(f"  Output    : {output}")
    if api_url and case_id:
        print(f"  Upload    : {api_url}  →  case {case_id}")
    print(f"  Categories: {len(collect_set)}")
    if _live_windows:
        print(f"  Mode      : live Windows  ({path_arg})")
    elif path_arg:
        print(f"  Mode      : dead-box directory  ({path_arg})")
    elif disk:
        print(f"  Mode      : dead-box raw device  ({disk})")
    else:
        print(f"  Mode      : live {platform.system()}")
    if bitlocker_key:
        print(f"  BitLocker : key provided ({len(bitlocker_key)} chars)")

    # ── Collection ───────────────────────────────────────────────────────────
    print(f"\n{_HR}")
    print(f"  Collecting forensic artifacts")
    print(f"{_HR}\n")

    # Check for dead-box limitations and warn user
    if path_arg or disk:
        temp_coll = Collector.__new__(Collector)
        temp_coll.collect = collect_set
        temp_coll.verbose = args.verbose
        limitations = temp_coll._check_deadbox_mode()
        if limitations:
            print(f"  ⚠  Dead-box directory mode detected")
            print(f"     The following categories may fail or produce limited results:")
            for cat, reason in limitations.items():
                if args.skip_problematic and cat in collect_set:
                    print(f"       • {cat:<20} - SKIPPED ({reason[:50]}...)")
                else:
                    print(f"       • {cat:<20} ({reason[:50]}...)")
            print()
            
            if args.skip_problematic:
                # Remove problematic categories from collection set
                collect_set = collect_set - set(limitations.keys())
                print(f"     Adjusted collection set: {len(collect_set)} categories\n")

    external_root = path_arg or disk or ""

    if external_root:
        ext_path = Path(external_root)
        if disk and not ext_path.is_dir() and not IS_LINUX:
            print("  Raw block-device collection requires Linux (ntfs-3g + dislocker).",
                  file=sys.stderr)
            sys.exit(1)
        collector: Collector = ExternalDiskCollector(
            external_root, bitlocker_key=bitlocker_key,
            output=output, collect=collect_set, verbose=args.verbose, 
            dry_run=args.dry_run, skip_problematic=skip_problematic,
        )
    elif IS_WINDOWS:
        collector = WindowsCollector(output, collect_set, args.verbose, args.dry_run, skip_problematic)
    elif IS_MACOS:
        collector = MacOSCollector(output, collect_set, args.verbose, args.dry_run, skip_problematic)
    elif IS_LINUX:
        collector = LinuxCollector(output, collect_set, args.verbose, args.dry_run, skip_problematic)
    else:
        print(f"  Unsupported OS: {platform.system()}", file=sys.stderr)
        sys.exit(1)

    collector.collect_all()
    t_collect = time.monotonic() - t_start

    # ── Dry-run report ───────────────────────────────────────────────────────
    if args.dry_run:
        print(f"\n{_HR}")
        print(f"  Dry run — {len(collector._items)} files would be archived")
        print(_HR)
        for arcname, _ in collector._items:
            print(f"    {arcname}")
        collector.cleanup()
        return

    # ── Package ──────────────────────────────────────────────────────────────
    collector.package()
    t_total = time.monotonic() - t_start

    # ── Upload ───────────────────────────────────────────────────────────────
    if api_url and case_id:
        upload_to_fo(output, api_url, case_id, api_token=api_token)
    elif api_url or case_id:
        print("  Both --api-url and --case-id are required for upload.", file=sys.stderr)

    collector.cleanup()

    # ── Results summary ───────────────────────────────────────────────────────
    results  = collector._results
    n_ok     = sum(1 for r in results if r["ok"])
    n_fail   = len(results) - n_ok
    n_files  = len(collector._items)
    n_warns  = len(collector._errors)

    print(f"\n{_HR}")
    print(f"  Results")
    print(_HR)
    print()

    if n_fail == 0:
        print(f"  ✓  All {n_ok} categories collected")
    else:
        print(f"  ✓  {n_ok} categor{'y' if n_ok == 1 else 'ies'} collected")
        print(f"  ✗  {n_fail} categor{'y' if n_fail == 1 else 'ies'} found no files:")
        for r in results:
            if not r["ok"]:
                hint = f"  ({r['errors'][0][:50]})" if r["errors"] else ""
                print(f"       · {r['label']}{hint}")

    print()
    print(f"  Files     : {n_files}")
    print(f"  Collection: {t_collect:.1f}s")
    print(f"  Total     : {t_total:.1f}s")

    if n_warns:
        print(f"\n  ⚠  {n_warns} warning(s):")
        for msg in collector._errors[:8]:
            print(f"       · {msg[:72]}")
        if n_warns > 8:
            print(f"       · … and {n_warns - 8} more")

    print(f"\n{_HR}\n")


if __name__ == "__main__":
    main()
