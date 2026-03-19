#!/usr/bin/env python3
"""
ForensicsOperator Artifact Collector
=====================================
Collect forensic artifacts from a live Windows or Linux system and package
them as a timestamped ZIP archive ready for upload to ForensicsOperator.

Windows  — run as Administrator for full collection (registry, EVTX, Prefetch,
           LNK, browser artifacts, system triage data)
Linux    — run as root for full collection (auth logs, journal, shell history,
           cron, SSH, network state, running processes)

Usage
-----
  # Collect locally (default output: fo-artifacts-<HOST>-<TIMESTAMP>.zip)
  fo-collector

  # Custom output path
  fo-collector --output /cases/evidence.zip

  # Collect and upload directly to a ForensicsOperator case
  fo-collector --api-url http://forensics.internal/api/v1 --case-id <CASE_ID>

  # Preview what would be collected without writing anything
  fo-collector --dry-run --verbose

Build
-----
  Windows EXE:  pyinstaller --onefile --name fo-collector collect.py
  Linux ELF:    pyinstaller --onefile --name fo-collector collect.py
"""
from __future__ import annotations

import argparse
import datetime
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

VERSION  = "1.0.0"
HOSTNAME = socket.gethostname()
TS_NOW   = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MACOS   = platform.system() == "Darwin"

BANNER = f"""
╔══════════════════════════════════════════════════════════╗
║         ForensicsOperator Artifact Collector  v{VERSION}       ║
╚══════════════════════════════════════════════════════════╝"""


# ─────────────────────────────────────────────────────────────────────────────
# Base Collector
# ─────────────────────────────────────────────────────────────────────────────

class Collector:
    def __init__(self, output: Path, verbose: bool = False, dry_run: bool = False):
        self.output   = output
        self.verbose  = verbose
        self.dry_run  = dry_run
        self.staging  = Path(tempfile.mkdtemp(prefix="fo_collect_"))
        self._items: list[tuple[str, Path]] = []   # (arcname, src_path)
        self._errors: list[str] = []

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"    {msg}")

    def _warn(self, msg: str) -> None:
        self._errors.append(msg)
        print(f"  [!] {msg}", file=sys.stderr)

    def _info(self, msg: str) -> None:
        print(f"  [*] {msg}")

    # ── File helpers ──────────────────────────────────────────────────────────

    def _add(self, src: Path, arcname: str) -> bool:
        """Register a file for archiving. Returns True on success."""
        if not src.exists():
            self._log(f"missing: {src}")
            return False
        if not src.is_file():
            return False
        size = src.stat().st_size
        if size == 0:
            self._log(f"empty:   {src.name}")
            return False
        self._items.append((arcname, src))
        self._log(f"ok  ({size:>10,} B)  {arcname}")
        return True

    def _copy_locked(self, src: Path, dest: Path) -> bool:
        """Copy a file that may be open/locked by the OS."""
        try:
            shutil.copy2(str(src), str(dest))
            return True
        except (PermissionError, OSError):
            return False

    def _run_cmd(self, cmd: list[str], timeout: int = 30) -> str:
        """Run a subprocess and return stdout. Empty string on failure."""
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
        """Write content to staging, add to archive."""
        dest = self.staging / filename
        try:
            dest.write_text(content, encoding="utf-8", errors="replace")
            self._add(dest, arcname)
        except Exception as exc:
            self._warn(f"Could not write {filename}: {exc}")

    # ── Abstract ──────────────────────────────────────────────────────────────

    def collect(self) -> None:
        raise NotImplementedError

    # ── Packaging ─────────────────────────────────────────────────────────────

    def package(self) -> None:
        n = len(self._items)
        print(f"\n  [+] Packaging {n} file{'s' if n != 1 else ''} → {self.output.name}")
        with zipfile.ZipFile(str(self.output), "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for arcname, path in self._items:
                try:
                    zf.write(str(path), arcname)
                except Exception as exc:
                    self._warn(f"Archive failed for {arcname}: {exc}")

        size_mb = self.output.stat().st_size / (1024 * 1024)
        print(f"  [+] Archive ready: {self.output}  ({size_mb:.1f} MB)")

    def cleanup(self) -> None:
        shutil.rmtree(self.staging, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Windows Collector
# ─────────────────────────────────────────────────────────────────────────────

class WindowsCollector(Collector):

    def collect(self) -> None:
        self._evtx()
        self._registry()
        self._prefetch()
        self._lnk()
        self._browser()
        self._scheduled_tasks()
        self._system_triage()

    # ── Event Logs ────────────────────────────────────────────────────────────

    def _evtx(self) -> None:
        self._info("Event Logs (EVTX)")
        evtx_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "winevt" / "Logs"
        if not evtx_dir.exists():
            self._warn(f"EVTX directory not found: {evtx_dir}")
            return

        # High-priority channels first
        priority = [
            "Security.evtx",
            "System.evtx",
            "Application.evtx",
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
            p = evtx_dir / name
            if self._add(p, f"evtx/{name}"):
                seen.add(name)

        # Remaining logs (capped at 100 additional)
        count = 0
        for p in sorted(evtx_dir.glob("*.evtx")):
            if count >= 100:
                break
            if p.name not in seen and self._add(p, f"evtx/{p.name}"):
                count += 1

    # ── Registry ──────────────────────────────────────────────────────────────

    def _registry(self) -> None:
        self._info("Registry hives")
        staging_reg = self.staging / "registry"
        staging_reg.mkdir(exist_ok=True)

        # Export live HKLM hives via reg.exe (requires elevation)
        hklm_hives = {
            "SYSTEM":   "HKLM\\SYSTEM",
            "SOFTWARE": "HKLM\\SOFTWARE",
            "SAM":      "HKLM\\SAM",
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
                    self._warn(f"reg.exe SAVE {name} failed (elevation required?)")
            except FileNotFoundError:
                self._warn("reg.exe not found")
            except Exception as exc:
                self._warn(f"reg.exe SAVE {name}: {exc}")

        # Per-user hives (NTUSER.DAT, USRCLASS.DAT) — may be locked
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        for user_dir in sorted(users_dir.iterdir()) if users_dir.exists() else []:
            if not user_dir.is_dir():
                continue
            for rel, arc_suffix in [
                ("NTUSER.DAT",
                 "NTUSER.DAT"),
                (r"AppData\Local\Microsoft\Windows\UsrClass.dat",
                 "USRCLASS.DAT"),
            ]:
                src  = user_dir / rel
                tmp  = staging_reg / f"{user_dir.name}_{arc_suffix}"
                if self._copy_locked(src, tmp):
                    self._add(tmp, f"registry/users/{user_dir.name}/{arc_suffix}")

    # ── Prefetch ──────────────────────────────────────────────────────────────

    def _prefetch(self) -> None:
        self._info("Prefetch files")
        pf_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
        count = 0
        for p in sorted(pf_dir.glob("*.pf")) if pf_dir.exists() else []:
            if count >= 500:
                break
            if self._add(p, f"prefetch/{p.name}"):
                count += 1

    # ── LNK / Recent Items ────────────────────────────────────────────────────

    def _lnk(self) -> None:
        self._info("LNK / Recent Items")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        count = 0
        for user_dir in sorted(users_dir.iterdir()) if users_dir.exists() else []:
            if not user_dir.is_dir():
                continue
            recent_dir = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            for p in (recent_dir.rglob("*.lnk") if recent_dir.exists() else []):
                if count >= 2000:
                    break
                if self._add(p, f"lnk/{user_dir.name}/{p.name}"):
                    count += 1

    # ── Browser Artifacts ─────────────────────────────────────────────────────

    def _browser(self) -> None:
        self._info("Browser artifacts")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"

        # (browser_tag, relative_path_from_user_dir)
        CHROME_EDGE_FILES = [
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\History"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Web Data"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Cookies"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Login Data"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\History"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\Cookies"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\Web Data"),
        ]

        for user_dir in sorted(users_dir.iterdir()) if users_dir.exists() else []:
            if not user_dir.is_dir():
                continue

            # Chromium-based browsers
            for browser, rel in CHROME_EDGE_FILES:
                src = user_dir / rel
                tmp = self.staging / f"{user_dir.name}_{browser}_{Path(rel).name}"
                if self._copy_locked(src, tmp):
                    self._add(tmp, f"browser/{browser}/{user_dir.name}/{Path(rel).name}")

            # Firefox — enumerate profiles
            ff_base = user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
            if ff_base.exists():
                for profile_dir in ff_base.iterdir():
                    if not profile_dir.is_dir():
                        continue
                    for db in ("places.sqlite", "cookies.sqlite", "logins.json",
                               "formhistory.sqlite"):
                        src = profile_dir / db
                        tmp = self.staging / f"{user_dir.name}_ff_{profile_dir.name}_{db}"
                        if self._copy_locked(src, tmp):
                            self._add(tmp, f"browser/firefox/{user_dir.name}/{profile_dir.name}/{db}")

    # ── Scheduled Tasks ───────────────────────────────────────────────────────

    def _scheduled_tasks(self) -> None:
        self._info("Scheduled Tasks (XML)")
        tasks_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        count = 0
        for p in (tasks_dir.rglob("*") if tasks_dir.exists() else []):
            if count >= 500:
                break
            if p.is_file() and not p.suffix:   # task files have no extension
                rel = p.relative_to(tasks_dir)
                if self._add(p, f"scheduled_tasks/{rel}"):
                    count += 1

    # ── System Triage ─────────────────────────────────────────────────────────

    def _system_triage(self) -> None:
        self._info("System triage (live commands)")
        lines: list[str] = []

        for header, cmd in [
            ("SYSTEM INFO",          ["systeminfo"]),
            ("NETWORK CONFIG",       ["ipconfig", "/all"]),
            ("NETWORK CONNECTIONS",  ["netstat", "-ano"]),
            ("ARP CACHE",            ["arp", "-a"]),
            ("DNS CACHE",            ["ipconfig", "/displaydns"]),
            ("RUNNING PROCESSES",    ["tasklist", "/v", "/fo", "list"]),
            ("LOCAL USERS",          ["net", "user"]),
            ("LOCAL GROUPS",         ["net", "localgroup"]),
            ("ADMINISTRATORS",       ["net", "localgroup", "administrators"]),
            ("SERVICES",             ["sc", "query", "state=", "all"]),
            ("STARTUP ITEMS",        ["wmic", "startup", "list", "full"]),
            ("SCHEDULED TASKS",      ["schtasks", "/query", "/fo", "list", "/v"]),
            ("SHARES",               ["net", "share"]),
            ("OPEN FILES",           ["openfiles", "/query", "/fo", "list"]),
            ("INSTALLED SOFTWARE",   ["wmic", "product", "get",
                                      "Name,Version,InstallDate", "/format:list"]),
            ("AUTORUN REGISTRY",     ["reg", "query",
                                      r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]),
            ("ENVIRONMENT",          ["set"]),
        ]:
            lines.append(f"\n{'='*60}\n{header}\n{'='*60}")
            lines.append(self._run_cmd(cmd, timeout=45))

        self._write_text("system_triage.txt", "\n".join(lines), "system_triage.txt")


# ─────────────────────────────────────────────────────────────────────────────
# Linux Collector
# ─────────────────────────────────────────────────────────────────────────────

class LinuxCollector(Collector):

    def collect(self) -> None:
        self._logs()
        self._shell_history()
        self._system_config()
        self._cron()
        self._ssh_artifacts()
        self._system_triage()

    # ── System Logs ───────────────────────────────────────────────────────────

    def _logs(self) -> None:
        self._info("System logs")
        log_dir = Path("/var/log")

        PRIORITY = [
            "auth.log", "syslog", "messages", "secure",
            "kern.log", "daemon.log", "user.log", "cron",
            "audit/audit.log",
            "apache2/access.log", "apache2/error.log",
            "nginx/access.log", "nginx/error.log",
            "dpkg.log", "apt/history.log",
        ]
        for name in PRIORITY:
            self._add(log_dir / name, f"logs/{name}")

        # Rotated / compressed logs
        for p in sorted(log_dir.rglob("*.gz"))[:80]:
            self._add(p, f"logs/{p.relative_to(log_dir)}")
        for p in sorted(log_dir.rglob("*.1"))[:30]:
            self._add(p, f"logs/{p.relative_to(log_dir)}")

        # Systemd journal export
        journal_tmp = self.staging / "journal.log"
        out = self._run_cmd(
            ["journalctl", "--no-pager", "-o", "short-iso", "-n", "100000"],
            timeout=120,
        )
        if out:
            journal_tmp.write_text(out, encoding="utf-8", errors="replace")
            self._add(journal_tmp, "logs/journal.log")

    # ── Shell Histories ───────────────────────────────────────────────────────

    def _shell_history(self) -> None:
        self._info("Shell histories")
        HIST_FILES = [
            ".bash_history", ".zsh_history", ".sh_history",
            ".python_history", ".mysql_history", ".psql_history",
        ]
        candidates: list[Path] = [Path("/root")]
        home = Path("/home")
        if home.exists():
            candidates += sorted(home.iterdir())

        for user_dir in candidates:
            if not user_dir.is_dir():
                continue
            for hist in HIST_FILES:
                self._add(user_dir / hist, f"history/{user_dir.name}/{hist}")

    # ── System Configuration ──────────────────────────────────────────────────

    def _system_config(self) -> None:
        self._info("System configuration files")
        for path_str in [
            "/etc/passwd", "/etc/group", "/etc/shadow",
            "/etc/sudoers", "/etc/hosts", "/etc/hostname",
            "/etc/resolv.conf", "/etc/crontab",
            "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
            "/etc/os-release", "/etc/issue",
            "/proc/version", "/proc/cmdline",
        ]:
            p = Path(path_str)
            self._add(p, f"config/{p.name}")

        # sudoers.d
        sudoers_d = Path("/etc/sudoers.d")
        if sudoers_d.exists():
            for f in sorted(sudoers_d.iterdir()):
                if f.is_file():
                    self._add(f, f"config/sudoers.d/{f.name}")

    # ── Cron ──────────────────────────────────────────────────────────────────

    def _cron(self) -> None:
        self._info("Cron jobs")
        for cron_dir_str in [
            "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
            "/etc/cron.weekly", "/etc/cron.monthly",
        ]:
            cron_dir = Path(cron_dir_str)
            if cron_dir.exists():
                for f in sorted(cron_dir.iterdir()):
                    if f.is_file():
                        self._add(f, f"cron/{cron_dir.name}/{f.name}")

        # User crontabs
        spool = Path("/var/spool/cron/crontabs")
        if spool.exists():
            for ct in sorted(spool.iterdir()):
                self._add(ct, f"cron/crontabs/{ct.name}")

        # Systemd timers
        out = self._run_cmd(["systemctl", "list-timers", "--all", "--no-pager"])
        if out:
            self._write_text("systemd_timers.txt", out, "cron/systemd_timers.txt")

    # ── SSH Artifacts ─────────────────────────────────────────────────────────

    def _ssh_artifacts(self) -> None:
        self._info("SSH authorized keys / known_hosts")
        candidates: list[Path] = [Path("/root")]
        home = Path("/home")
        if home.exists():
            candidates += sorted(home.iterdir())

        PRIVATE_KEYS = {"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}

        for user_dir in candidates:
            if not user_dir.is_dir():
                continue
            ssh_dir = user_dir / ".ssh"
            if not ssh_dir.exists():
                continue
            for f in sorted(ssh_dir.iterdir()):
                if f.is_file() and f.name not in PRIVATE_KEYS:
                    self._add(f, f"ssh/{user_dir.name}/{f.name}")

    # ── Live System Triage ────────────────────────────────────────────────────

    def _system_triage(self) -> None:
        self._info("System triage (live commands)")
        lines: list[str] = []

        for header, cmd in [
            ("UNAME",             ["uname", "-a"]),
            ("UPTIME",            ["uptime"]),
            ("PROCESSES",         ["ps", "auxf"]),
            ("NETWORK SOCKETS",   ["ss", "-tulpan"]),
            ("NETWORK INTERFACES",["ip", "addr"]),
            ("ROUTING TABLE",     ["ip", "route"]),
            ("ARP TABLE",         ["arp", "-n"]),
            ("LISTENING PORTS",   ["netstat", "-tlnp"]),
            ("CURRENT USERS",     ["who"]),
            ("LAST LOGINS",       ["last", "-F", "-n", "200"]),
            ("FAILED LOGINS",     ["lastb", "-n", "100"]),
            ("OPEN FILES",        ["lsof", "-nP"]),
            ("MOUNTS",            ["mount"]),
            ("DISK USAGE",        ["df", "-h"]),
            ("BLOCK DEVICES",     ["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,UUID"]),
            ("ENVIRONMENT",       ["env"]),
            ("LOADED MODULES",    ["lsmod"]),
            ("STARTUP SERVICES",  ["systemctl", "list-units", "--type=service", "--all", "--no-pager"]),
            ("INSTALLED PKGS",    ["dpkg", "-l"]),          # Debian/Ubuntu
            ("INSTALLED PKGS RPM",["rpm", "-qa"]),          # RHEL/CentOS
            ("SUID FILES",        ["find", "/", "-perm", "-4000", "-type", "f", "-ls"]),
            ("WORLD-WRITABLE",    ["find", "/tmp", "/var/tmp", "-type", "f", "-ls"]),
            ("CRONTAB ROOT",      ["crontab", "-l"]),
            ("SUDO VERSION",      ["sudo", "-V"]),
        ]:
            lines.append(f"\n{'='*60}\n{header}\n{'='*60}")
            lines.append(self._run_cmd(cmd, timeout=30))

        self._write_text("system_triage.txt", "\n".join(lines), "system_triage.txt")


# ─────────────────────────────────────────────────────────────────────────────
# Upload helper
# ─────────────────────────────────────────────────────────────────────────────

def upload_to_fo(zip_path: Path, api_url: str, case_id: str) -> None:
    """
    Upload the collected ZIP to ForensicsOperator via the ingest API.
    Uses only stdlib — no requests dependency needed.
    """
    import urllib.request
    import urllib.error

    url      = f"{api_url.rstrip('/')}/cases/{case_id}/ingest"
    boundary = f"fo_boundary_{datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')}"

    print(f"\n  [*] Uploading {zip_path.name} → {url}")

    with open(zip_path, "rb") as fh:
        file_data = fh.read()

    part_header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files"; filename="{zip_path.name}"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode()
    part_footer = f"\r\n--{boundary}--\r\n".encode()
    body = part_header + file_data + part_footer

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            print(f"  [+] Upload successful  (HTTP {resp.status})")
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read(512)
        print(f"  [!] Upload failed: HTTP {exc.code} — {body_bytes.decode(errors='replace')}",
              file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"  [!] Upload error: {exc}", file=sys.stderr)
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fo-collector",
        description="ForensicsOperator Artifact Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  fo-collector
  fo-collector --output /tmp/evidence.zip
  fo-collector --api-url http://fo.internal/api/v1 --case-id abc123def456
  fo-collector --dry-run --verbose
        """,
    )
    parser.add_argument("--output", "-o", type=Path, default=None,
                        help="Output ZIP path (default: fo-artifacts-<HOST>-<TIMESTAMP>.zip)")
    parser.add_argument("--api-url", type=str, default=None,
                        help="ForensicsOperator API base URL for direct upload")
    parser.add_argument("--case-id", type=str, default=None,
                        help="Case ID to upload artifacts into")
    parser.add_argument("--dry-run", action="store_true",
                        help="List files that would be collected without writing")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose per-file output")
    args = parser.parse_args()

    output = args.output or Path.cwd() / f"fo-artifacts-{HOSTNAME}-{TS_NOW}.zip"

    print(BANNER)
    print(f"  Host    : {HOSTNAME}")
    print(f"  OS      : {platform.system()} {platform.release()} {platform.machine()}")
    print(f"  Output  : {output}")
    if args.api_url:
        print(f"  Upload  : {args.api_url}  case={args.case_id}")
    print()

    if IS_WINDOWS:
        collector: Collector = WindowsCollector(output, args.verbose, args.dry_run)
    elif IS_LINUX or IS_MACOS:
        collector = LinuxCollector(output, args.verbose, args.dry_run)
    else:
        print(f"  [!] Unsupported OS: {platform.system()}", file=sys.stderr)
        sys.exit(1)

    collector.collect()

    if args.dry_run:
        print(f"\n  [Dry run] Would archive {len(collector._items)} files:")
        for arcname, _ in collector._items:
            print(f"    {arcname}")
    else:
        collector.package()

        if args.api_url and args.case_id:
            upload_to_fo(output, args.api_url, args.case_id)
        elif args.api_url or args.case_id:
            print("  [!] Both --api-url and --case-id are required for upload.",
                  file=sys.stderr)

    collector.cleanup()

    if collector._errors:
        print(f"\n  [{len(collector._errors)} warning(s) during collection — "
              "some artifacts may be missing]")


if __name__ == "__main__":
    main()
