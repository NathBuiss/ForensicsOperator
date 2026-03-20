#!/usr/bin/env python3
"""
TraceX Artifact Collector
==========================
Collect forensic artifacts from a live Windows or Linux system and package
them as a timestamped ZIP archive, then optionally upload directly to a case.

Usage
-----
  tracex-collector                                           # collect everything
  tracex-collector --collect evtx,registry,prefetch          # selective collection
  tracex-collector --api-url http://TRACEX/api/v1 --case-id XYZ  # upload to case
  tracex-collector --output /tmp/evidence.zip                # custom output path
  tracex-collector --dry-run --verbose                       # preview only

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
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

VERSION  = "1.1.0"
HOSTNAME = socket.gethostname()
TS_NOW   = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MACOS   = platform.system() == "Darwin"

BANNER = f"""
╔══════════════════════════════════════════════════════════╗
║              TraceX Artifact Collector  v{VERSION}             ║
╚══════════════════════════════════════════════════════════╝"""

# Default collection sets — all enabled when nothing is specified
DEFAULT_WINDOWS = {"evtx", "registry", "prefetch", "lnk", "browser", "tasks", "triage"}
DEFAULT_LINUX   = {"logs", "history", "config", "cron", "ssh", "triage"}

# Human-readable names (used in the header printout)
ARTIFACT_LABELS = {
    "evtx":     "Event Logs (EVTX)",
    "registry": "Registry Hives",
    "prefetch": "Prefetch Files",
    "lnk":      "LNK / Recent Items",
    "browser":  "Browser Artifacts",
    "tasks":    "Scheduled Tasks",
    "triage":   "System Triage (live)",
    "logs":     "System Logs",
    "history":  "Shell Histories",
    "config":   "System Configuration",
    "cron":     "Cron Jobs",
    "ssh":      "SSH Artifacts",
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
    ):
        self.output   = output
        self.collect  = collect
        self.verbose  = verbose
        self.dry_run  = dry_run
        self.staging  = Path(tempfile.mkdtemp(prefix="fo_collect_"))
        self._items: list[tuple[str, Path]] = []
        self._errors: list[str] = []

    def _want(self, key: str) -> bool:
        return key in self.collect

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"      {msg}")

    def _warn(self, msg: str) -> None:
        self._errors.append(msg)
        print(f"  [!] {msg}", file=sys.stderr)

    def _section(self, key: str, label: str) -> bool:
        """Print a section header and return False if the section is disabled."""
        if not self._want(key):
            return False
        print(f"  [*] {label}")
        return True

    def _add(self, src: Path, arcname: str) -> bool:
        if not src.exists() or not src.is_file():
            self._log(f"missing  {src}")
            return False
        size = src.stat().st_size
        if size == 0:
            self._log(f"empty    {src.name}")
            return False
        self._items.append((arcname, src))
        self._log(f"ok  ({size:>11,} B)  {arcname}")
        return True

    def _copy_locked(self, src: Path, dest: Path) -> bool:
        try:
            shutil.copy2(str(src), str(dest))
            return True
        except (PermissionError, OSError):
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

    def collect_all(self) -> None:
        if self._want("evtx"):     self._evtx()
        if self._want("registry"): self._registry()
        if self._want("prefetch"): self._prefetch()
        if self._want("lnk"):      self._lnk()
        if self._want("browser"):  self._browser()
        if self._want("tasks"):    self._scheduled_tasks()
        if self._want("triage"):   self._system_triage()

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
            if self._add(evtx_dir / name, f"evtx/{name}"):
                seen.add(name)
        count = 0
        for p in sorted(evtx_dir.glob("*.evtx")):
            if count >= 100:
                break
            if p.name not in seen and self._add(p, f"evtx/{p.name}"):
                count += 1

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
        for user_dir in (sorted(users_dir.iterdir()) if users_dir.exists() else []):
            if not user_dir.is_dir():
                continue
            for rel, suffix in [
                ("NTUSER.DAT", "NTUSER.DAT"),
                (r"AppData\Local\Microsoft\Windows\UsrClass.dat", "USRCLASS.DAT"),
            ]:
                src = user_dir / rel
                tmp = staging_reg / f"{user_dir.name}_{suffix}"
                if self._copy_locked(src, tmp):
                    self._add(tmp, f"registry/users/{user_dir.name}/{suffix}")

    def _prefetch(self) -> None:
        print("  [*] Prefetch Files")
        pf_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
        count = 0
        for p in (sorted(pf_dir.glob("*.pf")) if pf_dir.exists() else []):
            if count >= 500:
                break
            if self._add(p, f"prefetch/{p.name}"):
                count += 1

    def _lnk(self) -> None:
        print("  [*] LNK / Recent Items")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        count = 0
        for user_dir in (sorted(users_dir.iterdir()) if users_dir.exists() else []):
            if not user_dir.is_dir():
                continue
            recent = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            for p in (recent.rglob("*.lnk") if recent.exists() else []):
                if count >= 2000:
                    break
                if self._add(p, f"lnk/{user_dir.name}/{p.name}"):
                    count += 1

    def _browser(self) -> None:
        print("  [*] Browser Artifacts")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        PROFILES = [
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\History"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Web Data"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Cookies"),
            ("chrome", r"AppData\Local\Google\Chrome\User Data\Default\Login Data"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\History"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\Cookies"),
            ("edge",   r"AppData\Local\Microsoft\Edge\User Data\Default\Web Data"),
        ]
        for user_dir in (sorted(users_dir.iterdir()) if users_dir.exists() else []):
            if not user_dir.is_dir():
                continue
            for browser, rel in PROFILES:
                src = user_dir / rel
                tmp = self.staging / f"{user_dir.name}_{browser}_{Path(rel).name}"
                if self._copy_locked(src, tmp):
                    self._add(tmp, f"browser/{browser}/{user_dir.name}/{Path(rel).name}")
            ff_base = user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
            if ff_base.exists():
                for profile_dir in ff_base.iterdir():
                    if not profile_dir.is_dir():
                        continue
                    for db in ("places.sqlite", "cookies.sqlite", "logins.json", "formhistory.sqlite"):
                        src = profile_dir / db
                        tmp = self.staging / f"{user_dir.name}_ff_{profile_dir.name}_{db}"
                        if self._copy_locked(src, tmp):
                            self._add(tmp, f"browser/firefox/{user_dir.name}/{profile_dir.name}/{db}")

    def _scheduled_tasks(self) -> None:
        print("  [*] Scheduled Tasks")
        tasks_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        count = 0
        for p in (tasks_dir.rglob("*") if tasks_dir.exists() else []):
            if count >= 500:
                break
            if p.is_file() and not p.suffix:
                rel = p.relative_to(tasks_dir)
                if self._add(p, f"scheduled_tasks/{rel}"):
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


# ─────────────────────────────────────────────────────────────────────────────
# Linux Collector
# ─────────────────────────────────────────────────────────────────────────────

class LinuxCollector(Collector):

    def collect_all(self) -> None:
        if self._want("logs"):    self._logs()
        if self._want("history"): self._shell_history()
        if self._want("config"):  self._system_config()
        if self._want("cron"):    self._cron()
        if self._want("ssh"):     self._ssh_artifacts()
        if self._want("triage"):  self._system_triage()

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


# ─────────────────────────────────────────────────────────────────────────────
# Upload helper
# ─────────────────────────────────────────────────────────────────────────────

def upload_to_fo(zip_path: Path, api_url: str, case_id: str) -> None:
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
        print(f"  [!] Upload failed: HTTP {exc.code} — {exc.read(256).decode(errors='replace')}",
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
        prog="tracex-collector",
        description="TraceX Artifact Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output",   "-o", type=Path, default=None)
    parser.add_argument("--api-url",  type=str, default=None)
    parser.add_argument("--case-id",  type=str, default=None)
    parser.add_argument("--collect",  type=str, default=None,
                        help="Comma-separated artifact types (e.g. evtx,registry,prefetch)")
    parser.add_argument("--dry-run",  action="store_true")
    parser.add_argument("--verbose",  "-v", action="store_true")
    args = parser.parse_args()

    # Merge: EMBEDDED_CONFIG < CLI args (CLI wins)
    cfg = {**EMBEDDED_CONFIG}
    if args.api_url:  cfg["api_url"]  = args.api_url
    if args.case_id:  cfg["case_id"]  = args.case_id
    if args.collect:  cfg["collect"]  = args.collect.split(",")
    if args.output:   cfg["output"]   = str(args.output)

    api_url  = cfg.get("api_url",  "")
    case_id  = cfg.get("case_id",  "")
    output   = Path(cfg["output"]) if cfg.get("output") else \
               Path.cwd() / f"fo-artifacts-{HOSTNAME}-{TS_NOW}.zip"

    # Resolve collect set
    raw_collect = cfg.get("collect", [])
    if IS_WINDOWS:
        collect_set = (set(raw_collect) & DEFAULT_WINDOWS) if raw_collect else DEFAULT_WINDOWS
    else:
        collect_set = (set(raw_collect) & DEFAULT_LINUX)   if raw_collect else DEFAULT_LINUX

    print(BANNER)
    print(f"  Host     : {HOSTNAME}")
    print(f"  OS       : {platform.system()} {platform.release()} {platform.machine()}")
    print(f"  Output   : {output}")
    if api_url and case_id:
        print(f"  Upload   : {api_url}  →  case {case_id}")
    print(f"  Collect  : {', '.join(sorted(collect_set)) or '(none)'}")
    print()

    if IS_WINDOWS:
        collector: Collector = WindowsCollector(output, collect_set, args.verbose, args.dry_run)
    elif IS_LINUX or IS_MACOS:
        collector = LinuxCollector(output, collect_set, args.verbose, args.dry_run)
    else:
        print(f"  [!] Unsupported OS: {platform.system()}", file=sys.stderr)
        sys.exit(1)

    collector.collect_all()

    if args.dry_run:
        print(f"\n  [Dry run] Would archive {len(collector._items)} files:")
        for arcname, _ in collector._items:
            print(f"    {arcname}")
    else:
        collector.package()
        if api_url and case_id:
            upload_to_fo(output, api_url, case_id)
        elif api_url or case_id:
            print("  [!] Both --api-url and --case-id required for upload.", file=sys.stderr)

    collector.cleanup()

    if collector._errors:
        print(f"\n  [{len(collector._errors)} warning(s) — some artifacts may be missing]")


if __name__ == "__main__":
    main()
