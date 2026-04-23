"""
Registry Plugin — parses Windows Registry hive files (NTUSER.DAT, SYSTEM, SAM, etc.).
Requires: python-registry (pip install python-registry)

Each key with values yields one or more events:
  • Significant keys (Run, Services, IFEO, …) → one event per relevant value
    with a context-aware message and artifact_type.
  • Service keys with ImagePath → one consolidated service event.
  • All other keys with values → one event per key with a summary message
    that includes the first few value names and data.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

try:
    from Registry import Registry
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False

try:
    from utils.enrichment import (
        classify_registry_key,
        decode_service_start,
        decode_service_type,
    )
    _ENRICHMENT = True
except ImportError:
    _ENRICHMENT = False

HIVE_FILENAMES = {
    "NTUSER.DAT", "USRCLASS.DAT", "SYSTEM", "SOFTWARE",
    "SAM", "SECURITY", "DEFAULT", "COMPONENTS",
    "BCD",
    "AMCACHE.HVE",
}

# How many value name=data pairs to show in the generic summary message
_MAX_SUMMARY_VALUES = 4
# Max chars for a single value data string in the message
_MAX_VAL_LEN = 120


def _shorten(s: str, n: int = _MAX_VAL_LEN) -> str:
    s = s.replace("\n", " ").replace("\r", "")
    return s if len(s) <= n else s[:n - 1] + "…"


def _v(values: dict, *names: str) -> str:
    """Return the data of the first matching value name (case-insensitive)."""
    nl = {k.lower(): v["data"] for k, v in values.items()}
    for name in names:
        val = nl.get(name.lower())
        if val is not None:
            return val
    return ""


class RegistryPlugin(BasePlugin):

    PLUGIN_NAME = "registry"
    PLUGIN_VERSION = "1.1.0"
    DEFAULT_ARTIFACT_TYPE = "registry"
    SUPPORTED_EXTENSIONS = [".dat", ".hive"]
    SUPPORTED_MIME_TYPES = []

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

    # ── Per-key dispatcher ───────────────────────────────────────────────────

    def _walk_key(self, key: Any, path: str) -> Generator[dict[str, Any], None, None]:
        full_path = f"{path}\\{key.name()}" if path else key.name()

        try:
            timestamp = key.timestamp().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        except Exception:
            timestamp = ""

        values: dict[str, dict] = {}
        for val in key.values():
            try:
                values[val.name() or "(Default)"] = {
                    "type": val.value_type_str(),
                    "data": str(val.value())[:4096],
                }
            except Exception:
                pass

        if values:
            yield from self._emit(full_path, key, values, timestamp)

        for subkey in key.subkeys():
            try:
                yield from self._walk_key(subkey, full_path)
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipped subkey %s: %s", full_path, exc)

    def _emit(
        self,
        full_path: str,
        key: Any,
        values: dict,
        timestamp: str,
    ) -> Generator[dict[str, Any], None, None]:
        if _ENRICHMENT:
            label, atype, mitre_id = classify_registry_key(full_path)
        else:
            label, atype, mitre_id = "", "registry", ""

        base_registry = {
            "key_path":       full_path,
            "key_name":       key.name(),
            "last_write_time": timestamp,
            "subkey_count":   key.number_of_subkeys(),
            "value_count":    key.number_of_values(),
            "values":         values,
        }

        # ── Service key (has ImagePath) ──────────────────────────────────────
        if label == "Service" and _v(values, "ImagePath"):
            yield from self._emit_service(full_path, key.name(), values,
                                          timestamp, base_registry, mitre_id)
            return

        # ── AutoRun / per-value persistence keys ────────────────────────────
        if label in ("AutoRun", "AutoRun Once", "AutoRun Services",
                     "AutoRun Svc Once", "CMD AutoRun"):
            for val_name, val_info in values.items():
                data = _shorten(val_info["data"])
                msg = f"[{label}] {val_name} = {data}"
                self._records_read += 1
                yield {

                    "artifact_type": atype,
                    "timestamp":     timestamp,
                    "timestamp_desc": "Key Last Write Time",
                    "message":       msg,
                    "mitre":         {"id": mitre_id, "tactic": "Persistence"} if mitre_id else {},
                    "registry":      {**base_registry, "matched_value": val_name},
                    "raw": {},
                }
            return

        # ── IFEO — flag if a Debugger value is present (hijack indicator) ───
        if label == "IFEO":
            debugger = _v(values, "Debugger")
            if debugger:
                msg = f"[IFEO Hijack] {key.name()} — Debugger = {_shorten(debugger)}"
            else:
                # IFEO key but no debugger — likely legitimate; generic summary
                msg = f"[IFEO] {key.name()} — {_generic_value_summary(values)}"
            self._records_read += 1
            yield {

                "artifact_type": atype if debugger else "registry",
                "timestamp":     timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message":       msg,
                "mitre":         {"id": mitre_id, "tactic": "Persistence"} if (mitre_id and debugger) else {},
                "registry":      base_registry,
                "raw": {},
            }
            return

        # ── AppInit / Boot Execute / AppCertDLL — flag the DLL list ─────────
        if label in ("AppInit DLL", "Boot Execute", "AppCertDLL"):
            data_str = _v(values, "AppInit_DLLs", "BootExecute", "(Default)") or \
                       next(iter(values.values()))["data"]
            msg = f"[{label}] {_shorten(data_str)}"
            self._records_read += 1
            yield {

                "artifact_type": atype,
                "timestamp":     timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message":       msg,
                "mitre":         {"id": mitre_id, "tactic": "Persistence"} if mitre_id else {},
                "registry":      base_registry,
                "raw": {},
            }
            return

        # ── Recent Docs / MRU — user activity evidence ───────────────────────
        if label in ("Recent Doc", "File Dialog MRU", "App Open MRU"):
            count = len(values)
            sample = ", ".join(
                _shorten(v["data"], 60) for v in list(values.values())[:3]
                if v["data"] and v["data"] != "(Default)"
            )
            msg = f"[{label}] {count} entries — {sample}" if sample else f"[{label}] {count} entries"
            self._records_read += 1
            yield {

                "artifact_type": atype,
                "timestamp":     timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message":       msg,
                "mitre":         {"id": mitre_id} if mitre_id else {},
                "registry":      base_registry,
                "raw": {},
            }
            return

        # ── USB device ────────────────────────────────────────────────────────
        if label == "USB Device":
            friendly = _v(values, "FriendlyName", "DeviceDesc", "(Default)")
            serial = key.name()
            msg = f"[USB] {friendly or serial}"
            if friendly and serial != friendly:
                msg += f" (S/N: {serial})"
            self._records_read += 1
            yield {

                "artifact_type": atype,
                "timestamp":     timestamp,
                "timestamp_desc": "Device First Seen",
                "message":       msg,
                "mitre":         {"id": mitre_id} if mitre_id else {},
                "registry":      base_registry,
                "raw": {},
            }
            return

        # ── TCP/IP config ─────────────────────────────────────────────────────
        if label == "TCP/IP Config":
            hostname = _v(values, "Hostname", "ComputerNamePhysicalDnsHostname")
            domain   = _v(values, "Domain", "DhcpDomain")
            ip       = _v(values, "DhcpIPAddress", "IPAddress")
            parts: list[str] = []
            if hostname: parts.append(f"host={hostname}")
            if domain:   parts.append(f"domain={domain}")
            if ip:       parts.append(f"ip={ip}")
            detail = ", ".join(parts) if parts else _generic_value_summary(values)
            msg = f"[TCP/IP] {detail}"
            self._records_read += 1
            yield {

                "artifact_type": atype,
                "timestamp":     timestamp,
                "timestamp_desc": "Key Last Write Time",
                "message":       msg,
                "registry":      base_registry,
                "raw": {},
            }
            return

        # ── SAM user account ──────────────────────────────────────────────────
        if label == "SAM User":
            msg = f"[SAM Account] {key.name()}"
            self._records_read += 1
            yield {

                "artifact_type": atype,
                "timestamp":     timestamp,
                "timestamp_desc": "Account Last Modified",
                "message":       msg,
                "mitre":         {"id": mitre_id} if mitre_id else {},
                "registry":      base_registry,
                "raw": {},
            }
            return

        # ── Generic enriched key event ────────────────────────────────────────
        if label:
            msg = f"[{label}] {full_path} — {_generic_value_summary(values)}"
        else:
            msg = f"[Registry] {full_path} — {_generic_value_summary(values)}"

        self._records_read += 1
        yield {
            "artifact_type": atype,
            "timestamp":     timestamp,
            "timestamp_desc": "Key Last Write Time",
            "message":       msg,
            "mitre":         {"id": mitre_id} if mitre_id else {},
            "registry":      base_registry,
            "raw": {},
        }

    # ── Service builder ──────────────────────────────────────────────────────

    def _emit_service(
        self,
        full_path: str,
        svc_name: str,
        values: dict,
        timestamp: str,
        base_registry: dict,
        mitre_id: str,
    ) -> Generator[dict[str, Any], None, None]:
        image_path   = _shorten(_v(values, "ImagePath"), 200)
        display_name = _v(values, "DisplayName") or svc_name
        start_raw    = _v(values, "Start")
        type_raw     = _v(values, "Type")
        object_name  = _v(values, "ObjectName")  # run-as account

        start_label  = decode_service_start(start_raw) if start_raw else ""
        type_label   = decode_service_type(type_raw)   if type_raw  else ""
        account_part = f" as {object_name}" if object_name else ""

        meta_parts = [p for p in [start_label, type_label] if p]
        meta_str   = f" [{', '.join(meta_parts)}]" if meta_parts else ""

        msg = f"[Service] {display_name} — {image_path}{meta_str}{account_part}"

        self._records_read += 1
        yield {
            "artifact_type": "persistence",
            "timestamp":     timestamp,
            "timestamp_desc": "Service Key Last Write",
            "message":       msg,
            "mitre":         {"id": mitre_id, "tactic": "Persistence"} if mitre_id else {},
            "process": {"name": svc_name, "path": image_path},
            "registry":      base_registry,
            "raw": {},
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read":    self._records_read,
            "records_skipped": self._records_skipped,
        }


# ── Helpers ──────────────────────────────────────────────────────────────────

def _generic_value_summary(values: dict) -> str:
    """Return a compact 'name=data, ...' summary of the first few values."""
    parts: list[str] = []
    for name, info in list(values.items())[:_MAX_SUMMARY_VALUES]:
        data = _shorten(info["data"], 60)
        parts.append(f"{name}={data}" if data else name)
    suffix = f" (+{len(values) - _MAX_SUMMARY_VALUES} more)" if len(values) > _MAX_SUMMARY_VALUES else ""
    return ", ".join(parts) + suffix
