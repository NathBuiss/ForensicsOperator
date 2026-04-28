"""
K3s / Kubernetes Log Plugin — parses structured k3s and kubelet log output.

Handles three common formats produced by k3s, kubelet, kube-apiserver, and
other Kubernetes control-plane components:

  1. Logfmt (Go standard library slog / logrus):
       time="2026-04-28T10:57:36Z" level=info msg="Starting controller" component=kubelet

  2. Syslog-wrapped logfmt (journald export):
       Apr 28 10:57:36 hostname k3s[1234]: time="..." level=info msg="..."

  3. JSON structured lines (klog v2 / zap):
       {"time":"2026-04-28T10:57:36Z","level":"info","msg":"Starting","component":"kubelet"}

For each line the plugin emits structured fields:
  kubernetes.level, kubernetes.component, kubernetes.namespace, kubernetes.pod,
  kubernetes.node, kubernetes.container, kubernetes.image, kubernetes.reason,
  kubernetes.object_kind, kubernetes.object_name

Priority 112 — above syslog (100) so k3s.log / kubelet.log are parsed here
instead of being treated as generic syslog, which loses all structured fields.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from plugins.base_plugin import BasePlugin, PluginContext, PluginFatalError

# ── Patterns ──────────────────────────────────────────────────────────────────

# logfmt key=value or key="quoted"
_LOGFMT_PAIR_RE = re.compile(
    r'([\w./-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\S+))'
)

# Syslog RFC3164 prefix
_SYSLOG_PREFIX_RE = re.compile(
    r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:\s+'
)

# k3s/kubelet logfmt marker
_K3S_LOGFMT_RE = re.compile(r'time\s*=\s*"[^"]+"\s+level\s*=')

# klog v1 text format: I0428 10:57:36.123456   1234 file.go:42] message
_KLOG_RE = re.compile(
    r'^([IWEF])(\d{4})\s+'         # level + date (MMDD)
    r'(\d{2}:\d{2}:\d{2}\.\d+)\s+' # time.microseconds
    r'(\d+)\s+'                      # PID
    r'([\w./-]+):(\d+)\]\s+'        # file:line
    r'(.*)'                          # message
)

_KLOG_LEVELS = {'I': 'info', 'W': 'warning', 'E': 'error', 'F': 'fatal'}

# ISO timestamp normalisation
_TS_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$'
)

_KNOWN_NAMES = frozenset({
    'k3s.log',
    'k3s-server.log',
    'k3s-agent.log',
    'kubelet.log',
    'kube-apiserver.log',
    'kube-controller-manager.log',
    'kube-scheduler.log',
    'kube-proxy.log',
    'k8s.log',
    'kubernetes.log',
    'etcd.log',
    'containerd.log',
    'crio.log',
    'flannel.log',
    'calico.log',
    'coredns.log',
    'traefik.log',
    'rancher.log',
    'rke2.log',
})

# Known k3s/kube field names → canonical key
_FIELD_MAP = {
    # pod
    'pod': 'pod', 'podName': 'pod', 'pod_name': 'pod',
    # namespace
    'namespace': 'namespace', 'ns': 'namespace',
    # node
    'node': 'node', 'nodeName': 'node', 'node_name': 'node',
    # container
    'container': 'container', 'containerName': 'container',
    # image
    'image': 'image', 'imageName': 'image',
    # component
    'component': 'component', 'comp': 'component',
    # reason/event
    'reason': 'reason',
    # object
    'kind': 'object_kind',
    'name': 'object_name',
    # error
    'err': 'error', 'error': 'error',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_logfmt(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for m in _LOGFMT_PAIR_RE.finditer(line):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


def _strip_syslog_prefix(line: str) -> str:
    m = _SYSLOG_PREFIX_RE.match(line)
    return line[m.end():] if m else line


def _normalise_ts(raw: str) -> str:
    raw = raw.strip()
    m = _TS_RE.match(raw)
    if not m:
        return raw
    base = m.group(1).replace(' ', 'T')
    tz = m.group(3) or 'Z'
    if tz == 'Z':
        return f"{base}Z"
    return f"{base}{tz}"


def _mtime_or_now(path: Path) -> str:
    try:
        return datetime.fromtimestamp(
            path.stat().st_mtime, tz=timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%SZ')
    except OSError:
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _extract_k8s_fields(fields: dict[str, str]) -> dict[str, str]:
    """Map raw logfmt fields to canonical kubernetes.* sub-fields."""
    out: dict[str, str] = {}
    for src_key, dst_key in _FIELD_MAP.items():
        if src_key in fields and fields[src_key]:
            out[dst_key] = fields[src_key]
    return out


def _detect_format(path: Path) -> str | None:
    """Return 'logfmt', 'json', 'klog', or None."""
    try:
        with open(path, 'r', errors='replace') as fh:
            for _ in range(10):
                line = fh.readline()
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                inner = _strip_syslog_prefix(stripped)
                if _K3S_LOGFMT_RE.search(inner):
                    return 'logfmt'
                if _KLOG_RE.match(stripped):
                    return 'klog'
                try:
                    obj = json.loads(stripped)
                    if isinstance(obj, dict) and (
                        'time' in obj or 'ts' in obj or 'timestamp' in obj
                    ) and (
                        'msg' in obj or 'message' in obj
                    ):
                        return 'json'
                except (json.JSONDecodeError, ValueError):
                    pass
    except OSError:
        pass
    return None


# ── Plugin ────────────────────────────────────────────────────────────────────

class K3sPlugin(BasePlugin):
    """Parses k3s / Kubernetes structured log lines into normalised events."""

    PLUGIN_NAME           = "k3s"
    PLUGIN_VERSION        = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "k8s_event"
    SUPPORTED_EXTENSIONS  = [".log"]
    SUPPORTED_MIME_TYPES  = ["text/plain"]
    PLUGIN_PRIORITY       = 112

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.name.lower() in _KNOWN_NAMES:
            return True
        return _detect_format(file_path) is not None

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        fmt = _detect_format(path) or 'logfmt'
        if fmt == 'json':
            yield from self._parse_json(path)
        elif fmt == 'klog':
            yield from self._parse_klog(path)
        else:
            yield from self._parse_logfmt(path)

    # ── logfmt / syslog-wrapped logfmt ───────────────────────────────────────

    def _parse_logfmt(self, path: Path) -> Generator[dict[str, Any], None, None]:
        try:
            fh = open(path, 'r', errors='replace')
        except OSError as exc:
            raise PluginFatalError(f"Cannot open k3s log: {exc}") from exc

        fallback_ts = _mtime_or_now(path)

        with fh:
            for raw in fh:
                line = raw.rstrip('\n')
                if not line.strip():
                    continue

                inner = _strip_syslog_prefix(line)
                fields = _parse_logfmt(inner)
                if not fields:
                    continue

                ts_raw  = fields.get('time', fields.get('ts', ''))
                ts      = _normalise_ts(ts_raw) if ts_raw else fallback_ts
                level   = fields.get('level', fields.get('severity', 'info')).lower()
                msg     = fields.get('msg', fields.get('message', inner[:300]))

                k8s_fields = _extract_k8s_fields(fields)
                error_val  = fields.get('error', fields.get('err', ''))

                # Build a human-readable display
                display = msg
                if k8s_fields.get('namespace') and k8s_fields.get('pod'):
                    display = f"[{k8s_fields['namespace']}/{k8s_fields['pod']}] {msg}"
                elif k8s_fields.get('component'):
                    display = f"[{k8s_fields['component']}] {msg}"

                event: dict[str, Any] = {
                    'timestamp':      ts,
                    'timestamp_desc': 'K8s Log',
                    'message':        display,
                    'artifact_type':  'k8s_event',
                    'kubernetes': {
                        'level': level,
                        **k8s_fields,
                    },
                }

                if error_val:
                    event['error'] = {'message': error_val}

                yield event

    # ── JSON structured lines ─────────────────────────────────────────────────

    def _parse_json(self, path: Path) -> Generator[dict[str, Any], None, None]:
        try:
            fh = open(path, 'r', errors='replace')
        except OSError as exc:
            raise PluginFatalError(f"Cannot open k3s log: {exc}") from exc

        fallback_ts = _mtime_or_now(path)

        with fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(obj, dict):
                    continue

                ts_raw = (obj.get('time') or obj.get('ts') or
                          obj.get('timestamp') or obj.get('@timestamp') or '')
                ts     = _normalise_ts(str(ts_raw)) if ts_raw else fallback_ts
                level  = str(obj.get('level', obj.get('severity', 'info'))).lower()
                msg    = str(obj.get('msg', obj.get('message', '')))

                k8s_fields: dict[str, str] = {}
                for src_key, dst_key in _FIELD_MAP.items():
                    val = obj.get(src_key)
                    if val:
                        k8s_fields[dst_key] = str(val)

                display = msg
                if k8s_fields.get('namespace') and k8s_fields.get('pod'):
                    display = f"[{k8s_fields['namespace']}/{k8s_fields['pod']}] {msg}"
                elif k8s_fields.get('component'):
                    display = f"[{k8s_fields['component']}] {msg}"

                error_val = obj.get('error', obj.get('err', ''))

                event: dict[str, Any] = {
                    'timestamp':      ts,
                    'timestamp_desc': 'K8s Log',
                    'message':        display,
                    'artifact_type':  'k8s_event',
                    'kubernetes': {
                        'level': level,
                        **k8s_fields,
                    },
                    'raw': obj,
                }

                if error_val:
                    event['error'] = {'message': str(error_val)}

                yield event

    # ── klog v1 text format ───────────────────────────────────────────────────

    def _parse_klog(self, path: Path) -> Generator[dict[str, Any], None, None]:
        """
        klog v1: I0428 10:57:36.123456   1234 reconciler.go:196] message here
        Date is MMDD without year — infer year from file mtime.
        """
        try:
            fh = open(path, 'r', errors='replace')
        except OSError as exc:
            raise PluginFatalError(f"Cannot open klog file: {exc}") from exc

        try:
            mtime_year = datetime.fromtimestamp(
                path.stat().st_mtime, tz=timezone.utc
            ).year
        except OSError:
            mtime_year = datetime.now(timezone.utc).year

        with fh:
            for raw in fh:
                line = raw.rstrip('\n')
                m = _KLOG_RE.match(line)
                if not m:
                    continue

                level_char, mmdd, time_str, pid, src_file, src_line, msg = m.groups()
                level = _KLOG_LEVELS.get(level_char, 'info')

                month = mmdd[:2]
                day   = mmdd[2:]
                time_part = time_str.split('.')[0]  # drop microseconds
                ts = f"{mtime_year}-{month}-{day}T{time_part}Z"

                event: dict[str, Any] = {
                    'timestamp':      ts,
                    'timestamp_desc': 'K8s Log',
                    'message':        msg.strip(),
                    'artifact_type':  'k8s_event',
                    'kubernetes': {
                        'level':    level,
                        'src_file': src_file,
                        'src_line': src_line,
                    },
                    'process': {'pid': int(pid)},
                }
                yield event

    def get_stats(self) -> dict[str, Any]:
        return {}
