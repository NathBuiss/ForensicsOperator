import { useEffect, useState, useRef } from 'react'
import {
  Puzzle, Upload, RefreshCw, FileCode2, X,
  CheckCircle, AlertCircle, Copy, Check, Lock, Clock,
} from 'lucide-react'
import { api } from '../api/client'

// ── Built-in ingester registry (mirrors processor/plugins/) ──────────────────
// available: true  → plugin ships with ForensicsOperator (active by default)
// available: false → planned / coming soon
const BUILTIN_INGESTERS = [
  // ── Windows artifacts ───────────────────────────────────────────────────
  {
    name: 'evtx',
    label: 'EVTX',
    description: 'Windows Event Log files — Security, System, Application and custom channels',
    extensions: ['.evtx'],
    filenames: [],
    available: true,
    category: 'Windows',
  },
  {
    name: 'prefetch',
    label: 'Prefetch',
    description: 'Windows Prefetch files — application execution history',
    extensions: ['.pf'],
    filenames: [],
    available: true,
    category: 'Windows',
  },
  {
    name: 'mft',
    label: 'MFT',
    description: 'NTFS Master File Table — complete filesystem metadata and timestamps',
    extensions: [],
    filenames: ['$MFT'],
    available: true,
    category: 'Windows',
  },
  {
    name: 'registry',
    label: 'Registry',
    description: 'Windows Registry hives — NTUSER.DAT, SYSTEM, SOFTWARE, SAM, SECURITY',
    extensions: ['.dat', '.hive'],
    filenames: ['NTUSER.DAT', 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'USRCLASS.DAT'],
    available: true,
    category: 'Windows',
  },
  {
    name: 'lnk',
    label: 'LNK',
    description: 'Windows Shortcut (.lnk) files — target paths, timestamps, volume info',
    extensions: ['.lnk'],
    filenames: [],
    available: true,
    category: 'Windows',
  },

  // ── Timeline / multi-source ─────────────────────────────────────────────
  {
    name: 'plaso',
    label: 'Plaso',
    description: 'Log2Timeline/Plaso .plaso storage files — multi-source supertimeline',
    extensions: ['.plaso'],
    filenames: [],
    available: true,
    category: 'Timeline',
  },
  {
    name: 'hayabusa',
    label: 'Hayabusa Output',
    description: 'Hayabusa JSONL / CSV output — import pre-generated Sigma detection results',
    extensions: ['.jsonl', '.csv'],
    filenames: [],
    available: true,
    category: 'Windows',
  },

  // ── Network artifacts ───────────────────────────────────────────────────
  {
    name: 'suricata',
    label: 'Suricata EVE JSON',
    description: 'Suricata IDS/IPS EVE JSON logs — alerts, DNS, HTTP, TLS, SSH, flows and more',
    extensions: ['.json', '.jsonl', '.ndjson'],
    filenames: ['eve.json', 'eve.log'],
    available: true,
    category: 'Network',
  },
  {
    name: 'zeek',
    label: 'Zeek / Bro Logs',
    description: 'Zeek network analysis logs — conn, dns, http, ssl, ssh, files and custom log types',
    extensions: ['.log'],
    filenames: ['conn.log', 'dns.log', 'http.log', 'ssl.log', 'ssh.log', 'files.log'],
    available: true,
    category: 'Network',
  },

  // ── Linux / UNIX artifacts ───────────────────────────────────────────────
  {
    name: 'syslog',
    label: 'Linux Syslog',
    description: 'RFC 3164 / RFC 5424 syslog files — auth.log, kern.log, daemon.log, messages, dmesg…',
    extensions: ['.log'],
    filenames: ['syslog', 'auth.log', 'kern.log', 'daemon.log', 'messages', 'secure'],
    available: true,
    category: 'Linux',
  },

  // ── Generic ─────────────────────────────────────────────────────────────
  {
    name: 'ndjson',
    label: 'JSON Lines / NDJSON',
    description: 'Generic NDJSON / JSON Lines files — auto-detects timestamps and message fields',
    extensions: ['.jsonl', '.ndjson'],
    filenames: [],
    available: true,
    category: 'Generic',
  },

  // ── Planned ─────────────────────────────────────────────────────────────
  {
    name: 'apache',
    label: 'Apache / Nginx Access Logs',
    description: 'Combined / common log format HTTP access logs from Apache or Nginx',
    extensions: ['.log'],
    filenames: ['access.log', 'access_log', 'error.log'],
    available: false,
    unavailableReason: 'Coming soon.',
    category: 'Network',
  },
  {
    name: 'iis',
    label: 'Windows IIS Logs',
    description: 'Microsoft IIS W3C extended log format — web server access logs',
    extensions: ['.log'],
    filenames: [],
    available: false,
    unavailableReason: 'Coming soon.',
    category: 'Windows',
  },
  {
    name: 'macos_ulog',
    label: 'macOS Unified Log',
    description: 'macOS Unified Logging (ULS) — system and app logs from Apple Silicon / Intel Macs',
    extensions: ['.logarchive', '.tracev3'],
    filenames: [],
    available: false,
    unavailableReason: 'Requires macOS host for log show / osxtools — coming soon.',
    category: 'macOS',
  },
  {
    name: 'android_logcat',
    label: 'Android Logcat',
    description: 'Android logcat output — system and app messages from Android devices',
    extensions: ['.log', '.txt'],
    filenames: ['logcat.txt', 'logcat.log'],
    available: false,
    unavailableReason: 'Coming soon.',
    category: 'Mobile',
  },
]

// ── Plugin template (identical to the old Plugins page) ──────────────────────
const INGESTER_TEMPLATE = `"""
my_artifact_plugin.py — parse my custom artifact format.

File must be named *_plugin.py to be auto-discovered by the loader.
Drop it in /app/plugins/ (or upload via the UI) and click "Reload All".
"""
from base_plugin import BasePlugin, PluginContext, ParsedEvent


class MyArtifactPlugin(BasePlugin):
    # Identifier used as artifact_type in events and index name suffix
    PLUGIN_NAME = "my-artifact"

    # File extensions this plugin handles (lower-case)
    SUPPORTED_EXTENSIONS = [".ext", ".ext2"]

    # Exact filenames to match (useful for system files like "$MFT")
    HANDLED_FILENAMES = []  # e.g. ["$MFT", "NTUSER.DAT"]

    def parse(self, file_path: str, context: PluginContext):
        """
        Generator — yield one ParsedEvent per event found in the file.

        Available context fields:
          context.case_id            current case ID
          context.job_id             ingest job ID
          context.source_file_path   path to the evidence file on disk
          context.source_minio_url   MinIO URL of the evidence file
        """
        with open(file_path, "rb") as f:
            for record in self._parse_records(f):
                yield ParsedEvent(
                    timestamp=record["timestamp"],     # ISO-8601 string
                    message=record["description"],
                    artifact_type=self.PLUGIN_NAME,
                    host={"hostname": record.get("hostname", "")},
                    user={"name": record.get("username", "")},
                    # Add any extra fields — stored as a sub-object in ES
                    # extra={"event_id": 4624, "channel": "Security"},
                )

    def _parse_records(self, file_handle):
        """Replace with your actual parsing logic."""
        return []
`

// ── TemplateModal ─────────────────────────────────────────────────────────────
function TemplateModal({ onClose }) {
  const [copied, setCopied] = useState(false)

  function copy() {
    navigator.clipboard.writeText(INGESTER_TEMPLATE)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div
      className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      <div className="bg-white border border-gray-200 rounded-xl w-full max-w-2xl shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <FileCode2 size={16} className="text-brand-accent" />
            <span className="text-sm font-semibold text-brand-text">Ingester Template</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={copy} className="btn-ghost text-xs">
              {copied
                ? <><Check size={13} className="text-green-600" /> Copied!</>
                : <><Copy size={13} /> Copy</>}
            </button>
            <button onClick={onClose} className="btn-ghost p-1.5">
              <X size={14} />
            </button>
          </div>
        </div>
        <div className="p-5">
          <pre className="code-block text-[11px] leading-relaxed overflow-x-auto max-h-[70vh] overflow-y-auto">
            {INGESTER_TEMPLATE}
          </pre>
        </div>
      </div>
    </div>
  )
}

// ── UploadZone ────────────────────────────────────────────────────────────────
function UploadZone({ onUploaded }) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile]         = useState(null)
  const [status, setStatus]     = useState(null) // null | 'uploading' | 'success' | 'error'
  const [message, setMessage]   = useState('')
  const inputRef = useRef()

  function handleDrop(e) {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) selectFile(f)
  }

  function selectFile(f) {
    if (!f.name.endsWith('.py')) {
      setStatus('error')
      setMessage('Only .py files are accepted.')
      return
    }
    setFile(f)
    setStatus(null)
    setMessage('')
  }

  async function upload() {
    if (!file) return
    setStatus('uploading')
    setMessage('')
    try {
      const fd = new FormData()
      fd.append('file', file)
      const r = await api.plugins.upload(fd)
      setStatus('success')
      setMessage(r.message)
      setFile(null)
      onUploaded(r.plugins)
    } catch (e) {
      setStatus('error')
      setMessage(e.message)
    }
  }

  return (
    <div className="mb-5">
      <div
        className={dragging ? 'drop-zone-active' : 'drop-zone-inactive'}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => !file && inputRef.current.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".py"
          className="hidden"
          onChange={e => e.target.files[0] && selectFile(e.target.files[0])}
        />

        {file ? (
          <div className="flex items-center justify-center gap-3">
            <FileCode2 size={20} className="text-brand-accent" />
            <div className="text-left">
              <p className="text-sm font-medium text-brand-text">{file.name}</p>
              <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(1)} KB</p>
            </div>
            <div className="flex gap-2 ml-4">
              <button
                onClick={e => { e.stopPropagation(); setFile(null) }}
                className="btn-ghost text-xs"
              >
                <X size={12} /> Remove
              </button>
              <button
                onClick={e => { e.stopPropagation(); upload() }}
                disabled={status === 'uploading'}
                className="btn-primary text-xs"
              >
                {status === 'uploading'
                  ? <><RefreshCw size={12} className="animate-spin" /> Uploading…</>
                  : <><Upload size={12} /> Upload Ingester</>}
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <div className="w-10 h-10 rounded-xl bg-gray-100 flex items-center justify-center">
              <Upload size={18} className="text-gray-500" />
            </div>
            <p className="text-sm text-gray-500">
              Drop an ingester file{' '}
              <code className="text-brand-accent">*_plugin.py</code> here
            </p>
            <p className="text-xs text-gray-400">or click to browse</p>
          </div>
        )}
      </div>

      {status === 'success' && (
        <div className="mt-2 flex items-center gap-2 text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2">
          <CheckCircle size={13} /> {message}
        </div>
      )}
      {status === 'error' && (
        <div className="mt-2 flex items-center gap-2 text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          <AlertCircle size={13} /> {message}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Ingesters() {
  const [customPlugins, setCustomPlugins] = useState([])
  const [loading, setLoading]             = useState(true)
  const [reloading, setReloading]         = useState(false)
  const [showTemplate, setShowTemplate]   = useState(false)

  function loadPlugins() {
    setLoading(true)
    api.plugins.list()
      .then(r => {
        // Exclude built-in ingesters (shown in the built-in section above).
        // Match case-insensitively against both `name` and `default_artifact_type`
        // to handle any casing differences between the plugin registry and the API.
        const builtinKeys = new Set(
          BUILTIN_INGESTERS.flatMap(b => [b.name.toLowerCase(), (b.name).toLowerCase()])
        )
        const custom = (r.plugins || []).filter(p => {
          const pName = (p.name || '').toLowerCase().trim()
          const pArt  = (p.default_artifact_type || '').toLowerCase().trim()
          return !builtinKeys.has(pName) && !builtinKeys.has(pArt)
        })
        setCustomPlugins(custom)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(loadPlugins, [])

  async function reload() {
    setReloading(true)
    try {
      const r = await api.plugins.reload()
      const builtinKeys = new Set(BUILTIN_INGESTERS.flatMap(b => [b.name.toLowerCase()]))
      const custom = (r.plugins || []).filter(p => {
        const pName = (p.name || '').toLowerCase().trim()
        const pArt  = (p.default_artifact_type || '').toLowerCase().trim()
        return !builtinKeys.has(pName) && !builtinKeys.has(pArt)
      })
      setCustomPlugins(custom)
    } catch (e) {
      alert('Reload failed: ' + e.message)
    } finally {
      setReloading(false)
    }
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {showTemplate && <TemplateModal onClose={() => setShowTemplate(false)} />}

      {/* Page header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-brand-text flex items-center gap-2">
            <Puzzle size={18} className="text-brand-accent" /> Ingesters
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Built-in parsers that convert uploaded forensic artifacts into timeline events
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowTemplate(true)} className="btn-ghost text-xs">
            <FileCode2 size={13} /> Template
          </button>
          <button onClick={reload} disabled={reloading} className="btn-primary text-xs">
            <RefreshCw size={13} className={reloading ? 'animate-spin' : ''} />
            {reloading ? 'Reloading…' : 'Reload All'}
          </button>
        </div>
      </div>

      {/* ── Section 1: Built-in ingesters ──────────────────────────────────── */}
      <section className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <h2 className="section-title">Built-in Ingesters</h2>
          <span className="badge bg-green-50 text-green-700 border border-green-200">
            {BUILTIN_INGESTERS.filter(b => b.available !== false).length} active
          </span>
          {BUILTIN_INGESTERS.some(b => b.available === false) && (
            <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
              {BUILTIN_INGESTERS.filter(b => b.available === false).length} planned
            </span>
          )}
        </div>
        <div className="space-y-2">
          {BUILTIN_INGESTERS.map(ing => {
            const isAvailable = ing.available !== false
            return (
              <div key={ing.name} className={`card p-4 ${isAvailable ? '' : 'opacity-60'}`}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
                      isAvailable
                        ? 'bg-brand-accentlight border border-brand-accent/20'
                        : 'bg-gray-100 border border-gray-200'
                    }`}>
                      <Puzzle size={14} className={isAvailable ? 'text-brand-accent' : 'text-gray-400'} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className={`text-sm font-semibold ${isAvailable ? 'text-brand-text' : 'text-gray-400'}`}>
                          {ing.label}
                        </span>
                        {isAvailable ? (
                          <span className="badge bg-green-50 text-green-700 border border-green-200">
                            <CheckCircle size={9} className="mr-1" /> active
                          </span>
                        ) : (
                          <span className="badge bg-amber-50 text-amber-600 border border-amber-200">
                            <Clock size={9} className="mr-1" /> coming soon
                          </span>
                        )}
                        <span className="badge bg-gray-100 text-gray-400 border border-gray-200 text-[10px] flex items-center gap-1">
                          <Lock size={8} /> built-in
                        </span>
                        {ing.category && (
                          <span className="badge bg-blue-50 text-blue-600 border border-blue-100 text-[10px]">
                            {ing.category}
                          </span>
                        )}
                      </div>
                      <p className={`text-xs ${isAvailable ? 'text-gray-500' : 'text-gray-400'}`}>
                        {ing.description}
                      </p>
                      {!isAvailable && ing.unavailableReason && (
                        <p className="text-[10px] text-gray-400 italic mt-0.5">{ing.unavailableReason}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1 justify-end max-w-xs">
                    {ing.extensions.map(ext => (
                      <span key={ext} className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono">
                        {ext}
                      </span>
                    ))}
                    {ing.filenames.slice(0, 3).map(fn => (
                      <span key={fn} className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono">
                        {fn}
                      </span>
                    ))}
                    {ing.filenames.length > 3 && (
                      <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
                        +{ing.filenames.length - 3}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      {/* ── Section 2: Custom ingesters ────────────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-3">
          <h2 className="section-title">Custom Ingesters</h2>
          {!loading && (
            <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
              {customPlugins.length}
            </span>
          )}
        </div>
        <p className="text-xs text-gray-400 mb-4">
          Upload a custom ingester file (named <code className="text-gray-500">*_plugin.py</code>) following the template above.
          Custom ingesters are stored in <code className="text-gray-500">/app/plugins/</code> and
          activated at worker startup (or after "Reload All").
        </p>

        <UploadZone onUploaded={plugins => {
          const builtinKeys = new Set(BUILTIN_INGESTERS.flatMap(b => [b.name.toLowerCase()]))
          setCustomPlugins((plugins || []).filter(p => {
            const pName = (p.name || '').toLowerCase().trim()
            const pArt  = (p.default_artifact_type || '').toLowerCase().trim()
            return !builtinKeys.has(pName) && !builtinKeys.has(pArt)
          }))
        }} />

        {loading ? (
          <div className="space-y-3">
            {[1, 2].map(i => <div key={i} className="skeleton h-16 w-full" />)}
          </div>
        ) : customPlugins.length === 0 ? (
          <div className="card p-10 text-center">
            <Puzzle size={28} className="text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500 text-sm font-medium mb-1">No custom ingesters</p>
            <p className="text-gray-400 text-xs">
              Upload a custom ingester above, or copy a{' '}
              <code className="text-gray-500">*_plugin.py</code> file into{' '}
              <code className="text-gray-500">/app/plugins/</code> and click Reload All.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {customPlugins.map(p => (
              <div key={p.name} className="card p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-lg bg-brand-accentlight border border-brand-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Puzzle size={14} className="text-brand-accent" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-semibold text-brand-text">{p.name}</span>
                        <span className="badge bg-gray-100 text-gray-600 border border-gray-200">
                          v{p.version}
                        </span>
                        <span className="badge bg-green-50 text-green-700 border border-green-200">
                          <CheckCircle size={9} className="mr-1" /> active
                        </span>
                      </div>
                      <p className="text-xs text-gray-500">
                        Artifact type:{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 py-0.5 rounded text-[10px]">
                          {p.default_artifact_type}
                        </code>
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1 justify-end max-w-xs">
                    {p.supported_extensions?.map(ext => (
                      <span key={ext} className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono">
                        {ext}
                      </span>
                    ))}
                    {p.handled_filenames?.map(fn => (
                      <span key={fn} className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono">
                        {fn}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
