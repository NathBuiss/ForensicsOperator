import { useEffect, useState, useRef } from 'react'
import { Puzzle, Upload, RefreshCw, FileCode2, X, CheckCircle, AlertCircle, Copy, Check } from 'lucide-react'
import { api } from '../api/client'

const PLUGIN_TEMPLATE = `"""
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

function TemplateModal({ onClose }) {
  const [copied, setCopied] = useState(false)

  function copy() {
    navigator.clipboard.writeText(PLUGIN_TEMPLATE)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700/60">
          <div className="flex items-center gap-2">
            <FileCode2 size={16} className="text-indigo-400" />
            <span className="text-sm font-semibold text-gray-100">Plugin Template</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={copy} className="btn-ghost text-xs">
              {copied ? <><Check size={13} className="text-green-400" /> Copied!</> : <><Copy size={13} /> Copy</>}
            </button>
            <button onClick={onClose} className="btn-ghost p-1.5">
              <X size={14} />
            </button>
          </div>
        </div>
        <div className="p-5">
          <pre className="code-block text-[11px] leading-relaxed overflow-x-auto max-h-[70vh] overflow-y-auto">
            {PLUGIN_TEMPLATE}
          </pre>
        </div>
      </div>
    </div>
  )
}

function UploadZone({ onUploaded }) {
  const [dragging, setDragging]       = useState(false)
  const [file, setFile]               = useState(null)
  const [status, setStatus]           = useState(null) // null | 'uploading' | 'success' | 'error'
  const [message, setMessage]         = useState('')
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
    <div className="mb-6">
      <div
        className={`drop-zone ${dragging ? 'drop-zone-active' : 'drop-zone-inactive'}`}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => !file && inputRef.current.click()}
      >
        <input ref={inputRef} type="file" accept=".py" className="hidden"
          onChange={e => e.target.files[0] && selectFile(e.target.files[0])} />

        {file ? (
          <div className="flex items-center justify-center gap-3">
            <FileCode2 size={20} className="text-indigo-400" />
            <div className="text-left">
              <p className="text-sm font-medium text-gray-200">{file.name}</p>
              <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(1)} KB</p>
            </div>
            <div className="flex gap-2 ml-4">
              <button onClick={e => { e.stopPropagation(); setFile(null) }}
                className="btn-ghost text-xs">
                <X size={12} /> Remove
              </button>
              <button onClick={e => { e.stopPropagation(); upload() }}
                disabled={status === 'uploading'}
                className="btn-primary text-xs">
                {status === 'uploading'
                  ? <><RefreshCw size={12} className="animate-spin" /> Uploading…</>
                  : <><Upload size={12} /> Upload Plugin</>}
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <div className="w-10 h-10 rounded-xl bg-gray-700/50 flex items-center justify-center">
              <Upload size={18} className="text-gray-500" />
            </div>
            <p className="text-sm text-gray-400">
              Drop a <code className="text-indigo-400">*_plugin.py</code> file here
            </p>
            <p className="text-xs text-gray-600">or click to browse</p>
          </div>
        )}
      </div>

      {status === 'success' && (
        <div className="mt-2 flex items-center gap-2 text-xs text-green-400 bg-green-900/20 border border-green-800/40 rounded-lg px-3 py-2">
          <CheckCircle size={13} /> {message}
        </div>
      )}
      {status === 'error' && (
        <div className="mt-2 flex items-center gap-2 text-xs text-red-400 bg-red-900/20 border border-red-800/40 rounded-lg px-3 py-2">
          <AlertCircle size={13} /> {message}
        </div>
      )}
    </div>
  )
}

export default function Plugins() {
  const [plugins, setPlugins]         = useState([])
  const [loading, setLoading]         = useState(true)
  const [reloading, setReloading]     = useState(false)
  const [showTemplate, setShowTemplate] = useState(false)

  function load() {
    setLoading(true)
    api.plugins.list()
      .then(r => setPlugins(r.plugins || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  async function reload() {
    setReloading(true)
    try {
      const r = await api.plugins.reload()
      setPlugins(r.plugins || [])
    } catch (e) {
      alert('Reload failed: ' + e.message)
    } finally {
      setReloading(false)
    }
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {showTemplate && <TemplateModal onClose={() => setShowTemplate(false)} />}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-gray-100 flex items-center gap-2">
            <Puzzle size={18} className="text-indigo-400" /> Plugins
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            {plugins.length} plugin{plugins.length !== 1 ? 's' : ''} loaded from{' '}
            <code className="text-gray-600">/app/plugins</code>
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

      {/* Upload zone */}
      <UploadZone onUploaded={plugins => setPlugins(plugins)} />

      {/* Plugin list */}
      {loading ? (
        <div className="space-y-3">
          {[1,2].map(i => <div key={i} className="skeleton h-16 w-full" />)}
        </div>
      ) : plugins.length === 0 ? (
        <div className="card p-10 text-center">
          <Puzzle size={28} className="text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400 text-sm font-medium mb-1">No plugins loaded</p>
          <p className="text-gray-600 text-xs">
            Upload a plugin above or copy a{' '}
            <code className="text-gray-500">*_plugin.py</code> file into{' '}
            <code className="text-gray-500">/app/plugins/</code> and click Reload.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {plugins.map(p => (
            <div key={p.name} className="card p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-indigo-900/30 border border-indigo-800/40 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Puzzle size={14} className="text-indigo-400" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold text-gray-100">{p.name}</span>
                      <span className="badge bg-gray-700/70 text-gray-400 border border-gray-600/40">
                        v{p.version}
                      </span>
                      <span className="badge bg-green-900/30 text-green-400 border border-green-800/40">
                        <CheckCircle size={9} className="mr-1" /> active
                      </span>
                    </div>
                    <p className="text-xs text-gray-500">
                      Artifact type:{' '}
                      <code className="text-indigo-400 bg-indigo-950/50 px-1 py-0.5 rounded text-[10px]">
                        {p.default_artifact_type}
                      </code>
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1 justify-end max-w-xs">
                  {p.supported_extensions?.map(ext => (
                    <span key={ext} className="badge bg-gray-700/60 text-gray-300 border border-gray-600/40 font-mono">
                      {ext}
                    </span>
                  ))}
                  {p.handled_filenames?.map(fn => (
                    <span key={fn} className="badge bg-gray-700/60 text-gray-300 border border-gray-600/40 font-mono">
                      {fn}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
