/**
 * Studio — in-browser code editor for custom ingesters and modules.
 *
 * Ingesters  → ingester/*_ingester.py  — BasePlugin subclasses
 * Modules    → modules/*_module.py     — standalone run(run_id, …) functions
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Code2, Plus, Save, Trash2, CheckCircle, AlertCircle,
  RefreshCw, FileCode2, X, ChevronRight, Cpu, Puzzle,
  Play, BookOpen, Copy, Check,
} from 'lucide-react'
import { api } from '../api/client'

// ── Templates ─────────────────────────────────────────────────────────────────

const INGESTER_TEMPLATE = (name = 'my_format') => `"""
${name}_ingester.py — custom ingester for ${name.replace(/_/g, ' ')} artifacts.

Naming rules
  • File must end with _ingester.py
  • PLUGIN_NAME must be unique (used as artifact_type and ES index suffix)

Docs: /docs  →  "Creating a Custom Ingester"
"""
from base_plugin import BasePlugin, PluginContext, ParsedEvent


class ${name.replace(/(^|_)([a-z])/g, (_, _p, c) => c.toUpperCase())}Ingester(BasePlugin):
    # Unique artifact type — used as the ES index name suffix
    PLUGIN_NAME = "${name.replace(/_/g, '-')}"

    # File extensions this ingester handles (lower-case, with leading dot)
    SUPPORTED_EXTENSIONS = [".log", ".txt"]

    # Exact filenames to match (useful for system files without extensions)
    HANDLED_FILENAMES = []  # e.g. ["$MFT", "NTUSER.DAT"]

    def parse(self, file_path: str, context: PluginContext):
        """
        Generator — yield one ParsedEvent per record found in the file.

        ParsedEvent fields
          timestamp     str   ISO-8601 (required)
          message       str   human-readable description (required)
          artifact_type str   defaults to PLUGIN_NAME
          host          dict  e.g. {"hostname": "DESKTOP-1"}
          user          dict  e.g. {"name": "alice", "domain": "CORP"}
          extra         dict  any additional fields stored under their own key
        """
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.rstrip("\\n")
                if not line:
                    continue
                yield ParsedEvent(
                    timestamp=self._extract_timestamp(line),
                    message=line,
                    artifact_type=self.PLUGIN_NAME,
                    # host={"hostname": ""},
                    # user={"name": ""},
                    # extra={"line_no": line_no},
                )

    def _extract_timestamp(self, line: str) -> str:
        """Return ISO-8601 timestamp from line, or a fallback."""
        # TODO: implement real timestamp extraction
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"
`

const MODULE_TEMPLATE = (name = 'my_analysis') => `"""
${name}_module.py — custom analysis module: ${name.replace(/_/g, ' ')}.

Naming rules
  • File must end with _module.py
  • MODULE_NAME must match the file stem before _module

Docs: /docs  →  "Creating a Custom Module"
"""
import json
import os
from pathlib import Path

# ── Metadata (read by the API to display in the Modules list) ─────────────────

MODULE_NAME        = "${name.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}"
MODULE_DESCRIPTION = "Custom analysis module — describe what it does here"
# INPUT_EXTENSIONS   = [".log", ".txt"]   # leave empty to accept any file
INPUT_EXTENSIONS   = []
INPUT_FILENAMES    = []


# ── Entry point ───────────────────────────────────────────────────────────────

def run(run_id: str, case_id: str, source_files: list, params: dict,
        minio_client, redis_client, tmp_dir: Path) -> dict:
    """
    Execute the module against the provided source files.

    Parameters
    ----------
    run_id        Unique ID for this run (string)
    case_id       Case this run belongs to
    source_files  List of dicts: [{job_id, filename, minio_key}]
    params        User-supplied parameters (arbitrary dict)
    minio_client  Boto3-compatible MinIO client
    redis_client  Redis client (decode_responses=True)
    tmp_dir       pathlib.Path to a clean temporary directory

    Returns
    -------
    dict with keys:
      hits         list of result dicts (required)
      total_hits   int  (optional — computed from len(hits) if omitted)
    """
    hits = []

    for sf in source_files:
        local_path = tmp_dir / sf["filename"]

        # Download the source file from MinIO
        minio_client.fget_object(
            os.getenv("MINIO_BUCKET", "forensics-cases"),
            sf["minio_key"],
            str(local_path),
        )

        # ── TODO: replace with your real analysis logic ───────────────────────
        hits.append({
            "filename": sf["filename"],
            "message":  f"Processed {sf['filename']}",
            "level":    "info",
        })

    return {
        "hits":       hits,
        "total_hits": len(hits),
    }
`

// ── Helpers ───────────────────────────────────────────────────────────────────

function fileId(type, name) { return `${type}:${name}` }

// ── NewFileModal ──────────────────────────────────────────────────────────────

function NewFileModal({ type, existing, onClose, onCreate }) {
  const [name, setName] = useState('')
  const suffix = type === 'ingester' ? '_ingester' : '_module'
  const ext    = '.py'

  function handleCreate(e) {
    e.preventDefault()
    const slug = name.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_')
    if (!slug) return
    const full = `${slug}${suffix}${ext}`
    if (existing.includes(full)) {
      alert(`${full} already exists.`)
      return
    }
    onCreate(full)
    onClose()
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box max-w-md">
        <div className="modal-header">
          <div className="flex items-center gap-2">
            <Plus size={16} className="text-brand-accent" />
            <span className="text-sm font-semibold">
              New {type === 'ingester' ? 'Ingester' : 'Module'}
            </span>
          </div>
          <button className="icon-btn" onClick={onClose}><X size={14} /></button>
        </div>
        <form onSubmit={handleCreate} className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1.5">
              Name <span className="text-gray-400">(letters, digits, underscores)</span>
            </label>
            <div className="flex items-center gap-1">
              <input
                autoFocus
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder={type === 'ingester' ? 'my_format' : 'my_analysis'}
                className="input flex-1"
              />
              <span className="text-xs text-gray-400 font-mono whitespace-nowrap">
                {suffix}{ext}
              </span>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary text-sm" disabled={!name.trim()}>
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── DeleteConfirmModal ────────────────────────────────────────────────────────

function DeleteConfirmModal({ file, onClose, onConfirm }) {
  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box max-w-sm">
        <div className="modal-header">
          <span className="text-sm font-semibold text-red-600">Delete file</span>
          <button className="icon-btn" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="p-5 space-y-4">
          <p className="text-sm text-gray-600">
            Delete <code className="text-brand-accent font-mono">{file}</code>?
            This cannot be undone.
          </p>
          <div className="flex justify-end gap-2">
            <button className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
            <button className="btn-danger text-sm" onClick={onConfirm}>Delete</button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── CodeEditor ────────────────────────────────────────────────────────────────

function CodeEditor({ value, onChange, readOnly = false }) {
  const textareaRef = useRef(null)

  // Tab key → insert 4 spaces
  function handleKeyDown(e) {
    if (readOnly) return
    if (e.key === 'Tab') {
      e.preventDefault()
      const ta = e.target
      const start = ta.selectionStart
      const end   = ta.selectionEnd
      const spaces = '    '
      const next  = value.substring(0, start) + spaces + value.substring(end)
      onChange(next)
      requestAnimationFrame(() => {
        ta.selectionStart = ta.selectionEnd = start + spaces.length
      })
    }
  }

  return (
    <textarea
      ref={textareaRef}
      value={value}
      onChange={e => onChange(e.target.value)}
      onKeyDown={handleKeyDown}
      readOnly={readOnly}
      spellCheck={false}
      className="w-full h-full resize-none font-mono text-xs leading-relaxed
                 bg-gray-950 text-gray-200 p-4 outline-none
                 focus:ring-0 border-0"
      style={{ tabSize: 4, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace' }}
    />
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Studio() {
  const [tab, setTab]               = useState('ingesters')  // 'ingesters' | 'modules'
  const [ingesterFiles, setIngFiles] = useState([])
  const [moduleFiles, setModFiles]   = useState([])
  const [selected, setSelected]     = useState(null)  // {type, name}
  const [code, setCode]             = useState('')
  const [originalCode, setOrigCode] = useState('')
  const [loading, setLoading]       = useState(false)
  const [saving, setSaving]         = useState(false)
  const [validating, setValidating] = useState(false)
  const [validation, setValidation] = useState(null)  // {valid, error?}
  const [saveMsg, setSaveMsg]       = useState(null)
  const [showNew, setShowNew]       = useState(false)
  const [showDelete, setShowDelete] = useState(false)
  const [copied, setCopied]         = useState(false)

  const isDirty = code !== originalCode

  // ── Load file lists ───────────────────────────────────────────────────────

  const loadLists = useCallback(async () => {
    try {
      const [ing, mod] = await Promise.all([
        api.editor.listIngesters(),
        api.editor.listModules(),
      ])
      setIngFiles(ing.files || [])
      setModFiles(mod.files || [])
    } catch (_) {}
  }, [])

  useEffect(() => { loadLists() }, [loadLists])

  // ── Open a file ───────────────────────────────────────────────────────────

  async function openFile(type, name) {
    if (isDirty && !confirm('Discard unsaved changes?')) return
    setLoading(true)
    setValidation(null)
    setSaveMsg(null)
    try {
      const res = type === 'ingester'
        ? await api.editor.getIngester(name)
        : await api.editor.getModule(name)
      setCode(res.content)
      setOrigCode(res.content)
      setSelected({ type, name })
    } catch (err) {
      alert('Failed to load: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // ── Create new file ───────────────────────────────────────────────────────

  async function handleCreate(name) {
    const type = tab === 'ingesters' ? 'ingester' : 'module'
    const stem = name.replace(/_ingester\.py$/, '').replace(/_module\.py$/, '')
    const template = type === 'ingester'
      ? INGESTER_TEMPLATE(stem)
      : MODULE_TEMPLATE(stem)

    setSaving(true)
    try {
      if (type === 'ingester') {
        await api.editor.saveIngester(name, { content: template })
      } else {
        await api.editor.saveModule(name, { content: template })
      }
      await loadLists()
      setCode(template)
      setOrigCode(template)
      setSelected({ type, name })
      setValidation(null)
      setSaveMsg({ ok: true, text: 'File created' })
      setTimeout(() => setSaveMsg(null), 3000)
    } catch (err) {
      alert('Create failed: ' + err.message)
    } finally {
      setSaving(false)
    }
  }

  // ── Save ──────────────────────────────────────────────────────────────────

  async function handleSave() {
    if (!selected) return
    setSaving(true)
    setValidation(null)
    setSaveMsg(null)
    try {
      if (selected.type === 'ingester') {
        await api.editor.saveIngester(selected.name, { content: code })
      } else {
        await api.editor.saveModule(selected.name, { content: code })
      }
      setOrigCode(code)
      setSaveMsg({ ok: true, text: 'Saved' })
      setTimeout(() => setSaveMsg(null), 3000)
    } catch (err) {
      setSaveMsg({ ok: false, text: err.message })
    } finally {
      setSaving(false)
    }
  }

  // ── Validate ──────────────────────────────────────────────────────────────

  async function handleValidate() {
    setValidating(true)
    setValidation(null)
    try {
      const res = await api.editor.validate(code)
      setValidation(res)
    } catch (_) {
      setValidation({ valid: false, error: 'Validation request failed' })
    } finally {
      setValidating(false)
    }
  }

  // ── Delete ────────────────────────────────────────────────────────────────

  async function handleDelete() {
    if (!selected) return
    setShowDelete(false)
    try {
      if (selected.type === 'ingester') {
        await api.editor.deleteIngester(selected.name)
      } else {
        await api.editor.deleteModule(selected.name)
      }
      setSelected(null)
      setCode('')
      setOrigCode('')
      setValidation(null)
      await loadLists()
    } catch (err) {
      alert('Delete failed: ' + err.message)
    }
  }

  // ── Copy ──────────────────────────────────────────────────────────────────

  function handleCopy() {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // ── File list for current tab ─────────────────────────────────────────────

  const files    = tab === 'ingesters' ? ingesterFiles : moduleFiles
  const fileType = tab === 'ingesters' ? 'ingester' : 'module'
  const existingNames = files.map(f => f.name)

  return (
    <div className="flex flex-1 overflow-hidden min-h-0">

      {/* ── Sidebar ─────────────────────────────────────────────────────────── */}
      <aside className="w-56 flex-shrink-0 flex flex-col border-r border-gray-200 bg-white overflow-hidden">

        {/* Tab switcher */}
        <div className="flex border-b border-gray-200 flex-shrink-0">
          <button
            onClick={() => setTab('ingesters')}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 text-xs font-medium transition-colors ${
              tab === 'ingesters'
                ? 'text-brand-accent border-b-2 border-brand-accent bg-brand-accentlight/50'
                : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
            }`}
          >
            <Puzzle size={13} /> Ingesters
          </button>
          <button
            onClick={() => setTab('modules')}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 text-xs font-medium transition-colors ${
              tab === 'modules'
                ? 'text-brand-accent border-b-2 border-brand-accent bg-brand-accentlight/50'
                : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
            }`}
          >
            <Cpu size={13} /> Modules
          </button>
        </div>

        {/* New file button */}
        <div className="px-3 py-2 flex-shrink-0">
          <button
            onClick={() => setShowNew(true)}
            className="w-full btn-primary text-xs justify-center py-1.5"
          >
            <Plus size={12} /> New {fileType === 'ingester' ? 'Ingester' : 'Module'}
          </button>
        </div>

        {/* File list */}
        <div className="flex-1 overflow-y-auto py-1">
          {files.length === 0 ? (
            <div className="px-3 py-4 text-center">
              <FileCode2 size={20} className="text-gray-300 mx-auto mb-2" />
              <p className="text-[11px] text-gray-400">No files yet</p>
            </div>
          ) : (
            files.map(f => {
              const isOpen = selected?.type === fileType && selected?.name === f.name
              return (
                <button
                  key={f.name}
                  onClick={() => openFile(fileType, f.name)}
                  className={`w-full flex items-center gap-2 px-3 py-1.5 text-left transition-colors ${
                    isOpen
                      ? 'bg-brand-accentlight text-brand-accent'
                      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                  }`}
                >
                  <FileCode2 size={13} className="flex-shrink-0 opacity-60" />
                  <span className="text-[11px] font-mono truncate flex-1">{f.name}</span>
                  {isOpen && <ChevronRight size={10} className="flex-shrink-0 opacity-50" />}
                </button>
              )
            })
          )}
        </div>
      </aside>

      {/* ── Editor pane ─────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {selected ? (
          <>
            {/* Editor toolbar */}
            <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 bg-white flex-shrink-0 gap-3">
              <div className="flex items-center gap-2 min-w-0">
                <span className={`badge text-[10px] ${
                  selected.type === 'ingester'
                    ? 'bg-blue-50 text-blue-700 border border-blue-100'
                    : 'bg-purple-50 text-purple-700 border border-purple-100'
                }`}>
                  {selected.type === 'ingester' ? 'ingester' : 'module'}
                </span>
                <code className="text-xs font-mono text-gray-700 truncate">{selected.name}</code>
                {isDirty && (
                  <span className="w-2 h-2 rounded-full bg-amber-400 flex-shrink-0" title="Unsaved changes" />
                )}
              </div>

              <div className="flex items-center gap-1.5 flex-shrink-0">
                {/* Validation result badge */}
                {validation && (
                  validation.valid
                    ? <span className="flex items-center gap-1 text-[11px] text-green-700 bg-green-50 border border-green-200 rounded-lg px-2 py-0.5">
                        <CheckCircle size={11} /> Valid
                      </span>
                    : <span className="flex items-center gap-1 text-[11px] text-red-600 bg-red-50 border border-red-200 rounded-lg px-2 py-0.5 max-w-xs truncate" title={validation.error}>
                        <AlertCircle size={11} />
                        <span className="truncate">{validation.error}</span>
                      </span>
                )}
                {/* Save message */}
                {saveMsg && (
                  <span className={`text-[11px] ${saveMsg.ok ? 'text-green-700' : 'text-red-600'}`}>
                    {saveMsg.ok ? <CheckCircle size={11} className="inline mr-1" /> : <AlertCircle size={11} className="inline mr-1" />}
                    {saveMsg.text}
                  </span>
                )}

                <button onClick={handleCopy} className="btn-ghost text-xs py-1 px-2">
                  {copied ? <><Check size={12} className="text-green-600" /> Copied</> : <><Copy size={12} /> Copy</>}
                </button>
                <button
                  onClick={handleValidate}
                  disabled={validating}
                  className="btn-outline text-xs py-1 px-2"
                >
                  {validating
                    ? <RefreshCw size={12} className="animate-spin" />
                    : <Play size={12} />}
                  {validating ? 'Checking…' : 'Validate'}
                </button>
                <button
                  onClick={handleSave}
                  disabled={saving || !isDirty}
                  className="btn-primary text-xs py-1 px-2"
                >
                  {saving
                    ? <RefreshCw size={12} className="animate-spin" />
                    : <Save size={12} />}
                  {saving ? 'Saving…' : 'Save'}
                </button>
                <button
                  onClick={() => setShowDelete(true)}
                  className="btn-danger text-xs py-1 px-2"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            </div>

            {/* Validation error detail */}
            {validation && !validation.valid && validation.error && (
              <div className="bg-red-50 border-b border-red-200 px-4 py-2 flex items-start gap-2">
                <AlertCircle size={13} className="text-red-500 flex-shrink-0 mt-0.5" />
                <pre className="text-[11px] text-red-700 font-mono whitespace-pre-wrap break-all leading-relaxed">
                  {validation.error}
                </pre>
              </div>
            )}

            {/* Code editor */}
            <div className="flex-1 overflow-hidden">
              {loading ? (
                <div className="h-full bg-gray-950 flex items-center justify-center">
                  <RefreshCw size={20} className="animate-spin text-gray-500" />
                </div>
              ) : (
                <CodeEditor value={code} onChange={setCode} />
              )}
            </div>
          </>
        ) : (
          /* Empty state */
          <div className="flex-1 flex flex-col items-center justify-center bg-gray-950 text-center p-8">
            <div className="w-16 h-16 rounded-2xl bg-white/5 flex items-center justify-center mb-4">
              <Code2 size={28} className="text-gray-500" />
            </div>
            <p className="text-gray-400 text-sm font-medium mb-1">
              Select a file to edit
            </p>
            <p className="text-gray-600 text-xs mb-6 max-w-xs">
              Choose an ingester or module from the sidebar, or create a new one.
            </p>
            <div className="flex gap-2">
              <a href="/docs" className="btn-outline text-xs">
                <BookOpen size={13} /> Read the docs
              </a>
            </div>
          </div>
        )}
      </div>

      {/* ── Modals ──────────────────────────────────────────────────────────── */}
      {showNew && (
        <NewFileModal
          type={fileType}
          existing={existingNames}
          onClose={() => setShowNew(false)}
          onCreate={handleCreate}
        />
      )}
      {showDelete && selected && (
        <DeleteConfirmModal
          file={selected.name}
          onClose={() => setShowDelete(false)}
          onConfirm={handleDelete}
        />
      )}
    </div>
  )
}
