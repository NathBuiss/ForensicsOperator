/**
 * Studio — in-browser code editor for custom ingesters and modules.
 * Supports VS Code-style multi-file tabs with independent dirty state per tab.
 *
 * Ingesters  → ingester/*_ingester.py  — BasePlugin subclasses
 * Modules    → modules/*_module.py     — standalone run(run_id, …) functions
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import {
  Code2, Plus, Save, Trash2, CheckCircle, AlertCircle,
  RefreshCw, FileCode2, X, ChevronRight, Cpu, Puzzle,
  Play, BookOpen, Copy, Check, Lock,
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
  const location = useLocation()

  // Sidebar panel selection ('ingesters' | 'modules')
  const [sidebarTab, setSidebarTab]     = useState('ingesters')
  const [ingesterFiles, setIngFiles]    = useState([])
  const [moduleFiles, setModFiles]      = useState([])

  // Multi-tab state — each tab: { type, name, code, originalCode, loading,
  //   saving, validating, validation, saveMsg, copied }
  const [openTabs, setOpenTabs]         = useState([])
  const [activeTabKey, setActiveTabKey] = useState(null)   // "type:name"

  // Modal visibility
  const [showNew, setShowNew]           = useState(false)
  const [showDelete, setShowDelete]     = useState(false)

  // Derived state
  const activeTab = openTabs.find(t => fileId(t.type, t.name) === activeTabKey) || null
  const isDirty   = activeTab ? activeTab.code !== activeTab.originalCode : false

  // ── Tab mutation helper ────────────────────────────────────────────────────

  function updateTab(type, name, patch) {
    setOpenTabs(tabs => tabs.map(t =>
      t.type === type && t.name === name ? { ...t, ...patch } : t
    ))
  }

  // ── Load file lists ────────────────────────────────────────────────────────

  const loadLists = useCallback(async () => {
    try {
      const [ing, mod, ingBuiltin, modBuiltin] = await Promise.all([
        api.editor.listIngesters(),
        api.editor.listModules(),
        api.editor.listBuiltinIngesters().catch(() => ({ files: [] })),
        api.editor.listBuiltinModules().catch(() => ({ files: [] })),
      ])
      // Built-ins first (read-only), then custom (editable)
      setIngFiles([...(ingBuiltin.files || []), ...(ing.files || [])])
      setModFiles([...(modBuiltin.files || []), ...(mod.files || [])])
    } catch (_) {}
  }, [])

  useEffect(() => { loadLists() }, [loadLists])

  // ── Auto-open file when navigated from Modules / Ingesters pages ──────────

  const didAutoOpen = useRef(false)
  useEffect(() => {
    if (didAutoOpen.current) return
    const state = location.state
    if (!state?.type) return
    const { type, name } = state
    const fileList = type === 'module' ? moduleFiles : ingesterFiles
    if (fileList.length === 0) return   // wait until lists are loaded
    didAutoOpen.current = true
    setSidebarTab(type === 'module' ? 'modules' : 'ingesters')
    if (name) {
      const suffix = type === 'module' ? '_module.py' : '_ingester.py'
      const candidateName = fileList.includes(name) ? name
        : fileList.includes(name + suffix) ? name + suffix
        : null
      if (candidateName) {
        setTimeout(() => openFile(type, candidateName), 50)
      }
    }
  }, [location.state, ingesterFiles, moduleFiles]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Open a file (or switch to existing tab) ───────────────────────────────

  async function openFile(type, name, builtin = false) {
    const key = fileId(type, name)

    // Already open? Just switch to it
    if (openTabs.some(t => fileId(t.type, t.name) === key)) {
      setActiveTabKey(key)
      return
    }

    // Add a new loading tab and make it active
    const newTab = {
      type, name, builtin,
      code: '', originalCode: '',
      loading: true, saving: false, validating: false,
      validation: null, saveMsg: null, copied: false,
    }
    setOpenTabs(tabs => [...tabs, newTab])
    setActiveTabKey(key)

    try {
      let res
      if (builtin) {
        res = type === 'ingester'
          ? await api.editor.getBuiltinIngester(name)
          : await api.editor.getBuiltinModule(name)
      } else {
        res = type === 'ingester'
          ? await api.editor.getIngester(name)
          : await api.editor.getModule(name)
      }
      updateTab(type, name, {
        code: res.content,
        originalCode: res.content,
        loading: false,
      })
    } catch (err) {
      // Remove the failed tab
      setOpenTabs(tabs => tabs.filter(t => fileId(t.type, t.name) !== key))
      setActiveTabKey(prev => prev === key ? null : prev)
      alert('Failed to load: ' + err.message)
    }
  }

  // ── Close a tab (with unsaved-changes confirmation) ───────────────────────

  function closeTab(type, name) {
    const tab = openTabs.find(t => t.type === type && t.name === name)
    if (!tab) return
    if (tab.code !== tab.originalCode) {
      if (!confirm(`Discard unsaved changes to ${name}?`)) return
    }
    const key = fileId(type, name)
    const idx = openTabs.findIndex(t => fileId(t.type, t.name) === key)
    const remaining = openTabs.filter(t => fileId(t.type, t.name) !== key)
    setOpenTabs(remaining)
    if (activeTabKey === key) {
      const nextTab = remaining[idx] ?? remaining[idx - 1] ?? null
      setActiveTabKey(nextTab ? fileId(nextTab.type, nextTab.name) : null)
    }
  }

  // ── Create new file ────────────────────────────────────────────────────────

  async function handleCreate(name) {
    const type = sidebarTab === 'ingesters' ? 'ingester' : 'module'
    const stem = name.replace(/_ingester\.py$/, '').replace(/_module\.py$/, '')
    const template = type === 'ingester'
      ? INGESTER_TEMPLATE(stem)
      : MODULE_TEMPLATE(stem)

    const key = fileId(type, name)
    const newTab = {
      type, name,
      code: template, originalCode: template,
      loading: false, saving: true, validating: false,
      validation: null, saveMsg: null, copied: false,
    }
    // Open (or replace) tab immediately
    setOpenTabs(tabs => {
      const exists = tabs.some(t => fileId(t.type, t.name) === key)
      return exists
        ? tabs.map(t => fileId(t.type, t.name) === key ? newTab : t)
        : [...tabs, newTab]
    })
    setActiveTabKey(key)

    try {
      if (type === 'ingester') {
        await api.editor.saveIngester(name, { content: template })
      } else {
        await api.editor.saveModule(name, { content: template })
      }
      await loadLists()
      updateTab(type, name, {
        saving: false,
        saveMsg: { ok: true, text: 'File created' },
      })
      setTimeout(() => updateTab(type, name, { saveMsg: null }), 3000)
    } catch (err) {
      updateTab(type, name, { saving: false })
      alert('Create failed: ' + err.message)
    }
  }

  // ── Save active tab ────────────────────────────────────────────────────────

  async function handleSave() {
    if (!activeTab) return
    const { type, name, code, builtin } = activeTab   // capture at call time
    updateTab(type, name, { saving: true, validation: null, saveMsg: null })
    try {
      if (builtin) {
        if (type === 'ingester') {
          await api.editor.saveBuiltinIngester(name, { content: code })
        } else {
          await api.editor.saveBuiltinModule(name, { content: code })
        }
      } else {
        if (type === 'ingester') {
          await api.editor.saveIngester(name, { content: code })
        } else {
          await api.editor.saveModule(name, { content: code })
        }
      }
      updateTab(type, name, {
        originalCode: code,
        saving: false,
        saveMsg: { ok: true, text: 'Saved' },
      })
      setTimeout(() => updateTab(type, name, { saveMsg: null }), 3000)
    } catch (err) {
      updateTab(type, name, {
        saving: false,
        saveMsg: { ok: false, text: err.message },
      })
    }
  }

  // ── Validate active tab ────────────────────────────────────────────────────

  async function handleValidate() {
    if (!activeTab) return
    const { type, name, code } = activeTab
    updateTab(type, name, { validating: true, validation: null })
    try {
      const res = await api.editor.validate(code)
      updateTab(type, name, { validating: false, validation: res })
    } catch (_) {
      updateTab(type, name, {
        validating: false,
        validation: { valid: false, error: 'Validation request failed' },
      })
    }
  }

  // ── Delete active tab's file ───────────────────────────────────────────────

  async function handleDelete() {
    if (!activeTab) return
    setShowDelete(false)
    const { type, name, builtin } = activeTab
    const key = fileId(type, name)
    const idx = openTabs.findIndex(t => fileId(t.type, t.name) === key)
    try {
      if (builtin) {
        if (type === 'ingester') {
          await api.editor.deleteBuiltinIngester(name)
        } else {
          await api.editor.deleteBuiltinModule(name)
        }
      } else {
        if (type === 'ingester') {
          await api.editor.deleteIngester(name)
        } else {
          await api.editor.deleteModule(name)
        }
      }
      // Force-close tab (no dirty check — file is already deleted)
      const remaining = openTabs.filter(t => fileId(t.type, t.name) !== key)
      setOpenTabs(remaining)
      const nextTab = remaining[idx] ?? remaining[idx - 1] ?? null
      setActiveTabKey(nextTab ? fileId(nextTab.type, nextTab.name) : null)
      await loadLists()
    } catch (err) {
      alert('Delete failed: ' + err.message)
    }
  }

  // ── Copy active tab ────────────────────────────────────────────────────────

  function handleCopy() {
    if (!activeTab) return
    const { type, name, code } = activeTab
    navigator.clipboard.writeText(code)
    updateTab(type, name, { copied: true })
    setTimeout(() => updateTab(type, name, { copied: false }), 2000)
  }

  // ── Sidebar helpers ────────────────────────────────────────────────────────

  const sidebarFiles    = sidebarTab === 'ingesters' ? ingesterFiles : moduleFiles
  const sidebarFileType = sidebarTab === 'ingesters' ? 'ingester' : 'module'
  // NewFileModal only cares about custom file names (no collisions with built-ins expected)
  const existingNames   = sidebarFiles.map(f => f.name)

  return (
    <div className="flex flex-1 overflow-hidden min-h-0">

      {/* ── Sidebar ─────────────────────────────────────────────────────────── */}
      <aside className="w-56 flex-shrink-0 flex flex-col border-r border-gray-200 bg-white overflow-hidden">

        {/* Panel tab switcher */}
        <div className="flex border-b border-gray-200 flex-shrink-0">
          <button
            onClick={() => setSidebarTab('ingesters')}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 text-xs font-medium transition-colors ${
              sidebarTab === 'ingesters'
                ? 'text-brand-accent border-b-2 border-brand-accent bg-brand-accentlight/50'
                : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
            }`}
          >
            <Puzzle size={13} /> Ingesters
          </button>
          <button
            onClick={() => setSidebarTab('modules')}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 text-xs font-medium transition-colors ${
              sidebarTab === 'modules'
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
            <Plus size={12} /> New {sidebarFileType === 'ingester' ? 'Ingester' : 'Module'}
          </button>
        </div>

        {/* File list */}
        <div className="flex-1 overflow-y-auto py-1">
          {sidebarFiles.length === 0 ? (
            <div className="px-3 py-4 text-center">
              <FileCode2 size={20} className="text-gray-300 mx-auto mb-2" />
              <p className="text-[11px] text-gray-400">No files yet</p>
            </div>
          ) : (() => {
            const builtins = sidebarFiles.filter(f => f.builtin)
            const customs  = sidebarFiles.filter(f => !f.builtin)
            const renderFile = f => {
              const key        = fileId(sidebarFileType, f.name)
              const isActive   = activeTabKey === key
              const openTab    = openTabs.find(t => fileId(t.type, t.name) === key)
              const isOpen     = Boolean(openTab)
              const isDirtyTab = isOpen && openTab.code !== openTab.originalCode
              return (
                <button
                  key={f.name}
                  onClick={() => openFile(sidebarFileType, f.name, !!f.builtin)}
                  className={`w-full flex items-center gap-2 px-3 py-1.5 text-left transition-colors ${
                    isActive
                      ? 'bg-brand-accentlight text-brand-accent'
                      : isOpen
                        ? 'bg-blue-50/50 text-gray-700 hover:bg-blue-50'
                        : f.builtin
                          ? 'text-gray-400 hover:bg-gray-50 hover:text-gray-600'
                          : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                  }`}
                >
                  {f.builtin
                    ? <Lock size={11} className="flex-shrink-0 opacity-50" />
                    : <FileCode2 size={13} className="flex-shrink-0 opacity-60" />
                  }
                  <span className="text-[11px] font-mono truncate flex-1">{f.name}</span>
                  {isDirtyTab && (
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0" title="Unsaved changes" />
                  )}
                  {isActive && !isDirtyTab && (
                    <ChevronRight size={10} className="flex-shrink-0 opacity-50" />
                  )}
                </button>
              )
            }
            return (
              <>
                {builtins.length > 0 && (
                  <>
                    <p className="px-3 pt-2 pb-1 text-[9px] font-semibold text-gray-400 uppercase tracking-widest">
                      Built-in
                    </p>
                    {builtins.map(renderFile)}
                  </>
                )}
                {customs.length > 0 && (
                  <>
                    <p className="px-3 pt-3 pb-1 text-[9px] font-semibold text-gray-400 uppercase tracking-widest">
                      Custom
                    </p>
                    {customs.map(renderFile)}
                  </>
                )}
              </>
            )
          })()}
        </div>
      </aside>

      {/* ── Editor pane ─────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* ── Tab bar ───────────────────────────────────────────────────────── */}
        {openTabs.length > 0 && (
          <div className="flex items-stretch border-b border-gray-200 bg-gray-50/80 overflow-x-auto flex-shrink-0">
            {openTabs.map(t => {
              const key      = fileId(t.type, t.name)
              const isActive = key === activeTabKey
              const tabDirty = t.code !== t.originalCode

              return (
                <div
                  key={key}
                  onClick={() => setActiveTabKey(key)}
                  className={`flex items-center gap-1.5 px-3 py-2 border-r border-gray-200
                    cursor-pointer flex-shrink-0 max-w-[200px] group transition-colors
                    ${isActive
                      ? 'bg-white border-b-2 border-b-brand-accent text-gray-800'
                      : 'border-b-2 border-b-transparent text-gray-500 hover:bg-gray-100 hover:text-gray-700'
                    }`}
                >
                  {/* Type badge */}
                  <span className={`text-[9px] px-1 py-px rounded font-bold flex-shrink-0 ${
                    t.type === 'ingester'
                      ? 'bg-blue-100 text-blue-600'
                      : 'bg-purple-100 text-purple-600'
                  }`}>
                    {t.type === 'ingester' ? 'I' : 'M'}
                  </span>

                  {/* Filename */}
                  <span className="text-[11px] font-mono truncate flex-1 min-w-0">{t.name}</span>

                  {/* Dirty dot — always visible when dirty; hidden by close btn on hover */}
                  {tabDirty && (
                    <span
                      className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0 group-hover:hidden"
                      title="Unsaved changes"
                    />
                  )}

                  {/* Close button — visible on hover or when active */}
                  <button
                    onClick={e => { e.stopPropagation(); closeTab(t.type, t.name) }}
                    className={`rounded p-0.5 hover:bg-gray-200 flex-shrink-0 transition-opacity
                      ${isActive ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}
                    title="Close tab"
                  >
                    <X size={9} className="text-gray-500" />
                  </button>
                </div>
              )
            })}
          </div>
        )}

        {activeTab ? (
          <>
            {/* Editor toolbar */}
            <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 bg-white flex-shrink-0 gap-3">
              <div className="flex items-center gap-2 min-w-0">
                <span className={`badge text-[10px] ${
                  activeTab.type === 'ingester'
                    ? 'bg-blue-50 text-blue-700 border border-blue-100'
                    : 'bg-purple-50 text-purple-700 border border-purple-100'
                }`}>
                  {activeTab.type === 'ingester' ? 'ingester' : 'module'}
                </span>
                <code className="text-xs font-mono text-gray-700 truncate">{activeTab.name}</code>
                {isDirty && (
                  <span className="w-2 h-2 rounded-full bg-amber-400 flex-shrink-0" title="Unsaved changes" />
                )}
              </div>

              <div className="flex items-center gap-1.5 flex-shrink-0">
                {/* Validation result badge */}
                {activeTab.validation && (
                  activeTab.validation.valid
                    ? <span className="flex items-center gap-1 text-[11px] text-green-700 bg-green-50 border border-green-200 rounded-lg px-2 py-0.5">
                        <CheckCircle size={11} /> Valid
                      </span>
                    : <span className="flex items-center gap-1 text-[11px] text-red-600 bg-red-50 border border-red-200 rounded-lg px-2 py-0.5 max-w-xs truncate" title={activeTab.validation.error}>
                        <AlertCircle size={11} />
                        <span className="truncate">{activeTab.validation.error}</span>
                      </span>
                )}

                {/* Save message */}
                {activeTab.saveMsg && (
                  <span className={`text-[11px] ${activeTab.saveMsg.ok ? 'text-green-700' : 'text-red-600'}`}>
                    {activeTab.saveMsg.ok
                      ? <CheckCircle size={11} className="inline mr-1" />
                      : <AlertCircle size={11} className="inline mr-1" />}
                    {activeTab.saveMsg.text}
                  </span>
                )}

                <button onClick={handleCopy} className="btn-ghost text-xs py-1 px-2">
                  {activeTab.copied
                    ? <><Check size={12} className="text-green-600" /> Copied</>
                    : <><Copy size={12} /> Copy</>}
                </button>
                <button
                  onClick={handleValidate}
                  disabled={activeTab.validating}
                  className="btn-outline text-xs py-1 px-2"
                >
                  {activeTab.validating
                    ? <RefreshCw size={12} className="animate-spin" />
                    : <Play size={12} />}
                  {activeTab.validating ? 'Checking…' : 'Validate'}
                </button>
                <button
                  onClick={handleSave}
                  disabled={activeTab.saving || !isDirty}
                  className="btn-primary text-xs py-1 px-2"
                >
                  {activeTab.saving
                    ? <RefreshCw size={12} className="animate-spin" />
                    : <Save size={12} />}
                  {activeTab.saving ? 'Saving…' : 'Save'}
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
            {activeTab.validation && !activeTab.validation.valid && activeTab.validation.error && (
              <div className="bg-red-50 border-b border-red-200 px-4 py-2 flex items-start gap-2">
                <AlertCircle size={13} className="text-red-500 flex-shrink-0 mt-0.5" />
                <pre className="text-[11px] text-red-700 font-mono whitespace-pre-wrap break-all leading-relaxed">
                  {activeTab.validation.error}
                </pre>
              </div>
            )}

            {/* Code editor — remount on tab switch to reset cursor position */}
            <div className="flex-1 overflow-hidden">
              {activeTab.loading ? (
                <div className="h-full bg-gray-950 flex items-center justify-center">
                  <RefreshCw size={20} className="animate-spin text-gray-500" />
                </div>
              ) : (
                <CodeEditor
                  key={activeTabKey}
                  value={activeTab.code}
                  onChange={v => updateTab(activeTab.type, activeTab.name, { code: v })}
                />
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
          type={sidebarFileType}
          existing={existingNames}
          onClose={() => setShowNew(false)}
          onCreate={handleCreate}
        />
      )}
      {showDelete && activeTab && (
        <DeleteConfirmModal
          file={activeTab.name}
          onClose={() => setShowDelete(false)}
          onConfirm={handleDelete}
        />
      )}
    </div>
  )
}
