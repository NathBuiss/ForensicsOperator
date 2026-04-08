/**
 * Studio — in-browser code editor for custom ingesters, modules,
 * YARA rules, and alert rules.
 *
 * Supports VS Code-style multi-file tabs with independent dirty state per tab.
 *
 * Ingesters   → ingester/*_ingester.py  — BasePlugin subclasses
 * Modules     → modules/*_module.py     — standalone run(run_id, …) functions
 * YARA Rules  → stored in Redis / YARA library
 * Alert Rules → stored in Redis / global alert-rule library (Sigma or custom YAML)
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import {
  Code2, Plus, Save, Trash2, CheckCircle, AlertCircle,
  RefreshCw, FileCode2, X, ChevronRight, Cpu, Puzzle,
  Play, BookOpen, Copy, Check, Lock, Shield, Bell,
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
  • MODULE_NAME is displayed in the Modules panel
  • INPUT_EXTENSIONS filters which source files are shown when launching

Security model
  • Code runs in an isolated subprocess with resource limits:
      CPU: 3600s   Memory: 2 GB   File writes: 500 MB   Subprocesses: 64
  • Sensitive env vars are stripped before your code runs
  • tmp_dir is the only writable work area (cleaned up automatically)
"""
import re
import subprocess
from pathlib import Path

# ── Module metadata (read by the platform to populate the Modules list) ────────

MODULE_NAME        = "${name.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}"
MODULE_DESCRIPTION = "Custom analysis module — describe what it does here"

# File extensions this module accepts (lower-case, with dot). Leave empty for any.
INPUT_EXTENSIONS   = []
# Exact filenames to match regardless of extension (e.g. ["NTUSER.DAT", "$MFT"])
INPUT_FILENAMES    = []


# ── Entry point ────────────────────────────────────────────────────────────────

def run(
    run_id: str,
    case_id: str,
    source_files: list,
    params: dict,
    minio_client,       # minio.Minio — fget_object / put_object / etc.
    redis_client,       # redis.Redis (decode_responses=True)
    tmp_dir: Path,      # clean temp directory, wiped after the run
) -> list:
    """
    Execute the module and return a list of findings.

    Each finding dict must have at minimum:
      filename  str   — source file the finding came from
      message   str   — human-readable description
      level     str   — "critical" | "high" | "medium" | "low" | "info"
    Additional fields are stored and rendered in the results panel as-is.
    """
    MINIO_BUCKET = "forensics-cases"
    hits = []

    for sf in source_files:
        local_path = tmp_dir / sf["filename"]

        # ── Download source file from MinIO ────────────────────────────────────
        minio_client.fget_object(MINIO_BUCKET, sf["minio_key"], str(local_path))

        # ── Example: extract printable strings and flag suspicious patterns ────
        try:
            proc = subprocess.run(
                ["strings", "-n", "8", str(local_path)],
                capture_output=True, text=True, timeout=120,
            )
            strings_found = proc.stdout.splitlines()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Pure-Python fallback if 'strings' binary is unavailable
            with open(local_path, "rb") as fh:
                data = fh.read()
            strings_found = [
                s.decode("ascii", errors="replace")
                for s in re.findall(rb"[ -~]{8,}", data)
            ]

        # Flag patterns of interest — replace or extend this dict
        ioc_patterns = {
            r"(?i)powershell":               ("high",     "PowerShell reference"),
            r"(?i)mimikatz":                 ("critical", "Mimikatz reference"),
            r"(?i)cmd\\.exe":                ("medium",   "cmd.exe reference"),
            r"https?://[^\\s]{10,}":         ("medium",   "URL found"),
            r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b": ("low", "IP address found"),
        }

        for string in strings_found:
            for pattern, (level, label) in ioc_patterns.items():
                if re.search(pattern, string):
                    hits.append({
                        "filename": sf["filename"],
                        "level":    level,
                        "message":  f"{label}: {string[:200]}",
                        "string":   string[:500],
                    })

        # Limit to first 1000 hits per file
        hits = hits[:1000]

    return hits
`

const YARA_TEMPLATE = (name = 'MyRule') => {
  const ruleName = name.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^[0-9]/, '_$&')
  return `rule ${ruleName} {
    meta:
        description = "Describe what this rule detects"
        author      = "analyst"
        date        = "${new Date().toISOString().slice(0, 10)}"

    strings:
        $s1 = "suspicious_string" nocase
        $s2 = "another_indicator"
        $b1 = { 4D 5A 90 00 }       // MZ header

    condition:
        any of them
}
`
}

const SIGMA_TEMPLATE = (name = 'My Rule') => `title: ${name}
id: ${crypto.randomUUID ? crypto.randomUUID() : ''}
status: experimental
description: Detect suspicious activity — describe here
author: analyst
date: ${new Date().toISOString().slice(0, 10)}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        CommandLine|contains: 'suspicious'
    condition: selection
level: medium
tags:
    - attack.execution
falsepositives:
    - Legitimate use
`

const CUSTOM_RULE_TEMPLATE = (name = 'My Rule') => `# Custom alert rule (not Sigma)
# Edit the fields below and save to add to the library.
name: ${name}
description: Detect suspicious activity
category: General
artifact_type: evtx
query: evtx.event_id:4625
threshold: 1
`

// ── Helpers ───────────────────────────────────────────────────────────────────

function fileId(type, name) { return `${type}:${name}` }

/** Parse a "custom rule YAML" string (fixed schema, no yaml library needed). */
function parseCustomAlertRuleYaml(text) {
  const get = (key) => {
    const m = text.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'))
    return m ? m[1].replace(/^["']|["']$/g, '').trim() : ''
  }
  return {
    name:          get('name'),
    description:   get('description'),
    category:      get('category'),
    artifact_type: get('artifact_type'),
    query:         get('query'),
    threshold:     parseInt(get('threshold'), 10) || 1,
    sigma_yaml:    '',
  }
}

/** Convert an alert rule object to its editable code representation. */
function alertRuleToCode(rule) {
  if (rule.sigma_yaml) return rule.sigma_yaml
  // Generate synthetic custom YAML from stored fields
  const lines = [
    `# Custom alert rule`,
    `name: ${rule.name || ''}`,
    `description: ${rule.description || ''}`,
    `category: ${rule.category || ''}`,
    `artifact_type: ${rule.artifact_type || ''}`,
    `query: ${rule.query || ''}`,
    `threshold: ${rule.threshold ?? 1}`,
  ]
  return lines.join('\n') + '\n'
}

// ── Type metadata ─────────────────────────────────────────────────────────────

const TYPE_BADGE = {
  ingester:  { letter: 'I', cls: 'bg-blue-100 text-blue-600' },
  module:    { letter: 'M', cls: 'bg-purple-100 text-purple-600' },
  yara:      { letter: 'Y', cls: 'bg-green-100 text-green-600' },
  alertrule: { letter: 'A', cls: 'bg-orange-100 text-orange-600' },
}

const TYPE_TOOLBAR = {
  ingester:  { label: 'ingester',   cls: 'bg-blue-50 text-blue-700 border border-blue-100' },
  module:    { label: 'module',     cls: 'bg-purple-50 text-purple-700 border border-purple-100' },
  yara:      { label: 'yara rule',  cls: 'bg-green-50 text-green-700 border border-green-100' },
  alertrule: { label: 'alert rule', cls: 'bg-orange-50 text-orange-700 border border-orange-100' },
}

// ── NewFileModal ──────────────────────────────────────────────────────────────

function NewFileModal({ type, existing, onClose, onCreate }) {
  const [name, setName]   = useState('')
  const [ruleKind, setRuleKind] = useState('sigma')   // 'sigma' | 'custom' — only for alertrule

  const isCodeFile = type === 'ingester' || type === 'module'
  const suffix = type === 'ingester' ? '_ingester' : type === 'module' ? '_module' : ''
  const ext    = isCodeFile ? '.py' : ''

  const titles = { ingester: 'Ingester', module: 'Module', yara: 'YARA Rule', alertrule: 'Alert Rule' }
  const placeholders = { ingester: 'my_format', module: 'my_analysis', yara: 'DetectMimikatz', alertrule: 'Suspicious Login' }

  function handleCreate(e) {
    e.preventDefault()
    const trimmed = name.trim()
    if (!trimmed) return
    if (isCodeFile) {
      const slug = trimmed.toLowerCase().replace(/[^a-z0-9_]/g, '_')
      const full = `${slug}${suffix}${ext}`
      if (existing.includes(full)) { alert(`${full} already exists.`); return }
      onCreate(full)
    } else {
      onCreate(trimmed, type === 'alertrule' ? ruleKind : undefined)
    }
    onClose()
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box max-w-md">
        <div className="modal-header">
          <div className="flex items-center gap-2">
            <Plus size={16} className="text-brand-accent" />
            <span className="text-sm font-semibold">New {titles[type] || 'File'}</span>
          </div>
          <button className="icon-btn" onClick={onClose}><X size={14} /></button>
        </div>
        <form onSubmit={handleCreate} className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1.5">
              Name {isCodeFile && <span className="text-gray-400">(letters, digits, underscores)</span>}
            </label>
            <div className="flex items-center gap-1">
              <input
                autoFocus
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder={placeholders[type] || 'name'}
                className="input flex-1"
              />
              {isCodeFile && (
                <span className="text-xs text-gray-400 font-mono whitespace-nowrap">{suffix}{ext}</span>
              )}
            </div>
          </div>

          {type === 'alertrule' && (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Format</label>
              <div className="flex gap-3">
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input type="radio" checked={ruleKind === 'sigma'} onChange={() => setRuleKind('sigma')} />
                  <span className="text-xs text-gray-700">Sigma YAML</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input type="radio" checked={ruleKind === 'custom'} onChange={() => setRuleKind('custom')} />
                  <span className="text-xs text-gray-700">Custom (name + query)</span>
                </label>
              </div>
            </div>
          )}

          <div className="flex justify-end gap-2">
            <button type="button" className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary text-sm" disabled={!name.trim()}>Create</button>
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
          <span className="text-sm font-semibold text-red-600">Delete</span>
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

  function handleKeyDown(e) {
    if (readOnly) return
    if (e.key === 'Tab') {
      e.preventDefault()
      const ta    = e.target
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

// ── ValidationModal ───────────────────────────────────────────────────────────

function ValidationModal({ type, validation, onClose }) {
  if (!validation) return null
  const isSkipped = !!validation.skipped
  const isValid   = validation.valid === true
  const details   = validation.details   // for alertrule Sigma parse
  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box max-w-lg">
        <div className="modal-header">
          <div className="flex items-center gap-2">
            {isSkipped
              ? <AlertCircle size={15} className="text-amber-500" />
              : isValid
                ? <CheckCircle size={15} className="text-green-600" />
                : <AlertCircle size={15} className="text-red-500" />}
            <span className="text-sm font-semibold">Validation Result</span>
          </div>
          <button className="icon-btn" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="p-5 space-y-4">
          {isSkipped ? (
            <div className="rounded-lg bg-amber-50 border border-amber-200 p-3 space-y-1.5">
              <p className="text-xs font-semibold text-amber-700">Validation skipped</p>
              <p className="text-xs text-amber-600">{validation.warning}</p>
            </div>
          ) : isValid ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <CheckCircle size={14} className="text-green-600" />
                <span className="text-sm font-semibold text-green-700">Valid</span>
              </div>
              {details && (
                <div className="rounded-lg bg-gray-50 border border-gray-200 p-3 space-y-2 text-xs">
                  {details.name && (
                    <div><span className="text-gray-500 font-medium">Name: </span><span className="text-gray-800">{details.name}</span></div>
                  )}
                  {details.description && (
                    <div><span className="text-gray-500 font-medium">Description: </span><span className="text-gray-700">{details.description}</span></div>
                  )}
                  {details.category && (
                    <div><span className="text-gray-500 font-medium">Category: </span><span className="text-gray-700">{details.category}</span></div>
                  )}
                  {details.artifact_type && (
                    <div><span className="text-gray-500 font-medium">Artifact type: </span><span className="text-gray-700">{details.artifact_type}</span></div>
                  )}
                  {details.query && (
                    <div>
                      <p className="text-gray-500 font-medium mb-1">ES Query:</p>
                      <code className="block bg-white border border-gray-200 rounded px-2 py-1.5 text-indigo-700 text-[11px] font-mono break-all whitespace-pre-wrap">{details.query}</code>
                    </div>
                  )}
                  {details.sigma_level && (
                    <div><span className="text-gray-500 font-medium">Level: </span>
                      <span className={`badge text-[9px] ml-1 ${
                        details.sigma_level === 'critical' ? 'bg-red-100 text-red-700 border-red-200' :
                        details.sigma_level === 'high'     ? 'bg-orange-100 text-orange-700 border-orange-200' :
                        details.sigma_level === 'medium'   ? 'bg-yellow-100 text-yellow-700 border-yellow-200' :
                        'bg-gray-100 text-gray-600 border-gray-200'
                      }`}>{details.sigma_level}</span>
                    </div>
                  )}
                  {(details.sigma_tags || []).length > 0 && (
                    <div>
                      <p className="text-gray-500 font-medium mb-1">Tags:</p>
                      <div className="flex flex-wrap gap-1">
                        {details.sigma_tags.map((t, i) => (
                          <span key={i} className="badge bg-blue-50 text-blue-600 border-blue-200 text-[9px]">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {details.customInfo && (
                    <div>
                      <p className="text-gray-500 font-medium mb-1">Query (custom rule):</p>
                      <code className="block bg-white border border-gray-200 rounded px-2 py-1.5 text-indigo-700 text-[11px] font-mono break-all">{details.customInfo}</code>
                    </div>
                  )}
                </div>
              )}
              {!details && validation.info && (
                <p className="text-xs text-gray-600 bg-gray-50 border border-gray-200 rounded px-3 py-2">{validation.info}</p>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <AlertCircle size={14} className="text-red-500" />
                <span className="text-sm font-semibold text-red-700">Invalid</span>
              </div>
              <pre className="text-[11px] text-red-700 font-mono whitespace-pre-wrap break-all bg-red-50 border border-red-200 rounded-lg px-3 py-2.5 leading-relaxed">
                {validation.error}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Studio() {
  const location = useLocation()

  // Sidebar panel: 'ingesters' | 'modules' | 'yara' | 'alertrule'
  const [sidebarTab, setSidebarTab]     = useState('ingesters')

  // Ingester / module file lists
  const [ingesterFiles, setIngFiles]    = useState([])
  const [moduleFiles,   setModFiles]    = useState([])
  const [refModFiles,   setRefModFiles] = useState([])
  const [showRef,       setShowRef]     = useState(false)

  // Rule lists (YARA + alert)
  const [yaraRules,      setYaraRules]     = useState([])
  const [alertRuleList,  setAlertRuleList] = useState([])

  // Multi-tab state — each tab:
  //   type, name (unique key), label (display), ruleId (for yara/alertrule),
  //   builtin, readOnly, code, originalCode, loading, saving, validating,
  //   validation, saveMsg, copied
  const [openTabs,      setOpenTabs]     = useState([])
  const [activeTabKey,  setActiveTabKey] = useState(null)

  // Modal visibility
  const [showNew,          setShowNew]          = useState(false)
  const [showDelete,       setShowDelete]       = useState(false)
  const [showValidateModal, setShowValidateModal] = useState(false)

  // Sidebar search filter (resets on tab change)
  const [filterText, setFilterText] = useState('')
  useEffect(() => { setFilterText('') }, [sidebarTab])

  // Derived
  const activeTab = openTabs.find(t => fileId(t.type, t.name) === activeTabKey) || null
  const isDirty   = activeTab ? activeTab.code !== activeTab.originalCode : false

  // ── Tab mutation helper ────────────────────────────────────────────────────

  function updateTab(type, name, patch) {
    setOpenTabs(tabs => tabs.map(t =>
      t.type === type && t.name === name ? { ...t, ...patch } : t
    ))
  }

  // ── Load all lists ─────────────────────────────────────────────────────────

  const loadLists = useCallback(async () => {
    try {
      const [ing, mod, ingBuiltin, modBuiltin, yara, alertLib] = await Promise.all([
        api.editor.listIngesters(),
        api.editor.listModules(),
        api.editor.listBuiltinIngesters().catch(() => ({ files: [] })),
        api.editor.listBuiltinModules().catch(() => ({ files: [] })),
        api.yaraRules.list().catch(() => ({ rules: [] })),
        api.alertRules.listLibrary().catch(() => ({ rules: [] })),
      ])
      setIngFiles([...(ingBuiltin.files || []), ...(ing.files || [])])
      setModFiles(mod.files || [])
      setRefModFiles(modBuiltin.files || [])
      setYaraRules([...(yara.rules || [])].sort((a, b) => a.name.localeCompare(b.name)))
      setAlertRuleList([...(alertLib.rules || [])].sort((a, b) => a.name.localeCompare(b.name)))
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
    if (fileList.length === 0) return
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

  // ── Open a file or rule (or switch to existing tab) ───────────────────────

  async function openFile(type, name, builtin = false) {
    const key = fileId(type, name)

    if (openTabs.some(t => fileId(t.type, t.name) === key)) {
      setActiveTabKey(key)
      return
    }

    const readOnly = builtin && type === 'module'

    const newTab = {
      type, name, label: name, ruleId: (type === 'yara' || type === 'alertrule') ? name : null,
      builtin, readOnly,
      code: '', originalCode: '',
      loading: true, saving: false, validating: false,
      validation: null, saveMsg: null, copied: false,
    }
    setOpenTabs(tabs => [...tabs, newTab])
    setActiveTabKey(key)

    try {
      let code = ''
      let label = name

      if (type === 'yara') {
        const rule = await api.yaraRules.get(name)
        code  = rule.content || ''
        label = rule.name   || name
      } else if (type === 'alertrule') {
        const rule = await api.alertRules.getLibraryRule(name)
        code  = alertRuleToCode(rule)
        label = rule.name || name
      } else if (builtin) {
        const res = type === 'ingester'
          ? await api.editor.getBuiltinIngester(name)
          : await api.editor.getBuiltinModule(name)
        code = res.content
      } else {
        const res = type === 'ingester'
          ? await api.editor.getIngester(name)
          : await api.editor.getModule(name)
        code = res.content
      }

      updateTab(type, name, { code, originalCode: code, label, loading: false })
    } catch (err) {
      setOpenTabs(tabs => tabs.filter(t => fileId(t.type, t.name) !== key))
      setActiveTabKey(prev => prev === key ? null : prev)
      alert('Failed to load: ' + err.message)
    }
  }

  // ── Close a tab ───────────────────────────────────────────────────────────

  function closeTab(type, name) {
    const tab = openTabs.find(t => t.type === type && t.name === name)
    if (!tab) return
    if (tab.code !== tab.originalCode) {
      if (!confirm(`Discard unsaved changes to ${tab.label || name}?`)) return
    }
    const key       = fileId(type, name)
    const idx       = openTabs.findIndex(t => fileId(t.type, t.name) === key)
    const remaining = openTabs.filter(t => fileId(t.type, t.name) !== key)
    setOpenTabs(remaining)
    if (activeTabKey === key) {
      const nextTab = remaining[idx] ?? remaining[idx - 1] ?? null
      setActiveTabKey(nextTab ? fileId(nextTab.type, nextTab.name) : null)
    }
  }

  // ── Create new file / rule ─────────────────────────────────────────────────

  async function handleCreate(name, subtype) {
    const type = sidebarTypeForCreate()

    if (type === 'ingester' || type === 'module') {
      // ── Code file: save immediately with template ──────────────────────────
      const stem     = name.replace(/_ingester\.py$/, '').replace(/_module\.py$/, '')
      const template = type === 'ingester' ? INGESTER_TEMPLATE(stem) : MODULE_TEMPLATE(stem)
      const key      = fileId(type, name)

      const newTab = {
        type, name, label: name, ruleId: null,
        builtin: false, readOnly: false,
        code: template, originalCode: template,
        loading: false, saving: true, validating: false,
        validation: null, saveMsg: null, copied: false,
      }
      setOpenTabs(tabs => {
        const exists = tabs.some(t => fileId(t.type, t.name) === key)
        return exists ? tabs.map(t => fileId(t.type, t.name) === key ? newTab : t) : [...tabs, newTab]
      })
      setActiveTabKey(key)

      try {
        if (type === 'ingester') await api.editor.saveIngester(name, { content: template })
        else                     await api.editor.saveModule(name, { content: template })
        await loadLists()
        updateTab(type, name, { saving: false, saveMsg: { ok: true, text: 'File created' } })
        setTimeout(() => updateTab(type, name, { saveMsg: null }), 3000)
      } catch (err) {
        updateTab(type, name, { saving: false })
        alert('Create failed: ' + err.message)
      }
    } else if (type === 'yara') {
      // ── YARA rule: open a new tab with template (save when ready) ──────────
      const tempKey  = `new_${Date.now()}`
      const template = YARA_TEMPLATE(name)
      const newTab = {
        type: 'yara', name: tempKey, label: name, ruleId: null,
        builtin: false, readOnly: false,
        code: template, originalCode: '',
        loading: false, saving: false, validating: false,
        validation: null, saveMsg: null, copied: false,
      }
      setOpenTabs(tabs => [...tabs, newTab])
      setActiveTabKey(fileId('yara', tempKey))
    } else if (type === 'alertrule') {
      // ── Alert rule: open a new tab with Sigma or custom template ──────────
      const tempKey  = `new_${Date.now()}`
      const template = subtype === 'custom' ? CUSTOM_RULE_TEMPLATE(name) : SIGMA_TEMPLATE(name)
      const newTab = {
        type: 'alertrule', name: tempKey, label: name, ruleId: null,
        builtin: false, readOnly: false,
        code: template, originalCode: '',
        loading: false, saving: false, validating: false,
        validation: null, saveMsg: null, copied: false,
      }
      setOpenTabs(tabs => [...tabs, newTab])
      setActiveTabKey(fileId('alertrule', tempKey))
    }
  }

  function sidebarTypeForCreate() {
    if (sidebarTab === 'ingesters')  return 'ingester'
    if (sidebarTab === 'modules')    return 'module'
    if (sidebarTab === 'yara')       return 'yara'
    if (sidebarTab === 'alertrule')  return 'alertrule'
    return 'ingester'
  }

  // ── Save active tab ────────────────────────────────────────────────────────

  async function handleSave() {
    if (!activeTab) return
    const { type, name, label, code, ruleId, builtin } = activeTab

    if (type === 'ingester' || type === 'module') {
      updateTab(type, name, { saving: true, validation: null, saveMsg: null })
      try {
        if (builtin) {
          if (type === 'ingester') await api.editor.saveBuiltinIngester(name, { content: code })
          else                     await api.editor.saveBuiltinModule(name, { content: code })
        } else {
          if (type === 'ingester') await api.editor.saveIngester(name, { content: code })
          else                     await api.editor.saveModule(name, { content: code })
        }
        updateTab(type, name, { originalCode: code, saving: false, saveMsg: { ok: true, text: 'Saved' } })
        setTimeout(() => updateTab(type, name, { saveMsg: null }), 3000)
      } catch (err) {
        updateTab(type, name, { saving: false, saveMsg: { ok: false, text: err.message } })
      }

    } else if (type === 'yara') {
      updateTab('yara', name, { saving: true, saveMsg: null })
      try {
        let result
        if (ruleId) {
          // Update existing — preserve name/description/tags from current record
          const existing = yaraRules.find(r => r.id === ruleId)
          result = await api.yaraRules.update(ruleId, {
            name:        existing?.name        || label,
            description: existing?.description || '',
            tags:        existing?.tags        || [],
            content:     code,
          })
          updateTab('yara', ruleId, { originalCode: code, saving: false, saveMsg: { ok: true, text: 'Saved' } })
          setTimeout(() => updateTab('yara', ruleId, { saveMsg: null }), 3000)
        } else {
          result = await api.yaraRules.create({ name: label, content: code, description: '', tags: [] })
          const newId = result.id
          // Transition tab from temp key to real ruleId
          setOpenTabs(tabs => tabs.map(t =>
            t.type === 'yara' && t.name === name
              ? { ...t, name: newId, ruleId: newId, label: result.name || label, originalCode: code, saving: false, saveMsg: { ok: true, text: 'Rule created' } }
              : t
          ))
          setActiveTabKey(fileId('yara', newId))
          setTimeout(() => updateTab('yara', newId, { saveMsg: null }), 3000)
        }
        await loadLists()
      } catch (err) {
        updateTab('yara', name, { saving: false, saveMsg: { ok: false, text: err.message } })
      }

    } else if (type === 'alertrule') {
      updateTab('alertrule', name, { saving: true, saveMsg: null })
      try {
        // Determine Sigma vs custom YAML
        const isSigma = /^\s*title:\s*/m.test(code)
        let data
        if (isSigma) {
          const parsed = await api.alertRules.parseSigma({ yaml: code })
            .catch(err => { throw new Error(err.message || 'Sigma parse error') })
          data = {
            name:          parsed.name,
            description:   parsed.description  || '',
            category:      parsed.category     || '',
            artifact_type: parsed.artifact_type || '',
            query:         parsed.query         || '',
            threshold:     1,
            sigma_yaml:    code,
          }
        } else {
          const parsed = parseCustomAlertRuleYaml(code)
          if (!parsed.name || !parsed.query) throw new Error('Need either Sigma YAML (title:) or custom YAML (name: + query:)')
          data = parsed
        }

        let result
        if (ruleId) {
          result = await api.alertRules.updateLibraryRule(ruleId, data)
          updateTab('alertrule', ruleId, {
            label: result.name || data.name,
            originalCode: code, saving: false, saveMsg: { ok: true, text: 'Saved' },
          })
          setTimeout(() => updateTab('alertrule', ruleId, { saveMsg: null }), 3000)
        } else {
          result = await api.alertRules.createLibraryRule(data)
          const newId = result.id
          setOpenTabs(tabs => tabs.map(t =>
            t.type === 'alertrule' && t.name === name
              ? { ...t, name: newId, ruleId: newId, label: result.name || data.name, originalCode: code, saving: false, saveMsg: { ok: true, text: 'Rule created' } }
              : t
          ))
          setActiveTabKey(fileId('alertrule', newId))
          setTimeout(() => updateTab('alertrule', newId, { saveMsg: null }), 3000)
        }
        await loadLists()
      } catch (err) {
        updateTab('alertrule', name, { saving: false, saveMsg: { ok: false, text: err.message } })
      }
    }
  }

  // ── Validate active tab ────────────────────────────────────────────────────

  async function handleValidate() {
    if (!activeTab) return
    const { type, name, code } = activeTab
    setShowValidateModal(false)
    updateTab(type, name, { validating: true, validation: null })
    try {
      let res
      if (type === 'ingester' || type === 'module') {
        res = await api.editor.validate(code)
      } else if (type === 'yara') {
        const r = await api.modules.validateYara(code)
        res = { valid: r.valid, error: r.error, warning: r.warning }
      } else if (type === 'alertrule') {
        const isSigma = /^\s*title:\s*/m.test(code)
        if (isSigma) {
          try {
            const r = await api.alertRules.parseSigma({ yaml: code })
            res = { valid: true, info: `${r.name}  ·  Query: ${r.query || '(empty)'}` }
          } catch (err) {
            res = { valid: false, error: err.message || 'Sigma parse failed' }
          }
        } else {
          const parsed = parseCustomAlertRuleYaml(code)
          if (parsed.name && parsed.query) {
            res = { valid: true, info: `${parsed.name}  ·  Query: ${parsed.query}` }
          } else {
            res = { valid: false, error: 'Need either Sigma YAML (title:) or custom YAML (name: + query:)' }
          }
        }
      }
      updateTab(type, name, { validating: false, validation: res })
    } catch (_) {
      updateTab(type, name, { validating: false, validation: { valid: false, error: 'Validation request failed' } })
    }
  }

  // ── Delete active tab's file or rule ──────────────────────────────────────

  async function handleDelete() {
    if (!activeTab) return
    setShowDelete(false)
    const { type, name, ruleId, builtin } = activeTab
    const key = fileId(type, name)
    const idx = openTabs.findIndex(t => fileId(t.type, t.name) === key)
    try {
      if (type === 'yara') {
        if (ruleId) await api.yaraRules.delete(ruleId)
        // If new (ruleId = null), just close tab
      } else if (type === 'alertrule') {
        if (ruleId) await api.alertRules.deleteLibraryRule(ruleId)
      } else if (builtin) {
        if (type === 'ingester') await api.editor.deleteBuiltinIngester(name)
        else                     await api.editor.deleteBuiltinModule(name)
      } else {
        if (type === 'ingester') await api.editor.deleteIngester(name)
        else                     await api.editor.deleteModule(name)
      }
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
  const existingNames   = sidebarFiles.map(f => f.name)

  const SIDEBAR_TABS = [
    { id: 'ingesters', icon: <Puzzle size={12} />, label: 'Ingest.' },
    { id: 'modules',   icon: <Cpu    size={12} />, label: 'Modules' },
    { id: 'yara',      icon: <Shield size={12} />, label: 'YARA' },
    { id: 'alertrule', icon: <Bell   size={12} />, label: 'Rules' },
  ]

  // ── New button label ───────────────────────────────────────────────────────

  const newBtnLabel = {
    ingesters:  'New Ingester',
    modules:    'New Module',
    yara:       'New YARA Rule',
    alertrule:  'New Alert Rule',
  }[sidebarTab] || 'New'

  const newBtnType = {
    ingesters: 'ingester', modules: 'module', yara: 'yara', alertrule: 'alertrule',
  }[sidebarTab]

  // ── Render sidebar file list (for ingesters/modules) ──────────────────────

  function renderCodeFileSidebar(files, type) {
    const filtered = filterText
      ? files.filter(f => f.name.toLowerCase().includes(filterText.toLowerCase()))
      : files
    if (files.length === 0) {
      return (
        <div className="px-3 py-4 text-center">
          <FileCode2 size={20} className="text-gray-300 mx-auto mb-2" />
          <p className="text-[11px] text-gray-400">No files yet</p>
        </div>
      )
    }
    if (filtered.length === 0) {
      return <p className="px-3 py-2 text-[11px] text-gray-400 italic">No matches</p>
    }
    const builtins = filtered.filter(f => f.builtin)
    const customs  = filtered.filter(f => !f.builtin)
    const renderFile = f => {
      const key        = fileId(type, f.name)
      const isActive   = activeTabKey === key
      const openTab    = openTabs.find(t => fileId(t.type, t.name) === key)
      const isOpen     = Boolean(openTab)
      const isDirtyTab = isOpen && openTab.code !== openTab.originalCode
      return (
        <button
          key={f.name}
          onClick={() => openFile(type, f.name, !!f.builtin)}
          className={`w-full flex items-center gap-2 px-3 py-1.5 text-left transition-colors ${
            isActive ? 'bg-brand-accentlight text-brand-accent'
            : isOpen  ? 'bg-blue-50/50 text-gray-700 hover:bg-blue-50'
            : f.builtin ? 'text-gray-400 hover:bg-gray-50 hover:text-gray-600'
            : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
          }`}
        >
          {f.builtin
            ? <Lock size={11} className="flex-shrink-0 opacity-50" />
            : <FileCode2 size={13} className="flex-shrink-0 opacity-60" />}
          <span className="text-[11px] font-mono truncate flex-1">{f.name}</span>
          {isDirtyTab && <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0" />}
          {isActive && !isDirtyTab && <ChevronRight size={10} className="flex-shrink-0 opacity-50" />}
        </button>
      )
    }
    return (
      <>
        {builtins.length > 0 && (
          <>
            <p className="px-3 pt-2 pb-1 text-[9px] font-semibold text-gray-400 uppercase tracking-widest">Built-in</p>
            {builtins.map(renderFile)}
          </>
        )}
        {customs.length > 0 && (
          <>
            <p className="px-3 pt-3 pb-1 text-[9px] font-semibold text-gray-400 uppercase tracking-widest">Custom</p>
            {customs.map(renderFile)}
          </>
        )}
      </>
    )
  }

  // ── Render rule sidebar (YARA / alert rules) ───────────────────────────────

  function renderRuleSidebar(rules, type) {
    // Also include any open "new unsaved" tabs for this type
    const unsaved = openTabs.filter(t => t.type === type && !t.ruleId)
    const filtered = filterText
      ? rules.filter(r => r.name.toLowerCase().includes(filterText.toLowerCase()))
      : rules

    if (rules.length === 0 && unsaved.length === 0) {
      return (
        <div className="px-3 py-4 text-center">
          {type === 'yara' ? <Shield size={20} className="text-gray-300 mx-auto mb-2" /> : <Bell size={20} className="text-gray-300 mx-auto mb-2" />}
          <p className="text-[11px] text-gray-400">No rules yet</p>
        </div>
      )
    }
    if (filtered.length === 0 && unsaved.length === 0) {
      return <p className="px-3 py-2 text-[11px] text-gray-400 italic">No matches</p>
    }

    const renderRule = (id, label, isUnsaved = false) => {
      const key      = fileId(type, id)
      const isActive = activeTabKey === key
      const openTab  = openTabs.find(t => fileId(t.type, t.name) === key)
      const dirty    = openTab && openTab.code !== openTab.originalCode
      return (
        <button
          key={id}
          onClick={() => isUnsaved ? setActiveTabKey(key) : openFile(type, id)}
          className={`w-full flex items-center gap-2 px-3 py-1.5 text-left transition-colors ${
            isActive ? 'bg-brand-accentlight text-brand-accent'
            : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
          }`}
        >
          {type === 'yara'
            ? <Shield size={11} className="flex-shrink-0 opacity-60 text-green-500" />
            : <Bell   size={11} className="flex-shrink-0 opacity-60 text-orange-500" />}
          <span className="text-[11px] truncate flex-1">{label}</span>
          {isUnsaved && <span className="text-[9px] text-gray-400 flex-shrink-0">new</span>}
          {dirty && !isUnsaved && <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0" />}
          {isActive && !dirty && <ChevronRight size={10} className="flex-shrink-0 opacity-50" />}
        </button>
      )
    }

    return (
      <>
        {unsaved.length > 0 && (
          <>
            <p className="px-3 pt-2 pb-1 text-[9px] font-semibold text-gray-400 uppercase tracking-widest">Unsaved</p>
            {unsaved.map(t => renderRule(t.name, t.label, true))}
          </>
        )}
        {filtered.length > 0 && (
          <>
            {unsaved.length > 0 && <p className="px-3 pt-3 pb-1 text-[9px] font-semibold text-gray-400 uppercase tracking-widest">Library</p>}
            {filtered.map(r => renderRule(r.id, r.name))}
          </>
        )}
      </>
    )
  }

  return (
    <div className="flex flex-1 overflow-hidden min-h-0">

      {/* ── Sidebar ─────────────────────────────────────────────────────────── */}
      <aside className="w-64 flex-shrink-0 flex flex-col border-r border-gray-200 bg-white overflow-hidden">

        {/* Panel tab switcher — 4 tabs */}
        <div className="flex border-b border-gray-200 flex-shrink-0">
          {SIDEBAR_TABS.map(({ id, icon, label }) => (
            <button
              key={id}
              onClick={() => setSidebarTab(id)}
              title={label}
              className={`flex-1 flex flex-col items-center justify-center gap-0.5 py-2 text-[10px] font-medium transition-colors ${
                sidebarTab === id
                  ? 'text-brand-accent border-b-2 border-brand-accent bg-brand-accentlight/40'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
              }`}
            >
              {icon}
              <span>{label}</span>
            </button>
          ))}
        </div>

        {/* New button + filter */}
        <div className="px-3 py-2 space-y-1.5 flex-shrink-0">
          <button
            onClick={() => setShowNew(true)}
            className="w-full btn-primary text-xs justify-center py-1.5"
          >
            <Plus size={12} /> {newBtnLabel}
          </button>
          <input
            value={filterText}
            onChange={e => setFilterText(e.target.value)}
            placeholder="Filter…"
            className="input w-full text-xs py-1"
          />
        </div>

        {/* File / rule list */}
        <div className="flex-1 overflow-y-auto py-1 min-h-0">
          {sidebarTab === 'ingesters' && renderCodeFileSidebar(ingesterFiles, 'ingester')}
          {sidebarTab === 'modules'   && renderCodeFileSidebar(moduleFiles,   'module')}
          {sidebarTab === 'yara'      && renderRuleSidebar(yaraRules,      'yara')}
          {sidebarTab === 'alertrule' && renderRuleSidebar(alertRuleList,  'alertrule')}
        </div>

        {/* Module Registry Reference (YAML files, read-only) */}
        {sidebarTab === 'modules' && refModFiles.length > 0 && (
          <div className="border-t border-gray-200 flex-shrink-0">
            <button
              onClick={() => setShowRef(v => !v)}
              className="w-full flex items-center gap-1.5 px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-widest hover:bg-gray-50 transition-colors"
            >
              <BookOpen size={10} />
              Registry Reference
              <ChevronRight size={10} className={`ml-auto transition-transform ${showRef ? 'rotate-90' : ''}`} />
            </button>
            {showRef && (
              <div className="py-1 max-h-40 overflow-y-auto">
                {refModFiles.map(f => (
                  <button
                    key={f.name}
                    onClick={() => openFile('module', f.name, true)}
                    className="w-full flex items-center gap-2 px-3 py-1.5 text-left text-gray-400 hover:bg-gray-50 hover:text-gray-600 transition-colors"
                  >
                    <Lock size={9} className="flex-shrink-0 opacity-50" />
                    <span className="text-[10px] font-mono truncate flex-1">{f.name}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </aside>

      {/* ── Editor pane ─────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* Tab bar */}
        {openTabs.length > 0 && (
          <div className="flex items-stretch border-b border-gray-200 bg-gray-50/80 overflow-x-auto flex-shrink-0">
            {openTabs.map(t => {
              const key      = fileId(t.type, t.name)
              const isActive = key === activeTabKey
              const tabDirty = t.code !== t.originalCode
              const badge    = TYPE_BADGE[t.type] || TYPE_BADGE.ingester

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
                  <span className={`text-[9px] px-1 py-px rounded font-bold flex-shrink-0 ${badge.cls}`}>
                    {badge.letter}
                  </span>
                  <span className="text-[11px] font-mono truncate flex-1 min-w-0">
                    {t.label || t.name}
                  </span>
                  {tabDirty && (
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0 group-hover:hidden" title="Unsaved changes" />
                  )}
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
                <span className={`badge text-[10px] ${(TYPE_TOOLBAR[activeTab.type] || TYPE_TOOLBAR.ingester).cls}`}>
                  {(TYPE_TOOLBAR[activeTab.type] || TYPE_TOOLBAR.ingester).label}
                </span>
                <code className="text-xs font-mono text-gray-700 truncate">
                  {activeTab.label || activeTab.name}
                </code>
                {isDirty && <span className="w-2 h-2 rounded-full bg-amber-400 flex-shrink-0" title="Unsaved changes" />}
              </div>

              <div className="flex items-center gap-1.5 flex-shrink-0">
                {/* Validation result — click to open full modal */}
                {activeTab.validation && (
                  activeTab.validation.valid
                    ? <button
                        onClick={() => setShowValidateModal(true)}
                        className="flex items-center gap-1 text-[11px] text-green-700 bg-green-50 border border-green-200 rounded-lg px-2 py-0.5 hover:bg-green-100 transition-colors"
                      >
                        <CheckCircle size={11} />
                        {activeTab.validation.info || 'Valid'}
                      </button>
                    : <button
                        onClick={() => setShowValidateModal(true)}
                        className="flex items-center gap-1 text-[11px] text-red-600 bg-red-50 border border-red-200 rounded-lg px-2 py-0.5 max-w-xs hover:bg-red-100 transition-colors"
                        title="Click to see full error"
                      >
                        <AlertCircle size={11} />
                        <span className="truncate max-w-[180px]">{activeTab.validation.error?.split('\n')[0]}</span>
                        <span className="text-[10px] underline flex-shrink-0">details</span>
                      </button>
                )}
                {/* Warning (yara: skipped) */}
                {activeTab.validation?.warning && (
                  <button
                    onClick={() => setShowValidateModal(true)}
                    className="text-[11px] text-amber-600 bg-amber-50 border border-amber-200 rounded-lg px-2 py-0.5 hover:bg-amber-100 transition-colors"
                  >
                    {activeTab.validation.warning}
                  </button>
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

                {activeTab.readOnly ? (
                  <span className="badge bg-gray-100 text-gray-500 text-[10px] flex items-center gap-1">
                    <Lock size={9} /> Read-only reference
                  </span>
                ) : (
                  <>
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
                      disabled={activeTab.saving || (!isDirty && (activeTab.type === 'ingester' || activeTab.type === 'module'))}
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
                  </>
                )}
              </div>
            </div>

            {/* Validation error hint — click to open modal */}
            {activeTab.validation && !activeTab.validation.valid && activeTab.validation.error && (
              <button
                onClick={() => setShowValidateModal(true)}
                className="w-full bg-red-50 border-b border-red-200 px-4 py-1.5 flex items-center gap-2 hover:bg-red-100 transition-colors text-left"
              >
                <AlertCircle size={12} className="text-red-500 flex-shrink-0" />
                <span className="text-[11px] text-red-700 font-mono truncate flex-1">
                  {activeTab.validation.error.split('\n')[0]}
                </span>
                <span className="text-[10px] text-red-500 underline flex-shrink-0">View full error</span>
              </button>
            )}

            {/* Code editor */}
            <div className="flex-1 overflow-hidden">
              {activeTab.loading ? (
                <div className="h-full bg-gray-950 flex items-center justify-center">
                  <RefreshCw size={20} className="animate-spin text-gray-500" />
                </div>
              ) : (
                <CodeEditor
                  key={activeTabKey}
                  value={activeTab.code}
                  onChange={v => !activeTab.readOnly && updateTab(activeTab.type, activeTab.name, { code: v })}
                  readOnly={activeTab.readOnly}
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
            <p className="text-gray-400 text-sm font-medium mb-1">Select a file or rule to edit</p>
            <p className="text-gray-600 text-xs mb-6 max-w-xs">
              Choose an ingester, module, YARA rule, or alert rule from the sidebar, or create a new one.
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
          type={newBtnType}
          existing={existingNames}
          onClose={() => setShowNew(false)}
          onCreate={handleCreate}
        />
      )}
      {showDelete && activeTab && (
        <DeleteConfirmModal
          file={activeTab.label || activeTab.name}
          onClose={() => setShowDelete(false)}
          onConfirm={handleDelete}
        />
      )}
      {showValidateModal && activeTab?.validation && (
        <ValidationModal
          type={activeTab.type}
          validation={activeTab.validation}
          onClose={() => setShowValidateModal(false)}
        />
      )}
    </div>
  )
}
