import { useState, useEffect, useCallback } from 'react'
import {
  FileText, HardDrive, Database, Activity, File, Search,
  ChevronRight, ChevronDown, Folder, FolderOpen, Loader2,
  X, ArrowLeft, AlertTriangle,
} from 'lucide-react'
import { api } from '../api/client'

// ── Category icons ────────────────────────────────────────────────────────────
function FileIcon({ category, size = 13 }) {
  switch (category) {
    case 'text':       return <FileText size={size} className="text-blue-500" />
    case 'disk_image': return <HardDrive size={size} className="text-orange-500" />
    case 'database':   return <Database size={size} className="text-teal-500" />
    case 'pcap':       return <Activity size={size} className="text-purple-500" />
    case 'evtx':       return <File size={size} className="text-red-500" />
    default:           return <File size={size} className="text-gray-400" />
  }
}

// ── File content viewer ───────────────────────────────────────────────────────
function ContentViewer({ caseId, file, onClose }) {
  const [content, setContent] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [filter, setFilter]   = useState('')

  useEffect(() => {
    setLoading(true)
    setError('')
    api.caseFiles.content(caseId, file.job_id)
      .then(r => setContent(r))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [caseId, file.job_id])

  // Format JSON if applicable
  let displayContent = content?.content || ''
  let isJson = false
  if (file.filename.match(/\.(json|jsonl|ndjson)$/i) && displayContent) {
    // For JSONL, pretty-print first line; for JSON, format the whole thing
    if (file.filename.match(/\.(jsonl|ndjson)$/i)) {
      // Show raw; formatting each line would be too expensive
    } else {
      try {
        displayContent = JSON.stringify(JSON.parse(displayContent), null, 2)
        isJson = true
      } catch {
        // Not valid JSON, show raw
      }
    }
  }

  // Filter lines
  const lines = displayContent.split('\n')
  const filteredLines = filter
    ? lines.map((l, i) => ({ line: i + 1, text: l })).filter(l => l.text.toLowerCase().includes(filter.toLowerCase()))
    : lines.map((l, i) => ({ line: i + 1, text: l }))

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-200 bg-white flex-shrink-0">
        <button onClick={onClose} className="icon-btn"><ArrowLeft size={14} /></button>
        <FileIcon category={file.category} size={14} />
        <span className="text-xs font-medium text-brand-text truncate flex-1">{file.filename}</span>
        {content && (
          <span className="text-[10px] text-gray-400 flex-shrink-0">
            {(content.size_bytes / 1024).toFixed(1)} KB · {lines.length} lines
          </span>
        )}
        <div className="relative flex-shrink-0">
          <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter lines…"
            className="input text-xs pl-6 py-1 w-40"
          />
          {filter && (
            <button onClick={() => setFilter('')} className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-400">
              <X size={10} />
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto bg-gray-950 font-mono text-xs p-3">
        {loading && (
          <div className="flex items-center gap-2 text-gray-400 mt-4 justify-center">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        )}
        {error && (
          <p className="text-red-400 p-4">{error}</p>
        )}
        {!loading && !error && (
          <>
            {filter && (
              <p className="text-gray-500 text-[10px] mb-2">
                {filteredLines.length} matching line{filteredLines.length !== 1 ? 's' : ''} (of {lines.length})
              </p>
            )}
            <table className="w-full">
              <tbody>
                {filteredLines.map(({ line, text }) => (
                  <tr key={line} className="hover:bg-white/5 group">
                    <td className="text-gray-600 pr-3 pl-1 text-right select-none w-10 border-r border-gray-800 align-top pt-px">{line}</td>
                    <td className="pl-3 whitespace-pre-wrap break-all text-gray-200 align-top pt-px">{text}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  )
}

// ── Disk image browser ────────────────────────────────────────────────────────
function DiskImageBrowser({ caseId, file }) {
  const [path, setPath]         = useState('/')
  const [entries, setEntries]   = useState([])
  const [total, setTotal]       = useState(0)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  const browse = useCallback((newPath) => {
    setLoading(true)
    setError('')
    api.caseFiles.browse(caseId, file.job_id, newPath)
      .then(r => {
        setEntries(r.entries || [])
        setTotal(r.total || 0)
        setPath(newPath)
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [caseId, file.job_id])

  useEffect(() => { browse('/') }, [browse])

  // Build breadcrumb from path
  const parts = path.replace(/\/$/, '').split('/').filter(Boolean)
  const crumbs = [
    { label: '/', path: '/' },
    ...parts.map((p, i) => ({
      label: p,
      path: '/' + parts.slice(0, i + 1).join('/') + '/',
    }))
  ]

  return (
    <div className="flex flex-col h-full">
      {/* Header + breadcrumb */}
      <div className="px-3 py-2 border-b border-gray-200 bg-white flex-shrink-0">
        <div className="flex items-center gap-1 text-xs flex-wrap">
          <HardDrive size={13} className="text-orange-500 flex-shrink-0" />
          <span className="font-medium text-brand-text truncate">{file.filename}</span>
          <span className="text-gray-300 mx-1">·</span>
          {crumbs.map((c, i) => (
            <span key={c.path} className="flex items-center gap-0.5">
              {i > 0 && <ChevronRight size={10} className="text-gray-300" />}
              <button
                onClick={() => browse(c.path)}
                className="text-brand-accent hover:text-brand-accenthover hover:underline"
              >
                {c.label}
              </button>
            </span>
          ))}
        </div>
        {total > 0 && <p className="text-[10px] text-gray-400 mt-0.5">{total} entries</p>}
      </div>

      {/* Directory listing */}
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center justify-center gap-2 py-8 text-gray-500 text-xs">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        )}
        {error && (
          <div className="m-3 p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-700 flex gap-2">
            <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium">Directory unavailable</p>
              <p className="text-amber-600">{error}</p>
              {file.status !== 'COMPLETED' && (
                <p className="mt-1 text-amber-600">
                  The disk image is still being processed ({file.status}).
                  The file tree will appear once indexing completes.
                </p>
              )}
            </div>
          </div>
        )}
        {!loading && !error && entries.length === 0 && (
          <div className="flex flex-col items-center justify-center py-10 text-gray-400 text-xs">
            <Folder size={28} className="mb-2 text-gray-300" />
            {file.status === 'COMPLETED'
              ? 'Empty directory'
              : `Processing… (${file.status})`}
          </div>
        )}
        {!loading && entries.length > 0 && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-50 border-b border-gray-200 z-10">
              <tr>
                <th className="text-left px-3 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Name</th>
                <th className="text-right px-3 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">Size</th>
                <th className="text-left px-3 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-40">Modified</th>
              </tr>
            </thead>
            <tbody>
              {path !== '/' && (
                <tr
                  className="border-b border-gray-50 hover:bg-blue-50/50 cursor-pointer"
                  onClick={() => {
                    const parent = path.replace(/[^/]+\/$/, '') || '/'
                    browse(parent)
                  }}
                >
                  <td className="px-3 py-1.5 flex items-center gap-2">
                    <FolderOpen size={13} className="text-yellow-500" />
                    <span className="text-gray-500">..</span>
                  </td>
                  <td /><td />
                </tr>
              )}
              {entries.map((entry, i) => (
                <tr
                  key={i}
                  className="border-b border-gray-50 hover:bg-blue-50/50 cursor-pointer"
                  onClick={() => entry.is_dir && browse(entry.path.endsWith('/') ? entry.path : entry.path + '/')}
                >
                  <td className="px-3 py-1.5 flex items-center gap-2">
                    {entry.is_dir
                      ? <Folder size={13} className="text-yellow-500 flex-shrink-0" />
                      : <File   size={13} className="text-gray-400 flex-shrink-0" />
                    }
                    <span className={`truncate ${entry.is_dir ? 'text-brand-text font-medium' : 'text-gray-700'}`}>
                      {entry.name}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-right text-gray-400 tabular-nums">
                    {entry.is_dir ? '—' : entry.size ? _fmtSize(entry.size) : '0 B'}
                  </td>
                  <td className="px-3 py-1.5 text-gray-400 tabular-nums">
                    {entry.mtime ? new Date(entry.mtime).toISOString().replace('T', ' ').slice(0, 19) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function _fmtSize(bytes) {
  if (bytes < 1024)       return `${bytes} B`
  if (bytes < 1048576)    return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

// ── File search panel ─────────────────────────────────────────────────────────
function FileSearchPanel({ caseId, onOpenFile }) {
  const [query, setQuery]   = useState('')
  const [regex, setRegex]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError]   = useState('')

  async function doSearch(e) {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const r = await api.caseFiles.search(caseId, { query, regex })
      setResult(r)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-4 space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-brand-text mb-1">Search File Contents</h3>
        <p className="text-xs text-gray-500">Search within all readable files stored in this case (JSON, logs, scripts, configs…)</p>
      </div>
      <form onSubmit={doSearch} className="space-y-2">
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder='Search text or regex… e.g. "admin", "192\.168\.", "password"'
            className="input pl-8 text-xs w-full"
            autoFocus
          />
        </div>
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-1.5 text-xs text-gray-600 cursor-pointer">
            <input type="checkbox" checked={regex} onChange={e => setRegex(e.target.checked)} className="rounded" />
            Regex pattern
          </label>
          <button type="submit" disabled={!query.trim() || loading} className="btn-primary text-xs px-3">
            {loading ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
            {loading ? 'Searching…' : 'Search'}
          </button>
        </div>
      </form>

      {error && <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>}

      {result && (
        <div className="space-y-3">
          <p className="text-xs text-gray-500">
            {result.files_matched} of {result.files_searched} files matched
          </p>
          {result.results.length === 0 && (
            <p className="text-xs text-gray-400 italic">No matches found.</p>
          )}
          {result.results.map(r => (
            <div key={r.job_id} className="card p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-brand-text flex items-center gap-1">
                  <FileText size={12} className="text-blue-500" />
                  {r.filename}
                </span>
                <div className="flex items-center gap-2">
                  {!r.skipped && (
                    <span className="badge bg-brand-accentlight text-brand-accent text-[10px]">
                      {r.match_count} match{r.match_count !== 1 ? 'es' : ''}
                    </span>
                  )}
                  {!r.skipped && (
                    <button
                      onClick={() => onOpenFile({ job_id: r.job_id, filename: r.filename, category: 'text', status: 'COMPLETED' })}
                      className="btn-ghost text-xs text-brand-accent"
                    >
                      View
                    </button>
                  )}
                </div>
              </div>
              {r.skipped
                ? <p className="text-[10px] text-amber-600">{r.reason}</p>
                : r.matches.slice(0, 5).map((m, i) => (
                    <div key={i} className="bg-gray-50 rounded p-2 font-mono text-[10px]">
                      <span className="text-gray-400 mr-2">:{m.line}</span>
                      <span className="text-brand-text">{m.text}</span>
                    </div>
                  ))
              }
              {!r.skipped && r.match_count > 5 && (
                <p className="text-[10px] text-gray-400">+{r.match_count - 5} more matches</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
const STATUS_COLORS = {
  COMPLETED: 'text-green-600',
  FAILED:    'text-red-600',
  RUNNING:   'text-brand-accent',
  PENDING:   'text-amber-600',
  UPLOADING: 'text-sky-500',
  SKIPPED:   'text-gray-400',
}

export default function CaseFiles({ caseId }) {
  const [files, setFiles]           = useState([])
  const [loading, setLoading]       = useState(true)
  const [activeView, setActiveView] = useState(null)   // { type: 'content'|'diskimage'|'search', file? }
  const [filter, setFilter]         = useState('')

  useEffect(() => {
    api.caseFiles.list(caseId)
      .then(r => setFiles(r.files || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [caseId])

  const shown = filter
    ? files.filter(f => f.filename.toLowerCase().includes(filter.toLowerCase()))
    : files

  // ── Main content area ───────────────────────────────────────────────────────
  if (activeView?.type === 'content') {
    return (
      <ContentViewer
        caseId={caseId}
        file={activeView.file}
        onClose={() => setActiveView(null)}
      />
    )
  }

  if (activeView?.type === 'diskimage') {
    return (
      <div className="flex flex-col h-full">
        <div className="px-3 py-2 border-b border-gray-200 flex-shrink-0">
          <button onClick={() => setActiveView(null)} className="flex items-center gap-1 text-xs text-gray-500 hover:text-brand-accent">
            <ArrowLeft size={12} /> Back to files
          </button>
        </div>
        <div className="flex-1 overflow-hidden">
          <DiskImageBrowser caseId={caseId} file={activeView.file} />
        </div>
      </div>
    )
  }

  if (activeView?.type === 'search') {
    return (
      <div className="flex flex-col h-full">
        <div className="px-3 py-2 border-b border-gray-200 flex-shrink-0">
          <button onClick={() => setActiveView(null)} className="flex items-center gap-1 text-xs text-gray-500 hover:text-brand-accent">
            <ArrowLeft size={12} /> Back to files
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <FileSearchPanel
            caseId={caseId}
            onOpenFile={file => setActiveView({ type: 'content', file })}
          />
        </div>
      </div>
    )
  }

  // ── File list ───────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="px-4 py-2.5 border-b border-gray-200 bg-white flex items-center gap-2 flex-shrink-0">
        <div className="relative flex-1">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter files…"
            className="input pl-7 text-xs w-full"
          />
        </div>
        <button
          onClick={() => setActiveView({ type: 'search' })}
          className="btn-ghost text-xs flex items-center gap-1.5"
        >
          <Search size={12} /> Search Contents
        </button>
      </div>

      {/* File list */}
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center justify-center gap-2 py-10 text-gray-500 text-xs">
            <Loader2 size={14} className="animate-spin" /> Loading files…
          </div>
        )}
        {!loading && shown.length === 0 && (
          <div className="flex flex-col items-center justify-center py-10 text-gray-400 text-xs">
            <File size={28} className="mb-2 text-gray-300" />
            {filter ? 'No files match your filter.' : 'No files ingested yet.'}
          </div>
        )}
        {!loading && shown.length > 0 && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-50 border-b border-gray-200 z-10">
              <tr>
                <th className="text-left px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">File</th>
                <th className="text-left px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-20">Status</th>
                <th className="text-right px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-20">Events</th>
                <th className="text-left px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">Plugin</th>
                <th className="px-3 py-2 w-28"></th>
              </tr>
            </thead>
            <tbody>
              {shown.map(file => (
                <tr key={file.job_id} className="border-b border-gray-50 hover:bg-gray-50/80">
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <FileIcon category={file.category} size={13} />
                      <div className="min-w-0">
                        <p className="font-medium text-brand-text truncate">{file.filename}</p>
                        {file.source_zip && (
                          <p className="text-[10px] text-gray-400 truncate">from {file.source_zip}</p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className={`px-3 py-2 font-mono text-[11px] ${STATUS_COLORS[file.status] || 'text-gray-500'}`}>
                    {file.status}
                  </td>
                  <td className="px-3 py-2 text-right text-gray-500 tabular-nums">
                    {file.events_indexed > 0 ? file.events_indexed.toLocaleString() : '—'}
                  </td>
                  <td className="px-3 py-2 text-gray-400 font-mono text-[10px] truncate">
                    {file.plugin_used || '—'}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {file.is_disk_image && file.status === 'COMPLETED' && (
                      <button
                        onClick={() => setActiveView({ type: 'diskimage', file })}
                        className="btn-ghost text-xs text-orange-600 hover:text-orange-800"
                      >
                        <Folder size={11} /> Browse
                      </button>
                    )}
                    {file.is_readable && file.status === 'COMPLETED' && (
                      <button
                        onClick={() => setActiveView({ type: 'content', file })}
                        className="btn-ghost text-xs text-brand-accent"
                      >
                        <FileText size={11} /> View
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
