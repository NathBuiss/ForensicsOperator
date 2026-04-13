/**
 * IngestPanel — slide-in evidence ingestion panel with two tabs:
 *   • Upload  — chunked direct upload (same logic as Ingest.jsx)
 *   • S3 Import — browse Import or Triage S3 bucket, multi-select, batch pull
 *
 * Job list is shared between tabs and always visible at the bottom.
 * Active S3 transfers are reported to UploadContext so the global sidebar
 * indicator stays accurate while the panel is closed.
 */
import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Upload, Cloud, X, RefreshCw, AlertTriangle,
  ChevronRight, Folder, File, Loader2, Database, Download, Trash2,
} from 'lucide-react'
import { api } from '../api/client'
import { useUpload } from '../contexts/UploadContext'

// ── Constants ─────────────────────────────────────────────────────────────────

const ACCEPTED_TYPES = [
  '.evtx', '.evt', '.plaso', '.pf', '.lnk', '.dat', '.hive',
  '.pcap', '.pcapng', '.cap', '.log', '.json', '.ndjson', '.jsonl',
  '.sqlite', '.db', '.sqlite3', '.sqlitedb', '.db3', '.esedb', '.edb',
  '.dmp', '.raw', '.lime', '.mem', '.vmem', '.vmdk', '.dd', '.img',
  '.e01', '.ex01', '.001', '.plist', '.asl', '.utmp', '.utmpx', '.wtmp',
  '.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx', '.ppt', '.pptm', '.pptx',
  '.rtf', '.mht', '.exe', '.dll', '.sys', '.scr', '.so', '.elf', '.bin',
  '.zip', '.tar', '.gz', '.7z', '.rar', '.ab',
  '.ps1', '.bat', '.vbs', '.js', '.txt', '.csv', '.msi', '.jar', '.pdf', '.xml',
]
const ACCEPT_ATTR   = ACCEPTED_TYPES.join(',')
const TERMINAL      = new Set(['COMPLETED', 'FAILED', 'SKIPPED'])
const STUCK_MS      = 5 * 60 * 1000
const CHUNK_SIZE    = 50 * 1024 * 1024   // 50 MB per upload chunk

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtSize(bytes) {
  if (!bytes) return '—'
  if (bytes < 1024)        return `${bytes} B`
  if (bytes < 1048576)     return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824)  return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

function useElapsed(iso) {
  const [e, setE] = useState(0)
  useEffect(() => {
    if (!iso) return
    const tick = () => setE(Date.now() - new Date(iso).getTime())
    tick()
    const id = setInterval(tick, 10_000)
    return () => clearInterval(id)
  }, [iso])
  return e
}

// ── JobCard ───────────────────────────────────────────────────────────────────

function JobCard({ jobId, jobData, onRetry, onDelete }) {
  const [retrying,  setRetrying]  = useState(false)
  const [deleting,  setDeleting]  = useState(false)
  const elapsed = useElapsed(jobData?.created_at)
  const job = jobData

  async function retryJob() {
    setRetrying(true)
    try { await api.ingest.retryJob(jobId); onRetry?.(jobId) }
    catch (err) { alert('Retry failed: ' + err.message) }
    finally { setRetrying(false) }
  }

  async function deleteJob() {
    if (!window.confirm(`Remove "${job.original_filename}"?\nThis deletes the file and all its indexed events.`)) return
    setDeleting(true)
    try {
      await api.ingest.deleteJob(jobId)
      onDelete?.(jobId)
    } catch (err) {
      alert('Delete failed: ' + err.message)
      setDeleting(false)
    }
  }

  if (!job) return <div className="text-gray-400 text-xs p-2">Loading…</div>

  const STATUS = {
    UPLOADING: 'text-sky-500',
    PENDING:   'text-amber-600',
    RUNNING:   'text-brand-accent',
    COMPLETED: 'text-green-600',
    FAILED:    'text-red-600',
    SKIPPED:   'text-gray-400',
  }

  const canRetry = job.status === 'FAILED' || (job.status === 'PENDING' && elapsed > STUCK_MS)

  return (
    <div className={`card p-3 ${job.status === 'FAILED' ? 'border-red-200' : ''}`}>
      <div className="flex items-center justify-between mb-1 gap-2">
        <span className="text-xs text-brand-text font-medium truncate">{job.original_filename}</span>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className={`text-xs font-mono ${STATUS[job.status] || 'text-gray-500'}`}>
            {job.status}
            {job.status === 'RUNNING' && <span className="ml-1 animate-pulse">●</span>}
          </span>
          {job.status === 'COMPLETED' && (
            <a
              href={api.caseFiles.downloadUrl(job.case_id, job.job_id)}
              download={job.original_filename}
              className="btn-ghost text-xs px-1.5 py-0.5 text-gray-500 hover:text-brand-accent flex items-center gap-1"
              title="Download original file"
            >
              <Download size={12} />
            </a>
          )}
          {canRetry && (
            <button onClick={retryJob} disabled={retrying}
              className="btn-ghost text-xs px-1.5 py-0.5 text-brand-accent hover:text-brand-accenthover flex items-center gap-1"
              title={job.status === 'PENDING' ? 'Re-queue stuck job' : 'Retry'}>
              <RefreshCw size={12} className={retrying ? 'animate-spin' : ''} />
              {job.status === 'PENDING' ? 'Re-queue' : 'Retry'}
            </button>
          )}
          {!['RUNNING', 'UPLOADING'].includes(job.status) && (
            <button onClick={deleteJob} disabled={deleting}
              className="btn-ghost text-xs px-1.5 py-0.5 text-red-400 hover:text-red-600 flex items-center gap-1"
              title="Delete this job and all its indexed events">
              {deleting
                ? <Loader2 size={12} className="animate-spin" />
                : <Trash2 size={12} />}
            </button>
          )}
        </div>
      </div>

      {job.plugin_used && (
        <p className="text-xs text-gray-500">Plugin: <code className="font-mono">{job.plugin_used}</code></p>
      )}

      {job.status === 'UPLOADING' && (
        <div className="mt-1">
          <div className="h-1 bg-gray-200 rounded overflow-hidden">
            <div className="h-full bg-sky-500 animate-pulse w-2/3 rounded" />
          </div>
          <p className="text-xs text-sky-500 mt-0.5">Uploading to storage…</p>
        </div>
      )}
      {job.status === 'RUNNING' && (
        <div className="mt-1">
          <div className="h-1 bg-gray-200 rounded overflow-hidden">
            <div className="h-full bg-brand-accent animate-pulse w-1/3 rounded" />
          </div>
          <p className="text-xs text-gray-500 mt-0.5">
            {parseInt(job.events_indexed || 0).toLocaleString()} events indexed
          </p>
        </div>
      )}
      {job.status === 'COMPLETED' && (
        <p className="text-xs text-green-600 mt-0.5">
          {parseInt(job.events_indexed || 0).toLocaleString()} events indexed
          {job.plugin_stats?.records_skipped > 0 && ` (${job.plugin_stats.records_skipped} skipped)`}
        </p>
      )}
      {job.status === 'FAILED' && (
        <p className="text-xs text-red-600 mt-0.5 break-all">{job.error}</p>
      )}
      {job.status === 'SKIPPED' && (
        <p className="text-xs text-gray-400 mt-0.5 break-all">{job.error}</p>
      )}
      {(job.status === 'UPLOADING' || job.status === 'PENDING') && elapsed > STUCK_MS && (
        <p className="text-[10px] text-amber-500 mt-0.5 flex items-center gap-1">
          <AlertTriangle size={10} />
          In queue {Math.floor(elapsed / 60_000)} min — worker will pick it up when free
        </p>
      )}
    </div>
  )
}

// ── Upload tab ────────────────────────────────────────────────────────────────

function UploadTab({ caseId, onJobsAdded }) {
  const [dragging,   setDragging]   = useState(false)
  const [uploading,  setUploading]  = useState(false)
  const [uploadPct,  setUploadPct]  = useState(0)
  const [error,      setError]      = useState('')
  const inputRef  = useRef()
  const folderRef = useRef()
  const { startUpload, updateUpload, finishUpload } = useUpload()

  async function handleFiles(files) {
    if (!files.length) return
    setError('')
    setUploading(true)
    setUploadPct(0)

    const token      = localStorage.getItem('fo_token') || ''
    const base       = window.location.origin
    const uploadId   = `${caseId}-${Date.now()}`
    const label      = files.length === 1 ? files[0].name : `${files.length} files`
    startUpload(uploadId, label)

    const totalBytes = Array.from(files).reduce((s, f) => s + f.size, 0)
    let sentBytes = 0
    const allJobs = []

    try {
      for (const file of files) {
        const totalChunks  = Math.max(1, Math.ceil(file.size / CHUNK_SIZE))
        const fileUploadId = crypto.randomUUID()

        for (let i = 0; i < totalChunks; i++) {
          const slice = file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)
          const fd    = new FormData()
          fd.append('upload_id',    fileUploadId)
          fd.append('filename',     file.name)
          fd.append('chunk_index',  i)
          fd.append('total_chunks', totalChunks)
          fd.append('chunk',        slice)

          const res = await fetch(`${base}/api/v1/cases/${caseId}/ingest/chunk`, {
            method: 'POST',
            headers: token ? { Authorization: `Bearer ${token}` } : {},
            body: fd,
          })
          if (!res.ok) {
            const body = await res.json().catch(() => ({}))
            throw new Error(body.detail || `HTTP ${res.status}`)
          }

          sentBytes += slice.size
          const pct  = Math.round((sentBytes / totalBytes) * 100)
          setUploadPct(pct)
          updateUpload(uploadId, pct)

          if (i === totalChunks - 1) {
            const r = await res.json()
            allJobs.push(...(r.jobs || []))
          }
        }
      }
      onJobsAdded(allJobs)
    } catch (err) {
      setError(`Upload failed: ${err.message}`)
    } finally {
      setUploading(false)
      setUploadPct(0)
      finishUpload(uploadId)
    }
  }

  return (
    <div className="p-4 space-y-3">
      {/* Drop zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => { e.preventDefault(); setDragging(false); handleFiles([...e.dataTransfer.files]) }}
        onClick={() => !uploading && inputRef.current?.click()}
        className={`${dragging ? 'drop-zone-active' : 'drop-zone-inactive'} ${uploading ? 'cursor-default' : ''}`}
      >
        <p className="text-2xl mb-2">📂</p>
        <p className="text-sm text-gray-500">
          {uploading ? `Transferring… ${uploadPct}%` : 'Drop files here or click to browse'}
        </p>
        {uploading && (
          <div className="mt-2 w-full max-w-xs mx-auto">
            <div className="h-1.5 bg-gray-200 rounded overflow-hidden">
              <div className="h-full bg-sky-500 rounded transition-all duration-300"
                style={{ width: `${uploadPct}%` }} />
            </div>
            <p className="text-[10px] text-sky-500 mt-1">
              Sending to server — jobs appear when transfer completes
            </p>
          </div>
        )}
        {!uploading && <p className="text-xs text-gray-400 mt-1">Multiple files or folders supported</p>}
        <input ref={inputRef} type="file" multiple accept={ACCEPT_ATTR} className="hidden"
          onChange={e => handleFiles([...e.target.files])} />
      </div>

      {/* Folder button */}
      <div className="flex items-center gap-2">
        <button onClick={() => folderRef.current?.click()} disabled={uploading} className="btn-outline text-xs">
          📁 Upload Folder
        </button>
        <span className="text-[10px] text-gray-400">All files inside will be uploaded</span>
        <input ref={folderRef} type="file"
          // @ts-ignore
          webkitdirectory="" directory="" multiple className="hidden"
          onChange={e => handleFiles([...e.target.files])} />
      </div>

      {error && <div className="card border-red-200 p-3 text-xs text-red-600">{error}</div>}
    </div>
  )
}

// ── S3 Browser tab ────────────────────────────────────────────────────────────

function S3Tab({ caseId, onJobsAdded }) {
  const [source,    setSource]    = useState('import')   // 'import' | 'triage'
  const [prefix,    setPrefix]    = useState('')
  const [entries,   setEntries]   = useState({ folders: [], files: [] })
  const [loading,   setLoading]   = useState(false)
  const [selected,  setSelected]  = useState(new Set())
  const [importing, setImporting] = useState(false)
  const [error,     setError]     = useState('')
  const { startUpload, finishUpload } = useUpload()

  const browse = useCallback(async (pfx, src) => {
    setLoading(true)
    setError('')
    try {
      const fn = src === 'import' ? api.s3.browse : api.s3Triage.browse
      const r  = await fn(pfx, '/')
      setEntries({ folders: r.folders || [], files: r.files || [] })
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    setPrefix('')
    setSelected(new Set())
    browse('', source)
  }, [source, browse])

  function navigateTo(folderKey) {
    setPrefix(folderKey)
    setSelected(new Set())
    browse(folderKey, source)
  }

  function jumpTo(idx) {
    const parts  = prefix.split('/').filter(Boolean)
    const newPfx = idx < 0 ? '' : parts.slice(0, idx + 1).join('/') + '/'
    setPrefix(newPfx)
    setSelected(new Set())
    browse(newPfx, source)
  }

  function toggleFile(key) {
    setSelected(prev => {
      const n = new Set(prev)
      n.has(key) ? n.delete(key) : n.add(key)
      return n
    })
  }

  function toggleAll() {
    setSelected(prev =>
      prev.size === entries.files.length
        ? new Set()
        : new Set(entries.files.map(f => f.key))
    )
  }

  async function importSelected() {
    if (!selected.size || importing) return
    setImporting(true)
    setError('')
    const transferId = `s3-${Date.now()}`
    const count      = selected.size
    startUpload(transferId, `S3 → ${count} file${count > 1 ? 's' : ''} (transferring…)`)
    try {
      const fn  = source === 'import' ? api.s3.importBatch : api.s3Triage.importBatch
      const r   = await fn(caseId, [...selected])
      onJobsAdded(r.jobs || [])
      if (r.errors?.length) {
        setError(`${r.errors.length} file(s) failed: ${r.errors.map(e => e.s3_key.split('/').pop()).join(', ')}`)
      }
      setSelected(new Set())
    } catch (e) {
      setError(e.message)
    } finally {
      setImporting(false)
      finishUpload(transferId)
    }
  }

  const crumbs = prefix.split('/').filter(Boolean)
  const allFilesSelected = entries.files.length > 0 && selected.size === entries.files.length
  const someFilesSelected = selected.size > 0 && selected.size < entries.files.length

  return (
    <div className="p-4 space-y-3">
      {/* Source toggle */}
      <div className="flex gap-0.5 bg-gray-100 rounded-lg p-0.5">
        {[['import', 'Import Bucket'], ['triage', 'Triage Bucket']].map(([k, l]) => (
          <button key={k} onClick={() => setSource(k)}
            className={`flex-1 text-xs py-1 rounded-md transition-colors ${
              source === k ? 'bg-white shadow text-brand-text font-medium' : 'text-gray-500 hover:text-gray-700'
            }`}>
            {l}
          </button>
        ))}
      </div>

      {/* Breadcrumb */}
      <div className="flex items-center gap-1 text-xs flex-wrap min-h-5">
        <button onClick={() => jumpTo(-1)}
          className="text-gray-500 hover:text-brand-accent transition-colors">
          root
        </button>
        {crumbs.map((c, i) => (
          <span key={i} className="flex items-center gap-1">
            <ChevronRight size={10} className="text-gray-300" />
            <button onClick={() => jumpTo(i)}
              className={`transition-colors ${
                i === crumbs.length - 1
                  ? 'font-medium text-brand-text'
                  : 'text-gray-500 hover:text-brand-accent'
              }`}>
              {c}
            </button>
          </span>
        ))}
        <button onClick={() => browse(prefix, source)}
          className="ml-auto text-gray-400 hover:text-brand-accent p-0.5 rounded transition-colors"
          title="Refresh">
          <RefreshCw size={11} />
        </button>
      </div>

      {error && (
        <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
          <AlertTriangle size={12} /> {error}
        </div>
      )}

      {/* File listing */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        {/* Column header + select-all */}
        {!loading && (entries.files.length > 0 || entries.folders.length > 0) && (
          <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-50 border-b border-gray-200">
            <input
              type="checkbox"
              checked={allFilesSelected}
              ref={el => { if (el) el.indeterminate = someFilesSelected }}
              onChange={toggleAll}
              className="w-3 h-3"
              title="Select / deselect all files"
            />
            <span className="text-[10px] text-gray-500 font-semibold uppercase tracking-wider">Name</span>
            {selected.size > 0 && (
              <span className="ml-auto text-[10px] text-brand-accent font-semibold">
                {selected.size} selected
              </span>
            )}
            {selected.size === 0 && (
              <span className="ml-auto text-[10px] text-gray-400">Size</span>
            )}
          </div>
        )}

        <div className="overflow-y-auto" style={{ maxHeight: '240px' }}>
          {loading && (
            <div className="flex items-center justify-center h-16 text-xs text-gray-400 gap-2">
              <Loader2 size={13} className="animate-spin" /> Loading…
            </div>
          )}
          {!loading && entries.folders.length === 0 && entries.files.length === 0 && (
            <div className="flex items-center justify-center h-12 text-xs text-gray-400">
              Empty — no objects found
            </div>
          )}

          {/* Folders */}
          {entries.folders.map(f => {
            const name = f.key.slice(prefix.length).replace(/\/$/, '')
            return (
              <button key={f.key} onClick={() => navigateTo(f.key)}
                className="flex items-center gap-2.5 w-full px-3 py-2 hover:bg-gray-50 border-b border-gray-50 transition-colors text-left text-xs">
                <span className="w-3 h-3 flex-shrink-0" />
                <Folder size={13} className="text-amber-500 flex-shrink-0" />
                <span className="flex-1 truncate text-gray-700">{name}/</span>
                <ChevronRight size={11} className="text-gray-300 flex-shrink-0" />
              </button>
            )
          })}

          {/* Files */}
          {entries.files.map(f => {
            const name = f.key.slice(prefix.length)
            const sel  = selected.has(f.key)
            return (
              <div key={f.key} onClick={() => toggleFile(f.key)}
                className={`flex items-center gap-2.5 px-3 py-2 cursor-pointer border-b border-gray-50 transition-colors text-xs ${
                  sel ? 'bg-brand-accentlight' : 'hover:bg-gray-50'
                }`}>
                <input type="checkbox" checked={sel}
                  onChange={() => toggleFile(f.key)}
                  onClick={e => e.stopPropagation()}
                  className="w-3 h-3 flex-shrink-0" />
                <File size={12} className="text-gray-400 flex-shrink-0" />
                <span className="flex-1 truncate font-mono text-[10px] text-gray-700">{name}</span>
                <span className="text-gray-400 text-[10px] flex-shrink-0 ml-2">{fmtSize(f.size)}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Import button */}
      <button onClick={importSelected}
        disabled={!selected.size || importing}
        className="btn-primary w-full justify-center text-xs">
        {importing
          ? <><Loader2 size={13} className="animate-spin" /> Transferring S3 → storage…</>
          : <><Cloud size={13} />
              {selected.size > 0
                ? `Import ${selected.size} file${selected.size > 1 ? 's' : ''} to case`
                : 'Select files above'}
            </>
        }
      </button>
      {selected.size > 0 && (
        <p className="text-[10px] text-gray-400 text-center -mt-1">
          Large files are streamed server-side — transfer time depends on S3 bandwidth.
        </p>
      )}
    </div>
  )
}

// ── Main IngestPanel ──────────────────────────────────────────────────────────

const JOB_SORT_ORDER = { RUNNING: 0, UPLOADING: 1, PENDING: 2, COMPLETED: 3, SKIPPED: 4, FAILED: 5 }

export default function IngestPanel({ caseId, onClose, onComplete }) {
  const [tab,          setTab]          = useState('upload')
  const [jobs,         setJobs]         = useState([])
  const [jobStatuses,  setJobStatuses]  = useState({})
  const [jobDataMap,   setJobDataMap]   = useState({})
  const [filterStatus, setFilterStatus] = useState(null)   // null = All
  const [searchQuery,  setSearchQuery]  = useState('')

  const jobsRef     = useRef([])
  const statusesRef = useRef({})

  useEffect(() => { jobsRef.current    = jobs        }, [jobs])
  useEffect(() => { statusesRef.current = jobStatuses }, [jobStatuses])

  // Load existing jobs on mount
  useEffect(() => {
    api.ingest.listJobs(caseId).then(r => {
      const all = r.jobs || []
      const sm = {}, dm = {}
      all.forEach(j => { sm[j.job_id] = j.status; dm[j.job_id] = j })
      setJobStatuses(sm)
      setJobDataMap(dm)
      setJobs([...all].sort((a, b) => (JOB_SORT_ORDER[a.status] ?? 9) - (JOB_SORT_ORDER[b.status] ?? 9)).map(j => j.job_id))
    }).catch(() => {})
  }, [caseId])

  // Central batch poller — one request per 3 s for all non-terminal jobs
  useEffect(() => {
    async function poll() {
      const active = jobsRef.current.filter(id => !TERMINAL.has(statusesRef.current[id]))
      if (!active.length) return
      for (let i = 0; i < active.length; i += 100) {
        try {
          const results = await api.ingest.batchJobs(active.slice(i, i + 100))
          if (!results?.length) continue
          setJobDataMap(p => { const n = { ...p }; results.forEach(j => { n[j.job_id] = j }); return n })
          setJobStatuses(p => { const n = { ...p }; results.forEach(j => { n[j.job_id] = j.status }); return n })
        } catch { /* ignore — retries on next tick */ }
      }
    }
    poll()
    const id = setInterval(poll, 3000)
    return () => clearInterval(id)
  }, [])

  const addJobs = useCallback((newJobs) => {
    const ids = newJobs.map(j => j.job_id)
    setJobs(prev => [...ids, ...prev])
    setJobStatuses(prev => { const n = { ...prev }; ids.forEach(id => { n[id] = 'PENDING' }); return n })
    setJobDataMap(prev => { const n = { ...prev }; newJobs.forEach(j => { n[j.job_id] = j }); return n })
    onComplete?.()
  }, [onComplete])

  const handleRetry = useCallback((id) => {
    setJobStatuses(p => ({ ...p, [id]: 'PENDING' }))
  }, [])

  const handleDelete = useCallback((id) => {
    setJobs(prev => prev.filter(jid => jid !== id))
    setJobStatuses(p => { const n = { ...p }; delete n[id]; return n })
    setJobDataMap(p => { const n = { ...p }; delete n[id]; return n })
  }, [])

  // ── Derived counts ────────────────────────────────────────────────────────
  const statusCounts = Object.values(jobStatuses).reduce((acc, s) => {
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})
  const activeCount = (statusCounts['RUNNING'] || 0) + (statusCounts['UPLOADING'] || 0)

  // Always sort by priority (active first, failed last), then filter by tab + search
  const sortedJobs = [...jobs].sort((a, b) =>
    (JOB_SORT_ORDER[jobStatuses[a]] ?? 9) - (JOB_SORT_ORDER[jobStatuses[b]] ?? 9)
  )
  const filteredJobs = sortedJobs.filter(jid => {
    const job = jobDataMap[jid]
    if (!job) return true
    if (filterStatus === 'ACTIVE'   && !['RUNNING', 'UPLOADING'].includes(job.status)) return false
    if (filterStatus === 'PENDING'  && job.status !== 'PENDING')                        return false
    if (filterStatus === 'COMPLETED'&& job.status !== 'COMPLETED')                      return false
    if (filterStatus === 'FAILED'   && job.status !== 'FAILED')                         return false
    if (searchQuery.trim()) {
      return (job.original_filename || '').toLowerCase().includes(searchQuery.toLowerCase())
    }
    return true
  })

  const FILTER_TABS = [
    { id: null,        label: 'All',     count: jobs.length },
    { id: 'ACTIVE',    label: 'Active',  count: activeCount },
    { id: 'PENDING',   label: 'Pending', count: statusCounts['PENDING']   || 0 },
    { id: 'COMPLETED', label: 'Done',    count: statusCounts['COMPLETED'] || 0 },
    { id: 'FAILED',    label: 'Failed',  count: statusCounts['FAILED']    || 0 },
  ].filter(f => f.id === null || f.count > 0)

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[580px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* ── Header + tabs ── */}
        <div className="flex items-center gap-3 px-5 py-3 border-b border-gray-200 flex-shrink-0">
          <Upload size={15} className="text-brand-accent flex-shrink-0" />
          <span className="font-semibold text-brand-text text-sm">Add Evidence</span>

          <div className="flex gap-0.5 bg-gray-100 rounded-lg p-0.5 ml-1">
            {[
              ['upload', '⬆\u2009Upload'],
              ['s3',     '☁\u2009S3 Import'],
            ].map(([k, l]) => (
              <button key={k} onClick={() => setTab(k)}
                className={`text-xs px-3 py-1 rounded-md transition-colors whitespace-nowrap ${
                  tab === k
                    ? 'bg-white shadow text-brand-text font-medium'
                    : 'text-gray-500 hover:text-gray-700'
                }`}>
                {l}
              </button>
            ))}
          </div>

          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg ml-auto">
            <X size={16} />
          </button>
        </div>

        {/* ── Tab content ── */}
        <div className="border-b border-gray-100 flex-shrink-0">
          {tab === 'upload' && <UploadTab caseId={caseId} onJobsAdded={addJobs} />}
          {tab === 's3'     && <S3Tab     caseId={caseId} onJobsAdded={addJobs} />}
        </div>

        {/* ── Shared job list — always visible, scrollable ── */}
        <div className="flex flex-col flex-1 min-h-0">
          {/* Filter + search bar — sticky above the scrollable list */}
          {jobs.length > 0 && (
            <div className="px-4 pt-3 pb-2 border-b border-gray-100 flex-shrink-0 space-y-2">
              {/* Status filter pills */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider mr-0.5">
                  Filter
                </span>
                {FILTER_TABS.map(f => (
                  <button
                    key={String(f.id)}
                    onClick={() => setFilterStatus(f.id)}
                    className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors font-medium ${
                      filterStatus === f.id
                        ? f.id === 'FAILED'
                          ? 'bg-red-500 text-white border-red-500'
                          : f.id === 'ACTIVE'
                            ? 'bg-brand-accent text-white border-brand-accent'
                            : 'bg-gray-700 text-white border-gray-700'
                        : f.id === 'FAILED' && f.count > 0
                          ? 'bg-red-50 text-red-500 border-red-200 hover:bg-red-100'
                          : f.id === 'ACTIVE' && f.count > 0
                            ? 'bg-brand-accentlight text-brand-accent border-brand-accent/30 hover:bg-brand-accent/10'
                            : 'bg-white text-gray-500 border-gray-200 hover:border-gray-400 hover:text-gray-700'
                    }`}
                  >
                    {f.label}
                    <span className={`ml-1 ${filterStatus === f.id ? 'opacity-80' : 'opacity-60'}`}>
                      {f.count}
                    </span>
                  </button>
                ))}
                {activeCount > 0 && (
                  <span className="ml-auto text-[10px] text-brand-accent animate-pulse font-medium">
                    {activeCount} running
                  </span>
                )}
              </div>
              {/* Filename search — only shown when there are enough jobs to warrant it */}
              {jobs.length >= 5 && (
                <div className="relative">
                  <input
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Search by filename…"
                    className="input w-full text-xs py-1 pr-7"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery('')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                    >
                      <X size={11} />
                    </button>
                  )}
                </div>
              )}
            </div>
          )}

          <div className="flex-1 overflow-y-auto p-4 min-h-0">
            {jobs.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 gap-2 text-gray-300">
                <Database size={28} />
                <p className="text-xs">No jobs yet — upload or import from S3</p>
              </div>
            ) : filteredJobs.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-24 gap-1.5 text-gray-300">
                <p className="text-xs">No jobs match this filter</p>
                <button onClick={() => { setFilterStatus(null); setSearchQuery('') }}
                  className="text-[10px] text-brand-accent hover:underline">
                  Clear filters
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                {filteredJobs.map(jid => (
                  <JobCard key={jid} jobId={jid} jobData={jobDataMap[jid]} onRetry={handleRetry} onDelete={handleDelete} />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
