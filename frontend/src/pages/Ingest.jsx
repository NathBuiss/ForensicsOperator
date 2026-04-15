import { useState, useEffect, useRef, useCallback } from 'react'
import {
  RefreshCw, AlertTriangle,
  FolderOpen, Play, CheckCircle2, XCircle, Ban, X, Loader2, Info,
} from 'lucide-react'
import { api } from '../api/client'
import { useUpload } from '../contexts/UploadContext'

// ── Accepted file types ───────────────────────────────────────────────────
// Covers every extension recognised by the built-in plugins and module runners.
// The accept attribute is a hint to the OS file picker — not a hard block.
const ACCEPTED_TYPES = [
  // Windows event logs & artifacts
  '.evtx', '.evt',
  // Plaso storage file
  '.plaso',
  // Prefetch, LNK, Registry hives
  '.pf', '.lnk', '.dat', '.hive',
  // Network captures
  '.pcap', '.pcapng', '.cap',
  // Structured logs / NDJSON
  '.log', '.json', '.ndjson', '.jsonl',
  // SQLite / ESE databases
  '.sqlite', '.db', '.sqlite3', '.sqlitedb', '.db3', '.esedb', '.edb',
  // Memory forensics images
  '.dmp', '.raw', '.lime', '.mem', '.vmem', '.vmdk', '.dd', '.img',
  '.e01', '.ex01', '.001',
  // macOS artifacts
  '.plist', '.asl',
  // Linux login records
  '.utmp', '.utmpx', '.wtmp',
  // Office / OLE documents (oletools)
  '.doc', '.docm', '.docx',
  '.xls', '.xlsm', '.xlsx',
  '.ppt', '.pptm', '.pptx',
  '.rtf', '.mht',
  // PE / executables / binaries
  '.exe', '.dll', '.sys', '.scr', '.ocx', '.so', '.elf', '.bin',
  // Archives (auto-extracted on ingest)
  '.zip', '.tar', '.gz', '.7z', '.rar',
  // Android backup
  '.ab',
  // Scripts / text / CSV
  '.ps1', '.bat', '.vbs', '.js', '.txt', '.csv',
  // Misc
  '.msi', '.jar', '.pdf', '.xml',
]

const ACCEPTED_NAMES = [
  // Windows Registry hives (no extension)
  '$MFT', 'NTUSER.DAT', 'USRCLASS.DAT', 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT',
  // Browser artefacts
  'HISTORY', 'COOKIES', 'LOGIN DATA', 'BOOKMARKS', 'WEB DATA', 'FAVICONS', 'SHORTCUTS',
  'TOP SITES', 'PLACES.SQLITE', 'COOKIES.SQLITE', 'FORMHISTORY.SQLITE',
  // iOS / macOS
  'SMS.DB', 'CALL_HISTORY.DB', 'ADDRESSBOOK.SQLITEDB', 'CONSOLIDATED.DB', 'MANIFEST.DB',
  // Zeek named logs
  'CONN.LOG', 'DNS.LOG', 'HTTP.LOG', 'SSL.LOG', 'SSH.LOG', 'FTP.LOG', 'SMTP.LOG',
  'FILES.LOG', 'WEIRD.LOG', 'NOTICE.LOG',
  // Linux syslogs
  'SYSLOG', 'AUTH.LOG', 'KERN.LOG', 'DAEMON.LOG', 'MESSAGES', 'SECURE', 'DMESG',
  // Suricata
  'EVE.JSON',
]

const ACCEPT_ATTR = [...ACCEPTED_TYPES, ...ACCEPTED_NAMES.map(n => `.${n.replace(/^\$/, '')}`)].join(',')

const STUCK_THRESHOLD_MS = 5 * 60 * 1000  // 5 minutes

function useElapsed(isoTimestamp) {
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (!isoTimestamp) return
    const tick = () => setElapsed(Date.now() - new Date(isoTimestamp).getTime())
    tick()
    const id = setInterval(tick, 10000)
    return () => clearInterval(id)
  }, [isoTimestamp])
  return elapsed
}

function JobCard({ jobId, jobData, onRetry }) {
  const [retrying, setRetrying] = useState(false)
  const elapsed = useElapsed(jobData?.created_at)
  const job = jobData

  async function retryJob() {
    setRetrying(true)
    try {
      await api.ingest.retryJob(jobId)
      onRetry?.(jobId)
    } catch (err) {
      alert('Retry failed: ' + err.message)
    } finally {
      setRetrying(false)
    }
  }

  if (!job) return <div className="text-gray-400 text-xs p-2">Loading…</div>

  const statusColors = {
    UPLOADING: 'text-sky-500',
    PENDING:   'text-amber-600',
    RUNNING:   'text-brand-accent',
    COMPLETED: 'text-green-600',
    FAILED:    'text-red-600',
    SKIPPED:   'text-gray-400',
  }

  return (
    <div className={`card p-3 ${job.status === 'FAILED' ? 'border-red-200' : ''}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-brand-text font-medium truncate">{job.original_filename}</span>
        <div className="flex items-center gap-2">
          <span className={`text-xs font-mono ${statusColors[job.status] || 'text-gray-500'}`}>
            {job.status}
            {job.status === 'RUNNING' && <span className="ml-1 animate-pulse">●</span>}
          </span>
          {(job.status === 'FAILED' || (job.status === 'PENDING' && elapsed > STUCK_THRESHOLD_MS)) && (
            <button
              onClick={retryJob}
              disabled={retrying}
              className="btn-ghost text-xs px-1.5 py-0.5 text-brand-accent hover:text-brand-accenthover"
              title={job.status === 'PENDING' ? 'Re-dispatch stuck job' : 'Retry this job'}
            >
              <RefreshCw size={12} className={retrying ? 'animate-spin' : ''} />
              {retrying ? '' : (job.status === 'PENDING' ? 'Re-queue' : 'Retry')}
            </button>
          )}
        </div>
      </div>

      {job.plugin_used && (
        <p className="text-xs text-gray-500">Plugin: <code className="font-mono">{job.plugin_used}</code></p>
      )}
      {job.source_zip && (
        <p className="text-xs text-gray-400">From: <span className="font-mono">{job.source_zip}</span></p>
      )}

      {(job.status === 'UPLOADING' || job.status === 'PENDING') && elapsed > STUCK_THRESHOLD_MS && (
        <p className="text-[10px] text-amber-500 mt-0.5 flex items-center gap-1">
          <AlertTriangle size={10} />
          In queue {Math.floor(elapsed / 60000)} min — processor is busy, job will run when a worker is free
        </p>
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
          {job.plugin_stats?.records_skipped > 0 &&
            ` (${job.plugin_stats.records_skipped} skipped)`}
        </p>
      )}

      {job.status === 'FAILED' && (
        <p className="text-xs text-red-600 mt-0.5 break-all">{job.error}</p>
      )}

      {job.status === 'SKIPPED' && (
        <p className="text-xs text-gray-400 mt-0.5 break-all">{job.error}</p>
      )}
    </div>
  )
}

const TERMINAL = new Set(['COMPLETED', 'FAILED', 'SKIPPED'])

// ── Server-side harvest run card ──────────────────────────────────────────────

function HarvestRunCard({ runId }) {
  const [run, setRun] = useState(null)
  const timerRef      = useRef(null)

  const poll = useCallback(async () => {
    try {
      const data = await api.harvest.getRun(runId)
      setRun(data)
      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(data.status)) {
        clearInterval(timerRef.current)
      }
    } catch {
      clearInterval(timerRef.current)
    }
  }, [runId])

  useEffect(() => {
    poll()
    timerRef.current = setInterval(poll, 3000)
    return () => clearInterval(timerRef.current)
  }, [poll])

  if (!run) return (
    <div className="flex items-center gap-1.5 text-xs text-gray-400">
      <Loader2 size={11} className="animate-spin" /> Loading…
    </div>
  )

  const isLive = ['RUNNING', 'OPENING_FILESYSTEM', 'PENDING'].includes(run.status)
  const statusColour = {
    PENDING:            'text-amber-600',
    RUNNING:            'text-blue-600',
    OPENING_FILESYSTEM: 'text-blue-600',
    COMPLETED:          'text-green-600',
    FAILED:             'text-red-600',
    CANCELLED:          'text-gray-400',
  }[run.status] || 'text-gray-400'

  return (
    <div className="rounded-lg border border-gray-200 bg-gray-50 overflow-hidden text-xs">
      <div className="flex items-center gap-2 px-3 py-2">
        {run.status === 'COMPLETED'
          ? <CheckCircle2 size={12} className="text-green-500 flex-shrink-0" />
          : run.status === 'FAILED'
          ? <XCircle     size={12} className="text-red-500 flex-shrink-0" />
          : run.status === 'CANCELLED'
          ? <Ban         size={12} className="text-gray-400 flex-shrink-0" />
          : <Loader2     size={12} className="text-blue-500 animate-spin flex-shrink-0" />
        }
        <span className="font-mono text-[10px] text-gray-400 truncate flex-1">{run.run_id}</span>
        <span className={`font-semibold ${statusColour}`}>{run.status}</span>
        {isLive && (
          <button
            onClick={() => api.harvest.cancelRun(runId).catch(() => {})}
            className="icon-btn text-red-400 hover:text-red-600" title="Cancel"
          >
            <X size={10} />
          </button>
        )}
      </div>
      {(run.current_category || run.total_dispatched != null || run.error) && (
        <div className="px-3 pb-2 space-y-0.5 text-gray-500">
          {run.current_category && isLive && (
            <div className="flex items-center gap-1 text-blue-600">
              <Loader2 size={9} className="animate-spin" />
              <span className="font-mono">{run.current_category}</span>
            </div>
          )}
          {run.total_dispatched != null && (
            <p><span className="font-semibold text-brand-text">{run.total_dispatched}</span> ingest jobs dispatched</p>
          )}
          {run.error && <p className="text-red-600">{run.error}</p>}
        </div>
      )}
    </div>
  )
}

export default function Ingest({ caseId, onComplete }) {
  const [dragging, setDragging]         = useState(false)
  const [uploading, setUploading]       = useState(false)
  const [uploadPct, setUploadPct]       = useState(0)
  const [jobs, setJobs]                 = useState([])       // ordered list of job IDs
  const [jobStatuses, setJobStatuses]   = useState({})       // jobId → status string
  const [jobDataMap, setJobDataMap]     = useState({})       // jobId → full job object
  const [error, setError]               = useState('')
  const inputRef   = useRef()
  const folderRef  = useRef()
  const jobsRef    = useRef([])          // mirror of jobs — readable inside setInterval
  const statusesRef = useRef({})         // mirror of jobStatuses — readable inside setInterval
  const { startUpload, updateUpload, finishUpload } = useUpload()

  // ── Server-side harvest state ─────────────────────────────────────────────
  const [harvestPath, setHarvestPath]       = useState('')
  const [harvestLevel, setHarvestLevel]     = useState('complete')
  const [harvestRuns, setHarvestRuns]       = useState([])
  const [harvestLoading, setHarvestLoading] = useState(false)
  const [harvestErr, setHarvestErr]         = useState(null)

  async function handleStartHarvest() {
    const path = harvestPath.trim()
    if (!path) { setHarvestErr('Enter a mounted path.'); return }
    setHarvestErr(null)
    setHarvestLoading(true)
    try {
      const res = await api.harvest.startRun(caseId, {
        level:        harvestLevel,
        categories:   [],
        mounted_path: path,
      })
      setHarvestRuns(prev => [res.run_id, ...prev])
    } catch (e) {
      setHarvestErr(e.message)
    } finally {
      setHarvestLoading(false)
    }
  }

  // Keep refs in sync with state so the central poller can read current values
  useEffect(() => { jobsRef.current = jobs }, [jobs])
  useEffect(() => { statusesRef.current = jobStatuses }, [jobStatuses])

  // ── Central batch poller ──────────────────────────────────────────────────
  // One request per tick for ALL active jobs, replacing per-JobCard polling.
  // Fires every 3 s; only includes non-terminal jobs so the interval naturally
  // becomes a no-op once everything is done.
  useEffect(() => {
    async function doPoll() {
      const activeIds = jobsRef.current.filter(id => !TERMINAL.has(statusesRef.current[id]))
      if (!activeIds.length) return

      // Batch in groups of 100 to keep request payloads small
      for (let i = 0; i < activeIds.length; i += 100) {
        const slice = activeIds.slice(i, i + 100)
        try {
          const results = await api.ingest.batchJobs(slice)
          if (!results?.length) continue
          setJobDataMap(prev => {
            const next = { ...prev }
            results.forEach(j => { next[j.job_id] = j })
            return next
          })
          setJobStatuses(prev => {
            const next = { ...prev }
            results.forEach(j => { next[j.job_id] = j.status })
            return next
          })
        } catch { /* ignore network errors — will retry on next tick */ }
      }
    }

    doPoll()
    const id = setInterval(doPoll, 3000)
    return () => clearInterval(id)
  }, []) // mount once — reads jobs/statuses via refs

  useEffect(() => {
    api.ingest.listJobs(caseId)
      .then(r => {
        const all = r.jobs || []
        const statusMap = {}
        const dataMap   = {}
        all.forEach(j => {
          statusMap[j.job_id] = j.status
          dataMap[j.job_id]   = j
        })
        setJobStatuses(statusMap)
        setJobDataMap(dataMap)
        // Sort: FAILED first, then RUNNING/PENDING, then COMPLETED
        const order = { FAILED: 0, RUNNING: 1, PENDING: 2, UPLOADING: 3, COMPLETED: 4, SKIPPED: 5 }
        const sorted = [...all].sort((a, b) =>
          (order[a.status] ?? 99) - (order[b.status] ?? 99)
        )
        setJobs(sorted.map(j => j.job_id))
      })
      .catch(() => {})
  }, [caseId])

  // Re-activate polling for a retried job by clearing its terminal status
  const handleRetry = useCallback((jobId) => {
    setJobStatuses(prev => ({ ...prev, [jobId]: 'PENDING' }))
  }, [])

  async function handleFiles(files) {
    if (!files.length) return
    setError('')
    setUploading(true)
    setUploadPct(0)

    const CHUNK_SIZE = 50 * 1024 * 1024  // 50 MB per chunk
    const token = localStorage.getItem('fo_token') || ''
    const base = window.location.origin
    const allJobIds  = []
    const allJobData = []   // partial job objects from upload response

    const uploadId = `${caseId}-${Date.now()}`
    const label = files.length === 1 ? files[0].name : `${files.length} files`
    startUpload(uploadId, label)

    // Total bytes across all files for overall progress
    const totalBytes = Array.from(files).reduce((s, f) => s + f.size, 0)
    let sentBytes = 0

    try {
      for (const file of files) {
        const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE))
        // Per-file upload_id keeps concurrent uploads isolated
        const fileUploadId = crypto.randomUUID()
        let jobIds = []

        for (let i = 0; i < totalChunks; i++) {
          const start = i * CHUNK_SIZE
          const slice = file.slice(start, start + CHUNK_SIZE)

          const fd = new FormData()
          fd.append('upload_id', fileUploadId)
          fd.append('filename', file.name)
          fd.append('chunk_index', i)
          fd.append('total_chunks', totalChunks)
          fd.append('chunk', slice)

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
          const pct = Math.round((sentBytes / totalBytes) * 100)
          setUploadPct(pct)
          updateUpload(uploadId, pct)

          // Last chunk response contains job IDs + partial job data
          if (i === totalChunks - 1) {
            const r = await res.json()
            jobIds = (r.jobs || []).map(j => j.job_id)
            allJobData.push(...(r.jobs || []))
          }
        }

        allJobIds.push(...jobIds)
      }

      setJobs(prev => [...allJobIds, ...prev])
      setJobStatuses(prev => {
        const next = { ...prev }
        allJobIds.forEach(id => { next[id] = 'UPLOADING' })
        return next
      })
      setJobDataMap(prev => {
        const next = { ...prev }
        allJobData.forEach(j => { next[j.job_id] = j })
        return next
      })
      onComplete?.()
    } catch (err) {
      setError(`Upload failed: ${err.message}`)
    } finally {
      setUploading(false)
      setUploadPct(0)
      finishUpload(uploadId)
    }
  }

  function onDrop(e) {
    e.preventDefault()
    setDragging(false)
    handleFiles([...e.dataTransfer.files])
  }

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h2 className="text-sm font-semibold text-brand-text mb-1">Ingest Forensics Files</h2>
      <p className="text-xs text-gray-500 mb-1">
        Supported: {ACCEPTED_TYPES.join(' ')} and common named artefacts (NTUSER.DAT, $MFT, conn.log, eve.json…)
      </p>
      <p className="text-xs text-gray-400 mb-4">
        📦 <strong>.zip</strong> archives are extracted automatically — each file inside is processed as a separate job.
        Large files are streamed directly to storage. Failed jobs can be retried.
      </p>

      {/* Dropzone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !uploading && inputRef.current?.click()}
        className={`${dragging ? 'drop-zone-active' : 'drop-zone-inactive'} mb-3 ${uploading ? 'cursor-default' : ''}`}>
        <p className="text-2xl mb-2">📂</p>
        <p className="text-sm text-gray-500">
          {uploading
            ? `Transferring… ${uploadPct}%`
            : 'Drop forensics files here or click to browse'}
        </p>
        {uploading && (
          <div className="mt-2 w-full max-w-xs mx-auto">
            <div className="h-1.5 bg-gray-700 rounded overflow-hidden">
              <div
                className="h-full bg-sky-500 rounded transition-all duration-300"
                style={{ width: `${uploadPct}%` }}
              />
            </div>
            <p className="text-[10px] text-sky-400 mt-1">
              Sending to server — job cards appear when transfer completes
            </p>
          </div>
        )}
        {!uploading && <p className="text-xs text-gray-400 mt-1">Multiple files or folders supported</p>}
        <input
          ref={inputRef}
          type="file"
          multiple
          accept={ACCEPT_ATTR}
          className="hidden"
          onChange={e => handleFiles([...e.target.files])}
        />
      </div>

      {/* Folder upload button */}
      <div className="flex items-center gap-2 mb-4">
        <button
          onClick={() => folderRef.current?.click()}
          disabled={uploading}
          className="btn-outline text-xs"
        >
          📁 Upload Folder
        </button>
        <span className="text-[10px] text-gray-400">
          Select a directory — all files inside will be uploaded
        </span>
        <input
          ref={folderRef}
          type="file"
          // @ts-ignore — webkitdirectory is non-standard but widely supported
          webkitdirectory=""
          directory=""
          multiple
          className="hidden"
          onChange={e => handleFiles([...e.target.files])}
        />
      </div>

      {/* ── Server-side harvest ───────────────────────────────────────── */}
      <div className="mt-5 pt-5 border-t border-gray-100">
        <div className="flex items-center gap-2 mb-2">
          <FolderOpen size={13} className="text-amber-500" />
          <span className="text-xs font-semibold text-brand-text">Server-side Harvest</span>
          <span className="badge bg-amber-50 text-amber-700 border border-amber-200 text-[10px]">server</span>
        </div>
        <p className="text-[11px] text-gray-400 mb-3">
          Collect Windows artifacts from a drive already mounted on the TraceX server
          (e.g. via dislocker-fuse or ntfs-3g). Artifacts are ingested directly into this case.
        </p>

        <div className="flex flex-col gap-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={harvestPath}
              onChange={e => setHarvestPath(e.target.value)}
              placeholder="/mnt/evidence"
              className="input flex-1 font-mono text-xs"
            />
            <div className="flex gap-1">
              {[
                { id: 'small',      label: 'S', title: 'Small',      colour: 'border-green-400  text-green-700  bg-green-50'  },
                { id: 'complete',   label: 'C', title: 'Complete',   colour: 'border-blue-400   text-blue-700   bg-blue-50'   },
                { id: 'exhaustive', label: 'E', title: 'Exhaustive', colour: 'border-purple-400 text-purple-700 bg-purple-50' },
              ].map(({ id, label, title, colour }) => (
                <button
                  key={id}
                  type="button"
                  title={title}
                  onClick={() => setHarvestLevel(id)}
                  className={`w-7 h-8 text-xs font-semibold rounded-lg border transition-all ${
                    harvestLevel === id ? colour : 'border-gray-200 bg-white text-gray-400 hover:border-gray-300'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <button
              onClick={handleStartHarvest}
              disabled={harvestLoading}
              className="btn-primary gap-1 text-xs px-3"
            >
              {harvestLoading
                ? <Loader2 size={12} className="animate-spin" />
                : <Play size={12} />
              }
              Start
            </button>
          </div>

          <p className="text-[10px] text-gray-400 flex items-center gap-1">
            <Info size={10} />
            Level: <strong className="text-gray-500">S</strong>=Small (core artifacts),{' '}
            <strong className="text-gray-500">C</strong>=Complete,{' '}
            <strong className="text-gray-500">E</strong>=Exhaustive (all categories)
          </p>

          {harvestErr && (
            <p className="text-xs text-red-600 flex items-center gap-1">
              <AlertTriangle size={11} /> {harvestErr}
            </p>
          )}
        </div>

        {harvestRuns.length > 0 && (
          <div className="mt-3 space-y-1.5">
            {harvestRuns.map(runId => (
              <HarvestRunCard key={runId} runId={runId} />
            ))}
          </div>
        )}
      </div>

      {error && (
        <div className="card border-red-200 p-3 mb-4 text-xs text-red-600">{error}</div>
      )}

      {/* Jobs list */}
      {jobs.length > 0 && (() => {
        const failedCount   = Object.values(jobStatuses).filter(s => s === 'FAILED').length
        const skippedCount  = Object.values(jobStatuses).filter(s => s === 'SKIPPED').length
        const activeCount   = Object.values(jobStatuses).filter(s => s === 'RUNNING' || s === 'PENDING' || s === 'UPLOADING').length
        return (
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                Ingestion Jobs
              </h3>
              <span className="text-[10px] text-gray-400">{jobs.length} total</span>
              {failedCount > 0 && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-red-600 bg-red-50 border border-red-200 rounded-full px-2 py-0.5">
                  <AlertTriangle size={10} /> {failedCount} failed
                </span>
              )}
              {skippedCount > 0 && (
                <span className="text-[10px] text-gray-400 bg-gray-100 border border-gray-200 rounded-full px-2 py-0.5">
                  {skippedCount} skipped
                </span>
              )}
              {activeCount > 0 && (
                <span className="text-[10px] text-brand-accent animate-pulse">{activeCount} running</span>
              )}
            </div>
            <div className="space-y-2">
              {jobs.map(jid => (
                <JobCard key={jid} jobId={jid} jobData={jobDataMap[jid]} onRetry={handleRetry} />
              ))}
            </div>
          </div>
        )
      })()}
    </div>
  )
}
