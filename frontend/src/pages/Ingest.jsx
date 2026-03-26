import { useState, useEffect, useRef, useCallback } from 'react'
import { RefreshCw, Upload, AlertTriangle } from 'lucide-react'
import { api } from '../api/client'

const ACCEPTED_TYPES = ['.evtx', '.plaso', '.pf', '.lnk', '.dat', '.hive', '.jsonl', '.csv', '.zip',
                         '.pcap', '.pcapng', '.cap', '.sqlite', '.db', '.sqlite3', '.sqlitedb',
                         '.plist', '.xml', '.log', '.ab', '.txt']
const ACCEPTED_NAMES = ['$MFT', 'NTUSER.DAT', 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY',
                        'HISTORY', 'COOKIES', 'LOGIN DATA', 'BOOKMARKS', 'WEB DATA',
                        'PLACES.SQLITE', 'COOKIES.SQLITE']
const ACCEPT_ATTR   = [...ACCEPTED_TYPES, ...ACCEPTED_NAMES.map(n => `.${n.replace('$', '')}`)].join(',')

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

function JobCard({ jobId, onStatusChange }) {
  const [job, setJob] = useState(null)
  const [retrying, setRetrying] = useState(false)
  const intervalRef = useRef(null)
  const elapsed = useElapsed(job?.created_at)

  function startPolling() {
    const poll = () => {
      api.ingest.getJob(jobId).then(j => {
        setJob(j)
        onStatusChange?.(jobId, j?.status)
      }).catch(() => {})
    }
    poll()
    intervalRef.current = setInterval(poll, 3000)
  }

  useEffect(() => {
    startPolling()
    return () => clearInterval(intervalRef.current)
  }, [jobId]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (job?.status === 'COMPLETED' || job?.status === 'FAILED') {
      clearInterval(intervalRef.current)
    }
  }, [job?.status])

  async function retryJob() {
    setRetrying(true)
    try {
      await api.ingest.retryJob(jobId)
      // Restart polling after retry
      clearInterval(intervalRef.current)
      startPolling()
    } catch (err) {
      alert('Retry failed: ' + err.message)
    } finally {
      setRetrying(false)
    }
  }

  if (!job) return <div className="text-gray-400 text-xs p-2">Loading job {jobId}...</div>

  const statusColors = {
    UPLOADING: 'text-sky-500',
    PENDING:   'text-amber-600',
    RUNNING:   'text-brand-accent',
    COMPLETED: 'text-green-600',
    FAILED:    'text-red-600',
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
          {job.status === 'FAILED' && (
            <button
              onClick={retryJob}
              disabled={retrying}
              className="btn-ghost text-xs px-1.5 py-0.5 text-brand-accent hover:text-brand-accenthover"
              title="Retry this job"
            >
              <RefreshCw size={12} className={retrying ? 'animate-spin' : ''} />
              {retrying ? '' : 'Retry'}
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
          Waiting {Math.floor(elapsed / 60000)} min — processor may be busy or unavailable
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
    </div>
  )
}

export default function Ingest({ caseId, onComplete }) {
  const [dragging, setDragging]         = useState(false)
  const [uploading, setUploading]       = useState(false)
  const [uploadPct, setUploadPct]       = useState(0)
  const [jobs, setJobs]                 = useState([])       // ordered list of job IDs
  const [jobStatuses, setJobStatuses]   = useState({})       // jobId → status
  const [error, setError]               = useState('')
  const inputRef  = useRef()
  const folderRef = useRef()

  useEffect(() => {
    api.ingest.listJobs(caseId)
      .then(r => {
        const all = r.jobs || []
        // Seed known statuses from the initial fetch so we can sort immediately
        const statusMap = {}
        all.forEach(j => { statusMap[j.job_id] = j.status })
        setJobStatuses(statusMap)
        // Sort: FAILED first, then RUNNING/PENDING, then COMPLETED
        const order = { FAILED: 0, RUNNING: 1, PENDING: 2, UPLOADING: 3, COMPLETED: 4 }
        const sorted = [...all].sort((a, b) =>
          (order[a.status] ?? 99) - (order[b.status] ?? 99)
        )
        setJobs(sorted.map(j => j.job_id))
      })
      .catch(() => {})
  }, [caseId])

  const handleStatusChange = useCallback((jobId, status) => {
    setJobStatuses(prev => {
      if (prev[jobId] === status) return prev
      return { ...prev, [jobId]: status }
    })
  }, [])

  function handleFiles(files) {
    if (!files.length) return
    setError('')
    setUploading(true)
    setUploadPct(0)

    const formData = new FormData()
    for (const f of files) formData.append('files', f)

    // Use XHR so we get upload progress events (fetch doesn't expose them)
    const token = localStorage.getItem('fo_token') || ''
    const xhr = new XMLHttpRequest()

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) setUploadPct(Math.round((e.loaded / e.total) * 100))
    }

    xhr.onload = () => {
      setUploading(false)
      setUploadPct(0)
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const r = JSON.parse(xhr.responseText)
          const newJobIds = (r.jobs || []).map(j => j.job_id)
          // New jobs start as PENDING — prepend them before existing jobs
          setJobs(prev => [...newJobIds, ...prev])
          setJobStatuses(prev => {
            const next = { ...prev }
            newJobIds.forEach(id => { next[id] = 'PENDING' })
            return next
          })
          onComplete?.()
        } catch {
          setError('Unexpected response from server')
        }
      } else {
        try {
          const r = JSON.parse(xhr.responseText)
          setError(r.detail || `Upload failed (HTTP ${xhr.status})`)
        } catch {
          setError(`Upload failed (HTTP ${xhr.status})`)
        }
      }
    }

    xhr.onerror = () => { setUploading(false); setUploadPct(0); setError('Network error during upload') }
    xhr.ontimeout = () => { setUploading(false); setUploadPct(0); setError('Upload timed out') }

    const base = window.location.origin
    xhr.open('POST', `${base}/api/v1/cases/${caseId}/ingest`)
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`)
    xhr.send(formData)
  }

  function onDrop(e) {
    e.preventDefault()
    setDragging(false)
    handleFiles([...e.dataTransfer.files])
  }

  return (
    <div className="p-6 max-w-2xl">
      <h2 className="text-sm font-semibold text-brand-text mb-1">Ingest Forensics Files</h2>
      <p className="text-xs text-gray-500 mb-1">
        Supported: {ACCEPTED_TYPES.join(', ')}, {ACCEPTED_NAMES.join(', ')}
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

      {error && (
        <div className="card border-red-200 p-3 mb-4 text-xs text-red-600">{error}</div>
      )}

      {/* Jobs list */}
      {jobs.length > 0 && (() => {
        const failedCount  = Object.values(jobStatuses).filter(s => s === 'FAILED').length
        const activeCount  = Object.values(jobStatuses).filter(s => s === 'RUNNING' || s === 'PENDING' || s === 'UPLOADING').length
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
              {activeCount > 0 && (
                <span className="text-[10px] text-brand-accent animate-pulse">{activeCount} running</span>
              )}
            </div>
            <div className="space-y-2">
              {jobs.map(jid => (
                <JobCard key={jid} jobId={jid} onStatusChange={handleStatusChange} />
              ))}
            </div>
          </div>
        )
      })()}
    </div>
  )
}
