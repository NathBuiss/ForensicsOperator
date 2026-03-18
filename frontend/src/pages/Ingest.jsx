import { useState, useEffect, useRef } from 'react'
import { api } from '../api/client'

const ACCEPTED_TYPES = ['.evtx', '.plaso', '.pf', '.lnk', '.dat', '.hive']
const ACCEPTED_NAMES = ['$MFT', 'NTUSER.DAT', 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY']

function JobCard({ jobId }) {
  const [job, setJob] = useState(null)
  const intervalRef = useRef(null)

  useEffect(() => {
    const poll = () => {
      api.ingest.getJob(jobId).then(setJob).catch(() => {})
    }
    poll()
    intervalRef.current = setInterval(poll, 3000)
    return () => clearInterval(intervalRef.current)
  }, [jobId])

  useEffect(() => {
    if (job?.status === 'COMPLETED' || job?.status === 'FAILED') {
      clearInterval(intervalRef.current)
    }
  }, [job?.status])

  if (!job) return <div className="text-gray-600 text-xs p-2">Loading job {jobId}...</div>

  const statusColors = {
    PENDING: 'text-yellow-400',
    RUNNING: 'text-blue-400',
    COMPLETED: 'text-green-400',
    FAILED: 'text-red-400',
  }

  return (
    <div className={`card p-3 ${job.status === 'FAILED' ? 'border-red-800/50' : ''}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-300 font-medium truncate">{job.original_filename}</span>
        <span className={`text-xs font-mono ${statusColors[job.status] || 'text-gray-400'}`}>
          {job.status}
          {job.status === 'RUNNING' && <span className="ml-1 animate-pulse">●</span>}
        </span>
      </div>

      {job.plugin_used && (
        <p className="text-xs text-gray-500">Plugin: <code>{job.plugin_used}</code></p>
      )}

      {job.status === 'RUNNING' && (
        <div className="mt-1">
          <div className="h-1 bg-gray-700 rounded overflow-hidden">
            <div className="h-full bg-indigo-500 animate-pulse w-1/3 rounded" />
          </div>
          <p className="text-xs text-gray-600 mt-0.5">
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
        <p className="text-xs text-red-400 mt-0.5 break-all">{job.error}</p>
      )}
    </div>
  )
}

export default function Ingest({ caseId, onComplete }) {
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [jobs, setJobs] = useState([])
  const [error, setError] = useState('')
  const inputRef = useRef()

  useEffect(() => {
    api.ingest.listJobs(caseId)
      .then(r => setJobs((r.jobs || []).map(j => j.job_id)))
      .catch(() => {})
  }, [caseId])

  async function handleFiles(files) {
    if (!files.length) return
    setError('')
    setUploading(true)

    const formData = new FormData()
    for (const f of files) formData.append('files', f)

    try {
      const r = await api.ingest.upload(caseId, formData)
      const newJobIds = (r.jobs || []).map(j => j.job_id)
      setJobs(prev => [...newJobIds, ...prev])
      onComplete?.()
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
    }
  }

  function onDrop(e) {
    e.preventDefault()
    setDragging(false)
    handleFiles([...e.dataTransfer.files])
  }

  return (
    <div className="p-6 max-w-2xl">
      <h2 className="text-sm font-semibold text-gray-200 mb-1">Ingest Forensics Files</h2>
      <p className="text-xs text-gray-500 mb-4">
        Supported: {ACCEPTED_TYPES.join(', ')}, {ACCEPTED_NAMES.join(', ')}
      </p>

      {/* Dropzone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-colors mb-4 ${
          dragging ? 'border-indigo-500 bg-indigo-950/20' : 'border-gray-600 hover:border-gray-500'
        } ${uploading ? 'opacity-50 pointer-events-none' : ''}`}>
        <p className="text-2xl mb-2">📂</p>
        <p className="text-sm text-gray-400">
          {uploading ? 'Uploading...' : 'Drop forensics files here or click to browse'}
        </p>
        <p className="text-xs text-gray-600 mt-1">Multiple files supported</p>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          onChange={e => handleFiles([...e.target.files])}
        />
      </div>

      {error && (
        <div className="card border-red-800/50 p-3 mb-4 text-xs text-red-400">{error}</div>
      )}

      {/* Jobs list */}
      {jobs.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">
            Processing Jobs
          </h3>
          <div className="space-y-2">
            {jobs.map(jid => <JobCard key={jid} jobId={jid} />)}
          </div>
        </div>
      )}
    </div>
  )
}
