import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Upload, Search, Bell, X, ChevronRight, AlertTriangle,
  CheckCircle, Clock, Database, Loader2, Shield,
  Cpu, RotateCcw, Plus, Download,
} from 'lucide-react'
import { api } from '../api/client'
import Timeline from './Timeline'
import Ingest from './Ingest'
import CollectorModal from '../components/CollectorModal'

// ── Artifact badge colours ────────────────────────────────────────────────────
const ARTIFACT_BADGE = {
  evtx:      'badge-evtx',
  prefetch:  'badge-prefetch',
  mft:       'badge-mft',
  registry:  'badge-registry',
  lnk:       'badge-lnk',
  plaso:     'badge-plaso',
  hayabusa:  'badge-hayabusa',
}

// ── Severity colours ──────────────────────────────────────────────────────────
const LEVEL_BADGE = {
  critical:      'badge-critical',
  high:          'badge-high',
  medium:        'badge-medium',
  low:           'badge-low',
  informational: 'badge-informational',
  info:          'badge-informational',
}

const MODULE_NAMES = {
  wintriage:   'Windows Triage',
  hayabusa:    'Hayabusa',
  hindsight:   'Hindsight',
  strings:     'Strings',
  regripper:   'RegRipper',
  chainsaw:    'Chainsaw',
  evtxecmd:    'EvtxECmd',
  volatility3: 'Volatility 3',
}

// ─────────────────────────────────────────────────────────────────────────────
// IngestModal
// ─────────────────────────────────────────────────────────────────────────────
function IngestModal({ caseId, onClose, onComplete }) {
  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[520px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Upload size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Add Evidence</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <Ingest caseId={caseId} onComplete={onComplete} />
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertResultsPanel
// ─────────────────────────────────────────────────────────────────────────────
function AlertResultsPanel({ results, onClose }) {
  const { matches = [], rules_checked = 0 } = results

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[580px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div>
            <div className="flex items-center gap-2">
              <Shield size={16} className="text-brand-accent" />
              <span className="font-semibold text-brand-text">Alert Results</span>
            </div>
            <p className="text-xs text-gray-500 mt-0.5">
              {rules_checked} rule{rules_checked !== 1 ? 's' : ''} checked ·{' '}
              <span className={matches.length > 0 ? 'text-red-600 font-medium' : 'text-green-600'}>
                {matches.length} match{matches.length !== 1 ? 'es' : ''}
              </span>
            </p>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {matches.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <CheckCircle size={40} className="text-green-400 mb-3" />
              <p className="font-medium text-brand-text">No alerts triggered</p>
              <p className="text-sm text-gray-500 mt-1">All rules checked — no matches found</p>
            </div>
          ) : matches.map((m, i) => (
            <AlertMatchCard key={i} match={m} />
          ))}
        </div>
      </div>
    </div>
  )
}

function AlertMatchCard({ match }) {
  const [open, setOpen] = useState(false)
  const rule = match.rule || {}
  const levelClass = LEVEL_BADGE[rule.level?.toLowerCase?.()] || 'badge-generic'

  return (
    <div className="card overflow-hidden">
      <button
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <AlertTriangle size={16} className="text-red-500 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-brand-text text-sm">{rule.name}</span>
            <span className="badge-pill bg-red-100 text-red-700">
              {match.match_count.toLocaleString()} hits
            </span>
            {rule.artifact_type && (
              <span className={`badge ${ARTIFACT_BADGE[rule.artifact_type] || 'badge-generic'}`}>
                {rule.artifact_type}
              </span>
            )}
          </div>
          {rule.description && (
            <p className="text-xs text-gray-500 mt-0.5 truncate">{rule.description}</p>
          )}
          <code className="text-xs text-gray-600 mt-1 block font-mono">{rule.query}</code>
        </div>
        <ChevronRight size={14} className={`text-gray-400 flex-shrink-0 mt-0.5 transition-transform ${open ? 'rotate-90' : ''}`} />
      </button>

      {open && match.sample_events?.length > 0 && (
        <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-2">
          <p className="section-title mb-2">Sample events</p>
          {match.sample_events.map((ev, j) => (
            <div key={j} className="bg-white rounded-lg border border-gray-200 p-2.5">
              <div className="flex items-center gap-2 text-xs text-gray-500 mb-1 font-mono">
                <Clock size={10} />
                {ev.timestamp || '—'}
              </div>
              <p className="text-xs text-brand-text">{ev.message || '—'}</p>
              {ev.host?.hostname && (
                <p className="text-xs text-gray-500 mt-0.5">Host: {ev.host.hostname}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleLaunchModal
// ─────────────────────────────────────────────────────────────────────────────
function ModuleLaunchModal({ caseId, onClose, onRunCreated }) {
  const [modules, setModules]               = useState([])
  const [sources, setSources]               = useState([])
  const [selectedModule, setSelectedModule] = useState(null)
  const [selectedJobs, setSelectedJobs]     = useState(new Set())
  const [sourceSearch, setSourceSearch]     = useState('')
  const [loading, setLoading]               = useState(true)
  const [running, setRunning]               = useState(false)
  const [error, setError]                   = useState(null)

  useEffect(() => {
    Promise.all([api.modules.list(), api.modules.listSources(caseId)])
      .then(([modResp, srcResp]) => {
        setModules(modResp.modules || [])
        setSources(srcResp.sources || [])
        setLoading(false)
      })
      .catch(err => { setError(err.message); setLoading(false) })
  }, [caseId])

  // Filter sources by extension OR exact basename (case-insensitive).
  // Empty both lists → module accepts all files (e.g. "strings").
  const compatibleSources = selectedModule
    ? sources.filter(s => {
        const fnameLower = (s.original_filename || '').toLowerCase()
        const extList  = selectedModule.input_extensions || []
        const nameList = selectedModule.input_filenames  || []
        if (extList.length === 0 && nameList.length === 0) return true
        const extMatch  = extList.some(ext => fnameLower.endsWith(ext.toLowerCase()))
        const basename  = fnameLower.split('/').pop().split('\\').pop()
        const nameMatch = nameList.some(fn => basename === fn.toLowerCase())
        return extMatch || nameMatch
      })
    : []

  const visibleSources = sourceSearch.trim()
    ? compatibleSources.filter(s =>
        (s.original_filename || '').toLowerCase().includes(sourceSearch.toLowerCase())
      )
    : compatibleSources

  function toggleJob(jobId) {
    setSelectedJobs(prev => {
      const next = new Set(prev)
      next.has(jobId) ? next.delete(jobId) : next.add(jobId)
      return next
    })
  }

  async function handleRun() {
    if (!selectedModule || selectedJobs.size === 0) return
    setRunning(true)
    setError(null)
    try {
      const run = await api.modules.createRun(caseId, {
        module_id: selectedModule.id,
        job_ids: [...selectedJobs],
      })
      onRunCreated(run)
    } catch (err) {
      setError(err.message)
      setRunning(false)
    }
  }

  const canRun = selectedModule && selectedJobs.size > 0 && !running

  // Sources to display in the right column:
  // if a module is selected → filtered; otherwise → all case sources
  const displaySources = selectedModule ? compatibleSources : sources

  const visibleDisplaySources = sourceSearch.trim()
    ? displaySources.filter(s =>
        (s.original_filename || '').toLowerCase().includes(sourceSearch.toLowerCase())
      )
    : displaySources

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[720px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Cpu size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Launch Module</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>

        {/* Body — two columns */}
        {loading ? (
          <div className="flex-1 flex items-center justify-center text-gray-400">
            <Loader2 size={20} className="animate-spin mr-2" />
            Loading…
          </div>
        ) : (
          <div className="flex-1 flex overflow-hidden">

            {/* Left: module list */}
            <div className="w-[300px] flex-shrink-0 border-r border-gray-100 flex flex-col">
              <div className="px-4 pt-4 pb-2">
                <p className="section-title">Select Module</p>
              </div>
              <div className="flex-1 overflow-y-auto px-4 pb-4 space-y-2">
                {modules.filter(m => m.available).map(mod => (
                  <button
                    key={mod.id}
                    onClick={() => { setSelectedModule(mod); setSelectedJobs(new Set()) }}
                    className={`w-full text-left p-3 rounded-lg border transition-all ${
                      selectedModule?.id === mod.id
                        ? 'border-brand-accent bg-brand-accentlight ring-1 ring-brand-accent/30'
                        : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    <p className="font-medium text-sm text-brand-text">{mod.name}</p>
                    <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{mod.description}</p>
                    {(mod.input_extensions?.length > 0 || mod.input_filenames?.length > 0) && (
                      <p className="text-[10px] text-gray-400 mt-1 font-mono">
                        {[...(mod.input_extensions || []), ...(mod.input_filenames || [])].join('  ')}
                      </p>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Right: source files */}
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="px-4 pt-4 pb-2 flex items-center justify-between">
                <p className="section-title">
                  Source Files
                  {displaySources.length > 0 && (
                    <span className="ml-1.5 font-normal text-gray-400">
                      ({selectedJobs.size}/{displaySources.length})
                    </span>
                  )}
                </p>
                {displaySources.length > 0 && (
                  <button
                    onClick={() => setSelectedJobs(new Set(displaySources.map(s => s.job_id)))}
                    className="text-xs text-brand-accent hover:underline"
                  >
                    Select all
                  </button>
                )}
              </div>

              {!selectedModule && sources.length === 0 && (
                <p className="px-4 text-xs text-gray-400 italic">
                  No ingested files in this case yet.
                </p>
              )}
              {!selectedModule && sources.length > 0 && (
                <p className="px-4 pb-2 text-[11px] text-gray-400 italic">
                  Select a module to filter compatible files.
                </p>
              )}
              {selectedModule && compatibleSources.length === 0 && (
                <p className="px-4 text-xs text-gray-400 italic">
                  No compatible files for <strong>{selectedModule.name}</strong>.
                  {(selectedModule.input_extensions?.length > 0 || selectedModule.input_filenames?.length > 0) && (
                    <> Ingest {[
                      ...(selectedModule.input_extensions || []),
                      ...(selectedModule.input_filenames  || []),
                    ].join(', ')} files first.</>
                  )}
                </p>
              )}

              {displaySources.length > 5 && (
                <div className="px-4 pb-2">
                  <input
                    type="text"
                    value={sourceSearch}
                    onChange={e => setSourceSearch(e.target.value)}
                    placeholder="Filter files…"
                    className="w-full px-3 py-1.5 text-xs border border-gray-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-accent/40 focus:border-brand-accent"
                  />
                </div>
              )}

              <div className="flex-1 overflow-y-auto px-4 pb-4 space-y-1">
                {visibleDisplaySources.map(src => (
                  <label
                    key={src.job_id}
                    className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-gray-50 cursor-pointer border border-transparent hover:border-gray-200 transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={selectedJobs.has(src.job_id)}
                      onChange={() => toggleJob(src.job_id)}
                      className="rounded border-gray-300 flex-shrink-0"
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-brand-text truncate font-medium">
                        {src.original_filename}
                      </p>
                      <p className="text-[10px] text-gray-400 mt-0.5">
                        {(src.events_indexed || 0).toLocaleString()} events
                        {src.plugin_used ? ` · ${src.plugin_used}` : ''}
                      </p>
                    </div>
                  </label>
                ))}
                {visibleDisplaySources.length === 0 && sourceSearch && (
                  <p className="text-xs text-gray-400 italic py-4 text-center">
                    No files match "{sourceSearch}"
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="border-t border-gray-200 px-5 py-4 flex items-center gap-3">
          {error && (
            <p className="flex-1 text-xs text-red-600 bg-red-50 border border-red-100 rounded-lg px-3 py-2 truncate" title={error}>
              {error}
            </p>
          )}
          <button
            onClick={handleRun}
            disabled={!canRun}
            className="btn-primary ml-auto justify-center"
          >
            {running
              ? <Loader2 size={14} className="animate-spin" />
              : <Cpu size={14} />
            }
            {running ? 'Launching…' : 'Run Module'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleRunCard
// ─────────────────────────────────────────────────────────────────────────────
function ModuleRunCard({ run }) {
  const [open, setOpen] = useState(false)

  const moduleName = MODULE_NAMES[run.module_id] || run.module_id

  const STATUS_STYLE = {
    PENDING:   'bg-gray-100 text-gray-600',
    RUNNING:   'bg-amber-100 text-amber-700',
    COMPLETED: 'bg-green-100 text-green-700',
    FAILED:    'bg-red-100 text-red-700',
  }
  const statusStyle = STATUS_STYLE[run.status] || STATUS_STYLE.PENDING

  const ts = run.completed_at || run.started_at
  const tsDisplay = ts
    ? new Date(ts).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
    : null

  const preview  = run.results_preview || []
  const byLevel  = run.hits_by_level   || {}

  return (
    <div className="card overflow-hidden">
      <button
        className="w-full flex items-start gap-3 p-3 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-sm text-brand-text">{moduleName}</span>
            <span className={`badge ${statusStyle} inline-flex items-center gap-1`}>
              {run.status === 'RUNNING' && <Loader2 size={9} className="animate-spin" />}
              {run.status}
            </span>
            {run.status === 'COMPLETED' && run.total_hits > 0 && (
              <span className="badge bg-gray-100 text-gray-600">
                {run.total_hits.toLocaleString()} hits
              </span>
            )}
            {run.status === 'COMPLETED' && run.total_hits === 0 && (
              <span className="badge bg-green-50 text-green-600">No detections</span>
            )}
          </div>
          {tsDisplay && (
            <p className="text-[10px] text-gray-400 mt-0.5 font-mono">{tsDisplay}</p>
          )}
          {run.status === 'FAILED' && run.error && (
            <p className="text-xs text-red-600 mt-0.5 truncate" title={run.error}>
              {run.error}
            </p>
          )}
        </div>
        <ChevronRight
          size={14}
          className={`text-gray-400 flex-shrink-0 mt-0.5 transition-transform ${open ? 'rotate-90' : ''}`}
        />
      </button>

      {open && run.status === 'COMPLETED' && (
        <div className="border-t border-gray-100 bg-gray-50 p-3 space-y-2">
          {/* Level summary */}
          {Object.keys(byLevel).length > 0 && (
            <div className="flex flex-wrap gap-1 mb-2">
              {['critical', 'high', 'medium', 'low', 'informational'].map(lvl => {
                const count = byLevel[lvl]
                if (!count) return null
                return (
                  <span key={lvl} className={`badge ${LEVEL_BADGE[lvl] || 'badge-generic'}`}>
                    {lvl}: {count}
                  </span>
                )
              })}
            </div>
          )}

          {preview.length === 0 ? (
            <p className="text-xs text-gray-400 text-center py-4 italic">No detections</p>
          ) : (
            <>
              {preview.slice(0, 50).map((hit, i) => (
                <div key={i} className="bg-white rounded border border-gray-200 p-2 text-xs">
                  <div className="flex items-center gap-2 flex-wrap mb-0.5">
                    <span className={`badge ${LEVEL_BADGE[hit.level] || 'badge-generic'}`}>
                      {hit.level}
                    </span>
                    <span className="font-medium text-brand-text">{hit.rule_title}</span>
                  </div>
                  <div className="flex gap-3 text-[10px] text-gray-400 font-mono flex-wrap">
                    {hit.computer  && <span>{hit.computer}</span>}
                    {hit.timestamp && <span>{hit.timestamp}</span>}
                  </div>
                  {hit.details_raw && (
                    <p className="text-[10px] text-gray-500 mt-1 break-all line-clamp-2"
                       title={hit.details_raw}>
                      {hit.details_raw}
                    </p>
                  )}
                </div>
              ))}
              {preview.length > 50 && (
                <p className="text-[10px] text-gray-400 text-center pt-1">
                  Showing first 50 of {run.total_hits.toLocaleString()} hits
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleRunsPanel
// ─────────────────────────────────────────────────────────────────────────────
function ModuleRunsPanel({ caseId, onClose }) {
  const [runs, setRuns]     = useState([])
  const [loading, setLoading] = useState(true)

  const fetchRuns = useCallback(() => {
    api.modules.listRuns(caseId)
      .then(r => { setRuns(r.runs || []); setLoading(false) })
      .catch(() => setLoading(false))
  }, [caseId])

  useEffect(() => { fetchRuns() }, [fetchRuns])

  // Auto-poll every 3 s while any run is active
  useEffect(() => {
    const hasActive = runs.some(r => r.status === 'PENDING' || r.status === 'RUNNING')
    if (!hasActive) return
    const id = setInterval(fetchRuns, 3000)
    return () => clearInterval(id)
  }, [runs, fetchRuns])

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[560px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Cpu size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Module Runs</span>
            {runs.length > 0 && (
              <span className="badge bg-gray-100 text-gray-600">{runs.length}</span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <button
              onClick={fetchRuns}
              className="btn-ghost p-1.5 rounded-lg"
              title="Refresh"
            >
              <RotateCcw size={14} />
            </button>
            <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {loading ? (
            <div className="flex items-center justify-center py-16 text-gray-400">
              <Loader2 size={20} className="animate-spin mr-2" />
              Loading runs…
            </div>
          ) : runs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Cpu size={40} className="text-gray-300 mb-3" />
              <p className="font-medium text-gray-500">No module runs yet</p>
              <p className="text-sm text-gray-400 mt-1">
                Launch a module to analyse ingested files
              </p>
            </div>
          ) : (
            runs.map(run => <ModuleRunCard key={run.run_id} run={run} />)
          )}
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// CaseTimeline — main page
// ─────────────────────────────────────────────────────────────────────────────
export default function CaseTimeline() {
  const { caseId } = useParams()
  const navigate = useNavigate()

  const [caseData, setCaseData]             = useState(null)
  const [loading, setLoading]               = useState(true)
  const [showIngest, setShowIngest]         = useState(false)
  const [alertResults, setAlertResults]     = useState(null)
  const [runningAlerts, setRunningAlerts]   = useState(false)
  const [showModules, setShowModules]       = useState(false)
  const [showModuleRuns, setShowModuleRuns] = useState(false)
  const [showCollector, setShowCollector]   = useState(false)

  const loadCase = useCallback(() => {
    api.cases.get(caseId)
      .then(setCaseData)
      .catch(() => navigate('/'))
      .finally(() => setLoading(false))
  }, [caseId, navigate])

  useEffect(() => { loadCase() }, [loadCase])

  async function runAlerts() {
    setRunningAlerts(true)
    setAlertResults(null)
    try {
      const r = await api.alertRules.runLibrary(caseId)
      setAlertResults(r)
    } catch (err) {
      console.error('Alert run failed:', err)
    } finally {
      setRunningAlerts(false)
    }
  }

  function handleRunCreated() {
    setShowModules(false)
    setShowModuleRuns(true)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400">
        <Loader2 size={20} className="animate-spin mr-2" />
        Loading case…
      </div>
    )
  }

  const artifactTypes = caseData?.artifact_types || []

  return (
    <div className="flex flex-col h-full">

      {/* ── Case header ──────────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-200 px-6 py-3 flex items-center gap-4 flex-shrink-0">

        {/* Case name + meta */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-base font-semibold text-brand-text truncate">
              {caseData?.name || 'Case'}
            </h1>

            {caseData?.event_count != null && (
              <span className="flex items-center gap-1 badge bg-gray-100 text-gray-600">
                <Database size={10} />
                {(caseData.event_count || 0).toLocaleString()} events
              </span>
            )}

            {artifactTypes.map(t => (
              <span key={t} className={ARTIFACT_BADGE[t] || 'badge-generic'}>
                {t}
              </span>
            ))}
          </div>

          {caseData?.description && (
            <p className="text-xs text-gray-500 mt-0.5 truncate">{caseData.description}</p>
          )}
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={() => setShowIngest(true)}
            className="btn-primary"
          >
            <Upload size={14} />
            Ingest
          </button>

          <button
            onClick={() => navigate(`/cases/${caseId}/search`)}
            className="btn-outline"
          >
            <Search size={14} />
            Search
          </button>

          <button
            onClick={runAlerts}
            disabled={runningAlerts}
            className="btn-outline"
          >
            {runningAlerts
              ? <Loader2 size={14} className="animate-spin" />
              : <Bell size={14} />
            }
            {runningAlerts ? 'Running…' : 'Run Alerts'}
          </button>

          <button
            onClick={() => { setShowModules(true); setShowModuleRuns(false) }}
            className="btn-outline"
          >
            <Cpu size={14} />
            Modules
          </button>

          <button
            onClick={() => setShowCollector(true)}
            className="btn-outline"
            title="Download artifact collector pre-configured for this case"
          >
            <Download size={14} />
            Collector
          </button>

          {/* View runs shortcut — only when runs panel is closed */}
          {!showModuleRuns && (
            <button
              onClick={() => { setShowModuleRuns(true); setShowModules(false) }}
              className="btn-ghost p-1.5 rounded-lg text-gray-400 hover:text-brand-accent"
              title="View module runs"
            >
              <RotateCcw size={14} />
            </button>
          )}
        </div>
      </div>

      {/* ── Timeline ─────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-hidden">
        <Timeline caseId={caseId} artifactTypes={artifactTypes} />
      </div>

      {/* ── Modals / Panels ───────────────────────────────────────────────── */}
      {showIngest && (
        <IngestModal
          caseId={caseId}
          onClose={() => setShowIngest(false)}
          onComplete={() => { setShowIngest(false); loadCase() }}
        />
      )}

      {alertResults && (
        <AlertResultsPanel
          results={alertResults}
          onClose={() => setAlertResults(null)}
        />
      )}

      {showModules && (
        <ModuleLaunchModal
          caseId={caseId}
          onClose={() => setShowModules(false)}
          onRunCreated={handleRunCreated}
        />
      )}

      {showModuleRuns && (
        <ModuleRunsPanel
          caseId={caseId}
          onClose={() => setShowModuleRuns(false)}
        />
      )}

      {showCollector && (
        <CollectorModal
          caseId={caseId}
          apiUrl={`${window.location.origin}/api/v1`}
          onClose={() => setShowCollector(false)}
        />
      )}
    </div>
  )
}
