import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Upload, Search, Bell, X, ChevronRight, AlertTriangle,
  CheckCircle, Clock, Database, Loader2, Shield,
} from 'lucide-react'
import { api } from '../api/client'
import Timeline from './Timeline'
import Ingest from './Ingest'

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

// ── Severity colours for alert results ───────────────────────────────────────
const LEVEL_BADGE = {
  critical:      'badge-critical',
  high:          'badge-high',
  medium:        'badge-medium',
  low:           'badge-low',
  informational: 'badge-informational',
}

// ─────────────────────────────────────────────────────────────────────────────
// Ingest Modal
// ─────────────────────────────────────────────────────────────────────────────
function IngestModal({ caseId, onClose, onComplete }) {
  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[520px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Upload size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Add Evidence</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>
        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          <Ingest caseId={caseId} onComplete={onComplete} />
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert Results Panel
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
        {/* Header */}
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

        {/* Body */}
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
// CaseTimeline — main page
// ─────────────────────────────────────────────────────────────────────────────
export default function CaseTimeline() {
  const { caseId } = useParams()
  const navigate = useNavigate()

  const [caseData, setCaseData]       = useState(null)
  const [loading, setLoading]         = useState(true)
  const [showIngest, setShowIngest]   = useState(false)
  const [alertResults, setAlertResults] = useState(null)
  const [runningAlerts, setRunningAlerts] = useState(false)

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

            {/* Event count */}
            {caseData?.event_count != null && (
              <span className="flex items-center gap-1 badge bg-gray-100 text-gray-600">
                <Database size={10} />
                {(caseData.event_count || 0).toLocaleString()} events
              </span>
            )}

            {/* Artifact type badges */}
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
        </div>
      </div>

      {/* ── Timeline (fills remaining space) ─────────────────────────────── */}
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
    </div>
  )
}
