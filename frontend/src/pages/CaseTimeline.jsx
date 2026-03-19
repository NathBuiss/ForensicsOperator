import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Upload, Search, Bell, X, ChevronRight, AlertTriangle,
  CheckCircle, Clock, Database, Loader2, Shield,
  Cpu, History, Plus, Download, Play, Terminal,
  AlertCircle, ChevronDown, FileCode, ExternalLink,
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
  yara:        'YARA Scanner',
  exiftool:    'ExifTool',
  bulk_extractor: 'Bulk Extractor',
  capa:        'CAPA',
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
function AlertResultsPanel({ results, caseId, onClose }) {
  const { matches = [], rules_checked = 0 } = results
  const navigate = useNavigate()

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
            <AlertMatchCard key={i} match={m} caseId={caseId} navigate={navigate} />
          ))}
        </div>
      </div>
    </div>
  )
}

function AlertMatchCard({ match, caseId, navigate }) {
  const [open, setOpen] = useState(false)
  const rule = match.rule || {}

  function goToSearch(q) {
    navigate(`/cases/${caseId}/search`, { state: { pivotQuery: q } })
  }

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

      {open && (
        <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-2">
          {/* View all hits link */}
          <button
            onClick={() => goToSearch(rule.query)}
            className="w-full flex items-center justify-between bg-brand-accent/10 hover:bg-brand-accent/20 border border-brand-accent/30 rounded-lg px-3 py-2 transition-colors"
          >
            <span className="text-xs font-medium text-brand-accent">
              View all {match.match_count.toLocaleString()} matching events in Search
            </span>
            <ExternalLink size={12} className="text-brand-accent flex-shrink-0" />
          </button>

          {/* Sample events */}
          {match.sample_events?.length > 0 && (
            <>
              <p className="section-title mt-1">Sample events</p>
              {match.sample_events.map((ev, j) => (
                <button
                  key={j}
                  onClick={() => ev.fo_id ? goToSearch(`fo_id:${ev.fo_id}`) : goToSearch(rule.query)}
                  className="w-full text-left bg-white hover:bg-blue-50 rounded-lg border border-gray-200 hover:border-blue-300 p-2.5 transition-colors group"
                  title="Click to view this event in Search"
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-1.5 text-xs text-gray-500 font-mono">
                      <Clock size={10} />
                      {ev.timestamp || '—'}
                    </div>
                    <ExternalLink size={10} className="text-gray-300 group-hover:text-blue-400 flex-shrink-0 transition-colors" />
                  </div>
                  <p className="text-xs text-brand-text">{ev.message || '—'}</p>
                  {ev.host?.hostname && (
                    <p className="text-xs text-gray-500 mt-0.5">Host: {ev.host.hostname}</p>
                  )}
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// LevelGroup — one severity accordion inside ModuleRunCard
// ─────────────────────────────────────────────────────────────────────────────
const LEVEL_HEADER_BG = {
  critical:      'bg-red-50',
  high:          'bg-orange-50',
  medium:        'bg-amber-50',
  low:           'bg-blue-50',
  informational: 'bg-gray-50',
}

function LevelGroup({ level, hits, totalInLevel, defaultOpen, caseId, navigate, buildQuery }) {
  const [open, setOpen]       = useState(defaultOpen)
  const [expandedHit, setExpandedHit] = useState(null)
  const headerBg = LEVEL_HEADER_BG[level] || 'bg-gray-50'

  return (
    <div className="border-t border-gray-100">
      <button
        className={`w-full flex items-center gap-2.5 px-4 py-2 text-left transition-colors hover:brightness-95 ${headerBg}`}
        onClick={() => setOpen(v => !v)}
      >
        <span className={`badge ${LEVEL_BADGE[level] || 'badge-generic'} flex-shrink-0`}>
          {level}
        </span>
        <span className="text-xs font-semibold text-gray-700 flex-1">
          {totalInLevel.toLocaleString()} detection{totalInLevel !== 1 ? 's' : ''}
          {hits.length < totalInLevel && (
            <span className="text-gray-400 font-normal"> · preview: first {hits.length}</span>
          )}
        </span>
        <ChevronDown size={12} className={`text-gray-400 flex-shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="divide-y divide-gray-100">
          {hits.map((hit, i) => {
            const isExpanded = expandedHit === i
            return (
              <div key={i} className="bg-white hover:bg-gray-50/70 transition-colors group">
                <div className="flex items-start gap-2 px-4 py-2.5">
                  {/* Hit detail */}
                  <div
                    className="flex-1 min-w-0 cursor-pointer"
                    onClick={() => setExpandedHit(isExpanded ? null : i)}
                  >
                    <div className="flex items-center gap-1.5 flex-wrap mb-0.5">
                      <span className="font-semibold text-xs text-brand-text leading-tight">
                        {hit.rule_title}
                      </span>
                      {hit.event_id && (
                        <span className="badge bg-purple-50 text-purple-700 border border-purple-100 font-mono text-[9px] flex-shrink-0">
                          EID {hit.event_id}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0 text-[10px] font-mono mt-0.5">
                      {hit.computer  && <span className="text-gray-600 font-semibold">{hit.computer}</span>}
                      {hit.channel   && (
                        <span className="text-blue-500 truncate max-w-[200px]" title={hit.channel}>
                          {hit.channel}
                        </span>
                      )}
                      {hit.timestamp && <span className="text-gray-400">{hit.timestamp}</span>}
                    </div>
                    {hit.details_raw && (
                      <p
                        className={`text-[10px] text-gray-500 font-mono mt-1 ${
                          isExpanded ? 'whitespace-pre-wrap break-all' : 'truncate'
                        }`}
                        title={!isExpanded ? hit.details_raw : undefined}
                      >
                        {hit.details_raw}
                      </p>
                    )}
                  </div>
                  {/* Search pivot */}
                  <button
                    onClick={() =>
                      navigate(`/cases/${caseId}/search`, {
                        state: { pivotQuery: buildQuery(hit) },
                      })
                    }
                    className="flex-shrink-0 opacity-0 group-hover:opacity-100 flex items-center gap-1 text-[10px] text-gray-400 hover:text-brand-accent hover:bg-brand-accentlight rounded px-1.5 py-1 transition-all"
                    title="Find matching events in Search"
                  >
                    <ExternalLink size={9} />
                    Search
                  </button>
                </div>
              </div>
            )
          })}
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

  // YARA-specific state
  const [yaraRules, setYaraRules]           = useState('')
  const [yaraValidating, setYaraValidating] = useState(false)
  const [yaraValid, setYaraValid]           = useState(null)  // null | {valid, error}
  const yaraDebounce                        = useRef(null)

  useEffect(() => {
    Promise.all([api.modules.list(), api.modules.listSources(caseId)])
      .then(([modResp, srcResp]) => {
        // Only show available modules
        setModules((modResp.modules || []).filter(m => m.available))
        setSources(srcResp.sources || [])
        setLoading(false)
      })
      .catch(err => { setError(err.message); setLoading(false) })
  }, [caseId])

  // Validate YARA rules with debounce
  useEffect(() => {
    if (selectedModule?.id !== 'yara') return
    if (!yaraRules.trim()) { setYaraValid(null); return }
    if (yaraDebounce.current) clearTimeout(yaraDebounce.current)
    setYaraValidating(true)
    yaraDebounce.current = setTimeout(() => {
      api.modules.validateYara(yaraRules)
        .then(r => setYaraValid(r))
        .catch(() => setYaraValid({ valid: false, error: 'Validation request failed' }))
        .finally(() => setYaraValidating(false))
    }, 600)
  }, [yaraRules, selectedModule])

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
    : sources

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

  function selectAll() {
    setSelectedJobs(new Set(compatibleSources.map(s => s.job_id)))
  }

  function selectModule(mod) {
    setSelectedModule(mod)
    setSelectedJobs(new Set())
    setYaraRules('')
    setYaraValid(null)
  }

  async function handleRun() {
    if (!selectedModule || selectedJobs.size === 0) return
    if (selectedModule.id === 'yara' && yaraValid && !yaraValid.valid) return
    setRunning(true)
    setError(null)
    try {
      const params = {}
      if (selectedModule.id === 'yara' && yaraRules.trim()) {
        params.custom_rules = yaraRules.trim()
      }
      const run = await api.modules.createRun(caseId, {
        module_id: selectedModule.id,
        job_ids:   [...selectedJobs],
        params,
      })
      onRunCreated(run)
    } catch (err) {
      setError(err.message)
      setRunning(false)
    }
  }

  const yaraInvalid = selectedModule?.id === 'yara' && yaraValid && !yaraValid.valid
  const canRun = selectedModule && selectedJobs.size > 0 && !running && !yaraInvalid

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[800px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Play size={15} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Run Analysis Module</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center text-gray-400">
            <Loader2 size={20} className="animate-spin mr-2" />Loading…
          </div>
        ) : (
          <div className="flex-1 flex overflow-hidden">

            {/* ── Left: module list ──────────────────────────────────────── */}
            <div className="w-[280px] flex-shrink-0 border-r border-gray-100 flex flex-col bg-gray-50/50">
              <div className="px-4 pt-4 pb-2">
                <p className="section-title text-[11px] uppercase tracking-wider text-gray-400">Modules</p>
              </div>
              <div className="flex-1 overflow-y-auto px-3 pb-4 space-y-1.5">
                {modules.map(mod => {
                  const isSelected = selectedModule?.id === mod.id
                  return (
                    <button
                      key={mod.id}
                      onClick={() => selectModule(mod)}
                      className={`w-full text-left p-3 rounded-xl border-2 transition-all ${
                        isSelected
                          ? 'border-brand-accent bg-brand-accentlight shadow-sm'
                          : 'border-transparent bg-white hover:border-gray-200 hover:shadow-sm'
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
                          isSelected ? 'bg-brand-accent text-white' : 'bg-gray-100 text-gray-500'
                        }`}>
                          <Cpu size={13} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-xs text-brand-text">{mod.name}</p>
                          <p className="text-[10px] text-gray-400 mt-0.5 line-clamp-2 leading-relaxed">
                            {mod.description}
                          </p>
                          {(mod.input_extensions?.length > 0 || mod.input_filenames?.length > 0) && (
                            <p className="text-[9px] text-gray-400 mt-1 font-mono truncate">
                              {[...(mod.input_extensions || []), ...(mod.input_filenames || [])].slice(0, 6).join(' ')}
                            </p>
                          )}
                        </div>
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* ── Right: source files + params ──────────────────────────── */}
            <div className="flex-1 flex flex-col overflow-hidden">

              {!selectedModule ? (
                <div className="flex-1 flex flex-col items-center justify-center text-center px-8 gap-3">
                  <div className="w-12 h-12 rounded-2xl bg-gray-100 flex items-center justify-center">
                    <Cpu size={22} className="text-gray-400" />
                  </div>
                  <p className="font-medium text-brand-text">Select a module</p>
                  <p className="text-xs text-gray-500 max-w-xs">
                    Choose an analysis module from the left panel, then select the source files to process.
                  </p>
                </div>
              ) : (
                <>
                  {/* Source file selection */}
                  <div className="flex items-center justify-between px-4 pt-4 pb-2 flex-shrink-0">
                    <p className="section-title text-[11px] uppercase tracking-wider text-gray-400">
                      Input Files
                      {compatibleSources.length > 0 && (
                        <span className="ml-1.5 font-normal normal-case text-gray-400">
                          {selectedJobs.size}/{compatibleSources.length} selected
                        </span>
                      )}
                    </p>
                    {compatibleSources.length > 0 && selectedJobs.size < compatibleSources.length && (
                      <button onClick={selectAll} className="text-xs text-brand-accent hover:underline">
                        Select all
                      </button>
                    )}
                  </div>

                  {compatibleSources.length === 0 ? (
                    <div className="mx-4 mb-4 p-4 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-800">
                      <p className="font-medium mb-1">No compatible files ingested yet</p>
                      <p>
                        {selectedModule.name} requires:{' '}
                        {[...(selectedModule.input_extensions || []), ...(selectedModule.input_filenames || [])].join(', ') || 'any file'}
                      </p>
                    </div>
                  ) : (
                    <>
                      {compatibleSources.length > 6 && (
                        <div className="px-4 pb-2 flex-shrink-0">
                          <input
                            type="text"
                            value={sourceSearch}
                            onChange={e => setSourceSearch(e.target.value)}
                            placeholder="Filter files…"
                            className="w-full px-3 py-1.5 text-xs border border-gray-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-accent/40 focus:border-brand-accent"
                          />
                        </div>
                      )}
                      <div className={`px-4 pb-3 space-y-1 ${selectedModule?.id === 'yara' ? 'max-h-48' : 'flex-1'} overflow-y-auto flex-shrink-0`}>
                        {visibleSources.map(src => (
                          <label
                            key={src.job_id}
                            className={`flex items-center gap-3 p-2.5 rounded-lg cursor-pointer border transition-colors ${
                              selectedJobs.has(src.job_id)
                                ? 'border-brand-accent/40 bg-brand-accentlight'
                                : 'border-gray-100 hover:border-gray-200 hover:bg-gray-50'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={selectedJobs.has(src.job_id)}
                              onChange={() => toggleJob(src.job_id)}
                              className="rounded border-gray-300 flex-shrink-0 accent-brand-accent"
                            />
                            <div className="flex-1 min-w-0">
                              <p className="text-xs text-brand-text truncate font-medium">
                                {src.original_filename}
                              </p>
                              <p className="text-[10px] text-gray-400 mt-0.5">
                                {(src.events_indexed || 0).toLocaleString()} events
                                {src.plugin_used ? ` · ${src.plugin_used}` : ''}
                              </p>
                            </div>
                          </label>
                        ))}
                        {visibleSources.length === 0 && sourceSearch && (
                          <p className="text-xs text-gray-400 italic py-4 text-center">
                            No files match "{sourceSearch}"
                          </p>
                        )}
                      </div>
                    </>
                  )}

                  {/* ── YARA custom rules ─────────────────────────────────── */}
                  {selectedModule.id === 'yara' && (
                    <div className="flex-1 flex flex-col px-4 pb-4 min-h-0">
                      <div className="flex items-center gap-2 mb-2 flex-shrink-0">
                        <FileCode size={12} className="text-gray-400" />
                        <p className="section-title text-[11px] uppercase tracking-wider text-gray-400">
                          Custom YARA Rules
                        </p>
                        <span className="text-[10px] text-gray-400">(appended to built-in rules)</span>
                        {yaraValidating && <Loader2 size={10} className="animate-spin text-gray-400 ml-auto" />}
                        {!yaraValidating && yaraValid && (
                          yaraValid.valid
                            ? <span className="ml-auto text-[10px] text-green-600 flex items-center gap-1">
                                <CheckCircle size={10} /> Valid
                              </span>
                            : <span className="ml-auto text-[10px] text-red-500 flex items-center gap-1">
                                <AlertCircle size={10} /> Syntax error
                              </span>
                        )}
                      </div>
                      <textarea
                        value={yaraRules}
                        onChange={e => setYaraRules(e.target.value)}
                        placeholder={`rule MyRule {\n    meta:\n        description = "My custom rule"\n        severity = "high"\n    strings:\n        $s1 = "suspicious_string" ascii nocase\n    condition:\n        any of them\n}`}
                        spellCheck={false}
                        className={`flex-1 w-full min-h-0 px-3 py-2.5 text-[11px] font-mono border rounded-xl resize-none focus:outline-none focus:ring-2 leading-relaxed ${
                          yaraValid && !yaraValid.valid
                            ? 'border-red-300 bg-red-50 focus:ring-red-200'
                            : 'border-gray-200 bg-gray-950 text-green-300 focus:ring-brand-accent/30 focus:border-brand-accent'
                        }`}
                      />
                      {yaraValid && !yaraValid.valid && (
                        <p className="mt-1 text-[10px] text-red-500 font-mono flex-shrink-0">
                          {yaraValid.error}
                        </p>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="border-t border-gray-200 px-5 py-3.5 flex items-center gap-3 bg-gray-50/50">
          {error && (
            <p className="flex-1 text-xs text-red-600 bg-red-50 border border-red-100 rounded-lg px-3 py-2 truncate" title={error}>
              {error}
            </p>
          )}
          <div className="ml-auto flex items-center gap-2">
            {selectedModule && selectedJobs.size === 0 && (
              <p className="text-xs text-gray-400">Select at least one file</p>
            )}
            <button
              onClick={handleRun}
              disabled={!canRun}
              className={`flex items-center gap-2 px-5 py-2 rounded-xl font-semibold text-sm transition-all ${
                canRun
                  ? 'bg-brand-accent text-white hover:bg-brand-accent/90 shadow-sm hover:shadow'
                  : 'bg-gray-100 text-gray-400 cursor-not-allowed'
              }`}
            >
              {running
                ? <><Loader2 size={14} className="animate-spin" /> Launching…</>
                : <><Play size={14} /> Run {selectedModule?.name || 'Module'}</>
              }
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleRunCard
// ─────────────────────────────────────────────────────────────────────────────
const LEVEL_ORDER_KEYS = ['critical', 'high', 'medium', 'low', 'informational']

function ModuleRunCard({ run, caseId, navigate }) {
  const zeroDetected = run.status === 'COMPLETED' && run.total_hits === 0
  const [open, setOpen]             = useState(false)
  const [showOutput, setShowOutput] = useState(zeroDetected)

  const moduleName  = MODULE_NAMES[run.module_id] || run.module_id
  const preview     = run.results_preview || []
  const byLevel     = run.hits_by_level   || {}

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

  // Strip residual ANSI codes
  const _stripAnsi = s => s.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').replace(/\x1b[@-_][^\x1b]*/g, '')
  const rawOutput  = (run.tool_stdout || '') + (run.tool_log ? '\n--- log ---\n' + run.tool_log : '')
  const toolOutput = _stripAnsi(rawOutput)
  const hasOutput  = toolOutput.trim().length > 0

  // Group preview hits by level
  const hitsByLevel = {}
  for (const hit of preview) {
    const lvl = (hit.level || 'informational').toLowerCase()
    if (!hitsByLevel[lvl]) hitsByLevel[lvl] = []
    hitsByLevel[lvl].push(hit)
  }
  const levelsWithHits = LEVEL_ORDER_KEYS.filter(lvl => hitsByLevel[lvl]?.length > 0)

  // Build smart Lucene pivot query for a hit
  function buildQuery(hit) {
    const parts = []
    if (hit.event_id) parts.push(`evtx.event_id:${hit.event_id}`)
    if (hit.computer) parts.push(`host.hostname:"${hit.computer}"`)
    if (parts.length === 0) {
      const title = (hit.rule_title || '').replace(/"/g, '')
      return title ? `message:"${title}"` : '*'
    }
    return parts.join(' AND ')
  }

  return (
    <div className="card overflow-hidden">

      {/* ── Card header ───────────────────────────────────────── */}
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

            {/* Level pills in header — only for completed runs */}
            {run.status === 'COMPLETED' && LEVEL_ORDER_KEYS.map(lvl => {
              const count = byLevel[lvl] || 0
              if (!count) return null
              return (
                <span key={lvl} className={`badge ${LEVEL_BADGE[lvl] || 'badge-generic'}`}>
                  {count.toLocaleString()} {lvl === 'informational' ? 'info' : lvl.slice(0, 4)}
                </span>
              )
            })}
            {zeroDetected && (
              <span className="badge bg-green-50 text-green-600 border border-green-200">
                ✓ clean
              </span>
            )}
          </div>
          {tsDisplay && (
            <p className="text-[10px] text-gray-400 mt-0.5 font-mono">{tsDisplay}</p>
          )}
          {run.status === 'FAILED' && run.error && (
            <p className="text-xs text-red-600 mt-0.5 line-clamp-2" title={run.error}>
              {run.error}
            </p>
          )}
        </div>
        <ChevronDown
          size={14}
          className={`text-gray-400 flex-shrink-0 mt-0.5 transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {/* ── Expanded body ─────────────────────────────────────── */}
      {open && (
        <div>
          {/* No detections state */}
          {preview.length === 0 && run.status === 'COMPLETED' && (
            <div className="border-t border-gray-100 p-5 text-center bg-green-50/40">
              <CheckCircle size={20} className="text-green-400 mx-auto mb-2" />
              <p className="text-sm font-medium text-gray-700">No detections</p>
              <p className="text-xs text-gray-400 mt-0.5">
                {moduleName} found nothing suspicious in the selected files
              </p>
            </div>
          )}

          {/* Severity accordion groups */}
          {levelsWithHits.map(lvl => (
            <LevelGroup
              key={lvl}
              level={lvl}
              hits={hitsByLevel[lvl]}
              totalInLevel={byLevel[lvl] || hitsByLevel[lvl].length}
              defaultOpen={lvl === 'critical' || lvl === 'high'}
              caseId={caseId}
              navigate={navigate}
              buildQuery={buildQuery}
            />
          ))}

          {/* Truncation notice */}
          {run.total_hits > preview.length && preview.length > 0 && (
            <div className="border-t border-gray-100 px-4 py-2 bg-gray-50 text-center">
              <p className="text-[10px] text-gray-400">
                Showing first {preview.length} of{' '}
                <span className="font-semibold text-gray-600">{run.total_hits.toLocaleString()}</span>{' '}
                total detections
              </p>
            </div>
          )}

          {/* Tool output (stdout / log) */}
          {(hasOutput || run.status === 'FAILED') && (
            <div className="border-t border-gray-100 bg-gray-50/80 px-4 py-2.5">
              <button
                onClick={() => setShowOutput(v => !v)}
                className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-medium text-gray-600
                           bg-white border border-gray-200 rounded-md hover:bg-gray-50
                           hover:border-gray-300 transition-colors"
              >
                <Terminal size={10} />
                Tool output
                <ChevronDown size={9} className={`ml-1 transition-transform ${showOutput ? 'rotate-180' : ''}`} />
              </button>
              {showOutput && (
                <pre className="mt-1 bg-gray-950 text-green-300 rounded-lg p-3 text-[10px] font-mono overflow-x-auto max-h-72 leading-relaxed whitespace-pre-wrap break-all">
                  {toolOutput || run.error || '(no output)'}
                </pre>
              )}
            </div>
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
  const navigate              = useNavigate()
  const [runs, setRuns]       = useState([])
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
            runs.map(run => (
              <ModuleRunCard
                key={run.run_id}
                run={run}
                caseId={caseId}
                navigate={navigate}
              />
            ))
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
              <History size={14} />
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
          caseId={caseId}
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
