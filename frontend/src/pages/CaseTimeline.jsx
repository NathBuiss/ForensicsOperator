import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Upload, Search, Bell, X, ChevronRight, AlertTriangle,
  CheckCircle, Clock, Database, Loader2, Shield,
  Cpu, RefreshCw, Plus, Download, Play, Terminal,
  AlertCircle, ChevronDown, FileCode, ExternalLink,
  Flag, Filter, Sparkles, FileText,
  Monitor, HardDrive, Globe, Brain,
  Binary, Bug, Network, FileImage, TextSearch, Tag,
} from 'lucide-react'

const MOD_CATEGORY_ICONS = {
  'Threat Hunting':     <Shield     size={13} className="text-red-500     flex-shrink-0" />,
  'Malware Detection':  <Bug        size={13} className="text-red-400     flex-shrink-0" />,
  'Binary Analysis':    <Binary     size={13} className="text-orange-500  flex-shrink-0" />,
  'Windows':            <Monitor    size={13} className="text-sky-500     flex-shrink-0" />,
  'Memory Forensics':   <Brain      size={13} className="text-purple-500  flex-shrink-0" />,
  'Disk Forensics':     <HardDrive  size={13} className="text-amber-500   flex-shrink-0" />,
  'Browser Forensics':  <Globe      size={13} className="text-blue-500    flex-shrink-0" />,
  'Network':            <Network    size={13} className="text-teal-500    flex-shrink-0" />,
  'Threat Intelligence':<Tag        size={13} className="text-pink-500    flex-shrink-0" />,
  'Metadata Extraction':<FileImage  size={13} className="text-indigo-500  flex-shrink-0" />,
  'Search':             <TextSearch size={13} className="text-gray-400    flex-shrink-0" />,
}
const MOD_CATEGORY_ORDER = [
  'Threat Hunting', 'Malware Detection', 'Binary Analysis', 'Windows',
  'Memory Forensics', 'Disk Forensics', 'Browser Forensics', 'Network',
  'Threat Intelligence', 'Metadata Extraction', 'Search',
]
import { api } from '../api/client'
import Timeline from './Timeline'
import CollectorModal from '../components/CollectorModal'
import AlertRules from './AlertRules'
import CaseNotes from './CaseNotes'
import IngestPanel from '../components/IngestPanel'

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
            <span className="text-gray-400 font-normal"> · top {hits.length} by severity</span>
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
  const [runningAll, setRunningAll]         = useState(false)
  const [runAllProgress, setRunAllProgress] = useState(null)  // null | {done, total}
  const [error, setError]                   = useState(null)
  const [moduleSearch, setModuleSearch]     = useState('')
  const moduleSearchRef                     = useRef(null)

  // YARA-specific state
  const [yaraRules, setYaraRules]                   = useState('')
  const [yaraValidating, setYaraValidating]         = useState(false)
  const [yaraValid, setYaraValid]                   = useState(null)  // null | {valid, error}
  const [yaraLibraryRules, setYaraLibraryRules]     = useState([])
  const [selectedYaraIds, setSelectedYaraIds]       = useState(new Set())
  const [grepPatterns, setGrepPatterns]             = useState('')
  const yaraDebounce                                = useRef(null)

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

  // Load YARA library rules when YARA module is selected
  useEffect(() => {
    if (selectedModule?.id !== 'yara') return
    api.yaraRules.list()
      .then(r => setYaraLibraryRules(r.rules || []))
      .catch(() => {})
  }, [selectedModule])

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
        if (extList.some(e => e === '*' || e === '.*')) return true
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

  // Group modules by category for the left panel
  const groupedModules = useMemo(() => {
    const q = moduleSearch.toLowerCase().trim()
    const filtered = q
      ? modules.filter(m =>
          (m.name || '').toLowerCase().includes(q) ||
          (m.description || '').toLowerCase().includes(q) ||
          (m.category || '').toLowerCase().includes(q) ||
          (m.tags || []).some(t => t.toLowerCase().includes(q))
        )
      : modules
    const groups = {}
    filtered.forEach(m => {
      const cat = m.category || 'Other'
      if (!groups[cat]) groups[cat] = []
      groups[cat].push(m)
    })
    return Object.entries(groups).sort(([a], [b]) => {
      const ai = MOD_CATEGORY_ORDER.indexOf(a)
      const bi = MOD_CATEGORY_ORDER.indexOf(b)
      if (ai !== -1 && bi !== -1) return ai - bi
      if (ai !== -1) return -1
      if (bi !== -1) return 1
      return a.localeCompare(b)
    })
  }, [modules, moduleSearch])

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
    setGrepPatterns('')
  }

  async function handleRun() {
    if (!selectedModule || selectedJobs.size === 0) return
    if (selectedModule.id === 'yara' && yaraValid && !yaraValid.valid) return
    setRunning(true)
    setError(null)
    try {
      const params = {}
      if (selectedModule.id === 'yara') {
        if (yaraRules.trim()) params.custom_rules = yaraRules.trim()
        if (selectedYaraIds.size > 0) params.selected_rule_ids = [...selectedYaraIds]
      }
      if (selectedModule.id === 'grep_search' && grepPatterns.trim()) {
        params.patterns = grepPatterns.split('\n').map(p => p.trim()).filter(Boolean)
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

  async function handleRunAll() {
    if (runningAll || sources.length === 0) return
    const eligible = modules.filter(m => {
      // Skip modules that need custom config (YARA custom rules, grep patterns)
      // but allow them if they have library/default behaviour
      const extList  = m.input_extensions || []
      const nameList = m.input_filenames  || []
      const acceptsAll = extList.length === 0 && nameList.length === 0
      if (acceptsAll) return sources.length > 0
      const hasCompatible = sources.some(s => {
        const fnameLower = (s.original_filename || '').toLowerCase()
        if (extList.some(e => e === '*' || e === '.*')) return true
        const extMatch  = extList.some(ext => fnameLower.endsWith(ext.toLowerCase()))
        const basename  = fnameLower.split('/').pop().split('\\').pop()
        const nameMatch = nameList.some(fn => basename === fn.toLowerCase())
        return extMatch || nameMatch
      })
      return hasCompatible
    })
    if (eligible.length === 0) return
    if (!window.confirm(
      `Launch all ${eligible.length} applicable module${eligible.length > 1 ? 's' : ''} against their compatible files?\n\n` +
      eligible.map(m => `• ${m.name}`).join('\n')
    )) return

    setRunningAll(true)
    setRunAllProgress({ done: 0, total: eligible.length })
    setError(null)

    let done = 0
    for (const mod of eligible) {
      const extList  = mod.input_extensions || []
      const nameList = mod.input_filenames  || []
      const acceptsAll = extList.length === 0 && nameList.length === 0
      const jobIds = sources
        .filter(s => {
          if (acceptsAll) return true
          if (extList.some(e => e === '*' || e === '.*')) return true
          const fnameLower = (s.original_filename || '').toLowerCase()
          const extMatch  = extList.some(ext => fnameLower.endsWith(ext.toLowerCase()))
          const basename  = fnameLower.split('/').pop().split('\\').pop()
          const nameMatch = nameList.some(fn => basename === fn.toLowerCase())
          return extMatch || nameMatch
        })
        .map(s => s.job_id)
      if (jobIds.length === 0) { done++; setRunAllProgress({ done, total: eligible.length }); continue }
      try {
        const run = await api.modules.createRun(caseId, { module_id: mod.id, job_ids: jobIds, params: {} })
        onRunCreated(run)
      } catch {
        // best-effort — don't abort remaining modules on one failure
      }
      done++
      setRunAllProgress({ done, total: eligible.length })
    }
    setRunningAll(false)
    setRunAllProgress(null)
    onClose()
  }

  const yaraInvalid = selectedModule?.id === 'yara' && yaraValid && !yaraValid.valid
  const canRun = selectedModule && selectedJobs.size > 0 && !running && !yaraInvalid && !runningAll

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[860px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 32px rgba(0,0,0,0.12)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 bg-gray-50/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-brand-accent/10 flex items-center justify-center">
              <Play size={15} className="text-brand-accent" />
            </div>
            <div>
              <p className="font-bold text-brand-text text-base leading-tight">Run Analysis Module</p>
              <p className="text-[11px] text-gray-400 leading-tight mt-0.5">Select a module, pick source files, launch</p>
            </div>
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
            <div className="w-[320px] flex-shrink-0 border-r border-gray-100 flex flex-col bg-gray-50/60">
              {/* Search bar */}
              <div className="px-3 pt-3 pb-2 flex-shrink-0">
                <div className="relative">
                  <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
                  <input
                    ref={moduleSearchRef}
                    value={moduleSearch}
                    onChange={e => setModuleSearch(e.target.value)}
                    placeholder="Search modules…"
                    className="input w-full text-xs py-2 pl-8 pr-7 bg-white rounded-xl"
                  />
                  {moduleSearch && (
                    <button onClick={() => setModuleSearch('')}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                      <X size={11} />
                    </button>
                  )}
                </div>
              </div>

              {/* Categorized module list */}
              <div className="flex-1 overflow-y-auto px-2.5 pb-4">
                {groupedModules.length === 0 ? (
                  <p className="text-xs text-gray-400 italic text-center py-8">No modules match</p>
                ) : groupedModules.map(([category, mods]) => (
                  <div key={category} className="mb-4">
                    {/* Category header */}
                    <div className="flex items-center gap-2 px-1 pt-3 pb-2 sticky top-0 bg-gray-50/95 backdrop-blur-sm z-10">
                      <span className="flex items-center gap-1.5">
                        {MOD_CATEGORY_ICONS[category]}
                        <span className="text-[11px] font-bold uppercase tracking-widest text-gray-500">
                          {category}
                        </span>
                      </span>
                      <div className="flex-1 h-px bg-gray-200" />
                      <span className="text-[10px] text-gray-400 flex-shrink-0">{mods.length}</span>
                    </div>
                    {/* Module cards in this category */}
                    <div className="space-y-1">
                      {mods.map(mod => {
                        const isSelected = selectedModule?.id === mod.id
                        return (
                          <button
                            key={mod.id}
                            onClick={() => selectModule(mod)}
                            className={`w-full text-left px-3 py-2.5 rounded-xl border transition-all ${
                              isSelected
                                ? 'border-brand-accent bg-brand-accentlight shadow-sm'
                                : 'border-transparent hover:bg-white hover:border-gray-200 hover:shadow-sm'
                            }`}
                          >
                            <p className={`font-semibold text-sm leading-tight ${isSelected ? 'text-brand-accent' : 'text-brand-text'}`}>
                              {mod.name}
                            </p>
                            <p className={`text-[11px] mt-1 line-clamp-2 leading-relaxed ${isSelected ? 'text-brand-accent/70' : 'text-gray-500'}`}>
                              {mod.description}
                            </p>
                            {(mod.tags || []).length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-1.5">
                                {mod.tags.slice(0, 4).map(tag => (
                                  <span key={tag} className={`px-1.5 py-px rounded text-[9px] font-medium ${
                                    isSelected ? 'bg-brand-accent/10 text-brand-accent/80' : 'bg-gray-100 text-gray-500'
                                  }`}>
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </button>
                        )
                      })}
                    </div>
                  </div>
                ))}
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

                  {/* ── Grep search patterns ─────────────────────────────── */}
                  {selectedModule.id === 'grep_search' && (
                    <div className="flex-1 flex flex-col px-4 pb-4 min-h-0">
                      <p className="section-title text-[11px] uppercase tracking-wider text-gray-400 mb-2 flex-shrink-0">
                        Search Patterns
                        <span className="ml-1.5 font-normal normal-case text-gray-400">(one regex per line — leave empty for built-in IOC patterns)</span>
                      </p>
                      <textarea
                        value={grepPatterns}
                        onChange={e => setGrepPatterns(e.target.value)}
                        placeholder={"192\\.168\\.\\d+\\.\\d+\ncmd\\.exe\nbase64\\.b64decode"}
                        spellCheck={false}
                        className="flex-1 w-full min-h-0 px-3 py-2.5 text-[11px] font-mono border border-gray-200 bg-gray-950 text-green-300 rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent leading-relaxed"
                      />
                    </div>
                  )}

                  {/* ── YARA library rule selection ───────────────────────── */}
                  {selectedModule.id === 'yara' && yaraLibraryRules.length > 0 && (
                    <div className="px-4 pb-2 flex-shrink-0">
                      <p className="section-title text-[11px] uppercase tracking-wider text-gray-400 mb-1.5">
                        Library Rules <span className="normal-case font-normal text-gray-400 ml-1">(leave all unchecked to run all)</span>
                      </p>
                      <div className="max-h-32 overflow-y-auto space-y-0.5 border border-gray-200 rounded-lg p-2">
                        {yaraLibraryRules.map(rule => (
                          <label key={rule.id} className="flex items-center gap-2 cursor-pointer group">
                            <input
                              type="checkbox"
                              checked={selectedYaraIds.has(rule.id)}
                              onChange={e => setSelectedYaraIds(prev => {
                                const s = new Set(prev)
                                e.target.checked ? s.add(rule.id) : s.delete(rule.id)
                                return s
                              })}
                              className="accent-brand-accent"
                            />
                            <span className="text-[11px] text-gray-700 truncate group-hover:text-gray-900">{rule.name}</span>
                            {rule.tags?.length > 0 && (
                              <span className="text-[9px] text-gray-400 flex-shrink-0">{rule.tags[0]}</span>
                            )}
                          </label>
                        ))}
                      </div>
                    </div>
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
          {/* Launch all modules button */}
          <button
            onClick={handleRunAll}
            disabled={runningAll || running || sources.length === 0}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl font-medium text-xs border transition-all ${
              runningAll || running || sources.length === 0
                ? 'border-gray-200 text-gray-400 cursor-not-allowed bg-white'
                : 'border-gray-300 text-gray-600 hover:border-brand-accent hover:text-brand-accent bg-white'
            }`}
            title="Launch every applicable module against its compatible files"
          >
            {runningAll
              ? <><Loader2 size={12} className="animate-spin" /> {runAllProgress ? `${runAllProgress.done}/${runAllProgress.total}` : 'Launching…'}</>
              : <><Sparkles size={12} /> Launch all modules</>
            }
          </button>

          {error && (
            <p className="flex-1 text-xs text-red-600 bg-red-50 border border-red-100 rounded-lg px-3 py-2 truncate" title={error}>
              {error}
            </p>
          )}
          <div className="ml-auto flex items-center gap-2">
            {selectedModule && selectedJobs.size === 0 && !runningAll && (
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

// ── LLM analysis display ──────────────────────────────────────────────────────
const SEVERITY_BADGE = {
  critical:      'bg-red-100 text-red-700 border-red-200',
  high:          'bg-orange-100 text-orange-700 border-orange-200',
  medium:        'bg-yellow-100 text-yellow-700 border-yellow-200',
  low:           'bg-blue-100 text-blue-700 border-blue-200',
  informational: 'bg-gray-100 text-gray-600 border-gray-200',
  unknown:       'bg-gray-100 text-gray-500 border-gray-200',
}

function LLMAnalysisPanel({ analysis }) {
  if (!analysis) return null
  const sev = (analysis.severity || 'unknown').toLowerCase()
  return (
    <div className="border-t border-purple-100 bg-purple-50/40 px-4 py-3 space-y-3">
      <div className="flex items-center gap-2">
        <Sparkles size={13} className="text-purple-500 flex-shrink-0" />
        <span className="text-xs font-semibold text-purple-700">AI Analysis</span>
        {analysis.model_used && (
          <span className="text-[10px] text-purple-400 font-mono">{analysis.model_used}</span>
        )}
        <span className={`ml-auto text-[10px] font-medium border rounded-full px-2 py-0.5 ${SEVERITY_BADGE[sev] || SEVERITY_BADGE.unknown}`}>
          {sev}
        </span>
      </div>

      {analysis.summary && (
        <p className="text-xs text-gray-700 leading-relaxed">{analysis.summary}</p>
      )}

      {analysis.timeline?.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1">Timeline</p>
          <ul className="space-y-0.5">
            {analysis.timeline.map((item, i) => (
              <li key={i} className="text-xs text-gray-600 flex gap-1.5">
                <span className="text-purple-400 flex-shrink-0">▸</span>{item}
              </li>
            ))}
          </ul>
        </div>
      )}

      {analysis.indicators?.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1">Indicators</p>
          <div className="flex flex-wrap gap-1">
            {analysis.indicators.map((ioc, i) => (
              <span key={i} className="text-[10px] font-mono bg-white border border-gray-200 rounded px-1.5 py-0.5 text-gray-700">
                {ioc}
              </span>
            ))}
          </div>
        </div>
      )}

      {analysis.mitre_techniques?.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1">MITRE ATT&CK</p>
          <div className="flex flex-wrap gap-1">
            {analysis.mitre_techniques.map((t, i) => (
              <span key={i} className="text-[10px] bg-red-50 border border-red-200 text-red-700 rounded px-1.5 py-0.5">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {analysis.recommendations?.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1">Recommendations</p>
          <ul className="space-y-0.5">
            {analysis.recommendations.map((rec, i) => (
              <li key={i} className="text-xs text-gray-600 flex gap-1.5">
                <span className="text-green-500 flex-shrink-0">→</span>{rec}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function ModuleRunCard({
  run, caseId, navigate,
  // Hit-level filters (all optional — undefined = no filtering)
  activeLevels, activeComputers, activeChannels, activeTags, ruleSearch,
  onResetFilter,
}) {
  const zeroDetected = run.status === 'COMPLETED' && run.total_hits === 0
  const [showOutput, setShowOutput] = useState(zeroDetected)
  const [analyzing, setAnalyzing]   = useState(false)
  const [analysis,  setAnalysis]    = useState(run.llm_analysis || null)
  const [analyzeErr, setAnalyzeErr] = useState('')
  const [retrying,   setRetrying]   = useState(false)
  const [retryErr,   setRetryErr]   = useState('')

  async function retryRun() {
    setRetrying(true)
    setRetryErr('')
    try {
      await api.modules.retryRun(run.run_id)
    } catch (err) {
      setRetryErr(err.message)
    } finally {
      setRetrying(false)
    }
  }

  async function runAnalysis() {
    setAnalyzing(true)
    setAnalyzeErr('')
    try {
      const res = await api.modules.analyze(run.run_id)
      setAnalysis(res.analysis)
    } catch (err) {
      setAnalyzeErr(err.message)
    } finally {
      setAnalyzing(false)
    }
  }

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

  // ── Per-hit filtering ──────────────────────────────────────────────────────
  // Applies all active filters at once so every dimension is ANDed together.
  const filteredPreview = useMemo(() => {
    const hasFilters = (activeLevels?.size > 0) || ruleSearch?.trim() ||
                       (activeComputers?.size > 0) || (activeChannels?.size > 0) ||
                       (activeTags?.size > 0)
    if (!hasFilters) return preview
    return preview.filter(hit => {
      const lvl = (hit.level || 'informational').toLowerCase()
      if (activeLevels?.size  && !activeLevels.has(lvl))              return false
      if (ruleSearch?.trim()  && !hit.rule_title?.toLowerCase().includes(ruleSearch.trim().toLowerCase())) return false
      if (activeComputers?.size && !activeComputers.has(hit.computer)) return false
      if (activeChannels?.size  && !activeChannels.has(hit.channel))   return false
      if (activeTags?.size) {
        const ht = hit.tags || []
        if (!ht.some(t => activeTags.has(t))) return false
      }
      return true
    })
  }, [preview, activeLevels, ruleSearch, activeComputers, activeChannels, activeTags])

  // Group filtered hits by level for accordion display
  const hitsByLevel = {}
  for (const hit of filteredPreview) {
    const lvl = (hit.level || 'informational').toLowerCase()
    if (!hitsByLevel[lvl]) hitsByLevel[lvl] = []
    hitsByLevel[lvl].push(hit)
  }
  const filteredLevels = LEVEL_ORDER_KEYS.filter(lvl => hitsByLevel[lvl]?.length > 0)

  // Used to show "no detections at selected filters" empty state
  const anyHitsInPreview = preview.length > 0
  const hasFilteredHits  = filteredLevels.length > 0

  // Auto-open completed cards that have detections matching the active filter
  const [open, setOpen] = useState(hasFilteredHits && run.status === 'COMPLETED')

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

      {(run.status === 'FAILED' || run.status === 'PENDING') && (
        <div className="px-3 pb-2 flex items-center gap-2">
          <button
            onClick={retryRun}
            disabled={retrying}
            className="btn-ghost text-xs px-1.5 py-0.5 text-brand-accent hover:text-brand-accenthover flex items-center gap-1"
            title={run.status === 'PENDING' ? 'Re-dispatch stuck run' : 'Retry this module run'}
          >
            <RefreshCw size={11} className={retrying ? 'animate-spin' : ''} />
            {retrying ? '' : (run.status === 'PENDING' ? 'Re-queue' : 'Retry')}
          </button>
          {retryErr && <span className="text-[10px] text-red-500">{retryErr}</span>}
        </div>
      )}

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
          {filteredLevels.length === 0 && anyHitsInPreview && (
            <div className="border-t border-gray-100 px-4 py-5 text-center">
              <p className="text-xs text-gray-400">No detections match the active filters.</p>
              <button
                onClick={onResetFilter}
                className="mt-1 text-[11px] text-brand-accent hover:underline"
              >
                Clear filters
              </button>
            </div>
          )}
          {filteredLevels.map(lvl => (
            <LevelGroup
              key={lvl}
              level={lvl}
              hits={hitsByLevel[lvl]}
              totalInLevel={byLevel[lvl] || 0}
              defaultOpen={lvl === 'critical' || lvl === 'high'}
              caseId={caseId}
              navigate={navigate}
              buildQuery={buildQuery}
            />
          ))}

          {/* Truncation / filter notice */}
          {preview.length > 0 && (
            <div className="border-t border-gray-100 px-4 py-2 bg-gray-50 text-center">
              <p className="text-[10px] text-gray-400">
                {filteredPreview.length !== preview.length
                  ? <>{filteredPreview.length.toLocaleString()} matched / top {preview.length} by severity{run.total_hits > preview.length && <> of {run.total_hits.toLocaleString()} total</>}</>
                  : <>Top {preview.length} by severity{run.total_hits > preview.length && <> of{' '}<span className="font-semibold text-gray-600">{run.total_hits.toLocaleString()}</span> total</>}</>
                }
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

          {/* AI Analysis */}
          {run.status === 'COMPLETED' && (
            <>
              {analysis ? (
                <LLMAnalysisPanel analysis={analysis} />
              ) : (
                <div className="border-t border-gray-100 px-4 py-2 bg-gray-50/50 flex items-center gap-2">
                  <button
                    onClick={runAnalysis}
                    disabled={analyzing}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-medium text-purple-600
                               bg-purple-50 border border-purple-200 rounded-md hover:bg-purple-100
                               disabled:opacity-50 transition-colors"
                  >
                    {analyzing
                      ? <><Loader2 size={10} className="animate-spin" /> Analyzing…</>
                      : <><Sparkles size={10} /> Analyze with AI</>
                    }
                  </button>
                  {analyzeErr && (
                    <p className="text-[10px] text-red-500">{analyzeErr}</p>
                  )}
                </div>
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
  const navigate              = useNavigate()
  const [runs, setRuns]       = useState([])
  const [loading, setLoading] = useState(true)

  const [showFilters, setShowFilters]   = useState(false)

  // ── Level filter (hit-level) ───────────────────────────────────────────────
  const [activeLevels, setActiveLevels] = useState(new Set())

  // ── Run-level filters ──────────────────────────────────────────────────────
  const [moduleFilter, setModuleFilter] = useState('')   // '' = all
  const [dateFrom,     setDateFrom]     = useState('')
  const [dateTo,       setDateTo]       = useState('')
  const [flaggedOnly,  setFlaggedOnly]  = useState(false)

  // ── Hit-level filters ──────────────────────────────────────────────────────
  const [ruleSearch,      setRuleSearch]      = useState('')
  const [activeComputers, setActiveComputers] = useState(new Set())
  const [activeChannels,  setActiveChannels]  = useState(new Set())
  const [activeTags,      setActiveTags]      = useState(new Set())

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

  // Unique module IDs present in the runs list
  const uniqueModuleIds = useMemo(
    () => [...new Set(runs.map(r => r.module_id).filter(Boolean))],
    [runs],
  )

  // Apply run-level filters
  const filteredRuns = useMemo(() => runs.filter(run => {
    if (moduleFilter && run.module_id !== moduleFilter) return false

    const runDate = run.completed_at || run.started_at
    if (runDate) {
      const d = new Date(runDate)
      if (dateFrom && d < new Date(dateFrom))               return false
      if (dateTo   && d > new Date(dateTo + 'T23:59:59'))   return false
    }

    if (flaggedOnly) {
      const bl = run.hits_by_level || {}
      if (!((bl.critical || 0) > 0 || (bl.high || 0) > 0)) return false
    }

    return true
  }), [runs, moduleFilter, dateFrom, dateTo, flaggedOnly])

  const hasActiveRunFilters = moduleFilter || dateFrom || dateTo || flaggedOnly
  const hasActiveHitFilters = activeLevels.size > 0 || ruleSearch.trim() ||
                              activeComputers.size > 0 || activeChannels.size > 0 || activeTags.size > 0
  const hasActiveFilters    = hasActiveRunFilters || hasActiveHitFilters

  // Derive available filter options from the visible run previews
  const { allComputers, allChannels, allTags } = useMemo(() => {
    const computers = new Set()
    const channels  = new Set()
    const tags      = new Set()
    for (const run of filteredRuns) {
      for (const hit of (run.results_preview || [])) {
        if (hit.computer) computers.add(hit.computer)
        if (hit.channel)  channels.add(hit.channel)
        for (const t of (hit.tags || [])) tags.add(t)
      }
    }
    return {
      allComputers: [...computers].sort(),
      allChannels:  [...channels].sort(),
      allTags:      [...tags].sort(),
    }
  }, [filteredRuns])

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[580px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Cpu size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Module Runs</span>
            {runs.length > 0 && (
              <span className="badge bg-gray-100 text-gray-600">
                {filteredRuns.length !== runs.length
                  ? `${filteredRuns.length} / ${runs.length}`
                  : runs.length}
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <button onClick={fetchRuns} className="btn-ghost p-1.5 rounded-lg" title="Refresh">
              <RefreshCw size={14} />
            </button>
            <button
              onClick={() => setShowFilters(v => !v)}
              title="Toggle filters"
              className={`btn-ghost p-1.5 rounded-lg flex items-center gap-1 text-xs transition-colors ${showFilters ? 'bg-brand-accent/10 text-brand-accent' : ''}`}
            >
              <Filter size={13} />
              {hasActiveFilters && <span className="w-1.5 h-1.5 rounded-full bg-brand-accent flex-shrink-0" />}
            </button>
            <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* ── Filter panel (collapsible) ─────────────────────────────────── */}
        {showFilters && <div className="border-b border-gray-100 bg-gray-50/60 divide-y divide-gray-100">

          {/* Level filter row */}
          <div className="px-4 py-2 flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider w-10 flex-shrink-0">
              Level
            </span>
            <button
              onClick={() => setActiveLevels(new Set())}
              className={`badge cursor-pointer select-none transition-colors ${
                activeLevels.size === 0
                  ? 'bg-gray-600 text-white border-gray-500'
                  : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
              }`}
            >
              All
            </button>
            {LEVEL_ORDER_KEYS.map(lvl => {
              const active = activeLevels.has(lvl)
              return (
                <button
                  key={lvl}
                  onClick={() =>
                    setActiveLevels(prev => {
                      const next = new Set(prev)
                      if (next.has(lvl)) {
                        next.delete(lvl)
                        if (next.size === 0) return new Set()
                      } else {
                        next.add(lvl)
                      }
                      return next
                    })
                  }
                  className={`badge cursor-pointer select-none transition-colors ${
                    active
                      ? (LEVEL_BADGE[lvl] || 'badge-generic')
                      : 'bg-white text-gray-400 border-gray-200 hover:bg-gray-100'
                  }`}
                >
                  {lvl === 'informational' ? 'info' : lvl}
                </button>
              )
            })}
          </div>

          {/* Artifact / module type row */}
          <div className="px-4 py-2 flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider w-10 flex-shrink-0">
              Type
            </span>
            <button
              onClick={() => setModuleFilter('')}
              className={`badge cursor-pointer select-none transition-colors ${
                moduleFilter === ''
                  ? 'bg-gray-600 text-white border-gray-500'
                  : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
              }`}
            >
              All types
            </button>
            {uniqueModuleIds.map(id => (
              <button
                key={id}
                onClick={() => setModuleFilter(prev => prev === id ? '' : id)}
                className={`badge cursor-pointer select-none transition-colors ${
                  moduleFilter === id
                    ? 'bg-brand-accent text-white border-brand-accent'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
              >
                {MODULE_NAMES[id] || id}
              </button>
            ))}
          </div>

          {/* Date range + Flagged row */}
          <div className="px-4 py-2 flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider w-10 flex-shrink-0">
              Date
            </span>
            <input
              type="date"
              value={dateFrom}
              onChange={e => setDateFrom(e.target.value)}
              className="text-[11px] border border-gray-200 rounded-md px-2 py-1 text-gray-600 bg-white focus:outline-none focus:ring-1 focus:ring-brand-accent"
              title="From date"
            />
            <span className="text-[10px] text-gray-400">→</span>
            <input
              type="date"
              value={dateTo}
              onChange={e => setDateTo(e.target.value)}
              className="text-[11px] border border-gray-200 rounded-md px-2 py-1 text-gray-600 bg-white focus:outline-none focus:ring-1 focus:ring-brand-accent"
              title="To date"
            />
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => setFlaggedOnly(v => !v)}
                className={`flex items-center gap-1 badge cursor-pointer select-none transition-colors ${
                  flaggedOnly
                    ? 'bg-orange-100 text-orange-700 border-orange-200'
                    : 'bg-white text-gray-400 border-gray-200 hover:bg-gray-100'
                }`}
                title="Show only runs with critical or high detections"
              >
                <Flag size={9} />
                Flagged only
              </button>
            </div>
          </div>

          {/* Rule title search */}
          <div className="px-4 py-2 flex items-center gap-2">
            <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider w-10 flex-shrink-0">
              Rule
            </span>
            <input
              type="text"
              value={ruleSearch}
              onChange={e => setRuleSearch(e.target.value)}
              placeholder="Filter by rule title…"
              className="flex-1 text-[11px] border border-gray-200 rounded-md px-2.5 py-1 text-gray-600 bg-white focus:outline-none focus:ring-1 focus:ring-brand-accent placeholder-gray-300"
            />
            {ruleSearch && (
              <button onClick={() => setRuleSearch('')} className="text-gray-300 hover:text-gray-500">
                <X size={12} />
              </button>
            )}
          </div>

          {/* Computer filter — only shown when >1 computer appears in results */}
          {allComputers.length > 1 && (
            <div className="px-4 py-2 flex items-start gap-1.5 flex-wrap">
              <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider w-10 flex-shrink-0 mt-0.5">
                Host
              </span>
              <button
                onClick={() => setActiveComputers(new Set())}
                className={`badge cursor-pointer select-none transition-colors ${
                  activeComputers.size === 0
                    ? 'bg-gray-600 text-white border-gray-500'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
              >
                All
              </button>
              {allComputers.map(c => (
                <button
                  key={c}
                  onClick={() => setActiveComputers(prev => {
                    const next = new Set(prev)
                    if (next.has(c)) { next.delete(c); return next.size === 0 ? new Set() : next }
                    next.add(c); return next
                  })}
                  className={`badge cursor-pointer select-none transition-colors truncate max-w-[140px] ${
                    activeComputers.has(c)
                      ? 'bg-indigo-100 text-indigo-700 border-indigo-200'
                      : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                  }`}
                  title={c}
                >
                  {c}
                </button>
              ))}
            </div>
          )}

          {/* Channel filter — only shown when >1 channel */}
          {allChannels.length > 1 && (
            <div className="px-4 py-2 flex items-start gap-1.5 flex-wrap">
              <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider w-10 flex-shrink-0 mt-0.5">
                Chan
              </span>
              <button
                onClick={() => setActiveChannels(new Set())}
                className={`badge cursor-pointer select-none transition-colors ${
                  activeChannels.size === 0
                    ? 'bg-gray-600 text-white border-gray-500'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
              >
                All
              </button>
              {allChannels.map(ch => (
                <button
                  key={ch}
                  onClick={() => setActiveChannels(prev => {
                    const next = new Set(prev)
                    if (next.has(ch)) { next.delete(ch); return next.size === 0 ? new Set() : next }
                    next.add(ch); return next
                  })}
                  className={`badge cursor-pointer select-none transition-colors truncate max-w-[180px] ${
                    activeChannels.has(ch)
                      ? 'bg-teal-100 text-teal-700 border-teal-200'
                      : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                  }`}
                  title={ch}
                >
                  {ch.replace(/^Microsoft-Windows-/, '')}
                </button>
              ))}
            </div>
          )}

          {/* MITRE ATT&CK tags filter — only shown when tags exist */}
          {allTags.length > 0 && (
            <div className="px-4 py-2 flex items-start gap-1.5 flex-wrap">
              <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider w-10 flex-shrink-0 mt-0.5">
                Tags
              </span>
              <button
                onClick={() => setActiveTags(new Set())}
                className={`badge cursor-pointer select-none transition-colors ${
                  activeTags.size === 0
                    ? 'bg-gray-600 text-white border-gray-500'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
              >
                All
              </button>
              {allTags.map(tag => (
                <button
                  key={tag}
                  onClick={() => setActiveTags(prev => {
                    const next = new Set(prev)
                    if (next.has(tag)) { next.delete(tag); return next.size === 0 ? new Set() : next }
                    next.add(tag); return next
                  })}
                  className={`badge cursor-pointer select-none transition-colors truncate max-w-[180px] font-mono ${
                    activeTags.has(tag)
                      ? 'bg-purple-100 text-purple-700 border-purple-200'
                      : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                  }`}
                  title={tag}
                >
                  {tag.replace(/^attack\./, '')}
                </button>
              ))}
            </div>
          )}

          {/* Clear all filters */}
          {hasActiveFilters && (
            <div className="px-4 py-1.5 flex justify-end">
              <button
                onClick={() => {
                  setModuleFilter(''); setDateFrom(''); setDateTo(''); setFlaggedOnly(false)
                  setActiveLevels(new Set()); setRuleSearch(''); setActiveComputers(new Set())
                  setActiveChannels(new Set()); setActiveTags(new Set())
                }}
                className="text-[10px] text-brand-accent hover:underline"
              >
                Clear all filters
              </button>
            </div>
          )}
        </div>}

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
          ) : filteredRuns.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Filter size={28} className="text-gray-300 mb-3" />
              <p className="font-medium text-gray-500">No runs match the filters</p>
              <button
                onClick={() => {
                  setModuleFilter(''); setDateFrom(''); setDateTo(''); setFlaggedOnly(false)
                  setActiveLevels(new Set()); setRuleSearch(''); setActiveComputers(new Set())
                  setActiveChannels(new Set()); setActiveTags(new Set())
                }}
                className="mt-2 text-xs text-brand-accent hover:underline"
              >
                Clear all filters
              </button>
            </div>
          ) : (
            filteredRuns.map(run => (
              <ModuleRunCard
                key={run.run_id}
                run={run}
                caseId={caseId}
                navigate={navigate}
                activeLevels={activeLevels}
                activeComputers={activeComputers}
                activeChannels={activeChannels}
                activeTags={activeTags}
                ruleSearch={ruleSearch}
                onResetFilter={() => {
                  setActiveLevels(new Set()); setRuleSearch(''); setActiveComputers(new Set())
                  setActiveChannels(new Set()); setActiveTags(new Set())
                }}
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
  const [showAlertRules, setShowAlertRules] = useState(false)
  const [showNotes, setShowNotes]           = useState(false)
  const [jobSummary, setJobSummary]         = useState({ active: 0, failed: 0, eventsPerSec: null, totalEvents: 0 })
  const prevJobSnap                         = useRef(null)

  // Poll job counts + compute live events/s rate when the IngestPanel is closed.
  // Suspended while the panel is open — IngestPanel runs its own 3 s batch poller.
  useEffect(() => {
    if (showIngest) return
    prevJobSnap.current = null  // discard stale baseline on each poller start
    const ACTIVE = new Set(['RUNNING', 'PENDING', 'UPLOADING'])
    async function fetchSummary() {
      try {
        const r    = await api.ingest.listJobs(caseId)
        const jobs = r.jobs || []
        const now  = Date.now()

        // Sum events_indexed only across RUNNING jobs so that already-completed
        // jobs don't inflate the baseline and produce a false rate spike.
        const totalEvents = jobs
          .filter(j => j.status === 'RUNNING')
          .reduce((s, j) => s + (parseInt(j.events_indexed) || 0), 0)

        // Rate is undefined on the first sample (no baseline to diff against).
        let eventsPerSec = null
        if (prevJobSnap.current !== null) {
          const elapsed = (now - prevJobSnap.current.ts) / 1000
          if (elapsed > 0)
            eventsPerSec = Math.max(0, Math.round((totalEvents - prevJobSnap.current.total) / elapsed))
        }
        prevJobSnap.current = { total: totalEvents, ts: now }

        setJobSummary({
          active:      jobs.filter(j => ACTIVE.has(j.status)).length,
          failed:      jobs.filter(j => j.status === 'FAILED').length,
          totalEvents,
          eventsPerSec,
        })
      } catch { /* silent */ }
    }
    fetchSummary()
    const id = setInterval(fetchSummary, 3000)
    return () => clearInterval(id)
  }, [caseId, showIngest])

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
            {jobSummary.active > 0 && (
              <span className="ml-1 flex items-center gap-1 bg-white/20 rounded px-1.5 py-px text-[10px] font-mono leading-none">
                <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse flex-shrink-0" />
                {jobSummary.active}
                {jobSummary.eventsPerSec !== null && (
                  <span className="opacity-75">
                    {' · '}{jobSummary.eventsPerSec > 0
                      ? `${jobSummary.eventsPerSec.toLocaleString()} ev/s`
                      : 'indexing…'}
                  </span>
                )}
              </span>
            )}
            {jobSummary.failed > 0 && (
              <span className="ml-1 bg-red-500 rounded px-1.5 py-px text-[10px] font-mono">
                ⚠ {jobSummary.failed}
              </span>
            )}
          </button>

          <button
            onClick={() => navigate(`/cases/${caseId}/search`)}
            className="btn-outline"
          >
            <Search size={14} />
            Search
          </button>

          <button
            onClick={() => setShowNotes(v => !v)}
            className={`btn-outline ${showNotes ? 'bg-brand-accentlight border-brand-accent text-brand-accent' : ''}`}
          >
            <FileText size={14} />
            Notes
          </button>

          <button
            onClick={() => setShowAlertRules(v => !v)}
            className={`btn-outline ${showAlertRules ? 'bg-yellow-50 border-yellow-300 text-yellow-700' : ''}`}
          >
            <Bell size={14} />
            Alert Rules
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
              <Clock size={14} />
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
        <IngestPanel
          caseId={caseId}
          onClose={() => setShowIngest(false)}
          onComplete={() => loadCase()}
        />
      )}

      {showNotes && (
        <div className="panel-backdrop" onClick={() => setShowNotes(false)}>
          <div
            className="absolute right-0 top-0 h-full w-[560px] bg-white border-l border-gray-200 flex flex-col"
            style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
              <div className="flex items-center gap-2">
                <FileText size={16} className="text-brand-accent" />
                <span className="font-semibold text-brand-text">Investigator Notes</span>
              </div>
              <button onClick={() => setShowNotes(false)} className="btn-ghost p-1.5 rounded-lg">
                <X size={16} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto">
              <CaseNotes caseId={caseId} />
            </div>
          </div>
        </div>
      )}

      {showAlertRules && (
        <div className="panel-backdrop" onClick={() => setShowAlertRules(false)}>
          <div
            className="absolute right-0 top-0 h-full w-[760px] bg-white border-l border-gray-200 flex flex-col overflow-y-auto"
            style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200 flex-shrink-0">
              <div className="flex items-center gap-2">
                <Bell size={15} className="text-yellow-500" />
                <span className="font-semibold text-brand-text text-sm">Alert Rules</span>
              </div>
              <button onClick={() => setShowAlertRules(false)} className="btn-ghost p-1.5 rounded-lg">
                <X size={16} />
              </button>
            </div>
            <AlertRules
              caseId={caseId}
              onSearchQuery={q => {
                setShowAlertRules(false)
                navigate(`/cases/${caseId}/search`, { state: { pivotQuery: q } })
              }}
            />
          </div>
        </div>
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
