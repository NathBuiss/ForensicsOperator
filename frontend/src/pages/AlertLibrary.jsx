import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Bell, Plus, Trash2, ChevronDown, ChevronUp, Pencil, Check, X,
  AlertTriangle, Loader2, Search, Play, CheckCircle, Clock, RefreshCw,
  ExternalLink, Filter, Tag, Upload, FileCode, Sparkles, Bot, Info,
  ShieldAlert, Code2,
} from 'lucide-react'
import { api } from '../api/client'
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts'

// ── Category metadata ──────────────────────────────────────────────────────────
const CATEGORY_ORDER = [
  'Anti-Forensics',
  'Authentication',
  'Privilege Escalation',
  'Persistence',
  'Execution',
  'Lateral Movement',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Command & Control',
  'Exfiltration',
  'Other',
]

const CATEGORY_STYLES = {
  'Anti-Forensics':    { bg: 'bg-rose-100 text-rose-700 border-rose-200',    dot: 'bg-rose-400'    },
  'Authentication':    { bg: 'bg-blue-100 text-blue-700 border-blue-200',     dot: 'bg-blue-400'    },
  'Privilege Escalation': { bg: 'bg-orange-100 text-orange-700 border-orange-200', dot: 'bg-orange-400' },
  'Persistence':       { bg: 'bg-yellow-100 text-yellow-700 border-yellow-200', dot: 'bg-yellow-500' },
  'Execution':         { bg: 'bg-purple-100 text-purple-700 border-purple-200', dot: 'bg-purple-400' },
  'Lateral Movement':  { bg: 'bg-cyan-100 text-cyan-700 border-cyan-200',     dot: 'bg-cyan-400'    },
  'Defense Evasion':   { bg: 'bg-slate-100 text-slate-700 border-slate-200',  dot: 'bg-slate-400'   },
  'Credential Access': { bg: 'bg-red-100 text-red-700 border-red-200',        dot: 'bg-red-400'     },
  'Discovery':         { bg: 'bg-teal-100 text-teal-700 border-teal-200',     dot: 'bg-teal-400'    },
  'Command & Control': { bg: 'bg-indigo-100 text-indigo-700 border-indigo-200', dot: 'bg-indigo-400' },
  'Exfiltration':      { bg: 'bg-pink-100 text-pink-700 border-pink-200',     dot: 'bg-pink-400'    },
  'Other':             { bg: 'bg-gray-100 text-gray-600 border-gray-200',     dot: 'bg-gray-400'    },
}

const SIGMA_LEVEL_STYLES = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high:     'bg-orange-100 text-orange-700 border-orange-200',
  medium:   'bg-yellow-100 text-yellow-700 border-yellow-200',
  low:      'bg-blue-100 text-blue-700 border-blue-200',
  info:     'bg-gray-100 text-gray-600 border-gray-200',
}

function CategoryBadge({ category }) {
  if (!category) return null
  const style = CATEGORY_STYLES[category] || CATEGORY_STYLES['Other']
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-medium border rounded-full px-2 py-0.5 ${style.bg}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${style.dot}`} />
      {category}
    </span>
  )
}

function SigmaLevelBadge({ level }) {
  if (!level) return null
  const cls = SIGMA_LEVEL_STYLES[level.toLowerCase()] || SIGMA_LEVEL_STYLES.info
  return (
    <span className={`inline-flex items-center text-[10px] font-medium border rounded-full px-2 py-0.5 ${cls}`}>
      {level}
    </span>
  )
}

// ── Unified Sigma Rule Modal (create + edit) ──────────────────────────────────
// mode='create' → imports as new rule via importSigma
// mode='edit'   → parses YAML then updates existing rule via updateLibraryRule
function SigmaRuleModal({ rule = null, onClose, onSaved }) {
  const isEdit = !!rule
  const fileRef = useRef(null)

  const [yamlText, setYamlText]       = useState(rule?.sigma_yaml || '')
  const [saving, setSaving]           = useState(false)
  const [error, setError]             = useState('')
  const [result, setResult]           = useState(null)   // import result message

  // AI generation state
  const [showAI, setShowAI]           = useState(false)
  const [aiDesc, setAiDesc]           = useState('')
  const [aiCtx,  setAiCtx]           = useState('')
  const [aiLoading, setAiLoading]     = useState(false)
  const [aiError, setAiError]         = useState('')

  function handleFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => setYamlText(ev.target.result || '')
    reader.readAsText(file)
  }

  async function generateWithAI() {
    if (!aiDesc.trim()) return
    setAiLoading(true)
    setAiError('')
    try {
      const res = await api.alertRules.generateRule({ description: aiDesc, context: aiCtx })
      setYamlText(res.yaml || '')
      setShowAI(false)
      setAiDesc('')
      setAiCtx('')
    } catch (err) {
      setAiError(err.message)
    } finally {
      setAiLoading(false)
    }
  }

  async function doSave() {
    if (!yamlText.trim()) return
    setSaving(true)
    setError('')
    setResult(null)
    try {
      if (isEdit) {
        // Parse the YAML first to derive ES query + metadata
        const parsed = await api.alertRules.parseSigma({ yaml: yamlText })
        const updated = await api.alertRules.updateLibraryRule(rule.id, {
          name:          parsed.name,
          description:   parsed.description,
          category:      parsed.category,
          artifact_type: parsed.artifact_type,
          query:         parsed.query,
          sigma_yaml:    yamlText,
        })
        onSaved(updated)
        onClose()
      } else {
        const res = await api.alertRules.importSigma({ yaml: yamlText })
        if (res.imported > 0) {
          onSaved(res.rules)
          onClose()
        } else {
          // Surface specific skip reasons returned by the API
          const reasons = res.skip_reasons?.map(r => r.reason) || []
          setResult({ skipped: res.skipped, reasons })
        }
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  const placeholder = `title: Suspicious PowerShell Execution
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    CommandLine|contains: 'powershell'
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059.001`

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white border border-gray-200 rounded-xl w-full max-w-2xl shadow-2xl flex flex-col"
        style={{ maxHeight: '90vh' }}>

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <FileCode size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text text-sm">
              {isEdit ? 'Edit Sigma Rule' : 'New Sigma Rule'}
            </span>
            {isEdit && rule.sigma_level && <SigmaLevelBadge level={rule.sigma_level} />}
          </div>
          <button onClick={onClose} className="btn-ghost p-1"><X size={14} /></button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-3 overflow-y-auto flex-1">

          {/* AI generation panel */}
          {showAI ? (
            <div className="bg-indigo-50 border border-indigo-200 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles size={14} className="text-indigo-500" />
                  <span className="text-xs font-semibold text-indigo-700">Generate with AI</span>
                </div>
                <button onClick={() => setShowAI(false)} className="btn-ghost p-0.5 text-indigo-400 hover:text-indigo-600">
                  <X size={13} />
                </button>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  What should this rule detect? <span className="text-red-400">*</span>
                </label>
                <textarea
                  value={aiDesc}
                  onChange={e => setAiDesc(e.target.value)}
                  placeholder="e.g. Detect brute-force login attempts — multiple failed Windows logon events in a short period"
                  className="input text-xs w-full resize-none"
                  rows={3}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  Additional context <span className="text-gray-400 font-normal">(optional)</span>
                </label>
                <input
                  value={aiCtx}
                  onChange={e => setAiCtx(e.target.value)}
                  placeholder="e.g. Windows event logs, EventID 4625, TargetUserName field"
                  className="input text-xs w-full"
                />
              </div>
              {aiError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <X size={12} /> {aiError}
                </p>
              )}
              <button
                onClick={generateWithAI}
                disabled={!aiDesc.trim() || aiLoading}
                className="btn-primary text-xs"
              >
                {aiLoading ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
                {aiLoading ? 'Generating…' : 'Generate Sigma YAML'}
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowAI(true)}
                className="btn-outline text-xs flex items-center gap-1.5"
              >
                <Sparkles size={13} className="text-indigo-500" /> Generate with AI
              </button>
              <span className="text-gray-300 text-xs">or</span>
              <input ref={fileRef} type="file" accept=".yml,.yaml" className="hidden" onChange={handleFile} />
              <button
                onClick={() => fileRef.current?.click()}
                className="btn-outline text-xs"
              >
                <Upload size={13} /> Upload .yml file
              </button>
              {!isEdit && (
                <span className="text-xs text-gray-400 ml-auto flex items-center gap-1">
                  <Info size={11} /> paste Sigma YAML below
                </span>
              )}
            </div>
          )}

          {/* YAML editor */}
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1 flex items-center gap-1">
              <Code2 size={12} /> Sigma Rule YAML
            </label>
            <textarea
              value={yamlText}
              onChange={e => setYamlText(e.target.value)}
              placeholder={placeholder}
              className="input font-mono text-xs w-full resize-none"
              rows={16}
              spellCheck={false}
            />
          </div>

          {error && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <X size={12} /> {error}
            </p>
          )}

          {result && (
            <div className="text-xs rounded-lg border p-3 bg-amber-50 border-amber-200 text-amber-700 space-y-1.5">
              <p className="font-semibold flex items-center gap-1">
                <AlertTriangle size={12} />
                Rule could not be imported ({result.skipped} skipped)
              </p>
              {result.reasons?.map((r, i) => (
                <p key={i} className="text-amber-800 pl-4">• {r}</p>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-4 border-t border-gray-200 flex-shrink-0 flex items-center gap-2">
          <button
            onClick={doSave}
            disabled={!yamlText.trim() || saving}
            className="btn-primary text-xs"
          >
            {saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
            {isEdit ? 'Save Changes' : 'Import Rule'}
          </button>
          <button onClick={onClose} className="btn-ghost text-xs">Cancel</button>
        </div>
      </div>
    </div>
  )
}

// ── AI Analysis panel (shown inside RunOnCaseModal after a firing result) ──────
function AiAnalysisPanel({ rule, result }) {
  const [loading,  setLoading]  = useState(false)
  const [analysis, setAnalysis] = useState(null)
  const [error,    setError]    = useState('')

  async function analyze() {
    setLoading(true)
    setError('')
    setAnalysis(null)
    try {
      const sampleEvents = result.match?.sample_events || []
      const res = await api.alertRules.analyzeResult({
        rule_name:    rule.name,
        rule_query:   rule.query,
        match_count:  result.match?.match_count || 0,
        sample_events: sampleEvents,
      })
      setAnalysis(res.analysis || res.message || JSON.stringify(res))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="border border-indigo-200 rounded-lg bg-indigo-50 p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-indigo-700">
          <Bot size={13} /> AI Analysis
        </div>
        {!analysis && (
          <button onClick={analyze} disabled={loading} className="btn-primary text-xs py-1 px-2.5">
            {loading ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
            {loading ? 'Analyzing…' : 'Analyze with AI'}
          </button>
        )}
      </div>
      {error && <p className="text-xs text-red-600">{error}</p>}
      {analysis && (
        <div className="text-xs text-indigo-900 leading-relaxed whitespace-pre-wrap bg-white border border-indigo-100 rounded-lg p-3 max-h-64 overflow-y-auto">
          {analysis}
        </div>
      )}
    </div>
  )
}

// ── Run on Case modal ─────────────────────────────────────────────────────────
function RunOnCaseModal({ rule, cases, onClose }) {
  const navigate = useNavigate()
  const [running, setRunning]     = useState(false)
  const [result, setResult]       = useState(null)
  const [error, setError]         = useState('')
  const [selectedCase, setSelectedCase] = useState('')

  async function run() {
    if (!selectedCase) return
    setRunning(true)
    setResult(null)
    setError('')
    try {
      const r = await api.alertRules.runSingleRule(selectedCase, rule.id)
      setResult(r)
    } catch (err) {
      setError(err.message)
    } finally {
      setRunning(false)
    }
  }

  function goToSearch(q) {
    onClose()
    navigate(`/cases/${selectedCase}/search`, { state: { pivotQuery: q } })
  }

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl w-full max-w-md shadow-2xl flex flex-col"
        style={{ maxHeight: '90vh' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Play size={15} className="text-brand-accent" />
            <span className="font-semibold text-brand-text text-sm">Run Rule on Case</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1"><X size={14} /></button>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto flex-1">
          {/* Rule summary */}
          <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <p className="text-xs font-semibold text-brand-text">{rule.name}</p>
              {rule.category && <CategoryBadge category={rule.category} />}
              {rule.sigma_level && <SigmaLevelBadge level={rule.sigma_level} />}
            </div>
            <code className="block text-xs text-gray-500 font-mono break-all">{rule.query}</code>
          </div>

          {/* Case picker */}
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Target Case</label>
            <select className="input" value={selectedCase} onChange={e => setSelectedCase(e.target.value)}>
              <option value="">Select a case…</option>
              {cases.map(c => (
                <option key={c.case_id} value={c.case_id}>{c.name}</option>
              ))}
            </select>
          </div>

          <button onClick={run} disabled={!selectedCase || running} className="btn-primary w-full justify-center">
            {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            {running ? 'Running…' : 'Run Rule'}
          </button>

          {error && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>
          )}

          {result && (
            <div className={`rounded-lg border p-3 space-y-2 ${result.fired ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}`}>
              {result.fired ? (
                <>
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-xs font-semibold text-red-700 flex items-center gap-1">
                      <AlertTriangle size={12} /> {result.match.match_count.toLocaleString()} matches found
                    </p>
                    <button
                      onClick={() => goToSearch(rule.query)}
                      className="flex items-center gap-1 text-xs text-brand-accent hover:text-brand-accenthover font-medium"
                    >
                      View all in Search <ExternalLink size={11} />
                    </button>
                  </div>
                  {result.match.sample_events?.map((ev, i) => (
                    <button
                      key={i}
                      onClick={() => ev.fo_id ? goToSearch(`fo_id:${ev.fo_id}`) : goToSearch(rule.query)}
                      className="w-full text-left bg-white hover:bg-blue-50 rounded border border-red-100 hover:border-blue-300 p-2 transition-colors group"
                      title="Click to view this event in Search"
                    >
                      <div className="flex items-center justify-between gap-1">
                        <p className="text-[10px] text-gray-500 font-mono flex items-center gap-1">
                          <Clock size={9} />{ev.timestamp || '—'}
                        </p>
                        <ExternalLink size={9} className="text-gray-300 group-hover:text-blue-400 flex-shrink-0 transition-colors" />
                      </div>
                      <p className="text-xs text-gray-700 mt-0.5">{ev.message || '—'}</p>
                    </button>
                  ))}
                  {/* AI Analysis (only shown after a firing result) */}
                  <AiAnalysisPanel rule={rule} result={result} />
                </>
              ) : (
                <p className="text-xs text-green-700 flex items-center gap-1">
                  <CheckCircle size={12} /> No matches — rule did not fire
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Library rule card ─────────────────────────────────────────────────────────
function LibraryRuleCard({ rule, cases, onDelete, onUpdated }) {
  const [expanded, setExpanded] = useState(false)
  const [showEdit, setShowEdit] = useState(false)
  const [showRun,  setShowRun]  = useState(false)

  return (
    <>
      {showRun  && <RunOnCaseModal rule={rule} cases={cases} onClose={() => setShowRun(false)} />}
      {showEdit && (
        <SigmaRuleModal
          rule={rule}
          onClose={() => setShowEdit(false)}
          onSaved={updated => { onUpdated(updated); setShowEdit(false) }}
        />
      )}
      <div className="card overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3">
          <AlertTriangle size={15} className="text-amber-500 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-medium text-brand-text text-sm">{rule.name}</span>
              {rule.category    && <CategoryBadge category={rule.category} />}
              {rule.sigma_level && <SigmaLevelBadge level={rule.sigma_level} />}
              {rule.artifact_type && (
                <span className={`badge badge-${rule.artifact_type}`}>{rule.artifact_type}</span>
              )}
              <span className="text-xs text-gray-400">threshold ≥{rule.threshold}</span>
              {rule.sigma_yaml && (
                <span className="badge bg-indigo-50 text-indigo-600 border-indigo-200 text-[10px]">
                  <FileCode size={9} className="mr-0.5" /> Sigma
                </span>
              )}
            </div>
            {rule.description && (
              <p className="text-xs text-gray-500 truncate">{rule.description}</p>
            )}
          </div>
          <div className="flex items-center gap-1 flex-shrink-0">
            <button
              onClick={() => setShowRun(true)}
              className="btn-ghost px-2 py-1.5 text-xs text-brand-accent hover:text-brand-accenthover"
              title="Run on a case"
            >
              <Play size={13} />
            </button>
            <button
              onClick={() => setShowEdit(true)}
              className="btn-ghost px-2 py-1.5 text-xs"
              title="Edit rule as Sigma YAML"
            >
              <Pencil size={13} />
            </button>
            <button
              onClick={() => setExpanded(v => !v)}
              className="btn-ghost px-2 py-1.5 text-xs"
            >
              {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
            <button
              onClick={() => onDelete(rule.id)}
              className="btn-danger px-2 py-1.5"
              title="Delete rule"
            >
              <Trash2 size={13} />
            </button>
          </div>
        </div>

        {expanded && (
          <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-3">
            {/* ES Query */}
            <div>
              <p className="text-xs text-gray-500 mb-1">Elasticsearch Query</p>
              <code className="block text-xs font-mono text-brand-text bg-white border border-gray-200
                               rounded px-3 py-2 break-all">
                {rule.query}
              </code>
            </div>
            {/* Sigma YAML */}
            {rule.sigma_yaml && (
              <div>
                <p className="text-xs text-gray-500 mb-1 flex items-center gap-1">
                  <FileCode size={11} /> Sigma YAML
                </p>
                <pre className="text-[11px] font-mono text-gray-700 bg-white border border-gray-200
                                 rounded px-3 py-2 overflow-x-auto max-h-48 overflow-y-auto">
                  {rule.sigma_yaml}
                </pre>
              </div>
            )}
            {/* Tags */}
            {rule.sigma_tags?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {rule.sigma_tags.map(t => (
                  <span key={t} className="badge bg-gray-100 text-gray-500 border border-gray-200 font-mono">
                    {t}
                  </span>
                ))}
              </div>
            )}
            {rule.created_at && (
              <p className="text-xs text-gray-400">
                Added {new Date(rule.created_at).toLocaleDateString()}
              </p>
            )}
          </div>
        )}
      </div>
    </>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function AlertLibrary() {
  const [rules, setRules]     = useState([])
  const [cases, setCases]     = useState([])
  const [loading, setLoading] = useState(true)
  const [seeding, setSeeding]   = useState(false)
  const [seedMsg, setSeedMsg]   = useState(null)
  const [showSigmaModal, setShowSigmaModal] = useState(false)
  const [search, setSearch]             = useState('')
  const [artifactFilter, setArtifactFilter] = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const searchRef = useRef(null)

  useKeyboardShortcuts([
    { key: '/', handler: () => searchRef.current?.focus() },
  ])

  const artifactTypes = useMemo(
    () => ['all', ...new Set(rules.map(r => r.artifact_type).filter(Boolean))],
    [rules]
  )

  const presentCategories = useMemo(() => {
    const cats = new Set(rules.map(r => r.category || 'Other').filter(Boolean))
    return ['all', ...CATEGORY_ORDER.filter(c => cats.has(c))]
  }, [rules])

  const filteredRules = useMemo(() => {
    const q = search.toLowerCase()
    return rules.filter(r => {
      const textMatch = !q ||
        (r.name || '').toLowerCase().includes(q) ||
        (r.description || '').toLowerCase().includes(q)
      const artifactMatch = artifactFilter === 'all' || r.artifact_type === artifactFilter
      const cat = r.category || 'Other'
      const categoryMatch = categoryFilter === 'all' || cat === categoryFilter
      return textMatch && artifactMatch && categoryMatch
    })
  }, [rules, search, artifactFilter, categoryFilter])

  const groupedRules = useMemo(() => {
    const groups = new Map()
    for (const cat of CATEGORY_ORDER) {
      const items = filteredRules.filter(r => (r.category || 'Other') === cat)
      if (items.length > 0) groups.set(cat, items)
    }
    const known = new Set(CATEGORY_ORDER)
    const uncategorized = filteredRules.filter(r => !known.has(r.category || 'Other'))
    if (uncategorized.length > 0) {
      groups.set('Other', [...(groups.get('Other') || []), ...uncategorized])
    }
    return groups
  }, [filteredRules])

  const hasFilters = search || artifactFilter !== 'all' || categoryFilter !== 'all'

  const loadRules = useCallback(() => {
    api.alertRules.listLibrary()
      .then(r => setRules(r.rules || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    loadRules()
    api.cases.list().then(r => setCases(r.cases || [])).catch(() => {})
  }, [loadRules])

  async function seedDefaults(replace = false) {
    setSeeding(true)
    setSeedMsg(null)
    try {
      const r = await api.alertRules.seedLibrary(replace)
      setSeedMsg(r)
      loadRules()
      setTimeout(() => setSeedMsg(null), 4000)
    } catch (err) {
      console.error(err)
    } finally {
      setSeeding(false)
    }
  }

  function handleUpdated(updated) {
    setRules(prev => prev.map(r => r.id === updated.id ? updated : r))
  }

  async function deleteRule(id) {
    if (!confirm('Delete this rule?')) return
    try {
      await api.alertRules.deleteLibraryRule(id)
      setRules(prev => prev.filter(r => r.id !== id))
    } catch (err) {
      console.error(err)
    }
  }

  function clearFilters() {
    setSearch('')
    setArtifactFilter('all')
    setCategoryFilter('all')
  }

  return (
    <div className="p-6 max-w-4xl">

      {/* Page header */}
      <div className="mb-6">
        <div className="flex items-center gap-2.5 mb-1">
          <Bell size={20} className="text-brand-accent" />
          <h1 className="text-xl font-bold text-brand-text">Detection Rules</h1>
        </div>
        <p className="text-sm text-gray-500">
          Sigma-based detection rules. Use <Play size={11} className="inline" /> to run a rule on any case,
          or use <strong className="text-brand-text">Run Alerts</strong> on the case timeline to run all rules.
        </p>
      </div>

      {/* Library section */}
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <Search size={14} className="text-gray-500" />
          <h2 className="font-semibold text-brand-text">Library</h2>
          {!loading && (
            <span className="badge-pill bg-gray-100 text-gray-600">{rules.length}</span>
          )}
          <div className="ml-auto flex items-center gap-2">
            {seedMsg && (
              <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-3 py-1 flex items-center gap-1">
                <CheckCircle size={11} />
                {seedMsg.added > 0
                  ? `${seedMsg.added} rule${seedMsg.added !== 1 ? 's' : ''} added (${seedMsg.total} total)`
                  : 'Already up to date'}
              </span>
            )}
            <button
              onClick={() => setShowSigmaModal(true)}
              className="btn-primary text-xs"
            >
              <Plus size={13} /> New Rule
            </button>
            <button
              onClick={() => seedDefaults(false)}
              disabled={seeding}
              className="btn-outline text-xs"
              title="Append any built-in defaults not already in the library"
            >
              {seeding ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
              Load Defaults
            </button>
          </div>
        </div>

        {/* New Sigma Rule modal */}
        {showSigmaModal && (
          <SigmaRuleModal
            onClose={() => setShowSigmaModal(false)}
            onSaved={newRules => {
              // importSigma returns an array
              const arr = Array.isArray(newRules) ? newRules : [newRules]
              setRules(prev => [...prev, ...arr])
              setShowSigmaModal(false)
            }}
          />
        )}

        {/* Category pill filter row */}
        {!loading && rules.length > 0 && presentCategories.length > 2 && (
          <div className="flex items-center gap-1.5 mb-3 flex-wrap">
            <Tag size={12} className="text-gray-400 flex-shrink-0" />
            {presentCategories.map(cat => {
              const isActive = categoryFilter === cat
              const style = cat !== 'all' ? CATEGORY_STYLES[cat] || CATEGORY_STYLES['Other'] : null
              return (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  className={`inline-flex items-center gap-1 text-[11px] font-medium border rounded-full px-2.5 py-0.5 transition-colors ${
                    isActive
                      ? cat === 'all'
                        ? 'bg-gray-800 text-white border-gray-800'
                        : `${style.bg} border-current ring-1 ring-current ring-offset-1`
                      : 'bg-white text-gray-500 border-gray-200 hover:border-gray-400'
                  }`}
                >
                  {cat !== 'all' && <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${style.dot}`} />}
                  {cat === 'all' ? 'All categories' : cat}
                </button>
              )
            })}
          </div>
        )}

        {/* Search + artifact filter row */}
        {!loading && rules.length > 0 && (
          <div className="flex items-center gap-2 mb-3">
            <div className="relative flex-1">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
              <input
                ref={searchRef}
                className="input pl-8 text-xs"
                placeholder="Search rules… (press / to focus)"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            {artifactTypes.length > 2 && (
              <select
                className="input text-xs max-w-[140px]"
                value={artifactFilter}
                onChange={e => setArtifactFilter(e.target.value)}
              >
                {artifactTypes.map(a => (
                  <option key={a} value={a}>{a === 'all' ? 'All artifacts' : a}</option>
                ))}
              </select>
            )}
            {hasFilters && (
              <button onClick={clearFilters} className="btn-ghost text-xs flex items-center gap-1">
                <X size={12} /> Clear
              </button>
            )}
          </div>
        )}

        {/* Rule list */}
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map(i => <div key={i} className="skeleton h-14 w-full" />)}
          </div>
        ) : rules.length === 0 ? (
          <div className="card p-10 text-center">
            <ShieldAlert size={28} className="text-gray-300 mx-auto mb-3" />
            <p className="text-gray-600 text-sm font-medium mb-1">No rules in library</p>
            <p className="text-gray-400 text-xs mb-4">
              Create a rule with <strong>New Rule</strong>, or load the built-in defaults.
            </p>
            <button onClick={() => seedDefaults(false)} disabled={seeding} className="btn-outline text-xs mx-auto">
              {seeding ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
              Load Default Rules
            </button>
          </div>
        ) : filteredRules.length === 0 ? (
          <div className="card p-8 text-center">
            <Filter size={22} className="text-gray-300 mx-auto mb-2" />
            <p className="text-gray-500 text-sm">No rules match the current filters.</p>
            <button onClick={clearFilters} className="btn-ghost text-xs mt-2">
              <X size={12} /> Clear filters
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {[...groupedRules.entries()].map(([cat, items]) => (
              <div key={cat}>
                <div className="flex items-center gap-2 mb-2">
                  <CategoryBadge category={cat} />
                  <span className="text-xs text-gray-400">{items.length}</span>
                </div>
                <div className="space-y-2">
                  {items.map(rule => (
                    <LibraryRuleCard
                      key={rule.id}
                      rule={rule}
                      cases={cases}
                      onDelete={deleteRule}
                      onUpdated={handleUpdated}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
