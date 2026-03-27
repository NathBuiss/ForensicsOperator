import { useState, useEffect } from 'react'
import { AlertTriangle, Plus, Trash2, Play, CheckCircle, Loader2,
         ChevronDown, ChevronUp, Sparkles, Brain, RefreshCw, Clock } from 'lucide-react'
import { api } from '../api/client'

function LibraryRulesList({ rules }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="mb-4 border border-gray-200 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-3 py-2.5 bg-gray-50 hover:bg-gray-100 transition-colors text-xs"
      >
        <span className="flex items-center gap-1.5 font-semibold text-gray-600">
          <Play size={9} className="text-brand-accent" />
          Library Rules — run by "Check All"
        </span>
        <span className="flex items-center gap-2 text-gray-500">
          <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[9px]">{rules.length} rules</span>
          {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </span>
      </button>
      {open && (
        <div className="max-h-64 overflow-y-auto divide-y divide-gray-100">
          {rules.map(rule => (
            <div key={rule.id} className="flex items-center gap-2 px-3 py-1.5 text-xs">
              <AlertTriangle size={9} className="text-amber-500 flex-shrink-0" />
              <span className="text-gray-700 truncate flex-1">{rule.name}</span>
              {rule.artifact_type && (
                <span className="text-[9px] text-gray-500 flex-shrink-0">{rule.artifact_type}</span>
              )}
              <span className="text-gray-400 text-[9px] flex-shrink-0">≥{rule.threshold}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AlertRules({ caseId }) {
  const [rules, setRules]             = useState([])
  const [libraryRules, setLibraryRules] = useState([])
  const [loading, setLoading]         = useState(true)
  const [checking, setChecking]       = useState(false)
  const [run, setRun]                 = useState(null)   // full run: {ran_at, rules_checked, matches, analyses}
  const [showForm, setShowForm]       = useState(false)
  const [form, setForm]               = useState({ name:'', description:'', artifact_type:'', query:'', threshold:1 })
  const [expandedMatch, setExpandedMatch] = useState(null)
  // analyses keyed by rule_id; separate from run.analyses so UI updates in-place
  const [analyses, setAnalyses]           = useState({})
  // Set of rule IDs currently being (re-)analyzed
  const [analyzingIds, setAnalyzingIds]   = useState(new Set())
  // AI rule generation
  const [aiDesc, setAiDesc]           = useState('')
  const [generating, setGenerating]   = useState(false)
  const [showAiForm, setShowAiForm]   = useState(false)

  // ── Load on mount ─────────────────────────────────────────────────────────

  useEffect(() => {
    api.alertRules.list(caseId)
      .then(r => setRules(r.rules || []))
      .catch(() => {})
      .finally(() => setLoading(false))

    // Load global library rules (these are what Check All runs against)
    api.alertRules.listLibrary()
      .then(r => setLibraryRules(r.rules || []))
      .catch(() => {})

    // Restore last run + analyses from Redis (survives page refresh)
    api.alertRules.lastRun(caseId)
      .then(saved => {
        if (saved?.ran_at) {
          setRun(saved)
          setAnalyses(saved.analyses || {})
        }
      })
      .catch(() => {})
  }, [caseId])

  // ── Rule management ───────────────────────────────────────────────────────

  async function createRule(e) {
    e.preventDefault()
    if (!form.name.trim() || !form.query.trim()) return
    const r = await api.alertRules.create(caseId, form)
    setRules(p => [...p, r])
    setForm({ name:'', description:'', artifact_type:'', query:'', threshold:1 })
    setShowForm(false)
  }

  async function deleteRule(id) {
    await api.alertRules.delete(caseId, id)
    setRules(p => p.filter(r => r.id !== id))
  }

  // ── Check + auto-analyze ──────────────────────────────────────────────────

  async function checkRules() {
    setChecking(true)
    setAnalyses({})
    try {
      // Run all library rules against this case (same rules visible on /alert-rules page)
      const freshRun = await api.alertRules.runLibrary(caseId)
      setRun(freshRun)
      // Auto-analyze every triggered match in parallel (fire-and-forget)
      if (freshRun.matches?.length) {
        analyzeAll(freshRun.matches)
      }
    } catch (e) { alert('Check failed: ' + e.message) }
    finally { setChecking(false) }
  }

  async function analyzeAll(matches) {
    await Promise.allSettled(
      matches.map(m => runAnalysis(m.rule.id))
    )
  }

  async function runAnalysis(ruleId) {
    setAnalyzingIds(prev => new Set([...prev, ruleId]))
    try {
      const r = await api.alertRules.reanalyzeMatch(caseId, ruleId)
      setAnalyses(prev => ({ ...prev, [ruleId]: r.analysis }))
    } catch {
      // LLM not configured or failed — silently skip
    } finally {
      setAnalyzingIds(prev => { const s = new Set(prev); s.delete(ruleId); return s })
    }
  }

  // ── AI rule generation ────────────────────────────────────────────────────

  async function generateRule(e) {
    e.preventDefault()
    if (!aiDesc.trim()) return
    setGenerating(true)
    try {
      const r = await api.llm.generateRule({ description: aiDesc })
      setForm({
        name:          r.name || aiDesc.slice(0, 60),
        description:   r.description || '',
        artifact_type: r.artifact_type || '',
        query:         r.query || '',
        threshold:     r.threshold || 1,
      })
      setShowAiForm(false)
      setShowForm(true)
      setAiDesc('')
    } catch (err) {
      alert('AI generation failed: ' + err.message)
    } finally {
      setGenerating(false)
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  const matches = run?.matches || []

  function AnalysisBlock({ ruleId }) {
    const analysis   = analyses[ruleId]
    const isAnalyzing = analyzingIds.has(ruleId)

    if (isAnalyzing) {
      return (
        <div className="flex items-center gap-1.5 text-[10px] text-purple-500 mt-1">
          <Loader2 size={10} className="animate-spin" /> Analyzing…
        </div>
      )
    }

    if (!analysis) {
      return (
        <button
          onClick={() => runAnalysis(ruleId)}
          className="mt-1 flex items-center gap-1 text-[10px] text-gray-400 hover:text-purple-500 transition-colors"
          title="Run AI forensic analysis on this match"
        >
          <Brain size={10} /> AI Analysis
        </button>
      )
    }

    return (
      <div className="mt-2 p-2 rounded bg-purple-50 border border-purple-200 space-y-1.5">
        <div className="flex items-center gap-1">
          <Brain size={10} className="text-purple-500" />
          <span className="text-[10px] font-semibold text-purple-700">AI Forensic Analysis</span>
          <span className="ml-auto text-[9px] text-gray-400">{analysis.model_used}</span>
          <button
            onClick={() => runAnalysis(ruleId)}
            title="Re-analyze"
            className="ml-1 text-gray-400 hover:text-purple-500 transition-colors"
          >
            <RefreshCw size={9} />
          </button>
        </div>
        {analysis.summary && (
          <p className="text-[10px] text-gray-700">{analysis.summary}</p>
        )}
        {analysis.severity && (
          <span className={`badge text-[9px] ${
            analysis.severity === 'critical' ? 'bg-red-100 text-red-600 border-red-200' :
            analysis.severity === 'high'     ? 'bg-orange-100 text-orange-600 border-orange-200' :
            'bg-yellow-100 text-yellow-600 border-yellow-200'
          }`}>{analysis.severity}</span>
        )}
        {(analysis.recommendations || []).length > 0 && (
          <div>
            <p className="text-[9px] text-gray-500 font-semibold uppercase tracking-wider mb-0.5">Actions</p>
            {analysis.recommendations.slice(0, 3).map((r, k) => (
              <p key={k} className="text-[10px] text-gray-600">• {r}</p>
            ))}
          </div>
        )}
        {(analysis.mitre_techniques || []).length > 0 && (
          <div className="flex flex-wrap gap-1 pt-0.5">
            {analysis.mitre_techniques.slice(0, 5).map((t, k) => (
              <span key={k} className="badge bg-indigo-50 text-indigo-600 border-indigo-200 text-[9px]">{t}</span>
            ))}
          </div>
        )}
        {analysis.analyzed_at && (
          <p className="text-[9px] text-gray-400 flex items-center gap-0.5 pt-0.5">
            <Clock size={8} /> {new Date(analysis.analyzed_at).toLocaleString()}
          </p>
        )}
      </div>
    )
  }

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-base font-bold text-brand-text flex items-center gap-2">
            <AlertTriangle size={16} className="text-yellow-500" /> Alert Rules
          </h1>
          <p className="text-xs text-gray-500 mt-0.5">Define suspicious patterns and check them on demand</p>
        </div>
        <div className="flex gap-2 flex-wrap justify-end">
          <button onClick={() => setShowAiForm(v => !v)} className="btn-ghost text-xs">
            <Sparkles size={13} className="text-purple-500" /> AI Generate
          </button>
          <button onClick={() => setShowForm(v => !v)} className="btn-ghost text-xs">
            <Plus size={13} /> New Rule
          </button>
          <button onClick={checkRules} disabled={checking || libraryRules.length === 0} className="btn-primary text-xs"
            title={`Run all ${libraryRules.length} library rules against this case`}>
            {checking ? <><Loader2 size={12} className="animate-spin" /> Checking…</> : <><Play size={12} /> Check All ({libraryRules.length})</>}
          </button>
        </div>
      </div>

      {/* AI generate form */}
      {showAiForm && (
        <form onSubmit={generateRule} className="card p-4 mb-4 space-y-3 border border-purple-200 bg-purple-50">
          <p className="text-xs font-semibold text-purple-700 flex items-center gap-1.5">
            <Sparkles size={12} /> AI Rule Generation
          </p>
          <p className="text-[10px] text-gray-500">Describe what you want to detect in plain language. The AI will generate an Elasticsearch query and prefill the rule form.</p>
          <div className="flex gap-2">
            <input
              autoFocus
              value={aiDesc}
              onChange={e => setAiDesc(e.target.value)}
              placeholder="e.g. detect failed RDP logins followed by a successful one (pass-the-hash)"
              className="input flex-1 text-xs"
              required
            />
            <button type="submit" disabled={generating || !aiDesc.trim()} className="btn-primary text-xs whitespace-nowrap">
              {generating ? <Loader2 size={12} className="animate-spin" /> : <><Sparkles size={12} /> Generate</>}
            </button>
            <button type="button" onClick={() => setShowAiForm(false)} className="btn-ghost text-xs">Cancel</button>
          </div>
        </form>
      )}

      {/* Manual create form */}
      {showForm && (
        <form onSubmit={createRule} className="card p-4 mb-4 space-y-3">
          <p className="text-xs font-semibold text-gray-700">New Alert Rule</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Name *</label>
              <input value={form.name} onChange={e => setForm(p => ({...p, name: e.target.value}))}
                placeholder="Brute Force Detection" className="input w-full text-xs" required />
            </div>
            <div>
              <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Artifact Type</label>
              <input value={form.artifact_type} onChange={e => setForm(p => ({...p, artifact_type: e.target.value}))}
                placeholder="evtx (leave empty for all)" className="input w-full text-xs" />
            </div>
          </div>
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">ES Query * <span className="text-gray-400 normal-case font-normal">(query_string syntax)</span></label>
            <input value={form.query} onChange={e => setForm(p => ({...p, query: e.target.value}))}
              placeholder='evtx.event_id:4625 OR evtx.event_id:4771' className="input w-full text-xs font-mono" required />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Description</label>
              <input value={form.description} onChange={e => setForm(p => ({...p, description: e.target.value}))}
                placeholder="What this rule detects" className="input w-full text-xs" />
            </div>
            <div>
              <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Min Matches to Alert</label>
              <input type="number" min="1" value={form.threshold}
                onChange={e => setForm(p => ({...p, threshold: parseInt(e.target.value) || 1}))}
                className="input w-full text-xs" />
            </div>
          </div>
          <div className="flex gap-2 pt-1">
            <button type="submit" className="btn-primary text-xs"><Plus size={12} /> Create Rule</button>
            <button type="button" onClick={() => setShowForm(false)} className="btn-ghost text-xs">Cancel</button>
          </div>
        </form>
      )}

      {/* Check results */}
      {run?.rules_checked !== undefined && (
        <div className={`card p-4 mb-4 ${matches.length > 0 ? 'border-yellow-300 bg-yellow-50' : 'border-green-300 bg-green-50'}`}>
          <div className="flex items-center gap-2 mb-2">
            {matches.length > 0
              ? <AlertTriangle size={14} className="text-yellow-600" />
              : <CheckCircle size={14} className="text-green-600" />}
            <span className="text-sm font-semibold text-gray-800">
              {matches.length > 0
                ? `${matches.length} rule${matches.length !== 1 ? 's' : ''} triggered`
                : 'All clear — no rules triggered'}
            </span>
            <span className="text-xs text-gray-500 ml-auto flex items-center gap-1">
              <Clock size={10} />
              {run.ran_at ? new Date(run.ran_at).toLocaleString() : 'just now'}
              <span className="ml-1">{run.rules_checked} rules checked</span>
            </span>
          </div>
          {matches.map((m, i) => (
            <div key={m.rule.id} className="mt-2 border border-yellow-200 rounded-lg overflow-hidden">
              <button
                onClick={() => setExpandedMatch(expandedMatch === i ? null : i)}
                className="w-full flex items-center justify-between px-3 py-2 text-xs bg-yellow-50 hover:bg-yellow-100 transition-colors">
                <span className="font-medium text-yellow-700">{m.rule.name}</span>
                <div className="flex items-center gap-2">
                  {analyzingIds.has(m.rule.id) && (
                    <Loader2 size={10} className="text-purple-500 animate-spin" />
                  )}
                  {analyses[m.rule.id] && !analyzingIds.has(m.rule.id) && (
                    <Brain size={10} className="text-purple-500" title="AI analysis available" />
                  )}
                  <span className="badge bg-yellow-100 text-yellow-700 border border-yellow-200">
                    {m.match_count.toLocaleString()} match{m.match_count !== 1 ? 'es' : ''}
                  </span>
                  {expandedMatch === i ? <ChevronUp size={12} className="text-gray-500" /> : <ChevronDown size={12} className="text-gray-500" />}
                </div>
              </button>
              {expandedMatch === i && (
                <div className="px-3 py-2 space-y-2 bg-white">
                  <div className="space-y-1">
                    {m.sample_events.map((ev, j) => (
                      <div key={j} className="text-[10px] text-gray-600 font-mono truncate">
                        {ev.timestamp?.slice(0,19).replace('T',' ')} — {ev.message}
                      </div>
                    ))}
                    {m.match_count > 3 && (
                      <p className="text-[10px] text-gray-400 italic">…and {m.match_count - 3} more</p>
                    )}
                  </div>
                  <AnalysisBlock ruleId={m.rule.id} />
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Library rules — collapsible, read-only, these are what Check All runs */}
      {libraryRules.length > 0 && (
        <LibraryRulesList rules={libraryRules} />
      )}

      {/* Case-specific rules list */}
      {loading ? (
        <div className="space-y-2">{[1,2].map(i => <div key={i} className="skeleton h-14 w-full" />)}</div>
      ) : rules.length === 0 ? (
        <div className="card p-6 text-center">
          <p className="text-gray-500 text-xs">No case-specific rules — use AI Generate or New Rule to add ad-hoc rules for this case only.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map(rule => (
            <div key={rule.id} className="card p-3 flex items-start gap-3">
              <div className="w-7 h-7 rounded-lg bg-yellow-50 border border-yellow-200 flex items-center justify-center flex-shrink-0 mt-0.5">
                <AlertTriangle size={12} className="text-yellow-600" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-sm font-semibold text-gray-800">{rule.name}</span>
                  {rule.artifact_type && (
                    <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">{rule.artifact_type}</span>
                  )}
                  <span className="badge bg-gray-100 text-gray-400 border border-gray-200 text-[10px]">≥{rule.threshold}</span>
                </div>
                {rule.description && <p className="text-xs text-gray-500 mb-1">{rule.description}</p>}
                <code className="text-[10px] text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded">{rule.query}</code>
              </div>
              <button onClick={() => deleteRule(rule.id)} className="btn-ghost p-1.5 text-gray-400 hover:text-red-500">
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
