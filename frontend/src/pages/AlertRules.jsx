import { useState, useEffect } from 'react'
import { AlertTriangle, Plus, Trash2, Play, CheckCircle, Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { api } from '../api/client'

export default function AlertRules({ caseId }) {
  const [rules, setRules]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [checking, setChecking]   = useState(false)
  const [matches, setMatches]     = useState(null)
  const [showForm, setShowForm]   = useState(false)
  const [form, setForm]           = useState({ name:'', description:'', artifact_type:'', query:'', threshold:1 })
  const [expandedMatch, setExpandedMatch] = useState(null)

  useEffect(() => {
    api.alertRules.list(caseId).then(r => setRules(r.rules || [])).catch(() => {}).finally(() => setLoading(false))
  }, [caseId])

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

  async function checkRules() {
    setChecking(true); setMatches(null)
    try {
      const r = await api.alertRules.check(caseId)
      setMatches(r)
    } catch (e) { alert('Check failed: ' + e.message) }
    finally { setChecking(false) }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-base font-bold text-gray-100 flex items-center gap-2">
            <AlertTriangle size={16} className="text-yellow-400" /> Alert Rules
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">Define suspicious patterns and check them on demand</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowForm(v => !v)} className="btn-ghost text-xs">
            <Plus size={13} /> New Rule
          </button>
          <button onClick={checkRules} disabled={checking || rules.length === 0} className="btn-primary text-xs">
            {checking ? <><Loader2 size={12} className="animate-spin" /> Checking…</> : <><Play size={12} /> Check All</>}
          </button>
        </div>
      </div>

      {/* Create form */}
      {showForm && (
        <form onSubmit={createRule} className="card p-4 mb-4 space-y-3">
          <p className="text-xs font-semibold text-gray-300">New Alert Rule</p>
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
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">ES Query * <span className="text-gray-600 normal-case font-normal">(query_string syntax)</span></label>
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
      {matches !== null && (
        <div className={`card p-4 mb-4 ${matches.matches.length > 0 ? 'border-yellow-800/50 bg-yellow-950/10' : 'border-green-800/50 bg-green-950/10'}`}>
          <div className="flex items-center gap-2 mb-2">
            {matches.matches.length > 0
              ? <AlertTriangle size={14} className="text-yellow-400" />
              : <CheckCircle size={14} className="text-green-400" />}
            <span className="text-sm font-semibold text-gray-200">
              {matches.matches.length > 0
                ? `${matches.matches.length} rule${matches.matches.length !== 1 ? 's' : ''} triggered`
                : 'All clear — no rules triggered'}
            </span>
            <span className="text-xs text-gray-500 ml-auto">{matches.rules_checked} rules checked</span>
          </div>
          {matches.matches.map((m, i) => (
            <div key={i} className="mt-2 border border-yellow-900/40 rounded-lg overflow-hidden">
              <button
                onClick={() => setExpandedMatch(expandedMatch === i ? null : i)}
                className="w-full flex items-center justify-between px-3 py-2 text-xs bg-yellow-950/20 hover:bg-yellow-950/30 transition-colors">
                <span className="font-medium text-yellow-300">{m.rule.name}</span>
                <div className="flex items-center gap-2">
                  <span className="badge bg-yellow-900/40 text-yellow-400 border border-yellow-800/40">
                    {m.match_count.toLocaleString()} match{m.match_count !== 1 ? 'es' : ''}
                  </span>
                  {expandedMatch === i ? <ChevronUp size={12} className="text-gray-500" /> : <ChevronDown size={12} className="text-gray-500" />}
                </div>
              </button>
              {expandedMatch === i && (
                <div className="px-3 py-2 space-y-1">
                  {m.sample_events.map((ev, j) => (
                    <div key={j} className="text-[10px] text-gray-400 font-mono truncate">
                      {ev.timestamp?.slice(0,19).replace('T',' ')} — {ev.message}
                    </div>
                  ))}
                  {m.match_count > 3 && (
                    <p className="text-[10px] text-gray-600 italic">…and {m.match_count - 3} more</p>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Rules list */}
      {loading ? (
        <div className="space-y-2">{[1,2].map(i => <div key={i} className="skeleton h-14 w-full" />)}</div>
      ) : rules.length === 0 ? (
        <div className="card p-10 text-center">
          <AlertTriangle size={28} className="text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400 text-sm font-medium mb-1">No alert rules defined</p>
          <p className="text-gray-600 text-xs">Create rules to detect suspicious patterns like brute force, privilege escalation, or lateral movement.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map(rule => (
            <div key={rule.id} className="card p-3 flex items-start gap-3">
              <div className="w-7 h-7 rounded-lg bg-yellow-900/30 border border-yellow-800/40 flex items-center justify-center flex-shrink-0 mt-0.5">
                <AlertTriangle size={12} className="text-yellow-400" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-sm font-semibold text-gray-100">{rule.name}</span>
                  {rule.artifact_type && (
                    <span className="badge bg-gray-700/60 text-gray-400 border border-gray-600/40 text-[10px]">{rule.artifact_type}</span>
                  )}
                  <span className="badge bg-gray-700/60 text-gray-500 border border-gray-600/40 text-[10px]">≥{rule.threshold}</span>
                </div>
                {rule.description && <p className="text-xs text-gray-500 mb-1">{rule.description}</p>}
                <code className="text-[10px] text-indigo-400 bg-indigo-950/30 px-1.5 py-0.5 rounded">{rule.query}</code>
              </div>
              <button onClick={() => deleteRule(rule.id)} className="btn-ghost p-1.5 text-gray-600 hover:text-red-400">
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
