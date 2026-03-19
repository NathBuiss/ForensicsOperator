import { useState, useEffect, useCallback } from 'react'
import {
  Bell, Plus, Trash2, ChevronDown, ChevronUp, Pencil, Check, X,
  AlertTriangle, Loader2, Search, Play, CheckCircle, Clock,
} from 'lucide-react'
import { api } from '../api/client'

// ── Run on Case modal ─────────────────────────────────────────────────────────
function RunOnCaseModal({ rule, cases, onClose }) {
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

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2">
            <Play size={15} className="text-brand-accent" />
            <span className="font-semibold text-brand-text text-sm">Run Rule on Case</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1"><X size={14} /></button>
        </div>

        <div className="p-5 space-y-4">
          {/* Rule summary */}
          <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
            <p className="text-xs font-semibold text-brand-text">{rule.name}</p>
            <code className="block mt-1 text-xs text-gray-500 font-mono break-all">{rule.query}</code>
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
            <div className={`rounded-lg border p-3 ${result.fired ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}`}>
              {result.fired ? (
                <>
                  <p className="text-xs font-semibold text-red-700 flex items-center gap-1 mb-2">
                    <AlertTriangle size={12} /> {result.match.match_count.toLocaleString()} matches found
                  </p>
                  {result.match.sample_events?.map((ev, i) => (
                    <div key={i} className="bg-white rounded border border-red-100 p-2 mb-1">
                      <p className="text-[10px] text-gray-500 font-mono flex items-center gap-1">
                        <Clock size={9} />{ev.timestamp || '—'}
                      </p>
                      <p className="text-xs text-gray-700 mt-0.5">{ev.message || '—'}</p>
                    </div>
                  ))}
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

// ── Edit form (inline) ────────────────────────────────────────────────────────
function EditRuleForm({ rule, onSaved, onCancel }) {
  const [form, setForm] = useState({
    name: rule.name,
    description: rule.description || '',
    artifact_type: rule.artifact_type || '',
    query: rule.query,
    threshold: rule.threshold,
  })
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  async function save(e) {
    e.preventDefault()
    setSaving(true)
    setError('')
    try {
      const updated = await api.alertRules.updateLibraryRule(rule.id, {
        ...form,
        threshold: parseInt(form.threshold) || 1,
      })
      onSaved(updated)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={save} className="bg-gray-50 border border-gray-200 rounded-xl p-4 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Rule Name *</label>
          <input className="input text-xs" value={form.name} onChange={e => set('name', e.target.value)} required />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Artifact Type</label>
          <select className="input text-xs" value={form.artifact_type} onChange={e => set('artifact_type', e.target.value)}>
            <option value="">Any</option>
            <option value="evtx">evtx</option>
            <option value="prefetch">prefetch</option>
            <option value="mft">mft</option>
            <option value="registry">registry</option>
            <option value="lnk">lnk</option>
            <option value="hayabusa">hayabusa</option>
          </select>
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">Description</label>
        <input className="input text-xs" value={form.description} onChange={e => set('description', e.target.value)} />
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">ES Query *</label>
        <input className="input font-mono text-xs" value={form.query} onChange={e => set('query', e.target.value)} required />
      </div>
      <div className="flex items-end gap-3">
        <div className="w-28">
          <label className="block text-xs font-medium text-gray-600 mb-1">Min Matches</label>
          <input type="number" min="1" className="input text-xs" value={form.threshold} onChange={e => set('threshold', e.target.value)} />
        </div>
        <button type="submit" disabled={saving} className="btn-primary text-xs">
          {saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />} Save
        </button>
        <button type="button" onClick={onCancel} className="btn-ghost text-xs">
          <X size={13} /> Cancel
        </button>
      </div>
      {error && <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">{error}</p>}
    </form>
  )
}

// ── Library rule card ─────────────────────────────────────────────────────────
function LibraryRuleCard({ rule, cases, onDelete, onUpdated }) {
  const [expanded, setExpanded] = useState(false)
  const [editing, setEditing]   = useState(false)
  const [showRun, setShowRun]   = useState(false)

  if (editing) {
    return (
      <EditRuleForm
        rule={rule}
        onSaved={updated => { onUpdated(updated); setEditing(false) }}
        onCancel={() => setEditing(false)}
      />
    )
  }

  return (
    <>
      {showRun && <RunOnCaseModal rule={rule} cases={cases} onClose={() => setShowRun(false)} />}
      <div className="card overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3">
          <AlertTriangle size={15} className="text-amber-500 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-medium text-brand-text text-sm">{rule.name}</span>
              {rule.artifact_type && (
                <span className={`badge badge-${rule.artifact_type}`}>{rule.artifact_type}</span>
              )}
              <span className="text-xs text-gray-400">threshold ≥{rule.threshold}</span>
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
              onClick={() => setEditing(true)}
              className="btn-ghost px-2 py-1.5 text-xs"
              title="Edit rule"
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
          <div className="border-t border-gray-100 bg-gray-50 px-4 py-3">
            <p className="text-xs text-gray-500 mb-1">ES Query</p>
            <code className="block text-xs font-mono text-brand-text bg-white border border-gray-200
                             rounded px-3 py-2 break-all">
              {rule.query}
            </code>
            {rule.created_at && (
              <p className="text-xs text-gray-400 mt-2">
                Added {new Date(rule.created_at).toLocaleDateString()}
              </p>
            )}
          </div>
        )}
      </div>
    </>
  )
}

// ── Create rule form ──────────────────────────────────────────────────────────
function CreateRuleForm({ onCreated }) {
  const [form, setForm] = useState({
    name: '', description: '', artifact_type: '', query: '', threshold: 1,
  })
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  async function submit(e) {
    e.preventDefault()
    if (!form.name.trim() || !form.query.trim()) return
    setSaving(true)
    setError('')
    try {
      const rule = await api.alertRules.createLibraryRule({
        ...form,
        threshold: parseInt(form.threshold) || 1,
      })
      onCreated(rule)
      setForm({ name: '', description: '', artifact_type: '', query: '', threshold: 1 })
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={submit} className="card p-5 space-y-3">
      <h3 className="font-semibold text-brand-text flex items-center gap-2">
        <Plus size={15} className="text-brand-accent" />
        Create Custom Rule
      </h3>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Rule Name *</label>
          <input className="input" placeholder="e.g. Lateral Movement Detected"
            value={form.name} onChange={e => set('name', e.target.value)} required />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Artifact Type</label>
          <select className="input" value={form.artifact_type}
            onChange={e => set('artifact_type', e.target.value)}>
            <option value="">Any</option>
            <option value="evtx">evtx</option>
            <option value="prefetch">prefetch</option>
            <option value="mft">mft</option>
            <option value="registry">registry</option>
            <option value="lnk">lnk</option>
            <option value="hayabusa">hayabusa</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">Description</label>
        <input className="input" placeholder="What does this rule detect?"
          value={form.description} onChange={e => set('description', e.target.value)} />
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">
          Elasticsearch Query *
          <span className="text-gray-400 font-normal ml-1">(Lucene query string syntax)</span>
        </label>
        <input className="input font-mono" placeholder="evtx.event_id:4625 AND evtx.event_data.FailureReason:*"
          value={form.query} onChange={e => set('query', e.target.value)} required />
      </div>

      <div className="flex items-end gap-3">
        <div className="w-36">
          <label className="block text-xs font-medium text-gray-600 mb-1">Min Matches</label>
          <input type="number" min="1" className="input" value={form.threshold}
            onChange={e => set('threshold', e.target.value)} />
        </div>
        <button type="submit" disabled={saving} className="btn-primary">
          {saving ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
          Add Rule
        </button>
      </div>

      {error && (
        <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          {error}
        </p>
      )}
    </form>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function AlertLibrary() {
  const [rules, setRules]     = useState([])
  const [cases, setCases]     = useState([])
  const [loading, setLoading] = useState(true)

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

  function handleCreated(rule) {
    setRules(prev => [rule, ...prev])
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

  return (
    <div className="p-6 max-w-4xl">

      {/* Page header */}
      <div className="mb-6">
        <div className="flex items-center gap-2.5 mb-1">
          <Bell size={20} className="text-brand-accent" />
          <h1 className="text-xl font-bold text-brand-text">Alert Rule Library</h1>
        </div>
        <p className="text-sm text-gray-500">
          Define detection rules. Use <Play size={11} className="inline" /> to run a specific rule on any case,
          or use the <strong className="text-brand-text">Run Alerts</strong> button on the case timeline to run all rules at once.
        </p>
      </div>

      {/* Library — shown first */}
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <Search size={14} className="text-gray-500" />
          <h2 className="font-semibold text-brand-text">Library</h2>
          {!loading && (
            <span className="badge-pill bg-gray-100 text-gray-600">{rules.length}</span>
          )}
        </div>

        {loading ? (
          <div className="flex items-center gap-2 text-gray-400 py-8 justify-center">
            <Loader2 size={18} className="animate-spin" />
            Loading rules…
          </div>
        ) : rules.length === 0 ? (
          <div className="card p-10 flex flex-col items-center text-center text-gray-400">
            <Bell size={32} className="mb-3 opacity-30" />
            <p className="font-medium">No rules yet</p>
            <p className="text-sm mt-1">Create your first rule below.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {rules.map(r => (
              <LibraryRuleCard
                key={r.id}
                rule={r}
                cases={cases}
                onDelete={deleteRule}
                onUpdated={handleUpdated}
              />
            ))}
          </div>
        )}
      </div>

      {/* Create rule form — at the bottom */}
      <CreateRuleForm onCreated={handleCreated} />
    </div>
  )
}
