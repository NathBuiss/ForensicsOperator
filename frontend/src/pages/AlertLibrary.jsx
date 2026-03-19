import { useState, useEffect, useCallback } from 'react'
import {
  Bell, Plus, Trash2, ChevronDown, ChevronUp,
  Sparkles, Shield, AlertTriangle, Loader2, Search,
} from 'lucide-react'
import { api } from '../api/client'

// ── 3 pre-seeded suggested rules ─────────────────────────────────────────────
const SUGGESTED_RULES = [
  {
    name: 'Audit Log Cleared',
    description: 'Security audit log cleared — possible evidence tampering or attacker covering tracks.',
    artifact_type: 'evtx',
    query: 'evtx.event_id:1102',
    threshold: 1,
  },
  {
    name: 'Privileged Account Usage',
    description: 'Special privileges assigned to a non-SYSTEM account — monitor for unexpected admin elevation.',
    artifact_type: 'evtx',
    query: 'evtx.event_id:4672 AND NOT user.name:SYSTEM AND NOT user.name:LOCAL SERVICE',
    threshold: 10,
  },
  {
    name: 'New Service Installed',
    description: 'A new Windows service was installed — common persistence and lateral movement mechanism.',
    artifact_type: 'evtx',
    query: 'evtx.event_id:7045',
    threshold: 1,
  },
]

const LEVEL_COLOR = {
  critical:      'text-red-600',
  high:          'text-orange-600',
  medium:        'text-amber-600',
  low:           'text-blue-600',
  informational: 'text-gray-500',
}

// ── Suggested rule card ───────────────────────────────────────────────────────
function SuggestedRuleCard({ rule, onAdd, added }) {
  return (
    <div className="card p-4 flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-semibold text-brand-text text-sm">{rule.name}</span>
            {rule.artifact_type && (
              <span className={`badge badge-${rule.artifact_type}`}>{rule.artifact_type}</span>
            )}
          </div>
          <p className="text-xs text-gray-500">{rule.description}</p>
          <code className="block mt-1.5 text-xs text-gray-600 font-mono bg-gray-50 border border-gray-200 rounded px-2 py-1">
            {rule.query}
          </code>
          <p className="text-xs text-gray-400 mt-1">Threshold: ≥{rule.threshold} match{rule.threshold !== 1 ? 'es' : ''}</p>
        </div>
      </div>
      <button
        onClick={() => onAdd(rule)}
        disabled={added}
        className={added ? 'btn-success self-start' : 'btn-primary self-start'}
      >
        {added ? (
          <><Shield size={14} /> Added</>
        ) : (
          <><Plus size={14} /> Add to Library</>
        )}
      </button>
    </div>
  )
}

// ── Library rule card ─────────────────────────────────────────────────────────
function LibraryRuleCard({ rule, onDelete }) {
  const [expanded, setExpanded] = useState(false)
  return (
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
  const [rules, setRules]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [addedIds, setAddedIds] = useState(new Set())

  const loadRules = useCallback(() => {
    api.alertRules.listLibrary()
      .then(r => setRules(r.rules || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { loadRules() }, [loadRules])

  async function addSuggested(template) {
    try {
      const rule = await api.alertRules.createLibraryRule(template)
      setRules(prev => [...prev, rule])
      setAddedIds(prev => new Set([...prev, template.name]))
    } catch (err) {
      console.error(err)
    }
  }

  function handleCreated(rule) {
    setRules(prev => [...prev, rule])
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
          Define detection rules here. Run them against any case using the{' '}
          <strong className="text-brand-text">Run Alerts</strong> button from the case timeline.
        </p>
      </div>

      {/* Suggested rules */}
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <Sparkles size={14} className="text-amber-500" />
          <h2 className="font-semibold text-brand-text">Suggested Rules</h2>
          <span className="text-xs text-gray-500">— click to add to your library</span>
        </div>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          {SUGGESTED_RULES.map(r => (
            <SuggestedRuleCard
              key={r.name}
              rule={r}
              onAdd={addSuggested}
              added={addedIds.has(r.name) || rules.some(lr => lr.name === r.name)}
            />
          ))}
        </div>
      </div>

      {/* Create custom rule */}
      <div className="mb-8">
        <CreateRuleForm onCreated={handleCreated} />
      </div>

      {/* Library */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <Search size={14} className="text-gray-500" />
          <h2 className="font-semibold text-brand-text">
            Your Library
          </h2>
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
            <p className="text-sm mt-1">Add a suggested rule or create a custom one above.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {rules.map(r => (
              <LibraryRuleCard key={r.id} rule={r} onDelete={deleteRule} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
