import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search, FolderOpen, Database, Clock, Archive,
  Trash2, ChevronRight, Plus, X, RefreshCw,
  AlertTriangle, CheckCircle, Filter,
} from 'lucide-react'
import { api } from '../api/client'

// ── Constants ─────────────────────────────────────────────────────────────────

const STATUS_CFG = {
  active:   { label: 'Active',   dot: 'bg-green-400',  badge: 'bg-green-100 text-green-700 border border-green-200' },
  archived: { label: 'Archived', dot: 'bg-gray-400',   badge: 'bg-gray-100 text-gray-500 border border-gray-200' },
  closed:   { label: 'Closed',   dot: 'bg-red-400',    badge: 'bg-red-100 text-red-600 border border-red-200' },
}

const ARTIFACT_BADGES = {
  evtx:     'badge-evtx',
  prefetch: 'badge-prefetch',
  mft:      'badge-mft',
  registry: 'badge-registry',
  lnk:      'badge-lnk',
  plaso:    'badge-plaso',
  hayabusa: 'badge-hayabusa',
}

// A case is "stale" if not updated for this many days
const STALE_DAYS = 30

function daysAgo(dateStr) {
  if (!dateStr) return null
  const diff = Date.now() - new Date(dateStr).getTime()
  return Math.floor(diff / 86_400_000)
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function Cases() {
  const navigate = useNavigate()

  const [cases, setCases]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [search, setSearch]       = useState('')
  const [statusFilter, setStatus] = useState('all')   // all | active | archived | closed
  const [selected, setSelected]   = useState(new Set())
  const [confirm, setConfirm]     = useState(null)     // { action, ids, label }
  const [busy, setBusy]           = useState(false)
  const [toast, setToast]         = useState(null)

  // ── Load ──────────────────────────────────────────────────────────────────

  function load() {
    setLoading(true)
    api.cases.list()
      .then(r => setCases(r.cases || []))
      .catch(() => showToast('Failed to load cases', 'error'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  // ── Filter ────────────────────────────────────────────────────────────────

  const filtered = useMemo(() => {
    let list = cases
    if (statusFilter !== 'all') list = list.filter(c => c.status === statusFilter)
    if (search.trim()) {
      const q = search.trim().toLowerCase()
      list = list.filter(c =>
        c.name.toLowerCase().includes(q) ||
        (c.description || '').toLowerCase().includes(q) ||
        (c.analyst || '').toLowerCase().includes(q)
      )
    }
    return list
  }, [cases, statusFilter, search])

  const staleCases = useMemo(
    () => cases.filter(c => c.status === 'active' && (daysAgo(c.updated_at) ?? daysAgo(c.created_at) ?? 0) >= STALE_DAYS),
    [cases],
  )

  // ── Tab counts ────────────────────────────────────────────────────────────

  const counts = useMemo(() => ({
    all:      cases.length,
    active:   cases.filter(c => c.status === 'active').length,
    archived: cases.filter(c => c.status === 'archived').length,
    closed:   cases.filter(c => c.status === 'closed').length,
  }), [cases])

  // ── Selection ─────────────────────────────────────────────────────────────

  function toggleSelect(id) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function toggleAll() {
    setSelected(
      selected.size === filtered.length
        ? new Set()
        : new Set(filtered.map(c => c.case_id))
    )
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  function showToast(msg, type = 'success') {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3000)
  }

  async function archiveCases(ids) {
    setBusy(true)
    try {
      await Promise.all(ids.map(id => api.cases.update(id, { status: 'archived' })))
      showToast(`Archived ${ids.length} case${ids.length > 1 ? 's' : ''}`)
      setSelected(new Set())
      load()
    } catch {
      showToast('Archive failed', 'error')
    } finally {
      setBusy(false)
      setConfirm(null)
    }
  }

  async function deleteCases(ids) {
    setBusy(true)
    try {
      await Promise.all(ids.map(id => api.cases.delete(id)))
      showToast(`Deleted ${ids.length} case${ids.length > 1 ? 's' : ''}`)
      setSelected(new Set())
      load()
    } catch {
      showToast('Delete failed', 'error')
    } finally {
      setBusy(false)
      setConfirm(null)
    }
  }

  function requestConfirm(action, ids, label) {
    setConfirm({ action, ids, label })
  }

  async function handleConfirm() {
    if (!confirm) return
    if (confirm.action === 'archive') await archiveCases(confirm.ids)
    else if (confirm.action === 'delete') await deleteCases(confirm.ids)
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="h-full overflow-y-auto bg-gray-50">
      <div className="max-w-5xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-lg font-bold text-brand-text">Cases</h1>
            <p className="text-xs text-gray-500 mt-0.5">
              {counts.all} total · {counts.active} active · {counts.archived} archived
            </p>
          </div>
          <button className="btn-ghost p-1.5" onClick={load} title="Refresh">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        {/* Stale cases banner */}
        {staleCases.length > 0 && (
          <div className="flex items-start gap-3 p-3.5 mb-5 bg-amber-50 border border-amber-200 rounded-xl">
            <AlertTriangle size={14} className="text-amber-500 flex-shrink-0 mt-0.5" />
            <div className="flex-1 text-xs text-amber-800">
              <strong>{staleCases.length} active case{staleCases.length > 1 ? 's' : ''}</strong>{' '}
              {staleCases.length > 1 ? 'have' : 'has'} had no activity for {STALE_DAYS}+ days.
            </div>
            <button
              className="text-xs text-amber-700 font-semibold hover:text-amber-900 whitespace-nowrap"
              onClick={() => requestConfirm('archive', staleCases.map(c => c.case_id),
                `Archive ${staleCases.length} stale case${staleCases.length > 1 ? 's' : ''}?`)}
            >
              Archive all stale
            </button>
          </div>
        )}

        {/* Search + status tabs */}
        <div className="flex items-center gap-3 mb-4 flex-wrap">
          {/* Search */}
          <div className="relative flex-1 min-w-52">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              className="input pl-8 text-sm"
              placeholder="Search by name, description, analyst…"
              value={search}
              onChange={e => { setSearch(e.target.value); setSelected(new Set()) }}
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <X size={12} />
              </button>
            )}
          </div>

          {/* Status filter */}
          <div className="flex items-center bg-white border border-gray-200 rounded-lg overflow-hidden shadow-sm">
            {[
              { key: 'all',      label: 'All' },
              { key: 'active',   label: 'Active' },
              { key: 'archived', label: 'Archived' },
              { key: 'closed',   label: 'Closed' },
            ].map(({ key, label }) => (
              <button
                key={key}
                onClick={() => { setStatus(key); setSelected(new Set()) }}
                className={`px-3 py-1.5 text-xs font-medium transition-colors border-r border-gray-100 last:border-r-0 ${
                  statusFilter === key
                    ? 'bg-brand-accent text-white'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                {label}
                <span className={`ml-1.5 text-[10px] font-normal ${
                  statusFilter === key ? 'text-white/70' : 'text-gray-400'
                }`}>
                  {counts[key]}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Bulk action bar */}
        {selected.size > 0 && (
          <div className="flex items-center gap-3 mb-3 px-4 py-2.5 bg-brand-accent/5
                          border border-brand-accent/20 rounded-xl">
            <span className="text-xs font-medium text-brand-accent flex-1">
              {selected.size} case{selected.size > 1 ? 's' : ''} selected
            </span>
            <button
              className="btn-ghost text-xs py-1 gap-1.5"
              onClick={() => requestConfirm('archive', [...selected],
                `Archive ${selected.size} selected case${selected.size > 1 ? 's' : ''}?`)}
            >
              <Archive size={12} /> Archive
            </button>
            <button
              className="btn-danger text-xs py-1 gap-1.5"
              onClick={() => requestConfirm('delete', [...selected],
                `Permanently delete ${selected.size} case${selected.size > 1 ? 's' : ''}? This cannot be undone.`)}
            >
              <Trash2 size={12} /> Delete
            </button>
            <button className="icon-btn" onClick={() => setSelected(new Set())}>
              <X size={12} />
            </button>
          </div>
        )}

        {/* Table */}
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map(i => <div key={i} className="skeleton h-16 w-full rounded-xl" />)}
          </div>
        ) : filtered.length === 0 ? (
          <div className="card p-12 text-center">
            <FolderOpen size={28} className="text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500 text-sm font-medium">
              {search || statusFilter !== 'all' ? 'No cases match your filter' : 'No cases yet'}
            </p>
            {(search || statusFilter !== 'all') && (
              <button
                className="btn-ghost text-xs mt-2"
                onClick={() => { setSearch(''); setStatus('all') }}
              >
                Clear filters
              </button>
            )}
          </div>
        ) : (
          <div className="card overflow-hidden">
            {/* Header row */}
            <div className="flex items-center gap-3 px-4 py-2.5 bg-gray-50 border-b border-gray-200 text-[11px] font-semibold text-gray-400 uppercase tracking-wider">
              <input
                type="checkbox"
                checked={selected.size > 0 && selected.size === filtered.length}
                ref={el => { if (el) el.indeterminate = selected.size > 0 && selected.size < filtered.length }}
                onChange={toggleAll}
                className="accent-brand-accent cursor-pointer"
              />
              <span className="flex-1">Name</span>
              <span className="w-24 text-right hidden sm:block">Events</span>
              <span className="w-20 text-right hidden md:block">Age</span>
              <span className="w-24 text-center">Status</span>
              <span className="w-16" />
            </div>

            {filtered.map((c, i) => {
              const st      = STATUS_CFG[c.status] || STATUS_CFG.active
              const age     = daysAgo(c.updated_at ?? c.created_at)
              const isStale = c.status === 'active' && (age ?? 0) >= STALE_DAYS
              const isSelected = selected.has(c.case_id)

              return (
                <div
                  key={c.case_id}
                  className={`flex items-center gap-3 px-4 py-3 border-b border-gray-100 last:border-b-0
                              hover:bg-gray-50 transition-colors group ${
                    isSelected ? 'bg-brand-accent/5' : ''
                  }`}
                >
                  {/* Checkbox */}
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggleSelect(c.case_id)}
                    onClick={e => e.stopPropagation()}
                    className="accent-brand-accent cursor-pointer flex-shrink-0"
                  />

                  {/* Status dot */}
                  <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${st.dot}`} />

                  {/* Name + meta */}
                  <div
                    className="flex-1 min-w-0 cursor-pointer"
                    onClick={() => navigate(`/cases/${c.case_id}`)}
                  >
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-sm font-medium text-brand-text truncate">{c.name}</span>
                      {isStale && (
                        <span className="badge bg-amber-50 text-amber-600 border border-amber-200 text-[10px]">
                          stale
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      {c.analyst && (
                        <span className="text-xs text-gray-400">@{c.analyst}</span>
                      )}
                      {(c.artifact_types || []).map(at => (
                        <span key={at} className={`badge ${ARTIFACT_BADGES[at] || 'badge-generic'}`}>{at}</span>
                      ))}
                    </div>
                  </div>

                  {/* Event count */}
                  <div className="w-24 text-right text-xs text-gray-500 hidden sm:block flex-shrink-0">
                    <span className="flex items-center justify-end gap-1">
                      <Database size={10} />
                      {(c.event_count || 0).toLocaleString()}
                    </span>
                  </div>

                  {/* Age */}
                  <div className="w-20 text-right text-xs text-gray-400 hidden md:block flex-shrink-0">
                    {age != null ? `${age}d ago` : '—'}
                  </div>

                  {/* Status badge */}
                  <div className="w-24 flex justify-center flex-shrink-0">
                    <span className={`badge text-[10px] ${st.badge}`}>{st.label}</span>
                  </div>

                  {/* Row actions */}
                  <div className="w-16 flex items-center justify-end gap-1 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    {c.status === 'active' && (
                      <button
                        className="icon-btn text-gray-400 hover:text-amber-600"
                        title="Archive"
                        onClick={e => { e.stopPropagation(); archiveCases([c.case_id]) }}
                      >
                        <Archive size={13} />
                      </button>
                    )}
                    <button
                      className="icon-btn text-gray-400 hover:text-red-500"
                      title="Delete"
                      onClick={e => {
                        e.stopPropagation()
                        requestConfirm('delete', [c.case_id], `Delete "${c.name}"? This cannot be undone.`)
                      }}
                    >
                      <Trash2 size={13} />
                    </button>
                    <button
                      className="icon-btn text-gray-400 hover:text-brand-accent"
                      onClick={() => navigate(`/cases/${c.case_id}`)}
                    >
                      <ChevronRight size={13} />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* ── Confirm dialog ───────────────────────────────────────────────────── */}
      {confirm && (
        <div className="modal-overlay" onClick={() => setConfirm(null)}>
          <div className="modal-box" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div className="flex items-center gap-2">
                {confirm.action === 'delete'
                  ? <Trash2 size={15} className="text-red-500" />
                  : <Archive size={15} className="text-amber-500" />}
                <span className="text-sm font-semibold text-brand-text">
                  {confirm.action === 'delete' ? 'Delete cases' : 'Archive cases'}
                </span>
              </div>
              <button className="icon-btn" onClick={() => setConfirm(null)}><X size={14} /></button>
            </div>
            <div className="p-5">
              <p className="text-sm text-gray-600 mb-5">{confirm.label}</p>
              <div className="flex gap-3 justify-end">
                <button className="btn-ghost" onClick={() => setConfirm(null)}>Cancel</button>
                <button
                  className={confirm.action === 'delete' ? 'btn-danger' : 'btn-outline'}
                  onClick={handleConfirm}
                  disabled={busy}
                >
                  {busy ? 'Working…' : confirm.action === 'delete' ? 'Delete' : 'Archive'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Toast ────────────────────────────────────────────────────────────── */}
      {toast && (
        <div className={`fixed bottom-5 right-5 z-50 flex items-center gap-2 px-4 py-3
                         rounded-xl shadow-lg text-sm font-medium transition-all ${
          toast.type === 'error'
            ? 'bg-red-600 text-white'
            : 'bg-gray-900 text-white'
        }`}>
          {toast.type === 'error'
            ? <AlertTriangle size={14} />
            : <CheckCircle size={14} className="text-green-400" />}
          {toast.msg}
        </div>
      )}
    </div>
  )
}
