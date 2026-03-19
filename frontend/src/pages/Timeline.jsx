import { useEffect, useState, useCallback, useRef } from 'react'
import {
  Search, Filter, X, Flag, Loader2, Download,
  BarChart2, Plus, Minus, Keyboard,
} from 'lucide-react'
import { api } from '../api/client'
import EventDetail from '../components/shared/EventDetail'

const ARTIFACT_COLORS = {
  evtx:     'badge-evtx',
  prefetch: 'badge-prefetch',
  mft:      'badge-mft',
  registry: 'badge-registry',
  lnk:      'badge-lnk',
  plaso:    'badge-plaso',
  hayabusa: 'badge-hayabusa',
  generic:  'badge-generic',
}

const PAGE_SIZE = 100

const SHORTCUTS = [
  { keys: ['/'],        desc: 'Focus search bar' },
  { keys: ['↑', '↓'],  desc: 'Navigate events' },
  { keys: ['Enter'],    desc: 'Open selected event' },
  { keys: ['Esc'],      desc: 'Close panel / blur search' },
  { keys: ['?'],        desc: 'Toggle this help' },
]

export default function Timeline({ caseId, artifactTypes }) {
  const [events, setEvents]               = useState([])
  const [total, setTotal]                 = useState(0)
  const [page, setPage]                   = useState(0)
  const [loading, setLoading]             = useState(false)
  const [selectedType, setSelectedType]   = useState('')
  const [fromTs, setFromTs]               = useState('')
  const [toTs, setToTs]                   = useState('')
  const [query, setQuery]                 = useState('')
  const [inputVal, setInputVal]           = useState('')
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [histogram, setHistogram]         = useState([])
  const [showHistogram, setShowHistogram] = useState(true)
  const [selectedRowIdx, setSelectedRowIdx] = useState(-1)
  const [regexpMode, setRegexpMode]       = useState(false)
  const [showHelp, setShowHelp]           = useState(false)
  const [flaggedOnly, setFlaggedOnly]     = useState(false)

  const loaderRef = useRef(null)
  const searchRef = useRef(null)
  const rowRefs   = useRef({})

  // Load histogram once on mount
  useEffect(() => {
    api.search.facets(caseId, {})
      .then(r => setHistogram(r.facets?.events_over_time?.buckets || []))
      .catch(() => {})
  }, [caseId])

  const load = useCallback(async (pg = 0, reset = false) => {
    setLoading(true)
    try {
      const params = { page: pg, size: PAGE_SIZE }
      if (selectedType) params.artifact_type = selectedType
      if (fromTs) params.from = fromTs
      if (toTs)   params.to   = toTs
      // Merge flaggedOnly into the effective query
      let effectiveQ = query
      if (flaggedOnly) {
        effectiveQ = effectiveQ ? `(${effectiveQ}) AND is_flagged:true` : 'is_flagged:true'
      }
      const r = effectiveQ
        ? await api.search.search(caseId, { ...params, q: effectiveQ })
        : await api.search.timeline(caseId, params)
      setTotal(r.total || 0)
      setEvents(prev => reset ? (r.events || []) : [...prev, ...(r.events || [])])
      setPage(pg)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [caseId, selectedType, fromTs, toTs, query, flaggedOnly])

  useEffect(() => { load(0, true) }, [load])

  // Reset keyboard row selection when results change
  useEffect(() => {
    setSelectedRowIdx(-1)
    rowRefs.current = {}
  }, [query, selectedType, fromTs, toTs])

  // Scroll keyboard-selected row into view
  useEffect(() => {
    if (selectedRowIdx >= 0 && rowRefs.current[selectedRowIdx]) {
      rowRefs.current[selectedRowIdx].scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    }
  }, [selectedRowIdx])

  // Infinite scroll sentinel
  useEffect(() => {
    if (!loaderRef.current) return
    const obs = new IntersectionObserver(entries => {
      if (entries[0].isIntersecting && !loading && events.length < total)
        load(page + 1, false)
    }, { threshold: 0.1 })
    obs.observe(loaderRef.current)
    return () => obs.disconnect()
  }, [loaderRef.current, loading, events.length, total, page, load])

  // Global keyboard navigation
  useEffect(() => {
    function handleKey(e) {
      const tag = document.activeElement?.tagName
      const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)

      if (e.key === '?' && !inInput) {
        e.preventDefault()
        setShowHelp(v => !v)
        return
      }
      if (e.key === '/' && !inInput) {
        e.preventDefault()
        searchRef.current?.focus()
        return
      }
      if (e.key === 'Escape') {
        if (document.activeElement === searchRef.current) {
          searchRef.current.blur()
          return
        }
        if (showHelp)      { setShowHelp(false);      return }
        if (selectedEvent) { setSelectedEvent(null);  return }
        return
      }
      if (inInput) return
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedRowIdx(i => Math.min(i + 1, events.length - 1))
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedRowIdx(i => Math.max(i - 1, 0))
        return
      }
      if (e.key === 'Enter' && selectedRowIdx >= 0) {
        e.preventDefault()
        const ev = events[selectedRowIdx]
        if (ev) setSelectedEvent(ev)
      }
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [events, selectedRowIdx, selectedEvent, showHelp])

  function submitSearch(e) {
    e.preventDefault()
    let q = inputVal.trim()
    // In regexp mode, auto-wrap plain text (no field: prefix, no existing slashes) in /.../
    if (regexpMode && q && !q.includes(':') && !q.startsWith('/')) {
      q = `/${q}/`
    }
    setQuery(q)
  }

  function clearSearch() {
    setInputVal('')
    setQuery('')
  }

  // Append a filter clause to the active query and trigger search immediately
  function addFilter(field, value, exclude = false) {
    const term = `${field}:"${value}"`
    const clause = exclude ? `NOT ${term}` : term
    const next = query ? `${query} AND ${clause}` : clause
    setInputVal(next)
    setQuery(next)
  }

  function clickBar(bucket) {
    const day = new Date(bucket.key)
    const next = new Date(day); next.setDate(next.getDate() + 1)
    setFromTs(day.toISOString())
    setToTs(next.toISOString())
  }

  function downloadCsv() {
    const params = {}
    if (selectedType) params.artifact_type = selectedType
    if (query) params.q = query
    window.open(api.export.csv(caseId, params))
  }

  const maxCount = histogram.reduce((m, b) => Math.max(m, b.doc_count), 1)
  const hasFilters = selectedType || fromTs || toTs || flaggedOnly

  return (
    <div className="flex h-full">
      {/* ── Filter sidebar ──────────────────────────────── */}
      <div className="w-44 flex-shrink-0 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-3 border-b border-gray-200">
          <p className="flex items-center gap-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-widest">
            <Filter size={10} /> Filters
          </p>
        </div>

        <div className="p-3 space-y-3 flex-1 overflow-y-auto">
          {/* Artifact type */}
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">
              Artifact
            </label>
            <select
              value={selectedType}
              onChange={e => setSelectedType(e.target.value)}
              className="input w-full text-xs py-1"
            >
              <option value="">All types</option>
              {artifactTypes.map(at => <option key={at} value={at}>{at}</option>)}
            </select>
            {/* Active type badge */}
            {selectedType && (
              <div className="mt-1.5 flex items-center gap-1">
                <span className={`badge ${ARTIFACT_COLORS[selectedType] || ARTIFACT_COLORS.generic} flex-1 justify-center`}>
                  {selectedType}
                </span>
                <button
                  onClick={() => setSelectedType('')}
                  className="text-gray-400 hover:text-gray-600 transition-colors"
                  title="Clear type filter"
                >
                  <X size={10} />
                </button>
              </div>
            )}
          </div>

          {/* From */}
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">From</label>
            <input
              type="datetime-local"
              value={fromTs ? fromTs.slice(0, 16) : ''}
              onChange={e => setFromTs(e.target.value ? new Date(e.target.value).toISOString() : '')}
              className="input w-full text-xs py-1"
            />
          </div>

          {/* To */}
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">To</label>
            <input
              type="datetime-local"
              value={toTs ? toTs.slice(0, 16) : ''}
              onChange={e => setToTs(e.target.value ? new Date(e.target.value).toISOString() : '')}
              className="input w-full text-xs py-1"
            />
          </div>

          {/* Flagged only */}
          <div>
            <button
              onClick={() => setFlaggedOnly(v => !v)}
              className={`flex items-center gap-2 w-full text-xs px-2 py-1.5 rounded-lg border transition-colors ${
                flaggedOnly
                  ? 'bg-red-50 text-red-600 border-red-200'
                  : 'text-gray-600 hover:bg-gray-50 border-transparent'
              }`}
            >
              <Flag size={11} className={flaggedOnly ? 'text-red-500' : 'text-gray-400'} />
              Flagged only
            </button>
          </div>

          {hasFilters && (
            <button
              onClick={() => { setSelectedType(''); setFromTs(''); setToTs(''); setFlaggedOnly(false) }}
              className="btn-ghost w-full text-xs justify-center"
            >
              <X size={11} /> Clear all
            </button>
          )}
        </div>

        {/* Event count footer */}
        <div className="p-3 border-t border-gray-200 space-y-0.5">
          <p className="text-xs font-semibold text-brand-text">{total.toLocaleString()}</p>
          <p className="text-[10px] text-gray-500">{query ? 'search results' : 'events total'}</p>
          {events.length < total && (
            <p className="text-[10px] text-gray-400">{events.length.toLocaleString()} loaded</p>
          )}
        </div>
      </div>

      {/* ── Main content ────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* Search bar */}
        <div className="px-4 py-3 border-b border-gray-200 bg-white">
          <form onSubmit={submitSearch} className="flex gap-2 items-center">
            <div className="relative flex-1">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
              <input
                ref={searchRef}
                value={inputVal}
                onChange={e => setInputVal(e.target.value)}
                placeholder={regexpMode
                  ? 'Regexp… /lateral.*movement/ or field:/pattern/'
                  : 'Search… EventID:4624, host.hostname:DC01, message:"logon"'}
                className="input-lg pl-9 pr-4 text-xs"
              />
            </div>

            {/* Regexp mode toggle */}
            <button
              type="button"
              onClick={() => setRegexpMode(v => !v)}
              title={regexpMode ? 'Regexp mode ON — click to switch to query string' : 'Switch to regexp mode'}
              className={`btn-outline text-xs px-2.5 py-1.5 font-mono tracking-tight ${
                regexpMode ? 'border-brand-accent text-brand-accent bg-brand-accentlight' : 'text-gray-500'
              }`}
            >
              .*
            </button>

            <button type="submit" className="btn-primary text-xs px-4">Search</button>

            {(query || inputVal) && (
              <button type="button" onClick={clearSearch} className="btn-ghost text-xs" title="Clear search">
                <X size={13} />
              </button>
            )}

            <button
              type="button"
              onClick={downloadCsv}
              className="btn-ghost text-xs"
              title="Export CSV"
            >
              <Download size={13} />
            </button>

            {histogram.length > 0 && (
              <button
                type="button"
                onClick={() => setShowHistogram(v => !v)}
                className={`btn-ghost text-xs ${showHistogram ? 'text-brand-accent' : ''}`}
                title="Toggle histogram"
              >
                <BarChart2 size={13} />
              </button>
            )}

            <button
              type="button"
              onClick={() => setShowHelp(v => !v)}
              className={`btn-ghost text-xs ${showHelp ? 'text-brand-accent' : ''}`}
              title="Keyboard shortcuts (?)"
            >
              <Keyboard size={13} />
            </button>
          </form>

          {/* Active query badge */}
          {query && (
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              <span className="text-[10px] text-gray-500">Query:</span>
              <code className="badge bg-brand-accentlight text-brand-accent border border-brand-accent/20 text-[10px] max-w-xs truncate font-mono">
                {query}
              </code>
              {regexpMode && (
                <span className="badge bg-purple-100 text-purple-700 text-[10px]">regexp</span>
              )}
              <span className="text-[10px] text-gray-400">
                — {total.toLocaleString()} result{total !== 1 ? 's' : ''}
              </span>
            </div>
          )}
        </div>

        {/* Histogram */}
        {showHistogram && histogram.length > 0 && (
          <div className="px-4 py-2 border-b border-gray-200 bg-gray-50">
            <p className="text-[10px] text-gray-500 mb-1.5 flex items-center gap-1">
              <BarChart2 size={9} /> Event activity — click a bar to filter to that day
            </p>
            <div className="flex items-end gap-0.5 h-10 overflow-x-auto">
              {histogram.map((b, i) => {
                const h = Math.max(2, Math.round((b.doc_count / maxCount) * 36))
                const day = new Date(b.key).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
                const active = fromTs && toTs &&
                  b.key >= new Date(fromTs).getTime() &&
                  b.key <= new Date(toTs).getTime()
                return (
                  <div
                    key={i}
                    className="flex flex-col items-center group cursor-pointer flex-shrink-0"
                    onClick={() => clickBar(b)}
                    title={`${day}: ${b.doc_count.toLocaleString()} events`}
                  >
                    <div
                      style={{ height: h }}
                      className={`w-2 rounded-t transition-colors ${
                        active ? 'bg-brand-accent' : 'bg-brand-accent/25 group-hover:bg-brand-accent/50'
                      }`}
                    />
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Events table */}
        <div className="flex-1 overflow-y-auto">
          {events.length === 0 && !loading && (
            <div className="flex flex-col items-center justify-center h-48 text-center">
              <Search size={28} className="text-gray-300 mb-3" />
              <p className="text-gray-500 text-sm">
                {query ? 'No events match your search.' : 'No events yet.'}
              </p>
              <p className="text-gray-400 text-xs mt-1">
                {query ? 'Try a different query.' : 'Upload forensics files using the Ingest button.'}
              </p>
            </div>
          )}

          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-50 border-b border-gray-200 z-10">
              <tr>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-40">
                  Timestamp
                </th>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-28">
                  Type
                </th>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-32">
                  Host
                </th>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-28">
                  User
                </th>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">
                  Message
                </th>
                <th className="px-3 py-2.5 w-12" />
              </tr>
            </thead>
            <tbody>
              {events.map((ev, i) => (
                <EventRow
                  key={ev.fo_id || i}
                  index={i}
                  event={ev}
                  caseId={caseId}
                  onSelect={(ev, idx) => { setSelectedEvent(ev); setSelectedRowIdx(idx) }}
                  selected={selectedEvent?.fo_id === ev.fo_id}
                  keyboardSelected={selectedRowIdx === i}
                  onFilterIn={(field, value)  => addFilter(field, value, false)}
                  onFilterOut={(field, value) => addFilter(field, value, true)}
                  rowRef={el => { rowRefs.current[i] = el }}
                  onFlagged={(foId, flagged) =>
                    setEvents(prev => prev.map(e =>
                      e.fo_id === foId ? { ...e, is_flagged: flagged } : e
                    ))
                  }
                />
              ))}
            </tbody>
          </table>

          <div ref={loaderRef} className="py-5 flex items-center justify-center text-gray-400 text-xs gap-2">
            {loading
              ? <><Loader2 size={13} className="animate-spin" /> Loading…</>
              : events.length < total
              ? <span className="text-gray-400">↓ Scroll for more</span>
              : events.length > 0
              ? <span className="text-gray-300">— End of results —</span>
              : null}
          </div>
        </div>
      </div>

      {/* Event detail panel */}
      {selectedEvent && (
        <EventDetail
          event={selectedEvent}
          caseId={caseId}
          onClose={() => setSelectedEvent(null)}
          onFilterIn={(field, value)  => addFilter(field, value, false)}
          onFilterOut={(field, value) => addFilter(field, value, true)}
        />
      )}

      {/* ── Keyboard shortcuts overlay ───────────────────── */}
      {showHelp && (
        <div
          className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center"
          onClick={() => setShowHelp(false)}
        >
          <div
            className="bg-white rounded-xl shadow-2xl p-6 w-80 max-w-[90vw]"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <Keyboard size={16} className="text-brand-accent" />
                <h3 className="font-semibold text-brand-text">Keyboard Shortcuts</h3>
              </div>
              <button onClick={() => setShowHelp(false)} className="btn-ghost p-1 text-gray-400">
                <X size={14} />
              </button>
            </div>

            <div className="space-y-3">
              {SHORTCUTS.map(({ keys, desc }) => (
                <div key={desc} className="flex items-center justify-between gap-4">
                  <span className="text-sm text-gray-600">{desc}</span>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    {keys.map((k, ki) => (
                      <span key={k} className="flex items-center gap-1">
                        {ki > 0 && <span className="text-[10px] text-gray-400">/</span>}
                        <kbd className="kbd">{k}</kbd>
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-5 pt-4 border-t border-gray-200">
              <p className="text-xs text-gray-500 leading-relaxed">
                Hover any row and click{' '}
                <span className="inline-flex items-center justify-center w-4 h-4 rounded bg-green-100 text-green-700 text-[9px] font-bold">+</span>
                {' '}to filter in or{' '}
                <span className="inline-flex items-center justify-center w-4 h-4 rounded bg-red-100 text-red-600 text-[9px] font-bold">−</span>
                {' '}to exclude a value.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Filter +/− buttons (appear on row group-hover) ── */
function FilterButtons({ field, value, onIn, onOut }) {
  return (
    <span className="inline-flex gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0 ml-1">
      <button
        type="button"
        onClick={e => { e.stopPropagation(); onIn(field, value) }}
        className="w-4 h-4 rounded flex items-center justify-center bg-green-100 text-green-700 hover:bg-green-200 transition-colors"
        title={`Filter in: ${field}:"${value}"`}
      >
        <Plus size={8} />
      </button>
      <button
        type="button"
        onClick={e => { e.stopPropagation(); onOut(field, value) }}
        className="w-4 h-4 rounded flex items-center justify-center bg-red-100 text-red-600 hover:bg-red-200 transition-colors"
        title={`Exclude: NOT ${field}:"${value}"`}
      >
        <Minus size={8} />
      </button>
    </span>
  )
}

/* ── Event row ── */
function EventRow({ event, index, onSelect, selected, keyboardSelected, onFilterIn, onFilterOut, rowRef, caseId, onFlagged }) {
  const ts    = event.timestamp ? new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 19) : '—'
  const type  = event.artifact_type || 'generic'
  const color = ARTIFACT_COLORS[type] || ARTIFACT_COLORS.generic
  const host  = event.host?.hostname || ''
  const user  = event.user?.name || ''

  async function handleFlag(e) {
    e.stopPropagation()
    const next = !event.is_flagged
    onFlagged(event.fo_id, next)          // optimistic
    try {
      await api.search.flagEvent(caseId, event.fo_id)
    } catch {
      onFlagged(event.fo_id, event.is_flagged)  // revert on error
    }
  }

  return (
    <tr
      ref={rowRef}
      onClick={() => onSelect(event, index)}
      className={`border-b cursor-pointer transition-colors text-xs group ${
        selected
          ? 'bg-brand-accentlight border-brand-accent/20'
          : keyboardSelected
          ? 'bg-blue-50 border-blue-200'
          : event.is_flagged
          ? 'bg-red-50 hover:bg-red-100 border-red-100'
          : 'border-gray-100 hover:bg-gray-50'
      }`}
    >
      <td className="px-3 py-2 text-gray-400 font-mono whitespace-nowrap tabular-nums">{ts}</td>

      <td className="px-3 py-2">
        <div className="flex items-center">
          <span className={`badge ${color}`}>{type}</span>
          <FilterButtons field="artifact_type" value={type} onIn={onFilterIn} onOut={onFilterOut} />
        </div>
      </td>

      <td className="px-3 py-2 text-gray-500 max-w-[8rem]">
        <div className="flex items-center">
          <span className="truncate">{host}</span>
          {host && <FilterButtons field="host.hostname" value={host} onIn={onFilterIn} onOut={onFilterOut} />}
        </div>
      </td>

      <td className="px-3 py-2 text-gray-500 max-w-[7rem]">
        <div className="flex items-center">
          <span className="truncate">{user}</span>
          {user && <FilterButtons field="user.name" value={user} onIn={onFilterIn} onOut={onFilterOut} />}
        </div>
      </td>

      <td className="px-3 py-2 text-brand-text max-w-sm">
        <span className="line-clamp-1">{event.message}</span>
      </td>

      <td className="px-3 py-2 w-auto">
        <div className="flex items-center gap-1 justify-end flex-wrap">
          {/* Flag toggle button */}
          <button
            onClick={handleFlag}
            className={`p-0.5 rounded transition-colors flex-shrink-0 ${
              event.is_flagged
                ? 'text-red-500 hover:text-red-400'
                : 'text-gray-200 hover:text-red-400 opacity-0 group-hover:opacity-100'
            }`}
            title={event.is_flagged ? 'Unflag event' : 'Flag event'}
          >
            <Flag size={10} />
          </button>
          {/* Tag badges — each clickable to add tags:"value" filter */}
          {event.tags?.map(t => (
            <button
              key={t}
              onClick={e => { e.stopPropagation(); onFilterIn('tags', t) }}
              className="text-[9px] px-1.5 py-0.5 rounded-full bg-purple-100 text-purple-700 hover:bg-purple-200 transition-colors font-medium flex-shrink-0"
              title={`Filter: tags:"${t}"`}
            >
              {t}
            </button>
          ))}
        </div>
      </td>
    </tr>
  )
}
