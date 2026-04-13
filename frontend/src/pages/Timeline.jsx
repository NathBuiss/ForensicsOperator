import { useEffect, useState, useCallback, useRef } from 'react'
import {
  Search, Filter, X, Flag, Loader2, Download,
  BarChart2, Plus, Minus, Keyboard, SlidersHorizontal, Brain,
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

const LEVEL_COLORS = {
  crit:          'bg-red-100 text-red-700 border border-red-200',
  critical:      'bg-red-100 text-red-700 border border-red-200',
  high:          'bg-orange-100 text-orange-700 border border-orange-200',
  med:           'bg-yellow-100 text-yellow-700 border border-yellow-200',
  medium:        'bg-yellow-100 text-yellow-700 border border-yellow-200',
  low:           'bg-blue-100 text-blue-700 border border-blue-200',
  info:          'bg-gray-100 text-gray-500',
  informational: 'bg-gray-100 text-gray-500',
}

// ── Column definitions ───────────────────────────────────────────────────────
const ALL_COLUMNS = [
  { id: 'timestamp', label: 'Timestamp', defaultOn: true },
  { id: 'type',      label: 'Type',      defaultOn: true },
  { id: 'level',     label: 'Level',     defaultOn: true },
  { id: 'event_id',  label: 'Event ID',  defaultOn: true },
  { id: 'host',      label: 'Host',      defaultOn: true },
  { id: 'user',      label: 'User',      defaultOn: true },
  { id: 'process',   label: 'Process',   defaultOn: false },
  { id: 'channel',   label: 'Channel',   defaultOn: false },
  { id: 'rule',      label: 'Rule',      defaultOn: false },
  { id: 'message',   label: 'Message',   defaultOn: true },
  { id: 'tags',      label: 'Tags',      defaultOn: true },
]

const DEFAULT_COLUMNS = ALL_COLUMNS.filter(c => c.defaultOn).map(c => c.id)
const LS_KEY = 'timeline_visible_cols'

function loadSavedColumns() {
  try {
    const raw = localStorage.getItem(LS_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed) && parsed.length > 0) return parsed
    }
  } catch {}
  return DEFAULT_COLUMNS
}

const PAGE_SIZE = 100

const SHORTCUTS = [
  { keys: ['/'],        desc: 'Focus search bar' },
  { keys: ['↑', '↓'],  desc: 'Navigate events' },
  { keys: ['Enter'],    desc: 'Open selected event' },
  { keys: ['Esc'],      desc: 'Close panel / blur search' },
  { keys: ['?'],        desc: 'Toggle this help' },
]

// Helper: pull artifact-specific sub-object from event
function getArtifact(ev) {
  return ev[ev.artifact_type] || {}
}

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
  const [visibleCols, setVisibleCols]     = useState(loadSavedColumns)
  const [showColPicker, setShowColPicker] = useState(false)
  const colPickerRef                      = useRef(null)

  const [checkedFoIds, setCheckedFoIds]     = useState(new Set())
  const [explaining, setExplaining]         = useState(false)
  const [explainResult, setExplainResult]   = useState(null)
  const [naturalDate, setNaturalDate]       = useState('')
  const [showCustomRange, setShowCustomRange] = useState(false)
  const [naturalDateErr, setNaturalDateErr] = useState('')
  const [activePreset, setActivePreset]     = useState(null)

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

  useEffect(() => {
    setSelectedRowIdx(-1)
    rowRefs.current = {}
  }, [query, selectedType, fromTs, toTs])

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

  // Close col picker on outside click
  useEffect(() => {
    if (!showColPicker) return
    function handleClick(e) {
      if (colPickerRef.current && !colPickerRef.current.contains(e.target))
        setShowColPicker(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [showColPicker])

  // Global keyboard navigation
  useEffect(() => {
    function handleKey(e) {
      const tag = document.activeElement?.tagName
      const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)

      if (e.key === '?' && !inInput) { e.preventDefault(); setShowHelp(v => !v); return }
      if (e.key === '/' && !inInput) { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'Escape') {
        if (document.activeElement === searchRef.current) { searchRef.current.blur(); return }
        if (showHelp)      { setShowHelp(false);      return }
        if (selectedEvent) { setSelectedEvent(null);  return }
        return
      }
      if (inInput) return
      if (e.key === 'ArrowDown') { e.preventDefault(); setSelectedRowIdx(i => Math.min(i + 1, events.length - 1)); return }
      if (e.key === 'ArrowUp')   { e.preventDefault(); setSelectedRowIdx(i => Math.max(i - 1, 0)); return }
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
    if (regexpMode && q && !q.includes(':') && !q.startsWith('/')) q = `/${q}/`
    setQuery(q)
  }

  function clearSearch() { setInputVal(''); setQuery('') }

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

  function toggleCol(id) {
    const next = visibleCols.includes(id)
      ? visibleCols.filter(c => c !== id)
      : [...visibleCols, id]
    setVisibleCols(next)
    localStorage.setItem(LS_KEY, JSON.stringify(next))
  }

  function resetCols() {
    setVisibleCols(DEFAULT_COLUMNS)
    localStorage.setItem(LS_KEY, JSON.stringify(DEFAULT_COLUMNS))
  }

  // Parse natural language date phrases → ISO string (or null)
  function parseNaturalDate(text) {
    const t = text.trim().toLowerCase()
    const now = new Date()
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())

    if (t === 'today')     return today.toISOString()
    if (t === 'yesterday') { const d = new Date(today); d.setDate(d.getDate() - 1); return d.toISOString() }
    if (t === 'last week') { const d = new Date(today); d.setDate(d.getDate() - 7); return d.toISOString() }
    if (t === 'last month') { const d = new Date(today); d.setMonth(d.getMonth() - 1); return d.toISOString() }

    const daysMatch   = t.match(/^(\d+)\s*days?\s*ago$/)
    if (daysMatch)   { const d = new Date(today); d.setDate(d.getDate() - parseInt(daysMatch[1])); return d.toISOString() }
    const weeksMatch  = t.match(/^(\d+)\s*weeks?\s*ago$/)
    if (weeksMatch)  { const d = new Date(today); d.setDate(d.getDate() - parseInt(weeksMatch[1]) * 7); return d.toISOString() }
    const monthsMatch = t.match(/^(\d+)\s*months?\s*ago$/)
    if (monthsMatch) { const d = new Date(today); d.setMonth(d.getMonth() - parseInt(monthsMatch[1])); return d.toISOString() }
    const hoursMatch  = t.match(/^(\d+)\s*hours?\s*ago$/)
    if (hoursMatch)  { const d = new Date(now); d.setHours(d.getHours() - parseInt(hoursMatch[1])); return d.toISOString() }

    // Named weekdays: "monday", "last monday", "from monday"
    const DAYS = ['sunday','monday','tuesday','wednesday','thursday','friday','saturday']
    const dayName = t.replace(/^(from\s+|last\s+)/, '').trim()
    const dayIdx = DAYS.indexOf(dayName)
    if (dayIdx >= 0) {
      const d = new Date(today)
      const diff = (today.getDay() - dayIdx + 7) % 7
      d.setDate(d.getDate() - (diff === 0 ? 7 : diff))
      return d.toISOString()
    }

    return null
  }

  function applyNaturalDate(e) {
    e.preventDefault()
    if (!naturalDate.trim()) return
    setNaturalDateErr('')
    const iso = parseNaturalDate(naturalDate)
    if (iso) { setFromTs(iso); setNaturalDate(''); setNaturalDateErr(''); setActivePreset(null) }
    else setNaturalDateErr(`Try: "monday", "3 days ago", "last week", "2 months ago"`)
  }

  // Apply a quick date preset (null = clear)
  function applyPreset(preset) {
    setNaturalDateErr('')
    setActivePreset(preset)
    if (!preset) { setFromTs(''); setToTs(''); setShowCustomRange(false); return }
    const now = new Date()
    setToTs('')  // clear To so "now" is implied
    setShowCustomRange(false)
    switch (preset) {
      case '1h':  { const d = new Date(now); d.setHours(d.getHours() - 1);   setFromTs(d.toISOString()); break }
      case '6h':  { const d = new Date(now); d.setHours(d.getHours() - 6);   setFromTs(d.toISOString()); break }
      case '24h': { const d = new Date(now); d.setDate(d.getDate() - 1);      setFromTs(d.toISOString()); break }
      case '7d':  { const d = new Date(now); d.setDate(d.getDate() - 7);      setFromTs(d.toISOString()); break }
      case '30d': { const d = new Date(now); d.setDate(d.getDate() - 30);     setFromTs(d.toISOString()); break }
      default: break
    }
  }

  function downloadSelectedJSON() {
    const selectedEvs = events.filter(e => checkedFoIds.has(e.fo_id))
    if (!selectedEvs.length) return
    const blob = new Blob([JSON.stringify(selectedEvs, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `events-${caseId}-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Explain selected events with LLM
  async function explainSelected() {
    const selectedEvs = events.filter(e => checkedFoIds.has(e.fo_id))
    if (!selectedEvs.length) return
    setExplaining(true)
    setExplainResult(null)
    try {
      const r = await api.llm.explainEvents({ events: selectedEvs })
      setExplainResult(r)
    } catch (err) {
      setExplainResult({ error: err.message })
    } finally {
      setExplaining(false)
    }
  }

  function toggleCheck(foId) {
    setCheckedFoIds(prev => {
      const next = new Set(prev)
      if (next.has(foId)) next.delete(foId); else next.add(foId)
      return next
    })
  }

  const maxCount  = histogram.reduce((m, b) => Math.max(m, b.doc_count), 1)
  const hasFilters = selectedType || fromTs || toTs || flaggedOnly
  const vis        = col => visibleCols.includes(col)

  return (
    <div className="flex h-full">
      {/* ── Filter sidebar ─────────────────────────────── */}
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
            {selectedType && (
              <div className="mt-1.5 flex items-center gap-1">
                <span className={`badge ${ARTIFACT_COLORS[selectedType] || ARTIFACT_COLORS.generic} flex-1 justify-center`}>
                  {selectedType}
                </span>
                <button onClick={() => setSelectedType('')} className="text-gray-400 hover:text-gray-600" title="Clear">
                  <X size={10} />
                </button>
              </div>
            )}
          </div>

          {/* Date range */}
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">Time Range</label>

            {/* Quick presets */}
            <div className="grid grid-cols-3 gap-1 mb-1.5">
              {[
                { id: '1h',  label: '1h'  },
                { id: '6h',  label: '6h'  },
                { id: '24h', label: '24h' },
                { id: '7d',  label: '7d'  },
                { id: '30d', label: '30d' },
              ].map(p => (
                <button
                  key={p.id}
                  onClick={() => applyPreset(p.id)}
                  className={`text-[10px] py-0.5 rounded border transition-colors ${
                    activePreset === p.id
                      ? 'bg-brand-accent text-white border-brand-accent'
                      : 'bg-white text-gray-600 border-gray-200 hover:border-brand-accent hover:text-brand-accent'
                  }`}
                >
                  {p.label}
                </button>
              ))}
              <button
                onClick={() => { setShowCustomRange(v => !v); setActivePreset(null) }}
                className={`text-[10px] py-0.5 rounded border transition-colors col-span-3 mt-0.5 ${
                  showCustomRange
                    ? 'bg-brand-accent text-white border-brand-accent'
                    : 'bg-white text-gray-600 border-gray-200 hover:border-brand-accent hover:text-brand-accent'
                }`}
              >
                Custom range
              </button>
            </div>

            {/* Custom date range inputs */}
            {showCustomRange && (
              <div className="space-y-2 mt-1 p-2 bg-gray-50 rounded border border-gray-200">
                <div>
                  <p className="text-[9px] font-semibold text-gray-400 uppercase tracking-wider mb-0.5">From</p>
                  <input
                    type="datetime-local"
                    value={fromTs ? fromTs.slice(0, 16) : ''}
                    onChange={e => { setFromTs(e.target.value ? new Date(e.target.value).toISOString() : ''); setActivePreset(null) }}
                    className="input w-full text-[10px] py-0.5 px-1.5"
                  />
                </div>
                <div>
                  <p className="text-[9px] font-semibold text-gray-400 uppercase tracking-wider mb-0.5">To</p>
                  <input
                    type="datetime-local"
                    value={toTs ? toTs.slice(0, 16) : ''}
                    onChange={e => setToTs(e.target.value ? new Date(e.target.value).toISOString() : '')}
                    className="input w-full text-[10px] py-0.5 px-1.5"
                  />
                </div>
                <div>
                  <p className="text-[9px] font-semibold text-gray-400 uppercase tracking-wider mb-0.5">Natural language (From)</p>
                  <form onSubmit={applyNaturalDate} className="flex gap-1">
                    <input
                      type="text"
                      value={naturalDate}
                      onChange={e => { setNaturalDate(e.target.value); setNaturalDateErr('') }}
                      placeholder="monday, 3 days ago…"
                      className="input flex-1 text-[10px] py-0.5 px-1.5"
                    />
                    <button type="submit" className="btn-ghost text-[10px] px-1.5 py-0.5">→</button>
                  </form>
                  {naturalDateErr && (
                    <p className="text-[9px] text-amber-600 mt-0.5">{naturalDateErr}</p>
                  )}
                </div>
              </div>
            )}

            {/* Active range display */}
            {(fromTs || toTs) && (
              <div className="mt-1.5 flex items-center gap-1 text-[9px] text-gray-500 bg-gray-50 rounded px-1.5 py-1">
                <span className="flex-1 truncate">
                  {fromTs ? new Date(fromTs).toLocaleDateString() : '…'}
                  {' → '}
                  {toTs ? new Date(toTs).toLocaleDateString() : 'now'}
                </span>
                <button onClick={() => applyPreset(null)} className="text-gray-400 hover:text-red-500 flex-shrink-0">
                  <X size={9} />
                </button>
              </div>
            )}
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

      {/* ── Main content ──────────────────────────────── */}
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

            <button
              type="button"
              onClick={() => setRegexpMode(v => !v)}
              title={regexpMode ? 'Regexp mode ON' : 'Switch to regexp mode'}
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

            <button type="button" onClick={downloadCsv} className="btn-ghost text-xs" title="Export CSV">
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

            {/* Column picker trigger */}
            <div className="relative" ref={colPickerRef}>
              <button
                type="button"
                onClick={() => setShowColPicker(v => !v)}
                className={`btn-ghost text-xs ${showColPicker ? 'text-brand-accent' : ''}`}
                title="Configure columns"
              >
                <SlidersHorizontal size={13} />
              </button>

              {showColPicker && (
                <div className="absolute top-full right-0 mt-1 bg-white border border-gray-200 rounded-lg shadow-lg p-3 z-20 w-44">
                  <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Columns</p>
                  <div className="space-y-0.5">
                    {ALL_COLUMNS.map(col => (
                      <label key={col.id} className="flex items-center gap-2 cursor-pointer py-1 px-1 rounded hover:bg-gray-50">
                        <input
                          type="checkbox"
                          checked={visibleCols.includes(col.id)}
                          onChange={() => toggleCol(col.id)}
                          className="rounded border-gray-300 accent-brand-accent"
                        />
                        <span className="text-xs text-gray-700">{col.label}</span>
                      </label>
                    ))}
                  </div>
                  <div className="mt-2 pt-2 border-t border-gray-100">
                    <button
                      onClick={resetCols}
                      className="text-[10px] text-brand-accent hover:underline"
                    >
                      Reset to defaults
                    </button>
                  </div>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={() => setShowHelp(v => !v)}
              className={`btn-ghost text-xs ${showHelp ? 'text-brand-accent' : ''}`}
              title="Keyboard shortcuts (?)"
            >
              <Keyboard size={13} />
            </button>
          </form>

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

        {/* AI explain floating action bar */}
        {checkedFoIds.size > 0 && (
          <div className="px-4 py-2 border-b border-purple-200 bg-purple-50 flex items-center gap-3">
            <Brain size={13} className="text-purple-500 flex-shrink-0" />
            <span className="text-xs text-purple-700 font-medium">
              {checkedFoIds.size} event{checkedFoIds.size !== 1 ? 's' : ''} selected
            </span>
            <button
              onClick={downloadSelectedJSON}
              className="ml-auto btn-ghost text-xs text-gray-600 hover:text-gray-800 border border-gray-200 rounded-lg px-2.5 py-1 flex items-center gap-1.5"
              title="Download selected events as JSON"
            >
              <Download size={11} /> Download
            </button>
            <button
              onClick={explainSelected}
              disabled={explaining}
              className="btn-ghost text-xs text-purple-600 hover:text-purple-800 border border-purple-200 rounded-lg px-2.5 py-1 flex items-center gap-1.5"
            >
              {explaining
                ? <><Loader2 size={11} className="animate-spin" /> Analyzing…</>
                : <><Brain size={11} /> Explain with AI</>}
            </button>
            <button
              onClick={() => { setCheckedFoIds(new Set()); setExplainResult(null) }}
              className="text-gray-400 hover:text-gray-600"
              title="Deselect all"
            >
              <X size={13} />
            </button>
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
                {/* Checkbox for AI explain — always visible */}
                <th className="px-2 py-2.5 w-6">
                  <input
                    type="checkbox"
                    className="rounded border-gray-300 accent-brand-accent"
                    checked={events.length > 0 && events.every(e => checkedFoIds.has(e.fo_id))}
                    onChange={e => {
                      if (e.target.checked) setCheckedFoIds(new Set(events.map(ev => ev.fo_id)))
                      else setCheckedFoIds(new Set())
                    }}
                    title="Select all visible events"
                  />
                </th>
                {/* Flag — always visible */}
                <th className="px-2 py-2.5 w-6" />

                {vis('timestamp') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-40">
                    Timestamp
                  </th>
                )}
                {vis('type') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">
                    Type
                  </th>
                )}
                {vis('level') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-20">
                    Level
                  </th>
                )}
                {vis('event_id') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-20">
                    Event ID
                  </th>
                )}
                {vis('host') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-28">
                    Host
                  </th>
                )}
                {vis('user') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">
                    User
                  </th>
                )}
                {vis('process') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-28">
                    Process
                  </th>
                )}
                {vis('channel') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-28">
                    Channel
                  </th>
                )}
                {vis('rule') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-36">
                    Rule
                  </th>
                )}
                {vis('message') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">
                    Message
                  </th>
                )}
                {vis('tags') && (
                  <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-32">
                    Tags
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {events.map((ev, i) => (
                <EventRow
                  key={ev.fo_id || i}
                  index={i}
                  event={ev}
                  caseId={caseId}
                  visibleCols={visibleCols}
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
                  checked={checkedFoIds.has(ev.fo_id)}
                  onCheck={() => toggleCheck(ev.fo_id)}
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
          key={selectedEvent.fo_id}
          event={selectedEvent}
          caseId={caseId}
          onClose={() => setSelectedEvent(null)}
          onFilterIn={(field, value)  => addFilter(field, value, false)}
          onFilterOut={(field, value) => addFilter(field, value, true)}
        />
      )}

      {/* AI explain result panel */}
      {explainResult && (
        <div
          className="fixed inset-0 z-40 flex items-end justify-center pointer-events-none"
          style={{ paddingBottom: '1rem' }}
        >
          <div
            className="pointer-events-auto bg-white border border-purple-200 rounded-xl shadow-2xl p-5 w-full max-w-lg mx-4"
            style={{ maxHeight: '60vh', overflowY: 'auto' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Brain size={15} className="text-purple-500" />
                <span className="font-semibold text-sm text-gray-800">AI Event Explanation</span>
                {explainResult.events_count != null && (
                  <span className="badge bg-purple-100 text-purple-700 text-[10px]">
                    {explainResult.events_count} event{explainResult.events_count !== 1 ? 's' : ''}
                  </span>
                )}
                {explainResult.model_used && (
                  <span className="text-[10px] text-gray-400 ml-auto">{explainResult.model_used}</span>
                )}
              </div>
              <button
                onClick={() => { setExplainResult(null); setCheckedFoIds(new Set()) }}
                className="text-gray-400 hover:text-gray-600 ml-2"
              >
                <X size={14} />
              </button>
            </div>

            {explainResult.error ? (
              <p className="text-sm text-red-600">{explainResult.error}</p>
            ) : (
              <p className="text-sm text-gray-700 leading-relaxed whitespace-pre-wrap">
                {explainResult.explanation}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Keyboard shortcuts overlay */}
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

/* ── Filter +/− buttons ── */
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
function EventRow({ event, index, onSelect, selected, keyboardSelected, onFilterIn, onFilterOut, rowRef, caseId, onFlagged, visibleCols, checked, onCheck }) {
  const vis  = col => visibleCols.includes(col)
  const art  = getArtifact(event)
  let ts = '—'
  if (event.timestamp) {
    try { ts = new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 19) } catch { ts = String(event.timestamp).slice(0, 19) }
  }
  const type = event.artifact_type || 'generic'
  const color = ARTIFACT_COLORS[type] || ARTIFACT_COLORS.generic

  // Resolve per-column values (check artifact sub-doc first, then top-level)
  const level    = String(art.level || event.level || '').toLowerCase()
  const eventId  = art.event_id != null ? String(art.event_id) : ''
  const host     = event.host?.hostname || ''
  const user     = event.user?.name || ''
  const process  = event.process?.name || event.process?.path?.split(/[\\/]/).pop() || ''
  const channel  = art.channel  || event.channel  || ''
  const rule     = art.rule_title || event.rule_title || ''

  async function handleFlag(e) {
    e.stopPropagation()
    const next = !event.is_flagged
    onFlagged(event.fo_id, next)
    try {
      await api.search.flagEvent(caseId, event.fo_id)
    } catch {
      onFlagged(event.fo_id, event.is_flagged)
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
      {/* Checkbox for AI explain */}
      <td className="px-2 py-2 w-6 text-center">
        <input
          type="checkbox"
          checked={!!checked}
          onChange={e => { e.stopPropagation(); onCheck() }}
          onClick={e => e.stopPropagation()}
          className="rounded border-gray-300 accent-brand-accent cursor-pointer"
        />
      </td>
      {/* Flag — always visible */}
      <td className="px-2 py-2 w-6 text-center">
        <button
          onClick={handleFlag}
          className={`transition-colors flex-shrink-0 ${
            event.is_flagged
              ? 'text-red-500 hover:text-red-400'
              : 'text-gray-300 hover:text-red-400'
          }`}
          title={event.is_flagged ? 'Unflag event' : 'Flag event'}
        >
          <Flag size={11} />
        </button>
      </td>

      {vis('timestamp') && (
        <td className="px-3 py-2 text-gray-400 font-mono whitespace-nowrap tabular-nums">{ts}</td>
      )}

      {vis('type') && (
        <td className="px-3 py-2">
          <div className="flex items-center">
            <span className={`badge ${color}`}>{type}</span>
            <FilterButtons field="artifact_type" value={type} onIn={onFilterIn} onOut={onFilterOut} />
          </div>
        </td>
      )}

      {vis('level') && (
        <td className="px-3 py-2">
          {level ? (
            <span className={`badge text-[10px] px-1.5 py-0.5 font-semibold uppercase tracking-wide ${LEVEL_COLORS[level] || 'bg-gray-100 text-gray-500'}`}>
              {level}
            </span>
          ) : null}
        </td>
      )}

      {vis('event_id') && (
        <td className="px-3 py-2 font-mono text-gray-500">
          {eventId ? (
            <div className="flex items-center">
              <span>{eventId}</span>
              <FilterButtons field={`${type}.event_id`} value={eventId} onIn={onFilterIn} onOut={onFilterOut} />
            </div>
          ) : null}
        </td>
      )}

      {vis('host') && (
        <td className="px-3 py-2 text-gray-500 max-w-[7rem]">
          <div className="flex items-center">
            <span className="truncate">{host}</span>
            {host && <FilterButtons field="host.hostname" value={host} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('user') && (
        <td className="px-3 py-2 text-gray-500 max-w-[6rem]">
          <div className="flex items-center">
            <span className="truncate">{user}</span>
            {user && <FilterButtons field="user.name" value={user} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('process') && (
        <td className="px-3 py-2 text-gray-500 max-w-[7rem]">
          <div className="flex items-center">
            <span className="truncate">{process}</span>
            {process && <FilterButtons field="process.name" value={process} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('channel') && (
        <td className="px-3 py-2 text-gray-500 max-w-[7rem]">
          <div className="flex items-center">
            <span className="truncate">{channel}</span>
            {channel && <FilterButtons field={`${type}.channel`} value={channel} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('rule') && (
        <td className="px-3 py-2 text-gray-600 max-w-[9rem]">
          <div className="flex items-center">
            <span className="truncate">{rule}</span>
            {rule && <FilterButtons field={`${type}.rule_title`} value={rule} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('message') && (
        <td className="px-3 py-2 text-brand-text max-w-sm">
          <span className="line-clamp-1">{event.message}</span>
        </td>
      )}

      {vis('tags') && (
        <td className="px-3 py-2">
          <div className="flex items-center gap-1 flex-wrap">
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
      )}
    </tr>
  )
}
