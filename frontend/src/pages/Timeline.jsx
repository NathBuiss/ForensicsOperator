import { useEffect, useState, useCallback, useRef } from 'react'
import { Search, Filter, X, Flag, Tag, Loader2, Download, BarChart2 } from 'lucide-react'
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

export default function Timeline({ caseId, artifactTypes }) {
  const [events, setEvents]             = useState([])
  const [total, setTotal]               = useState(0)
  const [page, setPage]                 = useState(0)
  const [loading, setLoading]           = useState(false)
  const [selectedType, setSelectedType] = useState('')
  const [fromTs, setFromTs]             = useState('')
  const [toTs, setToTs]                 = useState('')
  const [query, setQuery]               = useState('')
  const [inputVal, setInputVal]         = useState('')
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [histogram, setHistogram]       = useState([])
  const [showHistogram, setShowHistogram] = useState(true)
  const loaderRef = useRef(null)

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
      const r = query
        ? await api.search.search(caseId, { ...params, q: query })
        : await api.search.timeline(caseId, params)
      setTotal(r.total || 0)
      setEvents(prev => reset ? (r.events || []) : [...prev, ...(r.events || [])])
      setPage(pg)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [caseId, selectedType, fromTs, toTs, query])

  useEffect(() => { load(0, true) }, [load])

  useEffect(() => {
    if (!loaderRef.current) return
    const obs = new IntersectionObserver(entries => {
      if (entries[0].isIntersecting && !loading && events.length < total)
        load(page + 1, false)
    }, { threshold: 0.1 })
    obs.observe(loaderRef.current)
    return () => obs.disconnect()
  }, [loaderRef.current, loading, events.length, total, page, load])

  function submitSearch(e) { e.preventDefault(); setQuery(inputVal.trim()) }
  function clearSearch()    { setInputVal(''); setQuery('') }

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

  return (
    <div className="flex h-full">
      {/* Filter sidebar */}
      <div className="w-44 flex-shrink-0 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-3 border-b border-gray-200">
          <p className="flex items-center gap-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-widest">
            <Filter size={10} /> Filters
          </p>
        </div>
        <div className="p-3 space-y-3 flex-1">
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">Artifact</label>
            <select value={selectedType} onChange={e => setSelectedType(e.target.value)} className="input w-full text-xs py-1">
              <option value="">All types</option>
              {artifactTypes.map(at => <option key={at} value={at}>{at}</option>)}
            </select>
          </div>
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">From</label>
            <input type="datetime-local" value={fromTs ? fromTs.slice(0,16) : ''}
              onChange={e => setFromTs(e.target.value ? new Date(e.target.value).toISOString() : '')}
              className="input w-full text-xs py-1" />
          </div>
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">To</label>
            <input type="datetime-local" value={toTs ? toTs.slice(0,16) : ''}
              onChange={e => setToTs(e.target.value ? new Date(e.target.value).toISOString() : '')}
              className="input w-full text-xs py-1" />
          </div>
          {(selectedType || fromTs || toTs) && (
            <button onClick={() => { setSelectedType(''); setFromTs(''); setToTs('') }} className="btn-ghost w-full text-xs justify-center">
              <X size={11} /> Clear
            </button>
          )}
        </div>
        <div className="p-3 border-t border-gray-200 space-y-0.5">
          <p className="text-xs font-semibold text-brand-text">{total.toLocaleString()}</p>
          <p className="text-[10px] text-gray-500">{query ? 'search results' : 'events total'}</p>
          {events.length < total && <p className="text-[10px] text-gray-400">{events.length} loaded</p>}
        </div>
      </div>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Search bar */}
        <div className="px-4 py-3 border-b border-gray-200 bg-white">
          <form onSubmit={submitSearch} className="flex gap-2">
            <div className="relative flex-1">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              <input value={inputVal} onChange={e => setInputVal(e.target.value)}
                placeholder='Search events… "EventID:4624", "hostname:DC01"'
                className="input-lg pl-9 pr-4 text-xs" />
            </div>
            <button type="submit" className="btn-primary text-xs px-4">Search</button>
            {query && <button type="button" onClick={clearSearch} className="btn-ghost text-xs"><X size={13} /></button>}
            <button type="button" onClick={downloadCsv} className="btn-ghost text-xs" title="Export CSV">
              <Download size={13} />
            </button>
            {histogram.length > 0 && (
              <button type="button" onClick={() => setShowHistogram(v => !v)}
                className={`btn-ghost text-xs ${showHistogram ? 'text-brand-accent' : ''}`} title="Toggle histogram">
                <BarChart2 size={13} />
              </button>
            )}
          </form>
          {query && (
            <div className="flex items-center gap-2 mt-2">
              <span className="text-[10px] text-gray-500">Query:</span>
              <span className="badge bg-brand-accentlight text-brand-accent border border-brand-accent/20 text-[10px]">{query}</span>
              <span className="text-[10px] text-gray-400">— {total.toLocaleString()} result{total !== 1 ? 's' : ''}</span>
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
                const day = new Date(b.key).toLocaleDateString(undefined, {month:'short',day:'numeric'})
                const active = fromTs && toTs && b.key >= new Date(fromTs).getTime() && b.key <= new Date(toTs).getTime()
                return (
                  <div key={i} className="flex flex-col items-center group cursor-pointer flex-shrink-0"
                    onClick={() => clickBar(b)} title={`${day}: ${b.doc_count.toLocaleString()} events`}>
                    <div style={{ height: h }}
                      className={`w-2 rounded-t transition-colors ${active ? 'bg-brand-accent' : 'bg-brand-accent/25 group-hover:bg-brand-accent/50'}`} />
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
              <p className="text-gray-500 text-sm">{query ? 'No events match your search.' : 'No events yet.'}</p>
              <p className="text-gray-400 text-xs mt-1">{query ? 'Try a different query.' : 'Upload forensics files using the Ingest button.'}</p>
            </div>
          )}
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-50 border-b border-gray-200 z-10">
              <tr>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-40">Timestamp</th>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">Type</th>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-28">Host</th>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">User</th>
                <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Message</th>
                <th className="px-3 py-2.5 w-12" />
              </tr>
            </thead>
            <tbody>
              {events.map((ev, i) => <EventRow key={ev.fo_id || i} event={ev} onSelect={setSelectedEvent} selected={selectedEvent?.fo_id === ev.fo_id} />)}
            </tbody>
          </table>
          <div ref={loaderRef} className="py-5 flex items-center justify-center text-gray-400 text-xs gap-2">
            {loading ? <><Loader2 size={13} className="animate-spin" /> Loading…</>
              : events.length < total ? <span className="text-gray-400">↓ Scroll for more</span>
              : events.length > 0 ? <span className="text-gray-300">— End of results —</span> : null}
          </div>
        </div>
      </div>

      {selectedEvent && (
        <EventDetail event={selectedEvent} caseId={caseId} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  )
}

function EventRow({ event, onSelect, selected }) {
  const ts    = event.timestamp ? new Date(event.timestamp).toISOString().replace('T',' ').slice(0,19) : '—'
  const type  = event.artifact_type || 'generic'
  const color = ARTIFACT_COLORS[type] || ARTIFACT_COLORS.generic
  return (
    <tr onClick={() => onSelect(event)}
      className={`border-b cursor-pointer transition-colors text-xs
        ${selected
          ? 'bg-brand-accentlight border-brand-accent/20'
          : event.is_flagged
          ? 'bg-red-50 hover:bg-red-100 border-red-100'
          : 'border-gray-100 hover:bg-gray-50'}`}>
      <td className="px-3 py-2 text-gray-400 font-mono whitespace-nowrap tabular-nums">{ts}</td>
      <td className="px-3 py-2"><span className={`badge ${color}`}>{type}</span></td>
      <td className="px-3 py-2 text-gray-500 truncate max-w-[7rem]">{event.host?.hostname || ''}</td>
      <td className="px-3 py-2 text-gray-500 truncate max-w-[6rem]">{event.user?.name || ''}</td>
      <td className="px-3 py-2 text-brand-text max-w-sm"><span className="line-clamp-1">{event.message}</span></td>
      <td className="px-3 py-2">
        <div className="flex items-center gap-1 justify-end">
          {event.is_flagged       && <Flag size={10} className="text-red-500" />}
          {event.tags?.length > 0 && <Tag  size={10} className="text-brand-accent" />}
        </div>
      </td>
    </tr>
  )
}
