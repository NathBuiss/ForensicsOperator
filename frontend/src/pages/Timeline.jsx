import { useEffect, useState, useCallback, useRef } from 'react'
import { api } from '../api/client'
import EventDetail from '../components/shared/EventDetail'

const ARTIFACT_COLORS = {
  evtx: 'bg-blue-900/40 text-blue-400',
  prefetch: 'bg-yellow-900/40 text-yellow-400',
  mft: 'bg-purple-900/40 text-purple-400',
  registry: 'bg-orange-900/40 text-orange-400',
  lnk: 'bg-pink-900/40 text-pink-400',
  timeline: 'bg-teal-900/40 text-teal-400',
  generic: 'bg-gray-700 text-gray-400',
}

const PAGE_SIZE = 100

export default function Timeline({ caseId, artifactTypes }) {
  const [events, setEvents] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(false)
  const [selectedType, setSelectedType] = useState('')
  const [fromTs, setFromTs] = useState('')
  const [toTs, setToTs] = useState('')
  const [selectedEvent, setSelectedEvent] = useState(null)
  const loaderRef = useRef(null)

  const load = useCallback(async (pg = 0, reset = false) => {
    setLoading(true)
    try {
      const params = { page: pg, size: PAGE_SIZE }
      if (selectedType) params.artifact_type = selectedType
      if (fromTs) params.from = fromTs
      if (toTs) params.to = toTs

      const r = await api.search.timeline(caseId, params)
      setTotal(r.total || 0)
      setEvents(prev => reset ? (r.events || []) : [...prev, ...(r.events || [])])
      setPage(pg)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [caseId, selectedType, fromTs, toTs])

  useEffect(() => { load(0, true) }, [load])

  // Intersection observer for infinite scroll
  useEffect(() => {
    if (!loaderRef.current) return
    const obs = new IntersectionObserver(entries => {
      if (entries[0].isIntersecting && !loading && events.length < total) {
        load(page + 1, false)
      }
    }, { threshold: 0.1 })
    obs.observe(loaderRef.current)
    return () => obs.disconnect()
  }, [loaderRef.current, loading, events.length, total, page, load])

  return (
    <div className="flex h-full">
      {/* Filters sidebar */}
      <div className="w-48 flex-shrink-0 bg-gray-900 border-r border-gray-700 p-3">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Filters</p>

        <div className="mb-3">
          <label className="text-xs text-gray-400 mb-1 block">Artifact Type</label>
          <select value={selectedType} onChange={e => setSelectedType(e.target.value)}
            className="input w-full text-xs">
            <option value="">All types</option>
            {artifactTypes.map(at => (
              <option key={at} value={at}>{at}</option>
            ))}
          </select>
        </div>

        <div className="mb-3">
          <label className="text-xs text-gray-400 mb-1 block">From</label>
          <input type="datetime-local" value={fromTs}
            onChange={e => setFromTs(e.target.value ? new Date(e.target.value).toISOString() : '')}
            className="input w-full text-xs" />
        </div>

        <div className="mb-3">
          <label className="text-xs text-gray-400 mb-1 block">To</label>
          <input type="datetime-local" value={toTs}
            onChange={e => setToTs(e.target.value ? new Date(e.target.value).toISOString() : '')}
            className="input w-full text-xs" />
        </div>

        <button onClick={() => { setSelectedType(''); setFromTs(''); setToTs('') }}
          className="btn-ghost w-full text-xs">Clear</button>

        <div className="mt-4 pt-3 border-t border-gray-700">
          <p className="text-xs text-gray-500">{total.toLocaleString()} events</p>
          <p className="text-xs text-gray-600">{events.length} loaded</p>
        </div>
      </div>

      {/* Event list */}
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 && !loading && (
          <div className="p-8 text-center text-gray-500 text-sm">
            No events found. Upload forensics files in the Ingest tab.
          </div>
        )}

        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 border-b border-gray-700">
            <tr>
              <th className="text-left px-3 py-2 text-gray-500 font-medium w-40">Timestamp</th>
              <th className="text-left px-3 py-2 text-gray-500 font-medium w-24">Type</th>
              <th className="text-left px-3 py-2 text-gray-500 font-medium w-28">Host</th>
              <th className="text-left px-3 py-2 text-gray-500 font-medium w-24">User</th>
              <th className="text-left px-3 py-2 text-gray-500 font-medium">Message</th>
              <th className="px-3 py-2 w-16"></th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev, i) => (
              <EventRow key={ev.fo_id || i} event={ev} onSelect={setSelectedEvent} />
            ))}
          </tbody>
        </table>

        <div ref={loaderRef} className="py-4 text-center text-gray-600 text-xs">
          {loading ? 'Loading...' : events.length < total ? 'Scroll for more' : ''}
        </div>
      </div>

      {/* Event detail panel */}
      {selectedEvent && (
        <EventDetail
          event={selectedEvent}
          caseId={caseId}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  )
}

function EventRow({ event, onSelect }) {
  const ts = event.timestamp ? new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 19) : '—'
  const type = event.artifact_type || 'generic'
  const colorClass = ARTIFACT_COLORS[type] || ARTIFACT_COLORS.generic
  const host = event.host?.hostname || ''
  const user = event.user?.name || ''

  return (
    <tr className={`border-b border-gray-800/50 hover:bg-gray-800/40 cursor-pointer transition-colors ${event.is_flagged ? 'bg-red-950/20' : ''}`}
      onClick={() => onSelect(event)}>
      <td className="px-3 py-1.5 text-gray-500 font-mono whitespace-nowrap">{ts}</td>
      <td className="px-3 py-1.5">
        <span className={`badge ${colorClass}`}>{type}</span>
      </td>
      <td className="px-3 py-1.5 text-gray-400 truncate max-w-28">{host}</td>
      <td className="px-3 py-1.5 text-gray-400 truncate max-w-24">{user}</td>
      <td className="px-3 py-1.5 text-gray-300 truncate max-w-sm">{event.message}</td>
      <td className="px-3 py-1.5 text-center">
        {event.is_flagged && <span title="Flagged">🚩</span>}
        {event.tags?.length > 0 && <span title={event.tags.join(', ')}>🏷</span>}
      </td>
    </tr>
  )
}
