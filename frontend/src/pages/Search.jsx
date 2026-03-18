import { useState, useCallback } from 'react'
import { api } from '../api/client'
import EventDetail from '../components/shared/EventDetail'

const ARTIFACT_COLORS = {
  evtx: 'bg-blue-900/40 text-blue-400',
  prefetch: 'bg-yellow-900/40 text-yellow-400',
  mft: 'bg-purple-900/40 text-purple-400',
  registry: 'bg-orange-900/40 text-orange-400',
  lnk: 'bg-pink-900/40 text-pink-400',
  generic: 'bg-gray-700 text-gray-400',
}

export default function Search({ caseId }) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])
  const [total, setTotal] = useState(0)
  const [facets, setFacets] = useState({})
  const [loading, setLoading] = useState(false)
  const [page, setPage] = useState(0)
  const [filters, setFilters] = useState({})
  const [selectedEvent, setSelectedEvent] = useState(null)

  const PAGE_SIZE = 50

  const doSearch = useCallback(async (q = query, f = filters, pg = 0) => {
    setLoading(true)
    try {
      const params = { q, page: pg, size: PAGE_SIZE, ...f }
      const [r, facsR] = await Promise.all([
        api.search.search(caseId, params),
        api.search.facets(caseId, { q, ...f }),
      ])
      setResults(pg === 0 ? (r.events || []) : prev => [...prev, ...(r.events || [])])
      setTotal(r.total || 0)
      setFacets(facsR.facets || {})
      setPage(pg)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [caseId, query, filters])

  function handleSearch(e) {
    e.preventDefault()
    doSearch(query, filters, 0)
  }

  function toggleFilter(field, value) {
    setFilters(prev => {
      const cur = prev[field]
      if (cur === value) {
        const next = { ...prev }
        delete next[field]
        return next
      }
      return { ...prev, [field]: value }
    })
  }

  return (
    <div className="flex h-full">
      {/* Facet sidebar */}
      <div className="w-52 flex-shrink-0 bg-gray-900 border-r border-gray-700 p-3 overflow-y-auto">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Facets</p>

        {Object.entries({
          by_artifact_type: 'Artifact Type',
          by_hostname: 'Hostname',
          by_username: 'Username',
          by_event_id: 'Event ID',
          by_channel: 'Channel',
        }).map(([key, label]) => {
          const buckets = facets[key]?.buckets || []
          if (!buckets.length) return null
          return (
            <div key={key} className="mb-4">
              <p className="text-xs text-gray-400 mb-1 font-medium">{label}</p>
              {buckets.slice(0, 10).map(b => (
                <button key={b.key}
                  onClick={() => toggleFilter(
                    key === 'by_artifact_type' ? 'artifact_type' :
                    key === 'by_hostname' ? 'hostname' :
                    key === 'by_username' ? 'username' :
                    key === 'by_event_id' ? 'event_id' : 'channel',
                    b.key
                  )}
                  className="flex items-center justify-between w-full px-2 py-0.5 rounded text-xs hover:bg-gray-700 text-gray-400 hover:text-gray-200 mb-0.5">
                  <span className="truncate">{b.key}</span>
                  <span className="text-gray-600 ml-1">{b.doc_count}</span>
                </button>
              ))}
            </div>
          )
        })}
      </div>

      {/* Main search area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Search bar */}
        <form onSubmit={handleSearch} className="p-3 border-b border-gray-700 flex gap-2">
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search events... (e.g. mimikatz, EventID:4624, hostname:DESKTOP-*)"
            className="input flex-1"
          />
          <button type="submit" className="btn-primary">Search</button>
          {Object.keys(filters).length > 0 && (
            <button type="button" onClick={() => { setFilters({}); doSearch(query, {}, 0) }}
              className="btn-ghost text-xs">Clear filters</button>
          )}
        </form>

        {/* Active filters */}
        {Object.entries(filters).length > 0 && (
          <div className="px-3 py-1.5 border-b border-gray-700 flex flex-wrap gap-1">
            {Object.entries(filters).map(([k, v]) => (
              <span key={k} className="badge bg-indigo-900/40 text-indigo-400 cursor-pointer"
                onClick={() => toggleFilter(k, v)}>
                {k}: {v} ×
              </span>
            ))}
          </div>
        )}

        {/* Results */}
        <div className="flex-1 overflow-y-auto">
          {loading && <div className="p-4 text-gray-500 text-xs">Searching...</div>}
          {!loading && results.length === 0 && (
            <div className="p-8 text-center text-gray-500 text-sm">
              {query || Object.keys(filters).length ? 'No results.' : 'Enter a search query above.'}
            </div>
          )}

          {results.length > 0 && (
            <>
              <div className="px-3 py-1.5 text-xs text-gray-500 border-b border-gray-700">
                {total.toLocaleString()} results
              </div>
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-gray-900 border-b border-gray-700">
                  <tr>
                    <th className="text-left px-3 py-2 text-gray-500 font-medium w-40">Timestamp</th>
                    <th className="text-left px-3 py-2 text-gray-500 font-medium w-24">Type</th>
                    <th className="text-left px-3 py-2 text-gray-500 font-medium w-28">Host</th>
                    <th className="text-left px-3 py-2 text-gray-500 font-medium">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((ev, i) => {
                    const ts = ev.timestamp
                      ? new Date(ev.timestamp).toISOString().replace('T', ' ').slice(0, 19)
                      : '—'
                    const type = ev.artifact_type || 'generic'
                    return (
                      <tr key={ev.fo_id || i}
                        className="border-b border-gray-800/50 hover:bg-gray-800/40 cursor-pointer"
                        onClick={() => setSelectedEvent(ev)}>
                        <td className="px-3 py-1.5 text-gray-500 font-mono whitespace-nowrap">{ts}</td>
                        <td className="px-3 py-1.5">
                          <span className={`badge ${ARTIFACT_COLORS[type] || ARTIFACT_COLORS.generic}`}>
                            {type}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 text-gray-400">{ev.host?.hostname || ''}</td>
                        <td className="px-3 py-1.5 text-gray-300 truncate max-w-md">{ev.message}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>

              {results.length < total && (
                <div className="p-3 text-center">
                  <button onClick={() => doSearch(query, filters, page + 1)}
                    className="btn-ghost text-xs">Load more</button>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {selectedEvent && (
        <EventDetail event={selectedEvent} caseId={caseId} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  )
}
