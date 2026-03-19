import { useState, useCallback, useEffect } from 'react'
import { useLocation, useParams } from 'react-router-dom'
import { Search as SearchIcon, Bookmark, BookmarkCheck, Download, X, Trash2, Loader2 } from 'lucide-react'
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
const PAGE_SIZE = 50

export default function Search() {
  const { caseId } = useParams()
  const location = useLocation()
  const [query, setQuery]           = useState('')
  const [inputVal, setInputVal]     = useState('')
  const [results, setResults]       = useState([])
  const [total, setTotal]           = useState(0)
  const [facets, setFacets]         = useState({})
  const [loading, setLoading]       = useState(false)
  const [page, setPage]             = useState(0)
  const [filters, setFilters]       = useState({})
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [savedSearches, setSavedSearches] = useState([])
  const [saveName, setSaveName]     = useState('')
  const [showSave, setShowSave]     = useState(false)

  // Load saved searches
  useEffect(() => {
    api.savedSearches.list(caseId).then(r => setSavedSearches(r.searches || [])).catch(() => {})
  }, [caseId])

  // Handle entity pivot from EventDetail
  useEffect(() => {
    const pq = location.state?.pivotQuery
    if (pq) {
      setInputVal(pq)
      setQuery(pq)
    }
  }, [location.state?.pivotQuery])

  const doSearch = useCallback(async (q = query, f = filters, pg = 0) => {
    if (!q && !Object.keys(f).length) return
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
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [caseId, query, filters])

  // Auto-run if pivot query came in
  useEffect(() => {
    if (query) doSearch(query, filters, 0)
  }, [query])

  function handleSearch(e) {
    e.preventDefault()
    setQuery(inputVal)
    doSearch(inputVal, filters, 0)
  }

  function toggleFilter(field, value) {
    setFilters(prev => {
      const next = { ...prev }
      if (next[field] === value) delete next[field]
      else next[field] = value
      return next
    })
  }

  async function saveSearch() {
    if (!saveName.trim()) return
    const s = await api.savedSearches.create(caseId, { name: saveName.trim(), query, filters })
    setSavedSearches(p => [...p, s])
    setSaveName(''); setShowSave(false)
  }

  async function deleteSavedSearch(id) {
    await api.savedSearches.delete(caseId, id)
    setSavedSearches(p => p.filter(s => s.id !== id))
  }

  function loadSavedSearch(s) {
    setInputVal(s.query)
    setQuery(s.query)
    setFilters(s.filters || {})
  }

  function downloadCsv() {
    window.open(api.export.csv(caseId, { q: query, ...filters }))
  }

  return (
    <div className="flex h-full">
      {/* Left sidebar: facets + saved searches */}
      <div className="w-52 flex-shrink-0 bg-white border-r border-gray-200 flex flex-col overflow-y-auto">
        {/* Saved searches */}
        <div className="p-3 border-b border-gray-200">
          <div className="flex items-center justify-between mb-2">
            <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest flex items-center gap-1">
              <Bookmark size={9} /> Saved
            </p>
            {query && (
              <button onClick={() => setShowSave(v => !v)}
                className="text-[10px] text-brand-accent hover:text-brand-accenthover">+ Save</button>
            )}
          </div>
          {showSave && (
            <div className="mb-2 flex gap-1">
              <input value={saveName} onChange={e => setSaveName(e.target.value)}
                placeholder="Name…" className="input flex-1 text-xs py-1" />
              <button onClick={saveSearch} className="btn-primary text-xs px-2">
                <BookmarkCheck size={11} />
              </button>
            </div>
          )}
          {savedSearches.length === 0 && (
            <p className="text-[10px] text-gray-400 italic">No saved searches yet</p>
          )}
          {savedSearches.map(s => (
            <div key={s.id} className="flex items-center gap-1 mb-0.5 group">
              <button onClick={() => loadSavedSearch(s)}
                className="flex-1 text-left text-xs text-gray-600 hover:text-brand-text truncate px-1 py-0.5 rounded hover:bg-gray-50 transition-colors">
                {s.name}
              </button>
              <button onClick={() => deleteSavedSearch(s.id)}
                className="opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-gray-100 text-gray-400 hover:text-red-500 transition-all">
                <Trash2 size={10} />
              </button>
            </div>
          ))}
        </div>

        {/* Facets */}
        <div className="p-3 flex-1">
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-2">Facets</p>
          {Object.entries({
            by_artifact_type: 'Artifact Type',
            by_hostname: 'Hostname',
            by_username: 'Username',
            by_event_id: 'Event ID',
            by_channel: 'Channel',
          }).map(([key, label]) => {
            const buckets = facets[key]?.buckets || []
            if (!buckets.length) return null
            const filterKey = key === 'by_artifact_type' ? 'artifact_type' : key === 'by_hostname' ? 'hostname'
              : key === 'by_username' ? 'username' : key === 'by_event_id' ? 'event_id' : 'channel'
            return (
              <div key={key} className="mb-3">
                <p className="text-[10px] font-medium text-gray-500 mb-1">{label}</p>
                {buckets.slice(0, 10).map(b => (
                  <button key={b.key}
                    onClick={() => toggleFilter(filterKey, b.key)}
                    className={`flex items-center justify-between w-full px-2 py-0.5 rounded text-xs mb-0.5 transition-colors
                      ${filters[filterKey] === b.key
                        ? 'bg-brand-accentlight text-brand-accent'
                        : 'text-gray-600 hover:bg-gray-50 hover:text-brand-text'}`}>
                    <span className="truncate">{b.key}</span>
                    <span className="text-gray-400 ml-1 flex-shrink-0">{b.doc_count}</span>
                  </button>
                ))}
              </div>
            )
          })}
        </div>
      </div>

      {/* Main */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <form onSubmit={handleSearch} className="p-3 border-b border-gray-200 flex gap-2 bg-white">
          <div className="relative flex-1">
            <SearchIcon size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input value={inputVal} onChange={e => setInputVal(e.target.value)}
              placeholder='Search… "mimikatz", "EventID:4624", "hostname:DC*"'
              className="input-lg pl-9 text-xs" />
          </div>
          <button type="submit" className="btn-primary text-xs">Search</button>
          {Object.keys(filters).length > 0 && (
            <button type="button" onClick={() => setFilters({})} className="btn-ghost text-xs"><X size={13} /></button>
          )}
          {results.length > 0 && (
            <button type="button" onClick={downloadCsv} className="btn-ghost text-xs" title="Export CSV">
              <Download size={13} />
            </button>
          )}
        </form>

        {Object.entries(filters).length > 0 && (
          <div className="px-3 py-1.5 border-b border-gray-200 flex flex-wrap gap-1 bg-gray-50">
            {Object.entries(filters).map(([k, v]) => (
              <span key={k} className="badge bg-brand-accentlight text-brand-accent border border-brand-accent/20 cursor-pointer hover:bg-brand-accent/10"
                onClick={() => toggleFilter(k, v)}>{k}: {v} ×</span>
            ))}
          </div>
        )}

        <div className="flex-1 overflow-y-auto">
          {loading && (
            <div className="flex items-center justify-center h-24 text-gray-500 text-xs gap-2">
              <Loader2 size={14} className="animate-spin" /> Searching…
            </div>
          )}
          {!loading && results.length === 0 && (
            <div className="flex flex-col items-center justify-center h-48 text-center">
              <SearchIcon size={28} className="text-gray-300 mb-3" />
              <p className="text-gray-500 text-sm">{query || Object.keys(filters).length ? 'No results.' : 'Enter a search query above.'}</p>
            </div>
          )}
          {results.length > 0 && (
            <>
              <div className="px-3 py-1.5 text-[10px] text-gray-500 border-b border-gray-200 bg-gray-50">
                {total.toLocaleString()} results
              </div>
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-40">Timestamp</th>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">Type</th>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-28">Host</th>
                    <th className="text-left px-3 py-2.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((ev, i) => {
                    const ts = ev.timestamp ? new Date(ev.timestamp).toISOString().replace('T',' ').slice(0,19) : '—'
                    const type = ev.artifact_type || 'generic'
                    return (
                      <tr key={ev.fo_id || i}
                        className="border-b border-gray-100 hover:bg-gray-50 cursor-pointer transition-colors"
                        onClick={() => setSelectedEvent(ev)}>
                        <td className="px-3 py-2 text-gray-400 font-mono whitespace-nowrap tabular-nums">{ts}</td>
                        <td className="px-3 py-2"><span className={`badge ${ARTIFACT_COLORS[type] || ARTIFACT_COLORS.generic}`}>{type}</span></td>
                        <td className="px-3 py-2 text-gray-500 truncate">{ev.host?.hostname || ''}</td>
                        <td className="px-3 py-2 text-brand-text max-w-md"><span className="line-clamp-1">{ev.message}</span></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {results.length < total && (
                <div className="p-3 text-center">
                  <button onClick={() => doSearch(query, filters, page + 1)} className="btn-ghost text-xs">
                    Load more
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {selectedEvent && <EventDetail event={selectedEvent} caseId={caseId} onClose={() => setSelectedEvent(null)} />}
    </div>
  )
}
