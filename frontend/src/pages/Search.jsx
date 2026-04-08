import { useState, useCallback, useEffect, useRef } from 'react'
import { useLocation, useParams, useNavigate } from 'react-router-dom'
import {
  Search as SearchIcon, Bookmark, BookmarkCheck, Download, X, Trash2,
  Loader2, HelpCircle, ArrowLeft, ChevronRight, Clock, Tag, Flag,
  ExternalLink, Filter, Sparkles,
} from 'lucide-react'
import { api } from '../api/client'
import EventDetail from '../components/shared/EventDetail'
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts'

// ── AI Search Assist Panel ────────────────────────────────────────────────────
function AiSearchPanel({ caseId, onApply, onClose }) {
  const [text, setText]       = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState(null)
  const [error, setError]     = useState('')

  async function submit(e) {
    e.preventDefault()
    if (!text.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const res = await api.llm.searchAssist({ query: text, case_id: caseId })
      setResult(res)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <div className="panel-backdrop" onClick={onClose} />
      <div className="fixed right-0 top-0 h-full w-80 bg-white border-l border-gray-200 shadow-xl z-50 overflow-y-auto flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Sparkles size={14} className="text-indigo-500" />
            <span className="font-semibold text-brand-text text-sm">AI Search Assist</span>
          </div>
          <button onClick={onClose} className="icon-btn"><X size={14} /></button>
        </div>
        <div className="p-4 flex-1 space-y-4">
          <p className="text-xs text-gray-500">
            Describe what you want to find in plain English — the AI will generate the Elasticsearch query for you.
          </p>
          <form onSubmit={submit} className="space-y-2">
            <textarea
              value={text}
              onChange={e => setText(e.target.value)}
              placeholder="e.g. failed logins from the last week&#10;mimikatz or credential dumping activity&#10;all network connections from workstation WS01"
              className="input w-full text-xs resize-none"
              rows={4}
              autoFocus
            />
            <button type="submit" disabled={!text.trim() || loading} className="btn-primary text-xs w-full justify-center">
              {loading ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
              {loading ? 'Generating…' : 'Generate Query'}
            </button>
          </form>

          {error && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <X size={12} /> {error}
            </p>
          )}

          {result && (
            <div className="space-y-2">
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
                <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-widest mb-1.5">Generated Query</p>
                <code className="block text-xs text-brand-accent font-mono break-all">{result.query}</code>
              </div>
              {result.explanation && (
                <p className="text-xs text-gray-500 italic">{result.explanation}</p>
              )}
              <button
                onClick={() => { onApply(result.query); onClose() }}
                className="btn-primary text-xs w-full justify-center"
              >
                <SearchIcon size={12} /> Apply Query
              </button>
            </div>
          )}
        </div>
      </div>
    </>
  )
}

// ── Search Help Panel ─────────────────────────────────────────────────────────
function SearchHelpPanel({ onClose }) {
  return (
    <>
      <div className="panel-backdrop" onClick={onClose} />
      <div className="fixed right-0 top-0 h-full w-80 bg-white border-l border-gray-200 shadow-xl z-50 overflow-y-auto flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <HelpCircle size={14} className="text-brand-accent" />
            <span className="font-semibold text-brand-text text-sm">Search Syntax</span>
          </div>
          <button onClick={onClose} className="icon-btn"><X size={14} /></button>
        </div>
        <div className="p-4 space-y-4 text-xs flex-1">
          <section>
            <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-widest mb-1.5">Basic</p>
            <div className="space-y-1">
              {[
                { q: 'apache error', desc: 'both words' },
                { q: '"apache error"', desc: 'exact phrase' },
                { q: 'error OR warning', desc: 'either term' },
                { q: 'error AND NOT timeout', desc: 'exclusion' },
                { q: 'err*', desc: 'wildcard prefix' },
              ].map(({ q, desc }) => (
                <div key={q} className="flex gap-2">
                  <code className="flex-shrink-0 bg-gray-100 text-brand-accent px-1.5 py-0.5 rounded font-mono text-[11px]">{q}</code>
                  <span className="text-gray-500">{desc}</span>
                </div>
              ))}
            </div>
          </section>
          <section>
            <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-widest mb-1.5">Fields</p>
            <div className="space-y-1">
              {[
                { q: 'EventID:4624', desc: 'field value' },
                { q: 'host.hostname:DC01', desc: 'nested field' },
                { q: 'message:*failed*', desc: 'wildcard in field' },
                { q: 'EventID:[4624 TO 4634]', desc: 'range' },
              ].map(({ q, desc }) => (
                <div key={q} className="flex gap-2">
                  <code className="flex-shrink-0 bg-gray-100 text-brand-accent px-1.5 py-0.5 rounded font-mono text-[11px]">{q}</code>
                  <span className="text-gray-500">{desc}</span>
                </div>
              ))}
            </div>
          </section>
          <section>
            <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-widest mb-1.5">Examples</p>
            <div className="space-y-1.5">
              {[
                { q: 'EventID:4624 AND username:admin', desc: 'admin logins' },
                { q: 'EventID:(4625 OR 4771)', desc: 'failed auth' },
                { q: 'host.hostname:DC* AND EventID:4768', desc: 'Kerberos on DCs' },
              ].map(({ q, desc }) => (
                <div key={q}>
                  <code className="block bg-gray-100 text-brand-accent px-2 py-0.5 rounded font-mono text-[11px] break-all">{q}</code>
                  <span className="text-gray-500">{desc}</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </>
  )
}

const ARTIFACT_COLORS = {
  evtx:     'badge-evtx',
  prefetch: 'badge-prefetch',
  mft:      'badge-mft',
  registry: 'badge-registry',
  lnk:      'badge-lnk',
  plaso:    'badge-plaso',
  hayabusa: 'badge-hayabusa',
  browser:  'badge-generic',
  network:  'badge-generic',
  android:  'badge-generic',
  ios:      'badge-generic',
  generic:  'badge-generic',
}
const PAGE_SIZE = 50

export default function Search() {
  const { caseId } = useParams()
  const location = useLocation()
  const navigate = useNavigate()
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
  const [showHelp, setShowHelp]     = useState(false)
  const [caseName, setCaseName]     = useState('')
  const [showFacets, setShowFacets]       = useState(true)
  const [showAiAssist, setShowAiAssist]   = useState(false)
  const queryInputRef = useRef(null)

  // Load case info for breadcrumb
  useEffect(() => {
    api.cases.get(caseId)
      .then(c => setCaseName(c.name || c.case_id || caseId))
      .catch(() => setCaseName(caseId))
  }, [caseId])

  useEffect(() => {
    api.savedSearches.list(caseId).then(r => setSavedSearches(r.searches || [])).catch(() => {})
  }, [caseId])

  useEffect(() => {
    const pq = location.state?.pivotQuery
    if (pq) { setInputVal(pq); setQuery(pq); return }
    // Also support ?q= URL param (used by "View in Search" links from AlertRules)
    const qParam = new URLSearchParams(location.search).get('q')
    if (qParam) { setInputVal(qParam); setQuery(qParam) }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

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

  useEffect(() => {
    if (query) doSearch(query, filters, 0)
  }, [query]) // eslint-disable-line react-hooks/exhaustive-deps

  useKeyboardShortcuts([
    { key: '/', handler: () => queryInputRef.current?.focus() },
    { key: 'cmd+enter', handler: () => { setQuery(inputVal); doSearch(inputVal, filters, 0) }, skipInputs: false },
    { key: 'shift+/', handler: () => setShowHelp(v => !v), skipInputs: false },
    { key: 'Escape', handler: () => { if (selectedEvent) setSelectedEvent(null); else if (showHelp) setShowHelp(false) } },
  ])

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

  // Re-run search when filters change (if there's an active query)
  useEffect(() => {
    if (query || Object.keys(filters).length) doSearch(query, filters, 0)
  }, [filters]) // eslint-disable-line react-hooks/exhaustive-deps

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

  const activeFacetKeys = Object.entries({
    by_artifact_type: { label: 'Type', key: 'artifact_type' },
    by_hostname:      { label: 'Host', key: 'hostname' },
    by_username:      { label: 'User', key: 'username' },
    by_event_id:      { label: 'Event ID', key: 'event_id' },
    by_channel:       { label: 'Channel', key: 'channel' },
  })

  const hasFacetData = activeFacetKeys.some(([k]) => (facets[k]?.buckets || []).length > 0)

  return (
    <div className="flex flex-col h-full">

      {/* ── Top bar: breadcrumb + search ─────────────────────────── */}
      <div className="bg-white border-b border-gray-200 flex-shrink-0">
        {/* Breadcrumb row */}
        <div className="px-3 py-2 flex items-center gap-2 border-b border-gray-100">
          <button
            onClick={() => navigate(`/cases/${caseId}`)}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-brand-accent transition-colors"
          >
            <ArrowLeft size={12} />
            <span className="truncate max-w-[200px]">{caseName}</span>
          </button>
          <ChevronRight size={10} className="text-gray-300" />
          <span className="text-xs font-medium text-brand-text">Search</span>
          <div className="ml-auto flex items-center gap-1.5">
            <button
              onClick={() => navigate(`/cases/${caseId}`)}
              className="btn-ghost text-[10px] px-2 py-0.5"
            >
              Timeline
            </button>
            <button
              onClick={() => navigate('/cases')}
              className="btn-ghost text-[10px] px-2 py-0.5"
            >
              All Cases
            </button>
            <button
              onClick={() => navigate('/alert-rules')}
              className="btn-ghost text-[10px] px-2 py-0.5"
            >
              Alert Rules
            </button>
          </div>
        </div>

        {/* Search bar row */}
        <form onSubmit={handleSearch} className="px-3 py-2 flex gap-2 items-center">
          <div className="relative flex-1">
            <SearchIcon size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              ref={queryInputRef}
              value={inputVal}
              onChange={e => setInputVal(e.target.value)}
              placeholder='Search… "mimikatz", "EventID:4624", "hostname:DC*"   (/ to focus, ⌘Enter to search)'
              className="input-lg pl-8 text-xs w-full"
            />
          </div>
          <button type="submit" className="btn-primary text-xs px-3">
            <SearchIcon size={12} /> Search
          </button>
          <button type="button" onClick={() => { setShowAiAssist(v => !v); setShowHelp(false) }}
            className={`btn-ghost text-xs p-1.5 ${showAiAssist ? 'text-indigo-500' : ''}`}
            title="AI search assist — describe what you want to find">
            <Sparkles size={14} />
          </button>
          <button type="button" onClick={() => { setShowHelp(v => !v); setShowAiAssist(false) }}
            className={`btn-ghost text-xs p-1.5 ${showHelp ? 'text-brand-accent' : ''}`}
            title="Search syntax help (Shift+/)">
            <HelpCircle size={14} />
          </button>
          {hasFacetData && (
            <button type="button" onClick={() => setShowFacets(v => !v)}
              className={`btn-ghost text-xs p-1.5 ${showFacets ? 'text-brand-accent' : ''}`}
              title="Toggle facets panel">
              <Filter size={14} />
            </button>
          )}
          {results.length > 0 && (
            <button type="button" onClick={downloadCsv} className="btn-ghost text-xs p-1.5" title="Export CSV">
              <Download size={13} />
            </button>
          )}
        </form>

        {/* Active filters chips */}
        {Object.entries(filters).length > 0 && (
          <div className="px-3 py-1.5 border-t border-gray-100 flex flex-wrap gap-1 bg-gray-50">
            {Object.entries(filters).map(([k, v]) => (
              <span key={k}
                className="badge bg-brand-accentlight text-brand-accent border border-brand-accent/20 cursor-pointer hover:bg-brand-accent/10"
                onClick={() => toggleFilter(k, v)}>
                {k}: {v} ×
              </span>
            ))}
            <button onClick={() => setFilters({})} className="text-[10px] text-gray-400 hover:text-gray-600 ml-1">
              Clear all
            </button>
          </div>
        )}
      </div>

      {/* ── Content area ──────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden min-h-0">

        {/* Facets sidebar (collapsible) */}
        {showFacets && hasFacetData && (
          <div className="w-44 flex-shrink-0 bg-white border-r border-gray-200 overflow-y-auto">
            {/* Saved searches */}
            <div className="p-2.5 border-b border-gray-200">
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest flex items-center gap-1">
                  <Bookmark size={9} /> Saved
                </p>
                {query && (
                  <button onClick={() => setShowSave(v => !v)}
                    className="text-[10px] text-brand-accent hover:text-brand-accenthover">+ Save</button>
                )}
              </div>
              {showSave && (
                <div className="mb-1.5 flex gap-1">
                  <input value={saveName} onChange={e => setSaveName(e.target.value)}
                    placeholder="Name…" className="input flex-1 text-[11px] py-0.5 px-1.5" />
                  <button onClick={saveSearch} className="btn-primary text-xs px-1.5 py-0.5">
                    <BookmarkCheck size={10} />
                  </button>
                </div>
              )}
              {savedSearches.length === 0 && (
                <p className="text-[10px] text-gray-400 italic">None yet</p>
              )}
              {savedSearches.map(s => (
                <div key={s.id} className="flex items-center gap-0.5 mb-0.5 group">
                  <button onClick={() => loadSavedSearch(s)}
                    className="flex-1 text-left text-[11px] text-gray-600 hover:text-brand-text truncate px-1 py-0.5 rounded hover:bg-gray-50 transition-colors">
                    {s.name}
                  </button>
                  <button onClick={() => deleteSavedSearch(s.id)}
                    className="opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-gray-100 text-gray-400 hover:text-red-500 transition-all">
                    <Trash2 size={9} />
                  </button>
                </div>
              ))}
            </div>

            {/* Facet groups */}
            <div className="p-2.5">
              {activeFacetKeys.map(([aggKey, { label, key: filterKey }]) => {
                const buckets = facets[aggKey]?.buckets || []
                if (!buckets.length) return null
                return (
                  <div key={aggKey} className="mb-3">
                    <p className="text-[10px] font-medium text-gray-500 mb-0.5">{label}</p>
                    {buckets.slice(0, 8).map(b => (
                      <button key={b.key}
                        onClick={() => toggleFilter(filterKey, b.key)}
                        className={`flex items-center justify-between w-full px-1.5 py-0.5 rounded text-[11px] mb-px transition-colors
                          ${filters[filterKey] === b.key
                            ? 'bg-brand-accentlight text-brand-accent font-medium'
                            : 'text-gray-600 hover:bg-gray-50 hover:text-brand-text'}`}>
                        <span className="truncate">{b.key}</span>
                        <span className="text-gray-400 ml-1 flex-shrink-0 text-[10px]">{b.doc_count}</span>
                      </button>
                    ))}
                    {buckets.length > 8 && (
                      <p className="text-[10px] text-gray-400 px-1.5">+{buckets.length - 8} more</p>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Results area */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {loading && (
            <div className="flex items-center justify-center h-20 text-gray-500 text-xs gap-2">
              <Loader2 size={14} className="animate-spin" /> Searching…
            </div>
          )}
          {!loading && results.length === 0 && (
            <div className="flex flex-col items-center justify-center flex-1 text-center p-8">
              <SearchIcon size={32} className="text-gray-200 mb-3" />
              <p className="text-gray-500 text-sm mb-1">
                {query || Object.keys(filters).length ? 'No results found.' : 'Enter a search query to get started.'}
              </p>
              <p className="text-gray-400 text-xs">
                Press <kbd className="px-1 py-0.5 bg-gray-100 rounded text-[10px] font-mono">/</kbd> to focus the search bar,{' '}
                <kbd className="px-1 py-0.5 bg-gray-100 rounded text-[10px] font-mono">⌘↵</kbd> to search
              </p>
            </div>
          )}
          {results.length > 0 && (
            <>
              <div className="px-3 py-1 text-[10px] text-gray-500 border-b border-gray-100 bg-gray-50/50 flex items-center justify-between">
                <span>{total.toLocaleString()} results</span>
                <span className="text-gray-400">Showing {results.length}</span>
              </div>
              <div className="flex-1 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-gray-50 border-b border-gray-200 z-10">
                    <tr>
                      <th className="text-left px-2 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-36">Timestamp</th>
                      <th className="text-left px-2 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-20">Type</th>
                      <th className="text-left px-2 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">Host</th>
                      <th className="text-left px-2 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((ev, i) => {
                      const ts = ev.timestamp ? new Date(ev.timestamp).toISOString().replace('T',' ').slice(0,19) : '—'
                      const type = ev.artifact_type || 'generic'
                      return (
                        <tr key={ev.fo_id || i}
                          className={`border-b border-gray-50 hover:bg-blue-50/50 cursor-pointer transition-colors
                            ${ev.is_flagged ? 'bg-amber-50/50' : ''}
                            ${selectedEvent?.fo_id === ev.fo_id ? 'bg-brand-accentlight' : ''}`}
                          onClick={() => setSelectedEvent(ev)}>
                          <td className="px-2 py-1.5 text-gray-400 font-mono whitespace-nowrap tabular-nums text-[11px]">{ts}</td>
                          <td className="px-2 py-1.5"><span className={`badge text-[10px] ${ARTIFACT_COLORS[type] || ARTIFACT_COLORS.generic}`}>{type}</span></td>
                          <td className="px-2 py-1.5 text-gray-500 truncate max-w-[120px] text-[11px]">{ev.host?.hostname || ''}</td>
                          <td className="px-2 py-1.5 text-brand-text max-w-md">
                            <span className="line-clamp-1 text-[11px]">{ev.message}</span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
                {results.length < total && (
                  <div className="p-2 text-center">
                    <button
                      onClick={() => doSearch(query, filters, page + 1)}
                      disabled={loading}
                      className="btn-ghost text-xs"
                    >
                      {loading ? <Loader2 size={12} className="animate-spin" /> : null}
                      Load more ({total - results.length} remaining)
                    </button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Event detail side panel — inside the flex row so it appears on the right */}
        {selectedEvent && (
          <EventDetail
            key={selectedEvent.fo_id}
            event={selectedEvent}
            caseId={caseId}
            onClose={() => setSelectedEvent(null)}
          />
        )}
      </div>

      {showHelp      && <SearchHelpPanel onClose={() => setShowHelp(false)} />}
      {showAiAssist  && (
        <AiSearchPanel
          caseId={caseId}
          onApply={q => { setInputVal(q); setQuery(q); doSearch(q, filters, 0) }}
          onClose={() => setShowAiAssist(false)}
        />
      )}
    </div>
  )
}
