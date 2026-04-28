import { useState, useEffect } from 'react'
import { Loader2, Search, Copy, ChevronDown, ChevronRight } from 'lucide-react'
import { api } from '../api/client'

const CATEGORIES = [
  { key: 'src_ips',       label: 'Source IPs',      searchField: 'network.src_ip',      color: 'text-red-600'    },
  { key: 'dst_ips',       label: 'Dest IPs',         searchField: 'network.dst_ip',      color: 'text-orange-600' },
  { key: 'hostnames',     label: 'Hostnames',        searchField: 'host.hostname',       color: 'text-sky-600'    },
  { key: 'usernames',     label: 'Users',            searchField: 'user.name',           color: 'text-violet-600' },
  { key: 'processes',     label: 'Processes',        searchField: 'process.name',        color: 'text-emerald-600'},
  { key: 'domains',       label: 'Domains',          searchField: 'network.dst_domain',  color: 'text-teal-600'   },
  { key: 'urls',          label: 'URLs / Paths',     searchField: 'http.request_path',   color: 'text-blue-600'   },
  { key: 'cmdlines',      label: 'Command Lines',    searchField: 'process.cmdline',     color: 'text-amber-600'  },
  { key: 'hashes_md5',    label: 'MD5 Hashes',       searchField: 'process.hash_md5',    color: 'text-pink-600'   },
  { key: 'hashes_sha256', label: 'SHA256 Hashes',    searchField: 'process.hash_sha256', color: 'text-pink-700'   },
  { key: 'reg_keys',      label: 'Registry Keys',    searchField: 'registry.key',        color: 'text-indigo-600' },
  { key: 'user_agents',   label: 'User Agents',      searchField: 'http.user_agent',     color: 'text-gray-600'   },
]

function IocCategory({ cat, items, onSearch }) {
  const [open, setOpen] = useState(items.length > 0 && items.length <= 10)
  if (!items.length) return null

  return (
    <div className="border border-gray-100 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-3 py-2 bg-gray-50 hover:bg-gray-100 transition-colors text-xs"
      >
        <span className={`font-semibold ${cat.color}`}>{cat.label}</span>
        <div className="flex items-center gap-2 text-gray-500">
          <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[9px]">{items.length}</span>
          {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        </div>
      </button>
      {open && (
        <div className="divide-y divide-gray-50 max-h-64 overflow-y-auto">
          {items.map((item, i) => (
            <div key={i} className="flex items-center gap-2 px-3 py-1.5 group hover:bg-blue-50 transition-colors">
              <span className="flex-1 text-[11px] font-mono text-gray-800 truncate" title={item.value}>
                {item.value}
              </span>
              <span className="text-[9px] text-gray-400 flex-shrink-0 tabular-nums">
                ×{item.count.toLocaleString()}
              </span>
              <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                <button
                  onClick={() => navigator.clipboard.writeText(item.value)}
                  className="p-0.5 rounded hover:bg-gray-200 text-gray-400 hover:text-gray-600 transition-colors"
                  title="Copy"
                >
                  <Copy size={9} />
                </button>
                <button
                  onClick={() => onSearch(`${cat.searchField}:"${item.value}"`)}
                  className="p-0.5 rounded hover:bg-blue-100 text-gray-400 hover:text-blue-600 transition-colors"
                  title="Search this value in timeline"
                >
                  <Search size={9} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function IocPanel({ caseId, onSearch }) {
  const [iocs, setIocs]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState('')

  useEffect(() => {
    setLoading(true)
    api.search.iocs(caseId)
      .then(setIocs)
      .catch(() => setIocs({}))
      .finally(() => setLoading(false))
  }, [caseId])

  const totalIocs = iocs
    ? Object.values(iocs).reduce((s, arr) => s + arr.length, 0)
    : 0

  const filteredCats = CATEGORIES.map(cat => {
    if (!iocs) return { ...cat, items: [] }
    const items = filter
      ? (iocs[cat.key] || []).filter(i => i.value.toLowerCase().includes(filter.toLowerCase()))
      : (iocs[cat.key] || [])
    return { ...cat, items }
  }).filter(c => c.items.length > 0)

  return (
    <div className="flex flex-col h-full p-4 space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-semibold text-brand-text">Observed Indicators</p>
          <p className="text-[10px] text-gray-400 mt-0.5">
            {loading ? 'Loading…' : `${totalIocs} unique values across ${filteredCats.length} categories`}
          </p>
        </div>
      </div>

      {/* Search filter */}
      <div className="relative">
        <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
        <input
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter indicators…"
          className="input w-full pl-7 text-xs"
        />
      </div>

      {/* Body */}
      {loading ? (
        <div className="flex items-center justify-center py-12 text-gray-400">
          <Loader2 size={16} className="animate-spin mr-2" />
          <span className="text-xs">Aggregating case data…</span>
        </div>
      ) : totalIocs === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-center text-gray-400">
          <p className="text-xs">No indicators found for this case.</p>
          <p className="text-[10px] mt-1">Ingest data to populate this panel.</p>
        </div>
      ) : filteredCats.length === 0 ? (
        <p className="text-xs text-gray-400 text-center py-6">No results for "{filter}"</p>
      ) : (
        <div className="space-y-2 overflow-y-auto flex-1">
          {filteredCats.map(cat => (
            <IocCategory key={cat.key} cat={cat} items={cat.items} onSearch={onSearch} />
          ))}
        </div>
      )}
    </div>
  )
}
