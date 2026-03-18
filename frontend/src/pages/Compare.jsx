import { useState, useEffect } from 'react'
import { GitCompare, Database, Layers, Users, RefreshCw } from 'lucide-react'
import { api } from '../api/client'

function CaseSelector({ label, cases, value, onChange }) {
  return (
    <div>
      <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">{label}</label>
      <select value={value} onChange={e => onChange(e.target.value)}
        className="input w-full text-sm">
        <option value="">Select a case…</option>
        {cases.map(c => <option key={c.case_id} value={c.case_id}>{c.name}</option>)}
      </select>
    </div>
  )
}

function CompareColumn({ caseData, facets, label }) {
  if (!caseData) return (
    <div className="flex-1 flex items-center justify-center text-gray-600 text-sm italic">
      Select a case
    </div>
  )

  const hostBuckets = facets?.by_hostname?.buckets?.slice(0, 8) || []
  const artifactBuckets = facets?.by_artifact_type?.buckets || []
  const userBuckets = facets?.by_username?.buckets?.slice(0, 5) || []

  return (
    <div className="flex-1 min-w-0 space-y-4">
      <div className="card p-4">
        <h3 className="text-sm font-bold text-gray-100 mb-3 truncate">{caseData.name}</h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-gray-700/30 rounded-lg p-3">
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Events</p>
            <p className="text-xl font-bold text-indigo-400 mt-1">{(caseData.event_count || 0).toLocaleString()}</p>
          </div>
          <div className="bg-gray-700/30 rounded-lg p-3">
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Artifacts</p>
            <p className="text-xl font-bold text-indigo-400 mt-1">{(caseData.artifact_types || []).length}</p>
          </div>
        </div>
      </div>

      <div className="card p-4">
        <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1">
          <Layers size={9} /> Artifact Types
        </p>
        <div className="flex flex-wrap gap-1">
          {(caseData.artifact_types || []).map(at => (
            <span key={at} className="badge bg-gray-700/60 text-gray-300 border border-gray-600/40 text-[10px]">{at}</span>
          ))}
          {(caseData.artifact_types || []).length === 0 && <span className="text-xs text-gray-600 italic">No data</span>}
        </div>
      </div>

      {hostBuckets.length > 0 && (
        <div className="card p-4">
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1">
            <Database size={9} /> Top Hosts
          </p>
          <div className="space-y-1.5">
            {hostBuckets.map(b => {
              const pct = Math.round((b.doc_count / (caseData.event_count || 1)) * 100)
              return (
                <div key={b.key}>
                  <div className="flex items-center justify-between text-xs mb-0.5">
                    <span className="text-gray-300 truncate">{b.key}</span>
                    <span className="text-gray-500 flex-shrink-0 ml-2">{b.doc_count.toLocaleString()}</span>
                  </div>
                  <div className="h-1 bg-gray-700/50 rounded-full overflow-hidden">
                    <div className="h-full bg-indigo-600/60 rounded-full" style={{ width: `${Math.min(pct, 100)}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {userBuckets.length > 0 && (
        <div className="card p-4">
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1">
            <Users size={9} /> Top Users
          </p>
          <div className="space-y-0.5">
            {userBuckets.map(b => (
              <div key={b.key} className="flex items-center justify-between text-xs">
                <span className="text-gray-300 truncate">{b.key}</span>
                <span className="text-gray-500">{b.doc_count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function Compare() {
  const [cases, setCases]       = useState([])
  const [caseAId, setCaseAId]   = useState('')
  const [caseBId, setCaseBId]   = useState('')
  const [dataA, setDataA]       = useState(null)
  const [dataB, setDataB]       = useState(null)
  const [facetsA, setFacetsA]   = useState(null)
  const [facetsB, setFacetsB]   = useState(null)
  const [loading, setLoading]   = useState(false)

  useEffect(() => {
    api.cases.list().then(r => setCases(r.cases || [])).catch(() => {})
  }, [])

  async function load() {
    if (!caseAId && !caseBId) return
    setLoading(true)
    try {
      const [resA, resB, fA, fB] = await Promise.all([
        caseAId ? api.cases.get(caseAId) : Promise.resolve(null),
        caseBId ? api.cases.get(caseBId) : Promise.resolve(null),
        caseAId ? api.search.facets(caseAId, {}) : Promise.resolve(null),
        caseBId ? api.search.facets(caseBId, {}) : Promise.resolve(null),
      ])
      setDataA(resA); setDataB(resB)
      setFacetsA(fA?.facets || null); setFacetsB(fB?.facets || null)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [caseAId, caseBId])

  // Compute shared hostnames
  const hostsA = new Set((facetsA?.by_hostname?.buckets || []).map(b => b.key))
  const hostsB = new Set((facetsB?.by_hostname?.buckets || []).map(b => b.key))
  const sharedHosts = [...hostsA].filter(h => hostsB.has(h))

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-gray-100 flex items-center gap-2">
          <GitCompare size={18} className="text-indigo-400" /> Case Comparison
        </h1>
        <p className="text-sm text-gray-500 mt-1">Compare two cases side by side to find overlaps and patterns</p>
      </div>

      {/* Case selectors */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <CaseSelector label="Case A" cases={cases} value={caseAId} onChange={setCaseAId} />
        <CaseSelector label="Case B" cases={cases.filter(c => c.case_id !== caseAId)} value={caseBId} onChange={setCaseBId} />
      </div>

      {loading && (
        <div className="flex items-center justify-center h-24 text-gray-500 text-xs gap-2">
          <RefreshCw size={14} className="animate-spin" /> Loading…
        </div>
      )}

      {/* Shared hosts banner */}
      {!loading && sharedHosts.length > 0 && (
        <div className="card p-3 mb-4 border-indigo-800/50 bg-indigo-950/20">
          <p className="text-xs font-semibold text-indigo-300 mb-1.5 flex items-center gap-1">
            <Database size={11} /> {sharedHosts.length} shared host{sharedHosts.length !== 1 ? 's' : ''} found in both cases
          </p>
          <div className="flex flex-wrap gap-1">
            {sharedHosts.map(h => (
              <span key={h} className="badge bg-indigo-900/40 text-indigo-300 border border-indigo-800/40 font-mono text-[10px]">{h}</span>
            ))}
          </div>
        </div>
      )}

      {/* Side-by-side comparison */}
      {!loading && (caseAId || caseBId) && (
        <div className="flex gap-4">
          <CompareColumn caseData={dataA} facets={facetsA} label="Case A" />
          <div className="w-px bg-gray-700/60 self-stretch" />
          <CompareColumn caseData={dataB} facets={facetsB} label="Case B" />
        </div>
      )}

      {!caseAId && !caseBId && (
        <div className="card p-12 text-center">
          <GitCompare size={32} className="text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400 text-sm font-medium mb-1">Select two cases to compare</p>
          <p className="text-gray-600 text-xs">Find shared hosts, overlapping time periods, and common patterns across incidents.</p>
        </div>
      )}
    </div>
  )
}
