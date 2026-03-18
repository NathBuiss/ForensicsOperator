import { useEffect, useState } from 'react'
import { useNavigate, useOutletContext } from 'react-router-dom'
import { api } from '../api/client'

const STATUS_COLORS = {
  active: 'bg-green-900/40 text-green-400 border-green-800',
  archived: 'bg-gray-700 text-gray-400 border-gray-600',
  closed: 'bg-red-900/40 text-red-400 border-red-800',
}

const ARTIFACT_BADGES = {
  evtx: { label: 'EVTX', color: 'bg-blue-900/40 text-blue-400' },
  prefetch: { label: 'Prefetch', color: 'bg-yellow-900/40 text-yellow-400' },
  mft: { label: 'MFT', color: 'bg-purple-900/40 text-purple-400' },
  registry: { label: 'Registry', color: 'bg-orange-900/40 text-orange-400' },
  lnk: { label: 'LNK', color: 'bg-pink-900/40 text-pink-400' },
  timeline: { label: 'Timeline', color: 'bg-teal-900/40 text-teal-400' },
}

export default function Dashboard() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    api.cases.list()
      .then(r => setCases(r.cases || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const totalEvents = cases.reduce((s, c) => s + (c.event_count || 0), 0)

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-gray-100">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">Forensics case management</p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        {[
          { label: 'Total Cases', value: cases.length },
          { label: 'Active Cases', value: cases.filter(c => c.status === 'active').length },
          { label: 'Total Events', value: totalEvents.toLocaleString() },
        ].map(stat => (
          <div key={stat.label} className="card p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wider">{stat.label}</p>
            <p className="text-2xl font-bold text-indigo-400 mt-1">{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Cases grid */}
      {loading ? (
        <div className="text-gray-500 text-sm">Loading cases...</div>
      ) : cases.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-gray-500 text-sm mb-3">No cases yet.</p>
          <p className="text-gray-600 text-xs">Click "+ New" in the sidebar to create your first case.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {cases.map(c => (
            <div key={c.case_id}
              className="card p-4 cursor-pointer hover:border-indigo-600 transition-colors"
              onClick={() => navigate(`/cases/${c.case_id}`)}>
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-semibold text-gray-100 truncate">{c.name}</h2>
                    <span className={`badge border ${STATUS_COLORS[c.status] || STATUS_COLORS.active}`}>
                      {c.status}
                    </span>
                  </div>
                  {c.description && (
                    <p className="text-xs text-gray-500 mt-0.5 truncate">{c.description}</p>
                  )}
                  <div className="flex items-center gap-3 mt-2">
                    <span className="text-xs text-gray-500">
                      {(c.event_count || 0).toLocaleString()} events
                    </span>
                    {c.analyst && (
                      <span className="text-xs text-gray-500">analyst: {c.analyst}</span>
                    )}
                    <span className="text-xs text-gray-600">
                      {new Date(c.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1 ml-4 max-w-48">
                  {(c.artifact_types || []).map(at => {
                    const badge = ARTIFACT_BADGES[at] || { label: at, color: 'bg-gray-700 text-gray-400' }
                    return (
                      <span key={at} className={`badge ${badge.color}`}>{badge.label}</span>
                    )
                  })}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
