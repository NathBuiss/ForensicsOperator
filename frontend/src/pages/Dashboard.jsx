import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FolderOpen, Activity, Database, ChevronRight, Plus, Clock } from 'lucide-react'
import { api } from '../api/client'

const STATUS_CONFIG = {
  active:   { label: 'Active',   dot: 'bg-green-400', badge: 'bg-green-100 text-green-700 border-green-200' },
  archived: { label: 'Archived', dot: 'bg-gray-400',  badge: 'bg-gray-100 text-gray-600 border-gray-300' },
  closed:   { label: 'Closed',   dot: 'bg-red-400',   badge: 'bg-red-100 text-red-700 border-red-200' },
}

const ARTIFACT_BADGES = {
  evtx:      'badge-evtx',
  prefetch:  'badge-prefetch',
  mft:       'badge-mft',
  registry:  'badge-registry',
  lnk:       'badge-lnk',
  plaso:     'badge-plaso',
  hayabusa:  'badge-hayabusa',
}

function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs text-gray-500 uppercase tracking-widest font-semibold">{label}</p>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${color}`}>
          <Icon size={15} />
        </div>
      </div>
      <p className="text-2xl font-bold text-brand-text">{value}</p>
    </div>
  )
}

export default function Dashboard() {
  const [cases, setCases]     = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    api.cases.list()
      .then(r => setCases(r.cases || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const totalEvents = cases.reduce((s, c) => s + (c.event_count || 0), 0)
  const activeCases = cases.filter(c => c.status === 'active').length

  return (
    <div className="p-6 max-w-5xl mx-auto">

      {/* Header */}
      <div className="mb-7">
        <h1 className="text-xl font-bold text-brand-text">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">Forensics case management platform</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        <StatCard icon={FolderOpen} label="Total Cases"  value={cases.length}
          color="bg-brand-accent/10 text-brand-accent" />
        <StatCard icon={Activity}   label="Active Cases" value={activeCases}
          color="bg-green-100 text-green-600" />
        <StatCard icon={Database}   label="Total Events" value={totalEvents.toLocaleString()}
          color="bg-purple-100 text-purple-600" />
      </div>

      {/* Cases */}
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-brand-text">Cases</h2>
        <span className="text-xs text-gray-500">{cases.length} total</span>
      </div>

      {loading ? (
        <div className="space-y-3">
          {[1,2,3].map(i => <div key={i} className="skeleton h-20 w-full" />)}
        </div>
      ) : cases.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="w-14 h-14 rounded-full bg-gray-100 flex items-center justify-center mx-auto mb-4">
            <FolderOpen size={24} className="text-gray-400" />
          </div>
          <p className="text-gray-500 text-sm font-medium mb-1">No cases yet</p>
          <p className="text-gray-400 text-xs">
            Click <Plus size={10} className="inline" /> in the sidebar to create your first case.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {cases.map(c => {
            const st = STATUS_CONFIG[c.status] || STATUS_CONFIG.active
            return (
              <div key={c.case_id}
                className="card-hover p-4 group"
                onClick={() => navigate(`/cases/${c.case_id}`)}>
                <div className="flex items-center gap-4">
                  {/* Status indicator */}
                  <div className={`w-1 self-stretch rounded-full ${st.dot}`} />

                  {/* Main info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-sm font-semibold text-brand-text truncate">{c.name}</h3>
                      <span className={`badge border text-[10px] ${st.badge}`}>{st.label}</span>
                    </div>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="flex items-center gap-1 text-xs text-gray-500">
                        <Database size={10} />
                        {(c.event_count || 0).toLocaleString()} events
                      </span>
                      <span className="flex items-center gap-1 text-xs text-gray-400">
                        <Clock size={10} />
                        {new Date(c.created_at).toLocaleDateString()}
                      </span>
                      {c.analyst && (
                        <span className="text-xs text-gray-400">@{c.analyst}</span>
                      )}
                    </div>
                  </div>

                  {/* Artifact badges */}
                  <div className="flex flex-wrap gap-1 max-w-52 justify-end">
                    {(c.artifact_types || []).map(at => (
                      <span key={at} className={`badge ${ARTIFACT_BADGES[at] || 'badge-generic'}`}>{at}</span>
                    ))}
                  </div>

                  <ChevronRight size={14} className="text-gray-400 group-hover:text-brand-accent flex-shrink-0 transition-colors" />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
