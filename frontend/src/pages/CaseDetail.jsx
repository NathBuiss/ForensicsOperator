import { useParams, useNavigate, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { api } from '../api/client'
import Timeline from './Timeline'
import Search from './Search'
import Ingest from './Ingest'
import AlertRules from './AlertRules'

export default function CaseDetail() {
  const { caseId } = useParams()
  const navigate = useNavigate()
  const [caseData, setCaseData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.cases.get(caseId)
      .then(setCaseData)
      .catch(() => navigate('/'))
      .finally(() => setLoading(false))
  }, [caseId])

  if (loading) return <div className="p-6 text-gray-500 text-sm">Loading...</div>
  if (!caseData) return null

  const tabs = [
    { path: 'timeline', label: 'Timeline' },
    { path: 'search', label: 'Search' },
    { path: 'ingest', label: 'Ingest' },
    { path: 'alerts', label: 'Alerts', icon: AlertTriangle },
  ]

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="bg-gray-900 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-base font-bold text-gray-100">{caseData.name}</h1>
            <p className="text-xs text-gray-500 mt-0.5">
              {(caseData.event_count || 0).toLocaleString()} events ·
              {(caseData.artifact_types || []).join(', ') || 'no data'} ·
              ID: <code className="text-gray-600">{caseId}</code>
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => {
                if (confirm('Delete this case and all its data?')) {
                  api.cases.delete(caseId).then(() => navigate('/'))
                }
              }}
              className="btn-danger text-xs">
              Delete Case
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mt-4">
          {tabs.map(tab => (
            <NavLink
              key={tab.path}
              to={tab.path}
              className={({ isActive }) =>
                `px-3 py-1 text-xs rounded transition-colors flex items-center gap-1 ${
                  isActive
                    ? 'bg-indigo-600 text-white'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'
                }`
              }>
              {tab.icon && <tab.icon size={11} />}
              {tab.label}
            </NavLink>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden">
        <Routes>
          <Route index element={<Navigate to="timeline" replace />} />
          <Route path="timeline" element={<Timeline caseId={caseId} artifactTypes={caseData.artifact_types || []} />} />
          <Route path="search" element={<Search caseId={caseId} />} />
          <Route path="ingest" element={<Ingest caseId={caseId} onComplete={() =>
            api.cases.get(caseId).then(setCaseData)} />} />
          <Route path="alerts" element={<AlertRules caseId={caseId} />} />
        </Routes>
      </div>
    </div>
  )
}
