import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { api } from '../../api/client'

const ARTIFACT_ICONS = {
  evtx: '📋', prefetch: '⚡', mft: '💾', registry: '🔑',
  lnk: '🔗', timeline: '⏱', browser: '🌐', filesystem: '📁',
}

export default function Layout() {
  const [cases, setCases] = useState([])
  const [showNewCase, setShowNewCase] = useState(false)
  const [newCaseName, setNewCaseName] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    api.cases.list().then(r => setCases(r.cases || [])).catch(() => {})
  }, [])

  async function createCase(e) {
    e.preventDefault()
    if (!newCaseName.trim()) return
    try {
      const c = await api.cases.create({ name: newCaseName.trim() })
      setCases(prev => [c, ...prev])
      setNewCaseName('')
      setShowNewCase(false)
      navigate(`/cases/${c.case_id}`)
    } catch (err) {
      alert('Failed: ' + err.message)
    }
  }

  return (
    <div className="flex h-screen overflow-hidden bg-gray-950">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-gray-900 border-r border-gray-700 flex flex-col">
        <div className="p-4 border-b border-gray-700">
          <NavLink to="/" className="flex items-center gap-2 text-indigo-400 font-bold text-sm tracking-wide">
            <span className="text-lg">🔍</span> ForensicsOp
          </NavLink>
        </div>

        <nav className="flex-1 overflow-y-auto py-3">
          <div className="px-3 mb-1">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Navigation</p>
            <NavLink to="/" end className={({ isActive }) =>
              `flex items-center gap-2 px-2 py-1.5 rounded text-sm mb-0.5 ${isActive ? 'bg-indigo-600/30 text-indigo-300' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'}`}>
              Dashboard
            </NavLink>
            <NavLink to="/plugins" className={({ isActive }) =>
              `flex items-center gap-2 px-2 py-1.5 rounded text-sm mb-0.5 ${isActive ? 'bg-indigo-600/30 text-indigo-300' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'}`}>
              Plugins
            </NavLink>
          </div>

          <div className="px-3 mt-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs text-gray-500 uppercase tracking-wider">Cases</p>
              <button onClick={() => setShowNewCase(true)}
                className="text-indigo-400 hover:text-indigo-300 text-xs">+ New</button>
            </div>

            {showNewCase && (
              <form onSubmit={createCase} className="mb-2">
                <input
                  autoFocus
                  value={newCaseName}
                  onChange={e => setNewCaseName(e.target.value)}
                  placeholder="Case name..."
                  className="input w-full mb-1 text-xs"
                />
                <div className="flex gap-1">
                  <button type="submit" className="btn-primary text-xs flex-1">Create</button>
                  <button type="button" onClick={() => setShowNewCase(false)}
                    className="btn-ghost text-xs flex-1">Cancel</button>
                </div>
              </form>
            )}

            {cases.map(c => (
              <NavLink key={c.case_id} to={`/cases/${c.case_id}`}
                className={({ isActive }) =>
                  `block px-2 py-1.5 rounded text-xs mb-0.5 truncate ${isActive ? 'bg-indigo-600/30 text-indigo-300' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'}`}>
                {c.name}
              </NavLink>
            ))}
          </div>
        </nav>

        <div className="p-3 border-t border-gray-700">
          <a href="/kibana" target="_blank" rel="noreferrer"
            className="text-xs text-gray-500 hover:text-gray-400 flex items-center gap-1">
            Kibana →
          </a>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <Outlet context={{ refreshCases: () => api.cases.list().then(r => setCases(r.cases || [])) }} />
      </main>
    </div>
  )
}
