import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
  Shield, LayoutDashboard, Puzzle, FolderOpen,
  Plus, X, ExternalLink, ChevronRight, GitCompare,
} from 'lucide-react'
import { api } from '../../api/client'

const STATUS_DOT = {
  active:   'bg-green-400',
  archived: 'bg-gray-500',
  closed:   'bg-red-400',
}

export default function Layout() {
  const [cases, setCases]           = useState([])
  const [showNewCase, setShowNewCase] = useState(false)
  const [newCaseName, setNewCaseName] = useState('')
  const navigate = useNavigate()

  const refreshCases = () =>
    api.cases.list().then(r => setCases(r.cases || [])).catch(() => {})

  useEffect(() => { refreshCases() }, [])

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
      <aside className="w-56 flex-shrink-0 flex flex-col bg-gray-900/80 border-r border-gray-700/60">

        {/* Logo */}
        <div className="px-4 py-4 border-b border-gray-700/60">
          <NavLink to="/" className="flex items-center gap-2.5 group">
            <div className="w-7 h-7 rounded-lg bg-indigo-600/20 border border-indigo-600/40 flex items-center justify-center">
              <Shield size={14} className="text-indigo-400" />
            </div>
            <span className="text-sm font-bold text-gray-100 tracking-wide group-hover:text-indigo-300 transition-colors">
              ForensicsOp
            </span>
          </NavLink>
        </div>

        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
          {/* Main nav */}
          <p className="px-2 mb-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-widest">
            Menu
          </p>

          <NavLink to="/" end className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <LayoutDashboard size={14} />
            Dashboard
          </NavLink>

          <NavLink to="/plugins" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Puzzle size={14} />
            Plugins
          </NavLink>

          <NavLink to="/compare" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <GitCompare size={14} />
            Compare
          </NavLink>

          {/* Cases section */}
          <div className="pt-3">
            <div className="flex items-center justify-between px-2 mb-1.5">
              <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest flex items-center gap-1">
                <FolderOpen size={10} /> Cases
              </p>
              <button
                onClick={() => setShowNewCase(v => !v)}
                className="w-5 h-5 rounded flex items-center justify-center text-gray-500
                           hover:text-indigo-400 hover:bg-indigo-900/30 transition-colors"
                title="New case"
              >
                <Plus size={12} />
              </button>
            </div>

            {showNewCase && (
              <form onSubmit={createCase} className="mb-2 px-1">
                <input
                  autoFocus
                  value={newCaseName}
                  onChange={e => setNewCaseName(e.target.value)}
                  placeholder="Case name..."
                  className="input w-full mb-1.5 text-xs"
                />
                <div className="flex gap-1">
                  <button type="submit" className="btn-primary text-xs flex-1 justify-center">
                    Create
                  </button>
                  <button type="button" onClick={() => setShowNewCase(false)}
                    className="btn-ghost text-xs px-2">
                    <X size={12} />
                  </button>
                </div>
              </form>
            )}

            <div className="space-y-0.5">
              {cases.map(c => (
                <NavLink key={c.case_id} to={`/cases/${c.case_id}`}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs transition-all duration-150 ${
                      isActive
                        ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-700/40'
                        : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700/50'
                    }`
                  }>
                  <span className={`status-dot ${STATUS_DOT[c.status] || STATUS_DOT.active}`} />
                  <span className="truncate flex-1">{c.name}</span>
                  <ChevronRight size={10} className="opacity-30 flex-shrink-0" />
                </NavLink>
              ))}
            </div>

            {cases.length === 0 && (
              <p className="px-2 py-2 text-xs text-gray-600 italic">No cases yet</p>
            )}
          </div>
        </nav>

        {/* Footer */}
        <div className="p-3 border-t border-gray-700/60">
          <a href="/kibana" target="_blank" rel="noreferrer"
            className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs text-gray-500
                       hover:text-gray-300 hover:bg-gray-700/50 transition-all">
            <ExternalLink size={12} />
            Open Kibana
          </a>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <Outlet context={{ refreshCases }} />
      </main>
    </div>
  )
}
