import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
  Shield, LayoutDashboard, Puzzle, FolderOpen,
  Plus, X, ExternalLink, ChevronRight, GitCompare, Bell,
} from 'lucide-react'
import { api } from '../../api/client'

const STATUS_DOT = {
  active:   'status-dot-active',
  archived: 'status-dot-archived',
  closed:   'status-dot-closed',
}

export default function Layout() {
  const [cases, setCases]            = useState([])
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
    <div className="flex h-screen overflow-hidden bg-gray-50">

      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <aside className="w-56 flex-shrink-0 flex flex-col bg-brand-sidebar">

        {/* Logo */}
        <div className="px-4 py-4 border-b border-white/10">
          <NavLink to="/" className="flex items-center gap-2.5 group">
            <div className="w-7 h-7 rounded-lg bg-brand-accent/20 border border-brand-accent/30
                            flex items-center justify-center flex-shrink-0">
              <Shield size={14} className="text-brand-accent" />
            </div>
            <span className="text-sm font-bold text-white tracking-wide leading-tight">
              Forensics Operator
            </span>
          </NavLink>
        </div>

        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5 scrollbar-thin">

          {/* Main nav */}
          <p className="px-2 mb-1.5 text-[10px] font-semibold text-white/30 uppercase tracking-widest">
            Navigation
          </p>

          <NavLink to="/" end className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <LayoutDashboard size={15} />
            Dashboard
          </NavLink>

          <NavLink to="/alert-rules" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Bell size={15} />
            Alert Rules
          </NavLink>

          <NavLink to="/plugins" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Puzzle size={15} />
            Plugins
          </NavLink>

          <NavLink to="/compare" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <GitCompare size={15} />
            Compare
          </NavLink>

          {/* Cases section */}
          <div className="pt-4">
            <div className="flex items-center justify-between px-2 mb-1.5">
              <p className="text-[10px] font-semibold text-white/30 uppercase tracking-widest
                            flex items-center gap-1.5">
                <FolderOpen size={10} /> Cases
              </p>
              <button
                onClick={() => setShowNewCase(v => !v)}
                className="w-5 h-5 rounded flex items-center justify-center text-brand-sidebarmuted
                           hover:text-white hover:bg-white/10 transition-colors"
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
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-2.5 py-1.5
                             text-xs text-white placeholder-white/40 outline-none
                             focus:border-brand-accent focus:ring-1 focus:ring-brand-accent/30
                             transition-colors mb-1.5"
                />
                <div className="flex gap-1">
                  <button type="submit"
                    className="flex-1 btn-primary text-xs justify-center py-1">
                    Create
                  </button>
                  <button type="button" onClick={() => setShowNewCase(false)}
                    className="px-2 py-1 rounded-lg text-brand-sidebarmuted hover:text-white
                               hover:bg-white/10 transition-colors">
                    <X size={12} />
                  </button>
                </div>
              </form>
            )}

            <div className="space-y-0.5">
              {cases.map(c => (
                <NavLink
                  key={c.case_id}
                  to={`/cases/${c.case_id}`}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs transition-all duration-150 ${
                      isActive
                        ? 'bg-white/10 text-white'
                        : 'text-brand-sidebarmuted hover:text-white hover:bg-white/[0.06]'
                    }`
                  }
                >
                  <span className={`status-dot ${STATUS_DOT[c.status] || STATUS_DOT.active}`} />
                  <span className="truncate flex-1">{c.name}</span>
                  <ChevronRight size={10} className="opacity-30 flex-shrink-0" />
                </NavLink>
              ))}

              {cases.length === 0 && !showNewCase && (
                <p className="px-2 py-2 text-xs text-white/20 italic">No cases yet</p>
              )}
            </div>
          </div>
        </nav>

        {/* Footer */}
        <div className="p-3 border-t border-white/10">
          <a href="/kibana" target="_blank" rel="noreferrer"
            className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs
                       text-brand-sidebarmuted hover:text-white hover:bg-white/10 transition-colors">
            <ExternalLink size={12} />
            Open Kibana
          </a>
        </div>
      </aside>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto bg-gray-50">
        <Outlet context={{ refreshCases }} />
      </main>
    </div>
  )
}
