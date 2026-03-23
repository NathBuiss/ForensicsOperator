import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
  LayoutDashboard, Puzzle, FolderOpen,
  Plus, X, ChevronRight, Bell, Sun, Moon, Cpu, PackageOpen, Layers,
  Code2, BookOpen, LogOut, UserCircle, Settings2, Stars,
} from 'lucide-react'
import { api } from '../../api/client'
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts'
import KeyboardShortcutsModal from '../KeyboardShortcutsModal'

const STATUS_DOT = {
  active:   'status-dot-active',
  archived: 'status-dot-archived',
  closed:   'status-dot-closed',
}

const THEMES = ['light', 'dark', 'midnight']

function useTheme() {
  const [theme, setTheme] = useState(() => {
    if (typeof window === 'undefined') return 'light'
    const saved = localStorage.getItem('fo-theme')
    if (saved && THEMES.includes(saved)) return saved
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })

  useEffect(() => {
    const root = document.documentElement
    THEMES.forEach(t => root.classList.remove(t))
    if (theme !== 'light') root.classList.add(theme)
    localStorage.setItem('fo-theme', theme)
  }, [theme])

  function cycleTheme() {
    setTheme(t => THEMES[(THEMES.indexOf(t) + 1) % THEMES.length])
  }

  return [theme, cycleTheme]
}

export default function Layout({ user, onLogout }) {
  const [cases, setCases]             = useState([])
  const [showNewCase, setShowNewCase] = useState(false)
  const [newCaseName, setNewCaseName] = useState('')
  const [theme, cycleTheme]            = useTheme()
  const [showShortcuts, setShowShortcuts] = useState(false)
  const navigate = useNavigate()

  useKeyboardShortcuts([
    { key: 'g d', handler: () => navigate('/') },
    { key: 'g c', handler: () => navigate('/cases') },
    { key: 'g m', handler: () => navigate('/modules') },
    { key: 'g a', handler: () => navigate('/alert-rules') },
    { key: 'g i', handler: () => navigate('/ingesters') },
    { key: 'g s', handler: () => navigate('/studio') },
    { key: 'shift+/', handler: () => setShowShortcuts(v => !v), skipInputs: false },
    { key: 'escape', handler: () => setShowShortcuts(false) },
  ])

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
        <div className="px-4 py-4 border-b border-white/10 flex items-center justify-between">
          <NavLink to="/" className="flex items-center group min-w-0">
            <span className="text-sm font-bold text-white tracking-wide leading-tight truncate">
              TraceX
            </span>
          </NavLink>

          {/* Theme toggle — cycles: light → dark → midnight */}
          <button
            onClick={cycleTheme}
            className="w-6 h-6 flex items-center justify-center rounded text-brand-sidebarmuted hover:text-white hover:bg-white/10 transition-colors flex-shrink-0 ml-1"
            title={`Theme: ${theme} (click to cycle)`}
          >
            {theme === 'light'    && <Moon size={13} />}
            {theme === 'dark'     && <Stars size={13} />}
            {theme === 'midnight' && <Sun size={13} />}
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto py-3 px-2 scrollbar-thin">

          {/* ── Platform ─────────────────────────────── */}
          <p className="px-2 mb-1.5 mt-1 text-[10px] font-semibold text-white/30 uppercase tracking-widest">
            Platform
          </p>

          <NavLink to="/" end className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <LayoutDashboard size={15} />
            Dashboard
          </NavLink>

          <NavLink to="/cases" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Layers size={15} />
            Cases
          </NavLink>

          <NavLink to="/collector" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <PackageOpen size={15} />
            Collector
          </NavLink>

          {/* ── Detection ────────────────────────────── */}
          <p className="px-2 mb-1.5 mt-4 text-[10px] font-semibold text-white/30 uppercase tracking-widest">
            Detection
          </p>

          <NavLink to="/alert-rules" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Bell size={15} />
            Alert Rules
          </NavLink>

          <NavLink to="/modules" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Cpu size={15} />
            Modules
          </NavLink>

          {/* ── Developer ────────────────────────────── */}
          <p className="px-2 mb-1.5 mt-4 text-[10px] font-semibold text-white/30 uppercase tracking-widest">
            Developer
          </p>

          <NavLink to="/ingesters" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Puzzle size={15} />
            Ingesters
          </NavLink>

          <NavLink to="/studio" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Code2 size={15} />
            Studio
          </NavLink>

          <NavLink to="/docs" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <BookOpen size={15} />
            Docs
          </NavLink>

          {/* ── Admin ─────────────────────────────────── */}
          <p className="px-2 mb-1.5 mt-4 text-[10px] font-semibold text-white/30 uppercase tracking-widest">
            Admin
          </p>

          <NavLink to="/settings" className={({ isActive }) =>
            isActive ? 'nav-item-active' : 'nav-item-inactive'}>
            <Settings2 size={15} />
            Settings
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

        {/* ── User / logout footer ───────────────────────────────────────── */}
        {user && (
          <div className="px-3 py-3 border-t border-white/10 flex items-center gap-2">
            <UserCircle size={16} className="text-brand-sidebarmuted flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-white truncate">{user.username}</p>
              <p className="text-[10px] text-white/40 capitalize">{user.role}</p>
            </div>
            <button
              onClick={() => setShowShortcuts(true)}
              className="icon-btn text-gray-400 hover:text-gray-600"
              title="Keyboard shortcuts (?)"
            >
              <span className="text-[11px] font-mono font-bold">?</span>
            </button>
            <button
              onClick={onLogout}
              title="Sign out"
              className="w-6 h-6 flex items-center justify-center rounded text-brand-sidebarmuted
                         hover:text-white hover:bg-white/10 transition-colors flex-shrink-0"
            >
              <LogOut size={13} />
            </button>
          </div>
        )}
      </aside>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      {/*
        flex flex-col: makes children that use flex-1 fill the height.
        overflow-y-auto: regular pages scroll; Studio/Docs manage their own overflow.
      */}
      <main className="flex-1 flex flex-col overflow-y-auto bg-gray-50">
        <Outlet context={{ refreshCases }} />
      </main>

      {showShortcuts && <KeyboardShortcutsModal onClose={() => setShowShortcuts(false)} />}
    </div>
  )
}
