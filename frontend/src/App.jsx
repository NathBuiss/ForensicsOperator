import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'

import Layout       from './components/layout/Layout'
import Dashboard    from './pages/Dashboard'
import CaseTimeline from './pages/CaseTimeline'
import Search       from './pages/Search'
import AlertLibrary from './pages/AlertLibrary'
import Ingesters    from './pages/Ingesters'
import Modules      from './pages/Modules'
import Collector    from './pages/Collector'
import Cases        from './pages/Cases'
import Studio       from './pages/Studio'
import Docs         from './pages/Docs'
import Login        from './pages/Login'

import { getToken, setToken, clearToken, isAuthenticated } from './api/client'

// ── Auth gate ─────────────────────────────────────────────────────────────────
// Redirects to /login if there is no token in localStorage.
// The token was already validated server-side on every request; here we only
// check that one exists so we can show the login page instead of a broken UI.

function ProtectedRoute({ children }) {
  const location = useLocation()
  if (!isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  return children
}

// ── Root app ──────────────────────────────────────────────────────────────────

export default function App() {
  // user is set after login so Layout can display username / logout button
  const [user, setUser] = useState(() => {
    try {
      const raw = localStorage.getItem('fo_user')
      return raw ? JSON.parse(raw) : null
    } catch { return null }
  })

  function handleLogin(token, userInfo) {
    setToken(token)
    setUser(userInfo)
    localStorage.setItem('fo_user', JSON.stringify(userInfo))
  }

  function handleLogout() {
    clearToken()
    setUser(null)
    localStorage.removeItem('fo_user')
    // ProtectedRoute will redirect to /login on next render
  }

  return (
    <BrowserRouter>
      <Routes>
        {/* ── Public ── */}
        <Route path="/login" element={<Login onLogin={handleLogin} />} />

        {/* ── Protected ── */}
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout user={user} onLogout={handleLogout} />
            </ProtectedRoute>
          }
        >
          <Route index                               element={<Dashboard />} />
          <Route path="cases"                        element={<Cases />} />
          <Route path="cases/:caseId"               element={<CaseTimeline />} />
          <Route path="cases/:caseId/search"        element={<Search />} />
          <Route path="alert-rules"                  element={<AlertLibrary />} />
          <Route path="ingesters"                    element={<Ingesters />} />
          <Route path="modules"                      element={<Modules />} />
          <Route path="collector"                    element={<Collector />} />
          <Route path="studio"                       element={<Studio />} />
          <Route path="docs"                         element={<Docs />} />
          <Route path="plugins" element={<Navigate to="/ingesters" replace />} />
          <Route path="*"       element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
