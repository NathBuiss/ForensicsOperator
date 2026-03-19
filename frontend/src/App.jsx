import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import Dashboard from './pages/Dashboard'
import CaseTimeline from './pages/CaseTimeline'
import Search from './pages/Search'
import AlertLibrary from './pages/AlertLibrary'
import Plugins from './pages/Plugins'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="cases/:caseId" element={<CaseTimeline />} />
          <Route path="cases/:caseId/search" element={<Search />} />
          <Route path="alert-rules" element={<AlertLibrary />} />
          <Route path="plugins" element={<Plugins />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
