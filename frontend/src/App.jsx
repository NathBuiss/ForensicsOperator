import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import Dashboard from './pages/Dashboard'
import CaseTimeline from './pages/CaseTimeline'
import Search from './pages/Search'
import AlertLibrary from './pages/AlertLibrary'
import Ingesters from './pages/Ingesters'
import Modules from './pages/Modules'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="cases/:caseId" element={<CaseTimeline />} />
          <Route path="cases/:caseId/search" element={<Search />} />
          <Route path="alert-rules" element={<AlertLibrary />} />
          <Route path="ingesters" element={<Ingesters />} />
          <Route path="modules" element={<Modules />} />
          {/* Legacy redirect — keep old /plugins links working */}
          <Route path="plugins" element={<Navigate to="/ingesters" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
