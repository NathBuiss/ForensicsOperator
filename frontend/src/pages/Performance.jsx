import { useState, useEffect, useRef } from 'react'
import { Activity, Database, HardDrive, Server, Cpu, RefreshCw, Pause, Play, AlertTriangle, CheckCircle, Layers, Clock } from 'lucide-react'
import { api } from '../api/client'

/* ── Helpers ─────────────────────────────────────────────────────────────── */

function statusColor(level) {
  if (level === 'green')  return { dot: 'bg-green-400', bg: 'bg-green-100', text: 'text-green-700', border: 'border-green-200' }
  if (level === 'yellow') return { dot: 'bg-amber-400', bg: 'bg-amber-100', text: 'text-amber-700', border: 'border-amber-200' }
  return { dot: 'bg-red-400', bg: 'bg-red-100', text: 'text-red-700', border: 'border-red-200' }
}

function percentLevel(pct) {
  if (pct < 70) return 'green'
  if (pct < 90) return 'yellow'
  return 'red'
}

function barColor(level) {
  if (level === 'green')  return 'bg-green-500'
  if (level === 'yellow') return 'bg-amber-500'
  return 'bg-red-500'
}

function formatUptime(seconds) {
  if (!seconds) return '--'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

function fmt(n) {
  if (n == null) return '--'
  return Number(n).toLocaleString()
}

function fmtMB(n) {
  if (n == null) return '--'
  if (n >= 1024) return `${(n / 1024).toFixed(1)} GB`
  return `${Number(n).toFixed(1)} MB`
}

/* ── Sub-components ──────────────────────────────────────────────────────── */

function ProgressBar({ percent, level }) {
  const pct = Math.min(100, Math.max(0, percent || 0))
  return (
    <div className="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full transition-all duration-500 ${barColor(level || percentLevel(pct))}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}

function MetricRow({ label, value, sub }) {
  return (
    <div className="flex items-center justify-between py-1.5">
      <span className="text-xs text-gray-500">{label}</span>
      <div className="text-right">
        <span className="text-sm font-semibold text-brand-text">{value}</span>
        {sub && <span className="text-xs text-gray-400 ml-1">{sub}</span>}
      </div>
    </div>
  )
}

function StatusDot({ level }) {
  const c = statusColor(level)
  return <span className={`inline-block w-2 h-2 rounded-full ${c.dot}`} />
}

function SectionCard({ icon: Icon, title, statusLevel, children }) {
  const c = statusLevel ? statusColor(statusLevel) : null
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon size={15} className="text-brand-accent" />
        <h2 className="font-semibold text-brand-text text-sm">{title}</h2>
        {c && (
          <span className={`ml-auto badge border text-[10px] ${c.bg} ${c.text} ${c.border}`}>
            {statusLevel === 'green' ? 'Healthy' : statusLevel === 'yellow' ? 'Warning' : 'Critical'}
          </span>
        )}
      </div>
      {children}
    </div>
  )
}

function SkeletonCard() {
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-4">
        <div className="skeleton w-4 h-4 rounded" />
        <div className="skeleton h-4 w-24 rounded" />
      </div>
      <div className="space-y-3">
        <div className="skeleton h-2 w-full rounded-full" />
        <div className="skeleton h-3 w-3/4 rounded" />
        <div className="skeleton h-3 w-1/2 rounded" />
        <div className="skeleton h-2 w-full rounded-full" />
        <div className="skeleton h-3 w-2/3 rounded" />
      </div>
    </div>
  )
}

/* ── Main Component ──────────────────────────────────────────────────────── */

export default function Performance() {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [paused, setPaused]   = useState(false)
  const [esExpanded, setEsExpanded] = useState(false)
  const intervalRef = useRef(null)

  async function fetchMetrics() {
    try {
      const res = await api.metrics.dashboard()
      setData(res)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchMetrics()
  }, [])

  useEffect(() => {
    if (paused) {
      if (intervalRef.current) clearInterval(intervalRef.current)
      intervalRef.current = null
      return
    }
    intervalRef.current = setInterval(fetchMetrics, 5000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [paused])

  const sys    = data?.system
  const es     = data?.elasticsearch
  const redis  = data?.redis
  const minio  = data?.minio
  const celery = data?.celery
  const cases  = data?.cases

  // Determine overall status levels
  const sysLevel = sys
    ? percentLevel(Math.max(sys.cpu_percent || 0, sys.memory_percent || 0, sys.disk_percent || 0))
    : null
  const esLevel = es
    ? (es.status === 'green' ? 'green' : es.status === 'yellow' ? 'yellow' : 'red')
    : null

  return (
    <div className="p-6 max-w-5xl mx-auto">

      {/* Header */}
      <div className="flex items-center justify-between mb-7">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <Activity size={20} className="text-brand-accent" />
            <h1 className="text-xl font-bold text-brand-text">Performance</h1>
          </div>
          <p className="text-sm text-gray-500">
            Real-time server metrics
            {data?.timestamp && (
              <span className="ml-2 text-xs text-gray-400">
                <Clock size={10} className="inline mr-0.5 -mt-px" />
                Last updated {new Date(data.timestamp).toLocaleTimeString()}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPaused(p => !p)}
            className="btn-outline text-xs"
          >
            {paused ? <Play size={13} /> : <Pause size={13} />}
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={() => { fetchMetrics() }}
            disabled={loading}
            className="btn-ghost text-xs"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="mb-4 text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
          <AlertTriangle size={12} />
          Failed to fetch metrics: {error}
        </div>
      )}

      {/* Loading skeletons */}
      {loading && !data ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1,2,3,4,5,6].map(i => <SkeletonCard key={i} />)}
        </div>
      ) : data ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

          {/* ── System ───────────────────────────────────────────────── */}
          <SectionCard icon={Cpu} title="System" statusLevel={sysLevel}>
            <div className="space-y-3">
              {/* CPU */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-gray-500">CPU</span>
                  <span className="text-xs font-semibold text-brand-text">{sys?.cpu_percent ?? '--'}%</span>
                </div>
                <ProgressBar percent={sys?.cpu_percent} />
              </div>
              {/* Memory */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-gray-500">Memory</span>
                  <span className="text-xs font-semibold text-brand-text">
                    {sys?.memory_percent ?? '--'}%
                    <span className="text-gray-400 font-normal ml-1">
                      ({fmtMB(sys?.memory_used_mb)} / {fmtMB(sys?.memory_total_mb)})
                    </span>
                  </span>
                </div>
                <ProgressBar percent={sys?.memory_percent} />
              </div>
              {/* Disk */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-gray-500">Disk</span>
                  <span className="text-xs font-semibold text-brand-text">
                    {sys?.disk_percent ?? '--'}%
                    <span className="text-gray-400 font-normal ml-1">
                      ({sys?.disk_used_gb != null ? `${sys.disk_used_gb.toFixed(1)} GB` : '--'} / {sys?.disk_total_gb != null ? `${sys.disk_total_gb.toFixed(1)} GB` : '--'})
                    </span>
                  </span>
                </div>
                <ProgressBar percent={sys?.disk_percent} />
              </div>
            </div>
          </SectionCard>

          {/* ── Elasticsearch ────────────────────────────────────────── */}
          <SectionCard icon={Database} title="Elasticsearch" statusLevel={esLevel}>
            <div className="space-y-1">
              <div className="flex items-center gap-2 mb-2">
                <StatusDot level={esLevel || 'green'} />
                <span className="text-xs font-medium text-brand-text capitalize">{es?.status ?? '--'}</span>
                <span className="text-xs text-gray-400">
                  {es?.node_count ?? '--'} node{es?.node_count !== 1 ? 's' : ''}
                </span>
              </div>
              <MetricRow label="Total Documents" value={fmt(es?.total_docs)} />
              <MetricRow label="Total Size" value={fmtMB(es?.total_size_mb)} />

              {/* Collapsible index list */}
              {es?.indices && es.indices.length > 0 && (
                <div className="mt-2">
                  <button
                    onClick={() => setEsExpanded(e => !e)}
                    className="text-[10px] text-brand-accent hover:underline cursor-pointer"
                  >
                    {esExpanded ? 'Hide' : 'Show'} {es.indices.length} indices
                  </button>
                  {esExpanded && (
                    <div className="mt-2 space-y-1 max-h-40 overflow-y-auto scrollbar-thin">
                      {es.indices.map(idx => (
                        <div key={idx.name} className="flex items-center justify-between text-[11px] py-0.5">
                          <span className="text-gray-600 font-mono truncate mr-2">{idx.name}</span>
                          <span className="text-gray-400 whitespace-nowrap">
                            {fmt(idx.docs)} docs &middot; {fmtMB(idx.size_mb)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </SectionCard>

          {/* ── Redis ────────────────────────────────────────────────── */}
          <SectionCard icon={Server} title="Redis">
            <div className="space-y-1">
              <MetricRow label="Memory Used" value={fmtMB(redis?.used_memory_mb)} />
              <MetricRow label="Connected Clients" value={fmt(redis?.connected_clients)} />
              <MetricRow label="Total Keys" value={fmt(redis?.total_keys)} />
              <MetricRow
                label="Uptime"
                value={formatUptime(redis?.uptime_seconds)}
              />
            </div>
          </SectionCard>

          {/* ── MinIO ────────────────────────────────────────────────── */}
          <SectionCard icon={HardDrive} title="MinIO">
            <div className="space-y-1">
              <MetricRow label="Buckets" value={fmt(minio?.bucket_count)} />
              <MetricRow label="Total Objects" value={fmt(minio?.total_objects)} />
              <MetricRow label="Total Size" value={fmtMB(minio?.total_size_mb)} />
            </div>
          </SectionCard>

          {/* ── Celery Workers ───────────────────────────────────────── */}
          <SectionCard icon={Layers} title="Celery Workers">
            <div className="space-y-1 mb-3">
              <MetricRow label="Registered Workers" value={fmt(celery?.registered_workers)} />
              <MetricRow label="Active Tasks" value={fmt(celery?.active_tasks)} />
              <MetricRow label="Reserved Tasks" value={fmt(celery?.reserved_tasks)} />
            </div>

            {/* Queue depths */}
            {celery?.queue_lengths && (
              <div>
                <p className="section-title mb-2">Queue Depths</p>
                <div className="space-y-2">
                  {Object.entries(celery.queue_lengths).map(([name, depth]) => {
                    const maxQueue = 50
                    const pct = Math.min(100, (depth / maxQueue) * 100)
                    const level = depth > 30 ? 'red' : depth > 10 ? 'yellow' : 'green'
                    return (
                      <div key={name}>
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="text-xs text-gray-500 font-mono">{name}</span>
                          <span className="text-xs font-semibold text-brand-text">{depth}</span>
                        </div>
                        <ProgressBar percent={pct} level={level} />
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </SectionCard>

          {/* ── Cases ────────────────────────────────────────────────── */}
          <SectionCard icon={Activity} title="Cases">
            <div className="space-y-1">
              <MetricRow label="Total Cases" value={fmt(cases?.total_cases)} />
              <MetricRow label="Total Jobs" value={fmt(cases?.total_jobs)} />
              <MetricRow label="Active Jobs" value={fmt(cases?.active_jobs)} />
              <div className="flex items-center justify-between py-1.5">
                <span className="text-xs text-gray-500">Failed Jobs</span>
                <span className={`text-sm font-semibold ${cases?.failed_jobs > 0 ? 'text-red-600' : 'text-brand-text'}`}>
                  {fmt(cases?.failed_jobs)}
                  {cases?.failed_jobs > 0 && <AlertTriangle size={11} className="inline ml-1 -mt-0.5" />}
                </span>
              </div>
            </div>
          </SectionCard>
        </div>
      ) : null}
    </div>
  )
}
