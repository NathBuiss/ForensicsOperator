/**
 * Harvest page — forensic triage from a raw disk image or mounted directory.
 *
 * Lets the analyst pick a case, choose a collection level (or override with
 * specific categories), point to a source (MinIO image key or mounted path),
 * then track each harvest run's progress in real time.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import {
  FolderSearch, Play, X, ChevronDown, ChevronRight,
  HardDrive, FolderOpen, CheckCircle2, XCircle, Loader2,
  RefreshCw, Layers, AlertCircle, Info, SquareStack,
  ListChecks, Ban,
} from 'lucide-react'
import { api } from '../api/client'

// ── Level colour coding ────────────────────────────────────────────────────────
const LEVEL_META = {
  small: {
    label: 'Small',
    colour: 'text-green-700 bg-green-50 border-green-200',
    desc:   'Core Windows artifacts — registry, event logs, prefetch, MFT, credentials.',
  },
  complete: {
    label: 'Complete',
    colour: 'text-blue-700 bg-blue-50 border-blue-200',
    desc:   'Full forensic collection — browsers, email, cloud storage, remote access, and more.',
  },
  exhaustive: {
    label: 'Exhaustive',
    colour: 'text-purple-700 bg-purple-50 border-purple-200',
    desc:   'Everything in Complete plus messaging apps, gaming, memory, file listings.',
  },
}

// ── Status badge helper ────────────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    PENDING:             'bg-amber-50  text-amber-700  border-amber-200',
    RUNNING:             'bg-blue-50   text-blue-700   border-blue-200',
    OPENING_FILESYSTEM:  'bg-blue-50   text-blue-700   border-blue-200',
    COMPLETED:           'bg-green-50  text-green-700  border-green-200',
    FAILED:              'bg-red-50    text-red-700    border-red-200',
    CANCELLED:           'bg-gray-100  text-gray-500   border-gray-200',
    UNKNOWN:             'bg-gray-100  text-gray-500   border-gray-200',
  }
  const cls = map[status] || map.UNKNOWN
  return (
    <span className={`badge border ${cls} font-medium`}>{status}</span>
  )
}

// ── RunCard — live polling card for an active/finished harvest run ─────────────
function RunCard({ runId, caseId, onDone }) {
  const [run, setRun]       = useState(null)
  const [error, setError]   = useState(null)
  const intervalRef         = useRef(null)

  const poll = useCallback(async () => {
    try {
      const data = await api.harvest.getRun(runId)
      setRun(data)
      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(data.status)) {
        clearInterval(intervalRef.current)
        if (onDone) onDone(data)
      }
    } catch (e) {
      setError(e.message)
      clearInterval(intervalRef.current)
    }
  }, [runId, onDone])

  useEffect(() => {
    poll()
    intervalRef.current = setInterval(poll, 3000)
    return () => clearInterval(intervalRef.current)
  }, [poll])

  if (error) return (
    <div className="card p-4 border-red-200 bg-red-50">
      <p className="text-sm text-red-700">Poll error: {error}</p>
    </div>
  )

  if (!run) return (
    <div className="card p-4 flex items-center gap-2 text-gray-500 text-sm">
      <Loader2 size={14} className="animate-spin" /> Loading run…
    </div>
  )

  const isLive = ['RUNNING', 'OPENING_FILESYSTEM'].includes(run.status)

  return (
    <div className="card overflow-hidden">
      {/* Header row */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-100">
        {isLive
          ? <Loader2 size={15} className="text-blue-500 animate-spin flex-shrink-0" />
          : run.status === 'COMPLETED'
            ? <CheckCircle2 size={15} className="text-green-500 flex-shrink-0" />
            : run.status === 'FAILED'
              ? <XCircle size={15} className="text-red-500 flex-shrink-0" />
              : <Ban size={15} className="text-gray-400 flex-shrink-0" />
        }
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-gray-400 truncate">{run.run_id}</span>
            <StatusBadge status={run.status} />
            {run.level && (
              <span className={`badge border text-xs ${LEVEL_META[run.level]?.colour || ''}`}>
                {run.level}
              </span>
            )}
          </div>
          <p className="text-[11px] text-gray-400 mt-0.5">
            Started {run.started_at ? new Date(run.started_at).toLocaleString() : '—'}
          </p>
        </div>

        {/* Cancel button for live runs */}
        {isLive && (
          <button
            onClick={async () => {
              try { await api.harvest.cancelRun(runId) }
              catch (e) { alert('Cancel failed: ' + e.message) }
            }}
            className="icon-btn text-red-400 hover:text-red-600 flex-shrink-0"
            title="Cancel run"
          >
            <X size={13} />
          </button>
        )}
      </div>

      {/* Progress body */}
      <div className="px-4 py-3 space-y-2 text-sm">
        {/* Current category */}
        {run.current_category && isLive && (
          <div className="flex items-center gap-2 text-xs text-blue-600">
            <Loader2 size={11} className="animate-spin" />
            Collecting <span className="font-mono font-medium">{run.current_category}</span>…
          </div>
        )}

        {/* Stats row */}
        <div className="flex gap-6 text-xs text-gray-500">
          {run.total_dispatched != null && (
            <span>
              <span className="font-semibold text-brand-text">{run.total_dispatched}</span> ingest jobs dispatched
            </span>
          )}
          {run.completed_at && (
            <span>Completed {new Date(run.completed_at).toLocaleString()}</span>
          )}
        </div>

        {/* Error */}
        {run.error && (
          <div className="rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-xs text-red-700">
            {run.error}
          </div>
        )}

        {/* Categories list (collapsed) */}
        {Array.isArray(run.categories) && run.categories.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {run.categories.map(c => (
              <span key={c}
                className={`badge text-[10px] border font-mono ${
                  run.current_category === c && isLive
                    ? 'bg-blue-50 text-blue-700 border-blue-200'
                    : 'bg-gray-50 text-gray-500 border-gray-200'
                }`}
              >
                {c}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}


// ── Main page component ────────────────────────────────────────────────────────
export default function Harvest() {
  // ── case selector ────────────────────────────────────────────────────────────
  const [cases,     setCases]     = useState([])
  const [caseId,    setCaseId]    = useState('')

  // ── level / category picker ──────────────────────────────────────────────────
  const [levels,      setLevels]      = useState({})
  const [categories,  setCategories]  = useState([])
  const [selectedLevel, setSelectedLevel] = useState('complete')
  // category overrides — empty means "use the level default"
  const [catOverrides, setCatOverrides]   = useState([])
  const [showCatPicker, setShowCatPicker] = useState(false)
  const [catFilter, setCatFilter]         = useState('')

  // ── source ───────────────────────────────────────────────────────────────────
  const [sourceMode,    setSourceMode]    = useState('minio')  // 'minio' | 'mounted'
  const [minioKey,      setMinioKey]      = useState('')
  const [mountedPath,   setMountedPath]   = useState('')

  // ── runs ─────────────────────────────────────────────────────────────────────
  const [runs,     setRuns]     = useState([])   // [{runId, caseId}]
  const [loading,  setLoading]  = useState(false)
  const [err,      setErr]      = useState(null)

  // ── load meta ────────────────────────────────────────────────────────────────
  useEffect(() => {
    api.cases.list().then(r => {
      const cs = r.cases || []
      setCases(cs)
      if (cs.length === 1) setCaseId(cs[0].case_id)
    }).catch(() => {})

    api.harvest.listLevels().then(r => setLevels(r.levels || {})).catch(() => {})
    api.harvest.listCategories().then(r => setCategories(r.categories || [])).catch(() => {})
  }, [])

  // ── disk images for minio picker ─────────────────────────────────────────────
  const [diskImages, setDiskImages] = useState([])
  useEffect(() => {
    if (!caseId) { setDiskImages([]); return }
    api.caseFiles.diskImages(caseId)
      .then(r => setDiskImages(r.images || []))
      .catch(() => setDiskImages([]))
  }, [caseId])

  // ── derived category list ─────────────────────────────────────────────────────
  const activeLevelCats = (levels[selectedLevel]?.categories) || []

  function toggleCat(name) {
    setCatOverrides(prev =>
      prev.includes(name)
        ? prev.filter(c => c !== name)
        : [...prev, name]
    )
  }

  const filteredAllCats = categories.filter(c =>
    !catFilter || c.name.includes(catFilter) || c.description.toLowerCase().includes(catFilter.toLowerCase())
  )

  // ── start run ─────────────────────────────────────────────────────────────────
  async function handleStart(e) {
    e.preventDefault()
    if (!caseId) { setErr('Please select a case.'); return }
    const source = sourceMode === 'minio' ? minioKey.trim() : mountedPath.trim()
    if (!source)  { setErr(`Please provide a ${sourceMode === 'minio' ? 'MinIO object key' : 'mounted path'}.`); return }

    setErr(null)
    setLoading(true)
    try {
      const body = {
        level:      selectedLevel,
        categories: catOverrides,
        minio_object_key: sourceMode === 'minio'    ? source : null,
        mounted_path:     sourceMode === 'mounted'  ? source : null,
      }
      const res = await api.harvest.startRun(caseId, body)
      setRuns(prev => [{ runId: res.run_id, caseId }, ...prev])
    } catch (e) {
      setErr(e.message)
    } finally {
      setLoading(false)
    }
  }

  // ── render ────────────────────────────────────────────────────────────────────
  return (
    <div className="flex-1 p-6 max-w-4xl mx-auto w-full space-y-6">

      {/* ── Page header ─────────────────────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <FolderSearch size={18} className="text-brand-accent" />
          <h1 className="text-lg font-bold text-brand-text">Forensic Harvest</h1>
        </div>
        <p className="text-sm text-gray-500">
          Triage a disk image or mounted Windows filesystem — extract artifacts by category
          and automatically dispatch them as ingest jobs.
        </p>
      </div>

      {/* ── Configuration form ───────────────────────────────────────────── */}
      <form onSubmit={handleStart} className="card p-5 space-y-5">

        {/* Case selector */}
        <div>
          <label className="section-title block mb-2">Case</label>
          <select
            value={caseId}
            onChange={e => setCaseId(e.target.value)}
            className="input w-full"
            required
          >
            <option value="">— select a case —</option>
            {cases.map(c => (
              <option key={c.case_id} value={c.case_id}>{c.name}</option>
            ))}
          </select>
        </div>

        {/* Level picker */}
        <div>
          <label className="section-title block mb-2">Collection level</label>
          <div className="grid grid-cols-3 gap-3">
            {Object.entries(LEVEL_META).map(([key, meta]) => {
              const count = levels[key]?.count ?? '?'
              return (
                <button
                  key={key}
                  type="button"
                  onClick={() => { setSelectedLevel(key); setCatOverrides([]) }}
                  className={`rounded-xl border p-3 text-left transition-all ${
                    selectedLevel === key
                      ? 'border-brand-accent bg-brand-accentlight ring-1 ring-brand-accent/30'
                      : 'border-gray-200 bg-white hover:border-gray-300'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${meta.colour}`}>
                      {meta.label}
                    </span>
                    <span className="text-[10px] text-gray-400">{count} cats</span>
                  </div>
                  <p className="text-[11px] text-gray-500 leading-snug">{meta.desc}</p>
                </button>
              )
            })}
          </div>
        </div>

        {/* Category overrides */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <label className="section-title">Category overrides</label>
            <span className="text-[10px] text-gray-400 italic">
              {catOverrides.length === 0
                ? `Using all ${activeLevelCats.length} categories from "${selectedLevel}"`
                : `${catOverrides.length} selected (overrides level)`
              }
            </span>
            <button
              type="button"
              onClick={() => setShowCatPicker(v => !v)}
              className="ml-auto text-xs text-brand-accent hover:underline flex items-center gap-1"
            >
              <ListChecks size={12} />
              {showCatPicker ? 'Hide' : 'Customize'}
            </button>
            {catOverrides.length > 0 && (
              <button
                type="button"
                onClick={() => setCatOverrides([])}
                className="text-xs text-red-500 hover:underline flex items-center gap-1"
              >
                <X size={11} /> Clear
              </button>
            )}
          </div>

          {showCatPicker && (
            <div className="rounded-xl border border-gray-200 overflow-hidden">
              {/* Search */}
              <div className="px-3 py-2 border-b border-gray-100 bg-gray-50">
                <input
                  value={catFilter}
                  onChange={e => setCatFilter(e.target.value)}
                  placeholder="Filter categories…"
                  className="input py-1 text-xs w-full"
                />
              </div>
              <div className="max-h-52 overflow-y-auto divide-y divide-gray-50">
                {filteredAllCats.map(cat => {
                  const inLevel    = activeLevelCats.includes(cat.name)
                  const overridden = catOverrides.includes(cat.name)
                  return (
                    <label
                      key={cat.name}
                      className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-gray-50 transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={catOverrides.length === 0 ? inLevel : overridden}
                        onChange={() => {
                          // First time clicking: seed overrides from level, then toggle
                          if (catOverrides.length === 0) {
                            const seed = [...activeLevelCats]
                            if (seed.includes(cat.name)) {
                              setCatOverrides(seed.filter(c => c !== cat.name))
                            } else {
                              setCatOverrides([...seed, cat.name])
                            }
                          } else {
                            toggleCat(cat.name)
                          }
                        }}
                        className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent/30"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-mono text-brand-text">{cat.name}</span>
                          {inLevel && catOverrides.length === 0 && (
                            <span className="badge bg-gray-100 text-gray-400 border border-gray-200 text-[9px]">
                              in level
                            </span>
                          )}
                        </div>
                        <p className="text-[10px] text-gray-400 truncate">{cat.description}</p>
                      </div>
                    </label>
                  )
                })}
              </div>
            </div>
          )}
        </div>

        {/* Source */}
        <div>
          <label className="section-title block mb-2">Artifact source</label>
          <div className="flex gap-3 mb-3">
            {[
              { id: 'minio',   label: 'MinIO disk image',       Icon: HardDrive },
              { id: 'mounted', label: 'Mounted directory',       Icon: FolderOpen },
            ].map(({ id, label, Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => setSourceMode(id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm transition-all ${
                  sourceMode === id
                    ? 'border-brand-accent bg-brand-accentlight text-brand-accent font-medium'
                    : 'border-gray-200 bg-white text-gray-600 hover:border-gray-300'
                }`}
              >
                <Icon size={14} />
                {label}
              </button>
            ))}
          </div>

          {sourceMode === 'minio' ? (
            <div>
              <label className="text-xs text-gray-500 mb-1 block">
                MinIO object key{' '}
                <span className="text-gray-400">(e.g. cases/abc/disk.dd)</span>
              </label>
              {diskImages.length > 0 ? (
                <select
                  value={minioKey}
                  onChange={e => setMinioKey(e.target.value)}
                  className="input w-full"
                >
                  <option value="">— select a disk image —</option>
                  {diskImages.map(img => (
                    <option key={img.minio_key} value={img.minio_key}>
                      {img.filename} ({img.minio_key})
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  value={minioKey}
                  onChange={e => setMinioKey(e.target.value)}
                  placeholder="cases/<case_id>/image.dd"
                  className="input w-full font-mono"
                />
              )}
              <p className="text-[10px] text-gray-400 mt-1 flex items-center gap-1">
                <Info size={10} />
                The image will be downloaded from MinIO to the worker and opened with pytsk3.
              </p>
            </div>
          ) : (
            <div>
              <label className="text-xs text-gray-500 mb-1 block">
                Path on the worker{' '}
                <span className="text-gray-400">(e.g. /mnt/windows)</span>
              </label>
              <input
                value={mountedPath}
                onChange={e => setMountedPath(e.target.value)}
                placeholder="/mnt/windows"
                className="input w-full font-mono"
              />
              <p className="text-[10px] text-gray-400 mt-1 flex items-center gap-1">
                <Info size={10} />
                The directory must already be mounted on the processor worker pod (e.g. via dislocker-fuse for BitLocker volumes).
              </p>
            </div>
          )}
        </div>

        {/* Error */}
        {err && (
          <div className="rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700 flex items-center gap-2">
            <AlertCircle size={14} />
            {err}
          </div>
        )}

        {/* Submit */}
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={loading}
            className="btn-primary flex items-center gap-2"
          >
            {loading
              ? <Loader2 size={14} className="animate-spin" />
              : <Play size={14} />
            }
            {loading ? 'Starting…' : 'Start harvest'}
          </button>
        </div>
      </form>

      {/* ── Active / completed runs ──────────────────────────────────────── */}
      {runs.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <SquareStack size={14} className="text-gray-400" />
            <h2 className="text-sm font-semibold text-brand-text">Harvest runs</h2>
            <span className="badge bg-gray-100 text-gray-500 border border-gray-200">{runs.length}</span>
          </div>
          <div className="space-y-3">
            {runs.map(({ runId, caseId: rid }) => (
              <RunCard
                key={runId}
                runId={runId}
                caseId={rid}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
