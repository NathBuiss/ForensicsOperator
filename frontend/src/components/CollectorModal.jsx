import { useState, useEffect, useRef, useCallback } from 'react'
import {
  X, Monitor, Terminal, FileCode, Download,
  ChevronRight, ChevronLeft, Check, Wifi, RefreshCw,
  Globe, Loader2, Trash2, Info, Copy, ExternalLink,
  HardDrive, FolderOpen, Play, CheckCircle2, XCircle,
  Ban, AlertTriangle, ListChecks,
} from 'lucide-react'
import { api } from '../api/client'

// ── Artifact definitions (script mode) ───────────────────────────────────────

const WINDOWS_ARTIFACTS = [
  { key: 'evtx',     label: 'Event Logs (EVTX)',   desc: 'Security, System, Application, PowerShell, Sysmon and more' },
  { key: 'registry', label: 'Registry Hives',       desc: 'SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat' },
  { key: 'prefetch', label: 'Prefetch Files',        desc: 'Program execution evidence (up to 500 .pf files)' },
  { key: 'lnk',      label: 'LNK / Recent Items',   desc: 'Shell link files from all user Recent folders' },
  { key: 'browser',  label: 'Browser Artifacts',    desc: 'Chrome, Edge, Firefox — history, cookies, login data' },
  { key: 'tasks',    label: 'Scheduled Tasks',      desc: 'Windows Task Scheduler XML files from System32\\Tasks' },
  { key: 'mft',      label: 'Master File Table ($MFT)', desc: 'Raw NTFS MFT — requires Administrator' },
  { key: 'triage',   label: 'Live System Triage',   desc: 'systeminfo, netstat, tasklist, services, installed software' },
  { key: 'memory',   label: 'Memory Dump',          desc: 'Physical memory via WinPmem — requires winpmem_mini_x64_rc2.exe beside the script', warn: true },
]

const LINUX_ARTIFACTS = [
  { key: 'logs',    label: 'System Logs',           desc: '/var/log — auth.log, syslog, audit, journalctl export' },
  { key: 'history', label: 'Shell Histories',       desc: '.bash_history, .zsh_history for root and all users' },
  { key: 'config',  label: 'System Configuration',  desc: '/etc/passwd, sudoers, hosts, ssh/sshd_config and more' },
  { key: 'cron',    label: 'Cron Jobs',             desc: 'cron.d, cron.daily, crontabs, systemd timers' },
  { key: 'ssh',     label: 'SSH Artifacts',         desc: 'known_hosts, authorized_keys, config (no private keys)' },
  { key: 'network', label: 'Network Captures',      desc: 'PCAP/tcpdump snapshots (5 min, 500 MB cap)' },
  { key: 'triage',  label: 'Live System Triage',    desc: 'ps, ss, ip, last, lsmod, services, installed packages' },
  { key: 'memory',  label: 'Memory Dump',           desc: 'Physical memory via avml or /dev/fmem — requires root + avml in PATH', warn: true },
]

// ── Harvest level metadata ────────────────────────────────────────────────────

const LEVEL_META = {
  small: {
    label: 'Small',
    colour: 'text-green-700 bg-green-50 border-green-200',
    desc: 'Registry, event logs, prefetch, MFT, credentials.',
  },
  complete: {
    label: 'Complete',
    colour: 'text-blue-700 bg-blue-50 border-blue-200',
    desc: 'Full collection — browsers, email, cloud storage, remote access.',
  },
  exhaustive: {
    label: 'Exhaustive',
    colour: 'text-purple-700 bg-purple-50 border-purple-200',
    desc: 'Everything in Complete plus messaging apps, gaming, memory.',
  },
}

// ── Platform definitions ──────────────────────────────────────────────────────

const PLATFORMS = [
  {
    id: 'win',
    label: 'Windows',
    Icon: Monitor,
    desc: 'Self-contained Python script — run as Administrator',
    tip: 'Requires Python 3.8+ on target. Build a zero-dependency EXE with: build.bat',
    artifacts: WINDOWS_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Linux / macOS',
    Icon: Terminal,
    desc: 'Self-contained Python script — run as root',
    tip: 'Requires Python 3.8+ on target. Build a zero-dependency ELF with: ./build.sh',
    artifacts: LINUX_ARTIFACTS,
  },
  {
    id: 'py',
    label: 'Python Script',
    Icon: FileCode,
    desc: 'Platform-agnostic — auto-detects OS at runtime',
    tip: 'Works on Windows, Linux & macOS. Use this when the target already has Python 3.8+.',
    artifacts: [...WINDOWS_ARTIFACTS, ...LINUX_ARTIFACTS].filter(
      (a, i, arr) => arr.findIndex(b => b.key === a.key) === i
    ),
  },
  // ── Disk image harvest ───────────────────────────────────────────────────
  {
    id: 'harvest',
    mode: 'harvest',
    label: 'Windows Disk Image',
    Icon: HardDrive,
    desc: 'Server-side triage of a raw disk image or mounted directory',
    tip: 'Requires pytsk3 on the processor worker. Artifacts are located and dispatched as ingest jobs automatically.',
    artifacts: [],
  },
]

// ── Small run-status card (harvest mode only) ─────────────────────────────────

function HarvestRunCard({ runId }) {
  const [run, setRun] = useState(null)
  const timerRef      = useRef(null)

  const poll = useCallback(async () => {
    try {
      const data = await api.harvest.getRun(runId)
      setRun(data)
      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(data.status)) {
        clearInterval(timerRef.current)
      }
    } catch {
      clearInterval(timerRef.current)
    }
  }, [runId])

  useEffect(() => {
    poll()
    timerRef.current = setInterval(poll, 3000)
    return () => clearInterval(timerRef.current)
  }, [poll])

  if (!run) return (
    <div className="flex items-center gap-1.5 text-xs text-gray-400 px-1">
      <Loader2 size={11} className="animate-spin" /> Loading…
    </div>
  )

  const isLive = ['RUNNING', 'OPENING_FILESYSTEM'].includes(run.status)
  return (
    <div className="rounded-lg border border-gray-200 bg-gray-50 overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2">
        {isLive
          ? <Loader2 size={12} className="text-blue-500 animate-spin flex-shrink-0" />
          : run.status === 'COMPLETED'
            ? <CheckCircle2 size={12} className="text-green-500 flex-shrink-0" />
            : run.status === 'FAILED'
              ? <XCircle size={12} className="text-red-500 flex-shrink-0" />
              : <Ban size={12} className="text-gray-400 flex-shrink-0" />
        }
        <span className="font-mono text-[10px] text-gray-400 truncate flex-1">{run.run_id}</span>
        <span className={`text-[11px] font-semibold ${
          run.status === 'COMPLETED' ? 'text-green-600' :
          run.status === 'FAILED'    ? 'text-red-600' :
          isLive                     ? 'text-blue-600' :
                                       'text-gray-400'
        }`}>{run.status}</span>
        {isLive && (
          <button onClick={() => api.harvest.cancelRun(runId).catch(() => {})}
                  className="icon-btn text-red-400 hover:text-red-600" title="Cancel">
            <X size={10} />
          </button>
        )}
      </div>
      {(run.current_category && isLive || run.total_dispatched != null) && (
        <div className="px-3 pb-2 text-[11px] text-gray-500 space-y-0.5">
          {run.current_category && isLive && (
            <div className="flex items-center gap-1 text-blue-600">
              <Loader2 size={9} className="animate-spin" />
              <span className="font-mono">{run.current_category}</span>
            </div>
          )}
          {run.total_dispatched != null && (
            <p><span className="font-semibold text-brand-text">{run.total_dispatched}</span> ingest jobs dispatched</p>
          )}
          {run.error && <p className="text-red-600">{run.error}</p>}
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function CollectorModal({ onClose, caseId, apiUrl: propApiUrl }) {
  const [step, setStep]           = useState(1)
  const [platform, setPlatform]   = useState(null)
  const [selected, setSelected]   = useState(new Set())
  const [apiUrl, setApiUrl]       = useState(propApiUrl || '')
  const [netIps, setNetIps]       = useState([])
  const [netLoading, setNetLoading] = useState(false)
  const [downloading, setDownloading] = useState(false)

  // K8s LoadBalancer state
  const [inK8s, setInK8s]         = useState(false)
  const [ingress, setIngress]     = useState(null)
  const [ingressBusy, setIngressBusy] = useState(false)

  // Harvest state
  const [harvestLevel, setHarvestLevel]               = useState('complete')
  const [harvestCatOverrides, setHarvestCatOverrides] = useState([])
  const [harvestSourceMode, setHarvestSourceMode]     = useState('minio')
  const [harvestMinioKey, setHarvestMinioKey]         = useState('')
  const [harvestMountedPath, setHarvestMountedPath]   = useState('')
  const [harvestLevels, setHarvestLevels]             = useState({})
  const [harvestAllCats, setHarvestAllCats]           = useState([])
  const [harvestRuns, setHarvestRuns]                 = useState([])
  const [harvestLoading, setHarvestLoading]           = useState(false)
  const [harvestErr, setHarvestErr]                   = useState(null)
  const [showCatPicker, setShowCatPicker]             = useState(false)
  const [diskImages, setDiskImages]                   = useState([])

  const platformDef = PLATFORMS.find(p => p.id === platform)
  const isHarvest   = platformDef?.mode === 'harvest'
  const artifacts   = platformDef?.artifacts || []

  // Pre-select all artifacts when platform chosen
  useEffect(() => {
    if (!platformDef) return
    if (isHarvest) {
      api.harvest.listLevels().then(r => setHarvestLevels(r.levels || {})).catch(() => {})
      api.harvest.listCategories().then(r => setHarvestAllCats(r.categories || [])).catch(() => {})
      setHarvestCatOverrides([])
    } else {
      setSelected(new Set(platformDef.artifacts.map(a => a.key)))
    }
  }, [platform])

  // Load disk images for MinIO picker (harvest mode, case provided via prop)
  useEffect(() => {
    if (!caseId || !isHarvest) { setDiskImages([]); return }
    api.caseFiles.diskImages(caseId).then(r => setDiskImages(r.images || [])).catch(() => setDiskImages([]))
  }, [caseId, isHarvest])

  // Fetch detected IPs + K8s status when script mode reaches step 3
  useEffect(() => {
    if (step !== 3 || isHarvest) return
    setNetLoading(true)
    api.collector.networkInterfaces()
      .then(r => {
        setNetIps(r.candidates || [])
        setInK8s(r.in_kubernetes || false)
        const lbEntry = (r.candidates || []).find(c => c.k8s && c.label?.includes('LoadBalancer'))
        if (lbEntry) setApiUrl(lbEntry.url)
      })
      .catch(() => {})
      .finally(() => setNetLoading(false))
  }, [step])

  async function createIngress() {
    setIngressBusy(true)
    try {
      const r = await api.collector.createIngress()
      setIngress(r)
      if (r.external_url) setApiUrl(r.external_url)
    } catch (e) {
      setIngress({ status: 'error', error: e.message })
    } finally { setIngressBusy(false) }
  }

  async function pollIngress() {
    setIngressBusy(true)
    try {
      const r = await api.collector.getIngress()
      setIngress(r)
      if (r.external_url) setApiUrl(r.external_url)
    } catch {} finally { setIngressBusy(false) }
  }

  async function removeIngress() {
    setIngressBusy(true)
    try { await api.collector.deleteIngress(); setIngress(null) }
    catch {} finally { setIngressBusy(false) }
  }

  function toggleArtifact(key) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  function toggleAll() {
    setSelected(selected.size === artifacts.length
      ? new Set()
      : new Set(artifacts.map(a => a.key))
    )
  }

  function handleDownload() {
    setDownloading(true)
    const url = api.collector.downloadUrl({
      platform,
      caseId: caseId || undefined,
      apiUrl: (apiUrl && caseId) ? apiUrl : undefined,
      collect: selected.size > 0 ? [...selected] : undefined,
    })
    const a = document.createElement('a')
    a.href = url
    a.download = 'fo-collector.py'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setTimeout(() => setDownloading(false), 1500)
  }

  // ── Harvest handlers ──────────────────────────────────────────────────────

  const activeLevelCats = harvestLevels[harvestLevel]?.categories || []

  function seedAndToggleCat(name) {
    if (harvestCatOverrides.length === 0) {
      const seed = [...activeLevelCats]
      setHarvestCatOverrides(
        seed.includes(name) ? seed.filter(c => c !== name) : [...seed, name]
      )
    } else {
      setHarvestCatOverrides(prev =>
        prev.includes(name) ? prev.filter(c => c !== name) : [...prev, name]
      )
    }
  }

  async function handleStartHarvest() {
    if (!caseId) { setHarvestErr('No case provided.'); return }
    const source = harvestSourceMode === 'minio'
      ? harvestMinioKey.trim()
      : harvestMountedPath.trim()
    if (!source) { setHarvestErr('Provide a source.'); return }
    setHarvestErr(null)
    setHarvestLoading(true)
    try {
      const res = await api.harvest.startRun(caseId, {
        level:            harvestLevel,
        categories:       harvestCatOverrides,
        minio_object_key: harvestSourceMode === 'minio'   ? source : null,
        mounted_path:     harvestSourceMode === 'mounted' ? source : null,
      })
      setHarvestRuns(prev => [{ runId: res.run_id }, ...prev])
    } catch (e) {
      setHarvestErr(e.message)
    } finally {
      setHarvestLoading(false)
    }
  }

  // ── Step labels ───────────────────────────────────────────────────────────

  const stepLabels = isHarvest
    ? ['Platform', 'Categories', 'Source & Start']
    : ['Platform', 'Artifacts', 'Download']

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box" style={{ maxWidth: 580 }}>

        {/* Header */}
        <div className="modal-header">
          <div>
            <h2 className="text-sm font-semibold text-brand-text">
              {isHarvest ? 'Disk Image Harvest' : 'Download Artifact Collector'}
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">
              {caseId
                ? `Case ${caseId}${isHarvest ? ' — artifacts dispatched as ingest jobs' : ' — auto-uploads on completion'}`
                : 'Configure collection options below'}
            </p>
          </div>
          <button className="icon-btn ml-3" onClick={onClose}><X size={15} /></button>
        </div>

        {/* Step bar */}
        <div className="flex items-center gap-2 px-5 py-3 bg-gray-50 border-b border-gray-200 flex-shrink-0">
          {stepLabels.map((label, i) => {
            const num    = i + 1
            const active = step === num
            const done   = step > num
            return (
              <div key={label} className="flex items-center gap-2">
                {i > 0 && <span className="text-gray-300 text-xs">›</span>}
                <button
                  disabled={!done}
                  onClick={() => done && setStep(num)}
                  className={`flex items-center gap-1.5 text-xs font-medium transition-colors ${
                    active ? 'text-brand-accent' :
                    done   ? 'text-gray-400 hover:text-brand-accent cursor-pointer' :
                             'text-gray-300 cursor-default'
                  }`}
                >
                  <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0 ${
                    active ? 'bg-brand-accent text-white' :
                    done   ? 'bg-green-500 text-white' :
                             'bg-gray-200 text-gray-400'
                  }`}>
                    {done ? <Check size={10} /> : num}
                  </span>
                  {label}
                </button>
              </div>
            )
          })}
        </div>

        {/* Step content */}
        <div className="flex-1 overflow-y-auto">

          {/* Step 1 — Platform */}
          {step === 1 && (
            <div className="p-5 space-y-3">
              {PLATFORMS.map(({ id, mode, label, Icon, desc, tip }) => {
                const active = platform === id && (mode ? platformDef?.mode === mode : !platformDef?.mode)
                return (
                  <button
                    key={`${id}-${mode || 'script'}`}
                    onClick={() => setPlatform(id)}
                    className={`w-full flex items-start gap-3 p-4 rounded-xl border-2 text-left transition-all ${
                      active
                        ? 'border-brand-accent bg-brand-accentlight'
                        : 'border-gray-200 bg-white hover:border-gray-300'
                    }`}
                  >
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
                      active ? 'bg-brand-accent text-white' : 'bg-gray-100 text-gray-500'
                    }`}>
                      <Icon size={17} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <div className="text-sm font-semibold text-brand-text mb-0.5">{label}</div>
                        {mode === 'harvest' && (
                          <span className="badge bg-amber-50 text-amber-700 border border-amber-200 text-[10px]">server-side</span>
                        )}
                      </div>
                      <div className="text-xs text-gray-500 mb-1">{desc}</div>
                      <div className="text-[11px] text-gray-400">{tip}</div>
                    </div>
                    {active && <Check size={15} className="text-brand-accent flex-shrink-0 mt-1" />}
                  </button>
                )
              })}
            </div>
          )}

          {/* Step 2 — Artifacts (script) */}
          {step === 2 && platformDef && !isHarvest && (
            <div className="p-5">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-gray-600">
                  {platformDef.label} artifacts
                  <span className="ml-1.5 text-gray-400 font-normal">({selected.size}/{artifacts.length} selected)</span>
                </span>
                <button className="btn-ghost text-xs py-1" onClick={toggleAll}>
                  {selected.size === artifacts.length ? 'Deselect all' : 'Select all'}
                </button>
              </div>
              <div className="space-y-2">
                {artifacts.map(a => {
                  const checked = selected.has(a.key)
                  return (
                    <label
                      key={a.key}
                      className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                        checked
                          ? a.warn
                            ? 'border-amber-400 bg-amber-50'
                            : 'border-brand-accent/50 bg-brand-accentlight'
                          : 'border-gray-200 bg-white hover:border-gray-300'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleArtifact(a.key)}
                        className="mt-0.5 accent-brand-accent cursor-pointer flex-shrink-0"
                      />
                      <div>
                        <div className="flex items-center gap-1.5">
                          <span className="text-sm font-medium text-brand-text">{a.label}</span>
                          {a.warn && <AlertTriangle size={11} className="text-amber-500 flex-shrink-0" />}
                        </div>
                        <div className="text-xs text-gray-500 mt-0.5">{a.desc}</div>
                      </div>
                    </label>
                  )
                })}
              </div>
            </div>
          )}

          {/* Step 2 — Categories (harvest) */}
          {step === 2 && isHarvest && (
            <div className="p-5 space-y-4">
              {/* Level picker */}
              <div>
                <p className="section-title mb-2">Collection level</p>
                <div className="space-y-2">
                  {Object.entries(LEVEL_META).map(([key, meta]) => {
                    const count = harvestLevels[key]?.count ?? '?'
                    return (
                      <button
                        key={key}
                        type="button"
                        onClick={() => { setHarvestLevel(key); setHarvestCatOverrides([]) }}
                        className={`w-full flex items-center gap-3 p-3 rounded-xl border text-left transition-all ${
                          harvestLevel === key
                            ? 'border-brand-accent bg-brand-accentlight ring-1 ring-brand-accent/30'
                            : 'border-gray-200 bg-white hover:border-gray-300'
                        }`}
                      >
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border flex-shrink-0 ${meta.colour}`}>
                          {meta.label}
                        </span>
                        <span className="text-xs text-gray-500 flex-1">{meta.desc}</span>
                        <span className="text-[10px] text-gray-400 flex-shrink-0">{count} cats</span>
                        {harvestLevel === key && <Check size={13} className="text-brand-accent flex-shrink-0" />}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Category overrides toggle */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <p className="section-title">
                    Category overrides{' '}
                    <span className="text-gray-400 font-normal text-[10px]">
                      {harvestCatOverrides.length === 0
                        ? `(${activeLevelCats.length} from level)`
                        : `(${harvestCatOverrides.length} custom)`}
                    </span>
                  </p>
                  <div className="flex items-center gap-2">
                    {harvestCatOverrides.length > 0 && (
                      <button onClick={() => setHarvestCatOverrides([])}
                              className="text-xs text-red-500 hover:underline flex items-center gap-1">
                        <X size={10} /> Clear
                      </button>
                    )}
                    <button onClick={() => setShowCatPicker(v => !v)}
                            className="text-xs text-brand-accent hover:underline flex items-center gap-1">
                      <ListChecks size={11} /> {showCatPicker ? 'Hide' : 'Customize'}
                    </button>
                  </div>
                </div>

                {showCatPicker && (
                  <div className="rounded-xl border border-gray-200 overflow-hidden max-h-52 overflow-y-auto divide-y divide-gray-50">
                    {harvestAllCats.map(cat => {
                      const inLevel = activeLevelCats.includes(cat.name)
                      const checked = harvestCatOverrides.length === 0 ? inLevel : harvestCatOverrides.includes(cat.name)
                      return (
                        <label
                          key={cat.name}
                          className="flex items-center gap-3 px-3 py-1.5 cursor-pointer hover:bg-gray-50"
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => seedAndToggleCat(cat.name)}
                            className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent/30"
                          />
                          <div className="flex-1 min-w-0">
                            <span className="text-xs font-mono text-brand-text">{cat.name}</span>
                            {inLevel && harvestCatOverrides.length === 0 && (
                              <span className="ml-1.5 badge bg-gray-100 text-gray-400 border border-gray-200 text-[9px]">in level</span>
                            )}
                            <p className="text-[10px] text-gray-400 truncate">{cat.description}</p>
                          </div>
                        </label>
                      )
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Step 3 — Download (script) */}
          {step === 3 && !isHarvest && (
            <div className="p-5 space-y-4">

              {/* Summary */}
              <div className="bg-gray-50 rounded-xl border border-gray-200 p-4 space-y-2">
                <SummaryRow label="Platform"  value={platformDef?.label} />
                <SummaryRow label="Artifacts" value={[...selected].join(', ') || '(none)'} />
                {caseId && <SummaryRow label="Case ID" value={caseId} mono />}
              </div>

              {/* API URL */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-medium text-gray-600">API upload URL</label>
                  <button className="btn-ghost text-xs py-1 gap-1.5" onClick={() => {
                    setNetLoading(true)
                    api.collector.networkInterfaces()
                      .then(r => setNetIps(r.candidates || []))
                      .catch(() => {})
                      .finally(() => setNetLoading(false))
                  }}>
                    {netLoading ? <RefreshCw size={11} className="animate-spin" /> : <Wifi size={11} />}
                    Detect IPs
                  </button>
                </div>
                <input
                  type="text"
                  className="input text-xs font-mono"
                  value={apiUrl}
                  onChange={e => setApiUrl(e.target.value)}
                  placeholder="http://192.168.1.x:8000/api/v1"
                />
                {netIps.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {netIps.map(c => (
                      <button
                        key={c.url}
                        onClick={() => setApiUrl(c.url)}
                        title={c.iface}
                        className={`inline-flex items-center gap-1 px-2 py-1 rounded-md border text-[11px] font-mono transition-colors ${
                          apiUrl === c.url
                            ? 'border-brand-accent bg-brand-accentlight text-brand-accent'
                            : 'border-gray-200 bg-white text-gray-600 hover:border-brand-accent/50'
                        }`}
                      >
                        <Wifi size={10} />
                        {c.ip}
                        {c.label && <span className="text-gray-400 font-sans">({c.label})</span>}
                      </button>
                    ))}
                  </div>
                )}
                {!apiUrl && caseId && (
                  <p className="text-[11px] text-amber-600 mt-1.5 flex items-center gap-1">
                    ⚠ Without an API URL the collector will save the ZIP locally only.
                  </p>
                )}
              </div>

              {/* K8s LB */}
              {inK8s && (
                <div className="border border-gray-200 rounded-xl p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <Globe size={12} className="text-brand-accent" />
                      <span className="text-xs font-medium text-gray-600">Kubernetes LoadBalancer</span>
                      {ingress?.status === 'ready'   && <span className="badge bg-green-100 text-green-700 border border-green-200 text-[10px]">ready</span>}
                      {ingress?.status === 'pending' && <span className="badge bg-amber-100 text-amber-700 border border-amber-200 text-[10px]">pending…</span>}
                    </div>
                    <div className="flex gap-1.5">
                      {ingress ? (
                        <>
                          <button className="btn-ghost text-xs py-0.5 gap-1" onClick={pollIngress} disabled={ingressBusy}>
                            {ingressBusy ? <Loader2 size={10} className="animate-spin" /> : <RefreshCw size={10} />} Refresh
                          </button>
                          <button className="btn-ghost text-xs py-0.5 gap-1 text-red-500 hover:text-red-600" onClick={removeIngress} disabled={ingressBusy}>
                            <Trash2 size={10} /> Delete
                          </button>
                        </>
                      ) : (
                        <button className="btn-primary text-xs py-0.5 gap-1" onClick={createIngress} disabled={ingressBusy}>
                          {ingressBusy ? <Loader2 size={10} className="animate-spin" /> : <Globe size={10} />} Create LB
                        </button>
                      )}
                    </div>
                  </div>
                  {ingress?.external_url && (
                    <div className="flex items-center gap-2 px-3 py-2 bg-green-50 border border-green-200 rounded-lg text-xs">
                      <Check size={11} className="text-green-600 flex-shrink-0" />
                      <span className="font-mono text-green-800 flex-1 truncate">{ingress.external_url}</span>
                      <button className="text-green-600 hover:text-green-800 text-[10px]" onClick={() => setApiUrl(ingress.external_url)}>Use</button>
                    </div>
                  )}
                  {ingress?.status === 'error' && <ModalRbacErrorBanner error={ingress.error} />}
                </div>
              )}

              {/* Download button */}
              <button
                className="btn-primary w-full justify-center h-10 gap-2"
                onClick={handleDownload}
                disabled={selected.size === 0 || downloading}
              >
                {downloading
                  ? 'Downloading…'
                  : <><Download size={14} /> Download fo-collector.py</>}
              </button>

              <div className="bg-gray-950 rounded-lg p-3 text-[11px] font-mono text-gray-300 leading-relaxed">
                {platform === 'win'
                  ? <><span className="text-gray-500"># Run as Administrator</span>{'\n'}python fo-collector.py</>
                  : <><span className="text-gray-500"># Run as root</span>{'\n'}python3 fo-collector.py</>
                }
                {caseId && apiUrl && (
                  <>{'\n\n'}<span className="text-gray-500"># Artifacts upload to case </span><span className="text-brand-accent">{caseId}</span></>
                )}
              </div>
            </div>
          )}

          {/* Step 3 — Harvest source & start */}
          {step === 3 && isHarvest && (
            <div className="p-5 space-y-4">

              {/* Source mode */}
              <div>
                <p className="section-title mb-2">Artifact source</p>
                <div className="flex gap-2 mb-3">
                  {[
                    { id: 'minio',   label: 'MinIO disk image',  Icon: HardDrive },
                    { id: 'mounted', label: 'Mounted directory', Icon: FolderOpen },
                  ].map(({ id, label, Icon }) => (
                    <button
                      key={id}
                      type="button"
                      onClick={() => setHarvestSourceMode(id)}
                      className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs transition-all ${
                        harvestSourceMode === id
                          ? 'border-brand-accent bg-brand-accentlight text-brand-accent font-medium'
                          : 'border-gray-200 bg-white text-gray-600 hover:border-gray-300'
                      }`}
                    >
                      <Icon size={12} /> {label}
                    </button>
                  ))}
                </div>

                {harvestSourceMode === 'minio' ? (
                  <div>
                    <label className="text-xs text-gray-500 mb-1 block">MinIO object key</label>
                    {diskImages.length > 0 ? (
                      <select
                        value={harvestMinioKey}
                        onChange={e => setHarvestMinioKey(e.target.value)}
                        className="input w-full text-sm"
                      >
                        <option value="">— select image —</option>
                        {diskImages.map(img => (
                          <option key={img.minio_key} value={img.minio_key}>{img.filename}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        value={harvestMinioKey}
                        onChange={e => setHarvestMinioKey(e.target.value)}
                        placeholder="cases/<case_id>/image.dd"
                        className="input w-full font-mono text-xs"
                      />
                    )}
                    <p className="text-[10px] text-gray-400 mt-1 flex items-center gap-1">
                      <Info size={10} /> Image is fetched from MinIO and opened with pytsk3 on the worker.
                    </p>
                  </div>
                ) : (
                  <div>
                    <label className="text-xs text-gray-500 mb-1 block">Path on the processor worker</label>
                    <input
                      value={harvestMountedPath}
                      onChange={e => setHarvestMountedPath(e.target.value)}
                      placeholder="/mnt/windows"
                      className="input w-full font-mono text-xs"
                    />
                    <p className="text-[10px] text-gray-400 mt-1 flex items-center gap-1">
                      <Info size={10} /> Must be mounted on the processor pod (e.g. via dislocker-fuse).
                    </p>
                  </div>
                )}
              </div>

              {/* Error */}
              {harvestErr && (
                <div className="rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-xs text-red-700 flex items-center gap-1.5">
                  <AlertTriangle size={12} /> {harvestErr}
                </div>
              )}

              {/* Start */}
              <button
                onClick={handleStartHarvest}
                disabled={harvestLoading || !caseId}
                className="btn-primary w-full justify-center h-9 gap-2"
              >
                {harvestLoading
                  ? <Loader2 size={13} className="animate-spin" />
                  : <Play size={13} />
                }
                {harvestLoading ? 'Starting…' : 'Start harvest'}
              </button>

              {!caseId && (
                <p className="text-[11px] text-amber-600 flex items-center gap-1">
                  ⚠ Open this modal from a case to link the harvest run automatically.
                </p>
              )}

              {/* Run cards */}
              {harvestRuns.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs font-semibold text-gray-600">Harvest runs</p>
                  {harvestRuns.map(({ runId }) => (
                    <HarvestRunCard key={runId} runId={runId} />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer nav */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-gray-200 flex-shrink-0 bg-white">
          <button
            className="btn-ghost gap-1"
            onClick={() => step > 1 ? setStep(s => s - 1) : onClose()}
          >
            <ChevronLeft size={13} />
            {step > 1 ? 'Back' : 'Cancel'}
          </button>
          {step < 3 && (
            <button
              className="btn-primary gap-1"
              onClick={() => setStep(s => s + 1)}
              disabled={step === 1 && !platform}
            >
              Next <ChevronRight size={13} />
            </button>
          )}
        </div>

      </div>
    </div>
  )
}

function SummaryRow({ label, value, mono }) {
  return (
    <div className="flex gap-3 text-xs">
      <span className="text-gray-400 w-16 flex-shrink-0">{label}</span>
      <span className={`text-brand-text break-all ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}

function ModalRbacErrorBanner({ error }) {
  const [yaml, setYaml]     = useState(null)
  const [copied, setCopied] = useState(false)
  const is403 = error?.includes('403') || error?.toLowerCase().includes('forbidden')

  useEffect(() => {
    if (!is403) return
    api.collector.getRbacYaml().then(t => setYaml(t)).catch(() => {})
  }, [is403])

  function copyYaml() {
    if (!yaml) return
    navigator.clipboard.writeText(yaml).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })
  }

  return (
    <div className="space-y-1">
      <p className="text-[11px] text-red-500">{error}</p>
      {is403 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-[11px] text-amber-800 space-y-2">
          <p className="font-semibold flex items-center gap-1.5"><Info size={11} /> RBAC setup required</p>
          <p>Download and apply from a machine with kubectl access:</p>
          <div className="flex items-center gap-2 flex-wrap">
            <a href={api.collector.rbacUrl()} download="fo-rbac.yaml"
               className="inline-flex items-center gap-1 px-2 py-1 bg-amber-100 rounded border border-amber-300 text-amber-800 hover:bg-amber-200 font-medium">
              <ExternalLink size={10} /> Download fo-rbac.yaml
            </a>
            {yaml && (
              <button onClick={copyYaml} className="inline-flex items-center gap-1 px-2 py-1 bg-amber-100 rounded border border-amber-300 text-amber-800 hover:bg-amber-200">
                <Copy size={10} /> {copied ? 'Copied!' : 'Copy YAML'}
              </button>
            )}
          </div>
          <pre className="bg-gray-900 text-green-300 rounded px-2 py-1.5 text-[10px] font-mono">kubectl apply -f fo-rbac.yaml</pre>
        </div>
      )}
    </div>
  )
}
