/**
 * Collector page — standalone artifact collector generator.
 *
 * Provides the same 3-step wizard as CollectorModal but as a full page,
 * accessible from the sidebar nav without being inside a specific case.
 * Optionally linked to a case via a case-selector dropdown.
 */
import { useState, useEffect } from 'react'
import {
  Monitor, Terminal, FileCode, Download, Check,
  ChevronRight, ChevronLeft, Wifi, RefreshCw,
  PackageOpen, AlertTriangle, Globe, Loader2, Trash2,
  Info,
} from 'lucide-react'
import { api } from '../api/client'

// ── Artifact definitions (shared with CollectorModal) ────────────────────────

const WINDOWS_ARTIFACTS = [
  { key: 'evtx',     label: 'Event Logs (EVTX)',   desc: 'Security, System, Application, PowerShell, Sysmon and more' },
  { key: 'registry', label: 'Registry Hives',       desc: 'SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat' },
  { key: 'prefetch', label: 'Prefetch Files',        desc: 'Program execution evidence (up to 500 .pf files)' },
  { key: 'lnk',      label: 'LNK / Recent Items',   desc: 'Shell link files from all user Recent folders' },
  { key: 'browser',  label: 'Browser Artifacts',    desc: 'Chrome, Edge, Firefox — history, cookies, login data' },
  { key: 'tasks',    label: 'Scheduled Tasks',      desc: 'Windows Task Scheduler XML from System32\\Tasks' },
  { key: 'triage',   label: 'Live System Triage',   desc: 'systeminfo, netstat, tasklist, services, installed software' },
]

const LINUX_ARTIFACTS = [
  { key: 'logs',    label: 'System Logs',           desc: '/var/log — auth.log, syslog, audit, journalctl export' },
  { key: 'history', label: 'Shell Histories',       desc: '.bash_history, .zsh_history for root and all users' },
  { key: 'config',  label: 'System Configuration',  desc: '/etc/passwd, sudoers, hosts, ssh/sshd_config and more' },
  { key: 'cron',    label: 'Cron Jobs',             desc: 'cron.d, cron.daily, crontabs, systemd timers' },
  { key: 'ssh',     label: 'SSH Artifacts',         desc: 'known_hosts, authorized_keys, config (no private keys)' },
  { key: 'triage',  label: 'Live System Triage',    desc: 'ps, ss, ip, last, lsmod, services, installed packages' },
]

const PLATFORMS = [
  {
    id: 'win',
    label: 'Windows',
    Icon: Monitor,
    color: 'text-blue-600',
    bg: 'bg-blue-50',
    border: 'border-blue-200',
    selectedBorder: 'border-blue-500',
    selectedBg: 'bg-blue-50',
    desc: 'Python script — run as Administrator',
    tip: 'Requires Python 3.8+ on target. For a zero-dependency EXE build with build.bat.',
    artifacts: WINDOWS_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Linux / macOS',
    Icon: Terminal,
    color: 'text-emerald-600',
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    selectedBorder: 'border-emerald-500',
    selectedBg: 'bg-emerald-50',
    desc: 'Python script — run as root',
    tip: 'Requires Python 3.8+ on target. For a zero-dependency ELF build with ./build.sh.',
    artifacts: LINUX_ARTIFACTS,
  },
  {
    id: 'py',
    label: 'Python Script',
    Icon: FileCode,
    color: 'text-violet-600',
    bg: 'bg-violet-50',
    border: 'border-violet-200',
    selectedBorder: 'border-violet-500',
    selectedBg: 'bg-violet-50',
    desc: 'Platform-agnostic — auto-detects OS at runtime',
    tip: 'Works on Windows, Linux & macOS. Best when the target already has Python 3.8+.',
    artifacts: [...WINDOWS_ARTIFACTS, ...LINUX_ARTIFACTS],
  },
]

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Collector() {
  const [step, setStep]               = useState(1)
  const [platform, setPlatform]       = useState(null)
  const [selected, setSelected]       = useState(new Set())
  const [caseId, setCaseId]           = useState('')
  const [apiUrl, setApiUrl]           = useState('')
  const [cases, setCases]             = useState([])
  const [netIps, setNetIps]           = useState([])
  const [inK8s, setInK8s]             = useState(false)
  const [netLoading, setNetLoading]   = useState(false)
  const [ipHint, setIpHint]           = useState(null)   // FO_PUBLIC_URL hint from backend
  const [ingress, setIngress]         = useState(null)   // {status, external_ip, external_url}
  const [ingressBusy, setIngressBusy] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [downloaded, setDownloaded]   = useState(false)

  const platformDef = PLATFORMS.find(p => p.id === platform)
  const artifacts   = platformDef?.artifacts || []

  useEffect(() => {
    api.cases.list().then(r => setCases(r.cases || [])).catch(() => {})
  }, [])

  // Pre-select all artifacts when platform chosen
  useEffect(() => {
    if (platformDef) setSelected(new Set(platformDef.artifacts.map(a => a.key)))
  }, [platform])

  function toggleArtifact(key) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  function toggleAll() {
    setSelected(
      selected.size === artifacts.length
        ? new Set()
        : new Set(artifacts.map(a => a.key))
    )
  }

  function detectIps() {
    setNetLoading(true)
    api.collector.networkInterfaces()
      .then(r => {
        const candidates = r.candidates || []
        setNetIps(candidates)
        setInK8s(r.in_kubernetes || false)
        setIpHint(r.public_url_hint || null)
        // Auto-fill best candidate
        const lbEntry = candidates.find(c => c.k8s && c.label?.includes('LoadBalancer'))
        const lanEntry = candidates.find(c => c.label === 'LAN' || c.label === 'host machine (Docker Desktop)')
        const best     = lbEntry || lanEntry
        if (best && !apiUrl) setApiUrl(best.url)
      })
      .catch(() => {})
      .finally(() => setNetLoading(false))
  }

  async function createIngress() {
    setIngressBusy(true)
    try {
      const r = await api.collector.createIngress()
      setIngress(r)
      if (r.external_url) setApiUrl(r.external_url)
    } catch (e) {
      setIngress({ status: 'error', error: e.message })
    } finally {
      setIngressBusy(false)
    }
  }

  async function pollIngress() {
    setIngressBusy(true)
    try {
      const r = await api.collector.getIngress()
      setIngress(r)
      if (r.external_url) setApiUrl(r.external_url)
    } catch {
      /* ignore */
    } finally {
      setIngressBusy(false)
    }
  }

  async function removeIngress() {
    setIngressBusy(true)
    try {
      await api.collector.deleteIngress()
      setIngress(null)
    } catch {
      /* ignore */
    } finally {
      setIngressBusy(false)
    }
  }

  function handleCaseSelect(id) {
    setCaseId(id)
    // Auto-detect IPs whenever case selection changes (or even when cleared)
    if (!apiUrl) detectIps()
  }

  function handleDownload() {
    setDownloading(true)
    setDownloaded(false)
    // Embed apiUrl whenever it is filled in, regardless of whether a case is selected.
    // Without caseId the script still runs and saves a local ZIP; with both it auto-uploads.
    const url = api.collector.downloadUrl({
      platform,
      caseId:  caseId   || undefined,
      apiUrl:  apiUrl   || undefined,
      collect: selected.size > 0 ? [...selected] : undefined,
    })
    const a = document.createElement('a')
    a.href = url
    a.download = 'fo-collector.py'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setTimeout(() => { setDownloading(false); setDownloaded(true) }, 1200)
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="h-full overflow-y-auto bg-gray-50">
      <div className="max-w-3xl mx-auto px-6 py-8">

        {/* Page header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-brand-accentlight border border-brand-accent/20
                          flex items-center justify-center">
            <PackageOpen size={18} className="text-brand-accent" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-brand-text">Artifact Collector</h1>
            <p className="text-xs text-gray-500">
              Generate a pre-configured script to collect forensic artifacts from any live system
            </p>
          </div>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-0 mb-6 bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          {['Platform', 'Artifacts', 'Configure & Download'].map((label, i) => {
            const num    = i + 1
            const active = step === num
            const done   = step > num
            return (
              <button
                key={label}
                disabled={!done && !active}
                onClick={() => done && setStep(num)}
                className={`flex-1 flex items-center justify-center gap-2 py-3.5 text-sm font-medium
                            transition-colors border-r border-gray-100 last:border-r-0 ${
                  active
                    ? 'bg-brand-accent/5 text-brand-accent'
                    : done
                    ? 'text-gray-400 hover:text-brand-accent hover:bg-gray-50 cursor-pointer'
                    : 'text-gray-300 cursor-default'
                }`}
              >
                <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                  active ? 'bg-brand-accent text-white' :
                  done   ? 'bg-green-500 text-white' :
                           'bg-gray-200 text-gray-400'
                }`}>
                  {done ? <Check size={10} /> : num}
                </span>
                {label}
              </button>
            )
          })}
        </div>

        {/* ── Step 1: Platform ─────────────────────────────────────────────── */}
        {step === 1 && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {PLATFORMS.map(({ id, label, Icon, desc, tip, selectedBorder, selectedBg, bg, color, border }) => {
              const active = platform === id
              return (
                <button
                  key={id}
                  onClick={() => setPlatform(id)}
                  className={`card flex flex-col items-center gap-3 p-5 text-center cursor-pointer
                              border-2 transition-all hover:shadow-md ${
                    active ? `${selectedBorder} ${selectedBg}` : `border-transparent`
                  }`}
                >
                  <div className={`w-12 h-12 rounded-xl ${bg} border ${border}
                                   flex items-center justify-center`}>
                    <Icon size={22} className={color} />
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-brand-text mb-1">{label}</div>
                    <div className="text-xs text-gray-500 mb-2">{desc}</div>
                    <div className="text-[11px] text-gray-400">{tip}</div>
                  </div>
                  {active && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-brand-accent
                                     text-white text-xs rounded-full">
                      <Check size={10} /> Selected
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        )}

        {/* ── Step 2: Artifacts ─────────────────────────────────────────────── */}
        {step === 2 && platformDef && (
          <div className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-brand-text">
                  {platformDef.label} artifact selection
                </h3>
                <p className="text-xs text-gray-500 mt-0.5">
                  {selected.size} of {artifacts.length} artifact types selected
                </p>
              </div>
              <button className="btn-ghost text-xs py-1" onClick={toggleAll}>
                {selected.size === artifacts.length ? 'Deselect all' : 'Select all'}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {artifacts.map(a => {
                const checked = selected.has(a.key)
                return (
                  <label
                    key={a.key}
                    className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                      checked
                        ? 'border-brand-accent/40 bg-brand-accentlight'
                        : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleArtifact(a.key)}
                      className="mt-0.5 accent-brand-accent cursor-pointer flex-shrink-0"
                    />
                    <div>
                      <div className="text-sm font-medium text-brand-text">{a.label}</div>
                      <div className="text-xs text-gray-500 mt-0.5">{a.desc}</div>
                    </div>
                  </label>
                )
              })}
            </div>
          </div>
        )}

        {/* ── Step 3: Configure & Download ─────────────────────────────────── */}
        {step === 3 && (
          <div className="space-y-4">

            {/* Summary */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Configuration summary
              </h3>
              <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
                <SummaryRow label="Platform"  value={platformDef?.label} />
                <SummaryRow label="Artifacts" value={`${selected.size} types`} />
              </div>
            </div>

            {/* Case selector (optional) */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Upload target <span className="text-gray-300 normal-case font-normal">— optional</span>
              </h3>
              <p className="text-xs text-gray-500 mb-3">
                Link the collector to a case so artifacts upload automatically when it runs.
                Leave blank to save the ZIP locally and upload manually.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {/* Case selector */}
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">
                    Case
                  </label>
                  <select
                    className="input text-sm"
                    value={caseId}
                    onChange={e => handleCaseSelect(e.target.value)}
                  >
                    <option value="">— No case (save locally) —</option>
                    {cases.map(c => (
                      <option key={c.case_id} value={c.case_id}>{c.name}</option>
                    ))}
                  </select>
                </div>

                {/* API URL */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-medium text-gray-600">API URL</label>
                    <button
                      className="btn-ghost text-xs py-0.5 gap-1"
                      onClick={detectIps}
                    >
                      {netLoading
                        ? <RefreshCw size={10} className="animate-spin" />
                        : <Wifi size={10} />}
                      Detect
                    </button>
                  </div>
                  <input
                    type="text"
                    className="input text-xs font-mono"
                    value={apiUrl}
                    onChange={e => setApiUrl(e.target.value)}
                    placeholder="http://192.168.1.x:8000/api/v1"
                  />
                </div>
              </div>

              {/* FO_PUBLIC_URL hint — shown when only Docker-internal IPs detected */}
              {ipHint && (
                <div className="mt-3 flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
                  <AlertTriangle size={13} className="flex-shrink-0 mt-0.5 text-amber-500" />
                  <div>
                    <strong>Only Docker-internal IPs detected.</strong>{' '}
                    Remote collectors cannot reach the API via these addresses.
                    Add the following to your <code className="bg-amber-100 px-1 rounded">docker-compose.yml</code>{' '}
                    under the <code className="bg-amber-100 px-1 rounded">api:</code> environment section,
                    replacing the IP with your machine's LAN address:
                    <pre className="mt-1.5 bg-white border border-amber-200 rounded px-2 py-1.5 text-[10px] leading-relaxed overflow-x-auto font-mono">
{`api:
  environment:
    - FO_PUBLIC_URL=http://192.168.x.x:8000`}
                    </pre>
                    <p className="mt-1 text-amber-700">
                      Then enter the URL manually in the field above, or click Detect again after restarting.
                    </p>
                  </div>
                </div>
              )}

              {/* Detected IP suggestions */}
              {netIps.length > 0 && (
                <div className="mt-3">
                  <p className="text-[11px] text-gray-400 mb-2 flex items-center gap-1">
                    <Wifi size={10} /> Detected addresses — click to use
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {netIps.map(c => {
                      // Visual hint: Docker bridge IPs are likely not reachable from target
                      const isInternal = c.ip.startsWith('172.') || c.label === 'docker bridge'
                      return (
                        <button
                          key={c.url}
                          onClick={() => setApiUrl(c.url)}
                          title={`Interface: ${c.iface}${isInternal ? ' — Docker-internal, may not be reachable externally' : ''}`}
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border
                                      text-xs font-mono transition-all ${
                            apiUrl === c.url
                              ? 'border-brand-accent bg-brand-accentlight text-brand-accent'
                              : isInternal
                              ? 'border-gray-200 bg-gray-50 text-gray-400 hover:border-amber-300'
                              : 'border-gray-200 bg-white text-gray-600 hover:border-brand-accent/50'
                          }`}
                        >
                          {c.k8s
                            ? <Globe size={10} />
                            : isInternal
                            ? <AlertTriangle size={10} className="text-amber-400" />
                            : <Wifi size={10} />}
                          <span>{c.ip}</span>
                          {c.label && (
                            <span className="text-gray-400 font-sans text-[10px]">({c.label})</span>
                          )}
                        </button>
                      )
                    })}
                  </div>
                  <p className="text-[11px] text-gray-400 mt-1.5 flex items-center gap-1">
                    <Info size={10} />
                    <span>
                      IPs marked <AlertTriangle size={9} className="inline text-amber-400" /> are Docker-internal and may not be reachable from the target machine.
                      Prefer a LAN IP or set <code className="bg-gray-100 px-0.5 rounded">FO_PUBLIC_URL</code> in docker-compose.yml.
                    </span>
                  </p>
                </div>
              )}

              {/* ── Kubernetes LoadBalancer ingress ──────────────────────── */}
              {inK8s && (
                <div className="mt-4 pt-4 border-t border-gray-100">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-1.5">
                      <Globe size={12} className="text-brand-accent" />
                      <span className="text-xs font-medium text-gray-600">
                        Kubernetes LoadBalancer
                      </span>
                      {ingress?.status === 'ready' && (
                        <span className="badge bg-green-100 text-green-700 border border-green-200 text-[10px]">ready</span>
                      )}
                      {ingress?.status === 'pending' && (
                        <span className="badge bg-amber-100 text-amber-700 border border-amber-200 text-[10px]">pending IP…</span>
                      )}
                    </div>
                    <div className="flex gap-1.5">
                      {ingress ? (
                        <>
                          <button className="btn-ghost text-xs py-0.5 gap-1" onClick={pollIngress} disabled={ingressBusy}>
                            {ingressBusy ? <Loader2 size={10} className="animate-spin" /> : <RefreshCw size={10} />}
                            Refresh
                          </button>
                          <button className="btn-ghost text-xs py-0.5 gap-1 text-red-500 hover:text-red-600"
                                  onClick={removeIngress} disabled={ingressBusy}>
                            <Trash2 size={10} /> Delete
                          </button>
                        </>
                      ) : (
                        <button className="btn-primary text-xs py-0.5 gap-1" onClick={createIngress} disabled={ingressBusy || !caseId}>
                          {ingressBusy ? <Loader2 size={10} className="animate-spin" /> : <Globe size={10} />}
                          Create LoadBalancer
                        </button>
                      )}
                    </div>
                  </div>
                  <p className="text-[11px] text-gray-500 mb-2">
                    Creates a Kubernetes <code className="bg-gray-100 px-1 rounded">LoadBalancer</code> Service
                    that exposes the API externally. The assigned IP is injected into the collector automatically.
                    Requires RBAC permission to create Services.
                  </p>
                  {ingress?.external_url && (
                    <div className="flex items-center gap-2 px-3 py-2 bg-green-50 border border-green-200 rounded-lg text-xs">
                      <Check size={11} className="text-green-600 flex-shrink-0" />
                      <span className="font-mono text-green-800 flex-1 truncate">{ingress.external_url}</span>
                      <button className="text-green-600 hover:text-green-800 text-[10px]"
                              onClick={() => setApiUrl(ingress.external_url)}>
                        Use
                      </button>
                    </div>
                  )}
                  {ingress?.status === 'error' && (
                    <div className="mt-2 space-y-1">
                      <p className="text-[11px] text-red-500">{ingress.error}</p>
                      {ingress.error?.includes('403') || ingress.error?.includes('forbidden') ? (
                        <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-[11px] text-amber-800 space-y-2">
                          <p className="font-medium flex items-center gap-1.5">
                            <Info size={11} /> RBAC permission required
                          </p>
                          <p>The pod's service account needs permission to create Services. Apply the RBAC manifest once:</p>
                          <code className="block bg-amber-100 rounded px-2 py-1.5 font-mono text-[10px] break-all select-all">
                            kubectl apply -f "{api.collector.rbacUrl()}"
                          </code>
                          <a
                            href={api.collector.rbacUrl()}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-amber-700 hover:text-amber-900 underline"
                          >
                            Download fo-rbac.yaml
                          </a>
                        </div>
                      ) : null}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Download */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Download
              </h3>

              <button
                className={`btn-primary w-full justify-center h-10 gap-2 ${
                  downloaded ? '!bg-green-600' : ''
                }`}
                onClick={handleDownload}
                disabled={selected.size === 0 || downloading}
              >
                {downloading
                  ? 'Generating…'
                  : downloaded
                  ? <><Check size={14} /> Downloaded — fo-collector.py</>
                  : <><Download size={14} /> Download fo-collector.py</>
                }
              </button>

              {downloaded && (
                <div className="mt-3 bg-gray-950 rounded-lg p-3.5 text-[11px] font-mono text-gray-300 leading-relaxed">
                  <span className="text-gray-500"># Run on the target machine</span>{'\n'}
                  {platform === 'win'
                    ? 'python fo-collector.py     # as Administrator'
                    : 'python3 fo-collector.py   # as root'
                  }
                  {caseId && apiUrl && (
                    <>
                      {'\n\n'}
                      <span className="text-gray-500"># Artifacts auto-upload to case </span>
                      <span className="text-brand-accent">{caseId}</span>
                      {'\n'}
                      <span className="text-gray-500"># via </span>
                      <span className="text-emerald-400">{apiUrl}</span>
                    </>
                  )}
                  {!caseId && apiUrl && (
                    <>
                      {'\n\n'}
                      <span className="text-gray-500"># API URL embedded: </span>
                      <span className="text-emerald-400">{apiUrl}</span>
                      {'\n'}
                      <span className="text-amber-400">
                        ⚠ No case linked — collector will save a local ZIP.{'\n'}
                        Drag & drop the ZIP into any case via Add Evidence.
                      </span>
                    </>
                  )}
                  {!caseId && !apiUrl && (
                    <>
                      {'\n\n'}
                      <span className="text-amber-400">
                        ⚠ No case or API URL — ZIP saved locally.{'\n'}
                        Upload manually via any case Ingest panel.
                      </span>
                    </>
                  )}
                  {caseId && !apiUrl && (
                    <>
                      {'\n\n'}
                      <span className="text-amber-400">
                        ⚠ No API URL set — ZIP will be saved locally.{'\n'}
                        Upload manually via the case Ingest panel.
                      </span>
                    </>
                  )}
                </div>
              )}

              {/* PyInstaller note */}
              <p className="text-[11px] text-gray-400 mt-3 leading-relaxed">
                The script requires <strong className="text-gray-500">Python 3.8+</strong> on the target.
                To build a zero-dependency binary (no Python required on target):
                {' '}<code className="text-[10px] bg-gray-100 px-1 py-0.5 rounded">build.bat</code> (Windows)
                {' '}or{' '}
                <code className="text-[10px] bg-gray-100 px-1 py-0.5 rounded">./build.sh</code> (Linux).
              </p>
            </div>
          </div>
        )}

        {/* ── Navigation ───────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between mt-6">
          <button
            className="btn-outline gap-1"
            onClick={() => step > 1 && setStep(s => s - 1)}
            disabled={step === 1}
          >
            <ChevronLeft size={14} /> Back
          </button>
          {step < 3 && (
            <button
              className="btn-primary gap-1"
              onClick={() => setStep(s => s + 1)}
              disabled={step === 1 && !platform}
            >
              Continue <ChevronRight size={14} />
            </button>
          )}
        </div>

      </div>
    </div>
  )
}

function SummaryRow({ label, value, mono }) {
  return (
    <div className="flex items-baseline gap-2 text-sm">
      <span className="text-gray-400 text-xs w-20 flex-shrink-0">{label}</span>
      <span className={`text-brand-text ${mono ? 'font-mono text-xs' : ''}`}>{value}</span>
    </div>
  )
}
