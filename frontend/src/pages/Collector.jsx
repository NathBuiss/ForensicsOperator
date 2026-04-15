/**
 * Collector page — artifact collection wizard.
 *
 * Two modes:
 *   Script   — generate a pre-configured Python script (Windows / Linux / macOS)
 *   Harvest  — server-side triage of a raw disk image or mounted directory
 *
 * The Harvest mode bypasses the download step entirely: artifacts are located by
 * the processor worker using pytsk3 / OS paths, uploaded to MinIO, and dispatched
 * as ingest jobs automatically — no script needs to run on the target.
 */
import { useState, useEffect } from 'react'
import {
  Monitor, Terminal, FileCode, Download, Check,
  ChevronRight, ChevronLeft, Wifi, RefreshCw,
  PackageOpen, AlertTriangle, Globe, Loader2, Trash2,
  Info, Copy, ExternalLink,
} from 'lucide-react'
import { api } from '../api/client'

// ── Artifact definitions (script mode) ───────────────────────────────────────

const WINDOWS_ARTIFACTS = [
  { key: 'evtx',      label: 'Event Logs (EVTX)',          desc: 'Security, System, Application, PowerShell, Sysmon and more' },
  { key: 'registry',  label: 'Registry Hives',              desc: 'SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat' },
  { key: 'prefetch',  label: 'Prefetch Files',               desc: 'Program execution evidence (up to 500 .pf files)' },
  { key: 'lnk',       label: 'LNK / Recent Items',          desc: 'Shell link files from all user Recent folders' },
  { key: 'browser',   label: 'Browser Artifacts',           desc: 'Chrome, Edge, Firefox, Brave — history, cookies, login data' },
  { key: 'tasks',     label: 'Scheduled Tasks',             desc: 'Windows Task Scheduler XML from System32\\Tasks' },
  { key: 'mft',       label: 'Master File Table ($MFT)',    desc: 'Raw NTFS MFT from all NTFS volumes — requires Administrator (feeds MFT ingester)' },
  { key: 'pe',        label: 'PE / Executable Binaries',    desc: 'EXE/DLL/PS1 from Temp, Downloads, AppData — feeds PE Analysis, YARA, de4dot, strings', warn: true },
  { key: 'documents', label: 'Office Documents & PDFs',     desc: 'DOCX, XLSX, PPTX, PDF from user Documents/Downloads/Desktop — feeds OLE analysis', warn: true },
  { key: 'triage',    label: 'Live System Triage',          desc: 'systeminfo, netstat, tasklist, services, installed software' },
  { key: 'memory',    label: 'Memory Dump',                 desc: 'Physical memory acquisition via WinPmem — 4–64 GB, requires winpmem_mini_x64_rc2.exe beside the script', warn: true },
]

const LINUX_ARTIFACTS = [
  { key: 'logs',      label: 'System Logs',                  desc: '/var/log — auth.log, syslog, audit, journalctl export (feeds syslog + access log ingesters)' },
  { key: 'history',   label: 'Shell Histories',              desc: '.bash_history, .zsh_history for root and all users' },
  { key: 'config',    label: 'System Configuration',         desc: '/etc/passwd, sudoers, hosts, ssh/sshd_config, plist preferences (macOS)' },
  { key: 'cron',      label: 'Cron Jobs',                    desc: 'cron.d, cron.daily, crontabs, systemd timers' },
  { key: 'ssh',       label: 'SSH Artifacts',                desc: 'known_hosts, authorized_keys, config (no private keys)' },
  { key: 'network',   label: 'Network Captures',             desc: 'PCAP/PCAPNG from /var/log, /tmp — live tcpdump if none found' },
  { key: 'suricata',  label: 'Suricata IDS Logs',           desc: 'EVE JSON alerts from /var/log/suricata (feeds suricata ingester)' },
  { key: 'zeek',      label: 'Zeek Network Logs',           desc: 'conn.log, dns.log, http.log, ssl.log and more (feeds zeek ingester)' },
  { key: 'plist',     label: 'macOS Preference Plists',      desc: '/Library/Preferences, ~/Library/Preferences — feeds plist ingester (macOS only)' },
  { key: 'pe',        label: 'PE / ELF Binaries',           desc: 'Suspicious binaries from /tmp, /var/tmp, ~/Downloads — feeds PE Analysis, YARA, strings', warn: true },
  { key: 'documents', label: 'Office Documents & PDFs',      desc: 'DOCX, XLSX, PPTX, PDF from home directories — feeds OLE analysis, ExifTool', warn: true },
  { key: 'triage',    label: 'Live System Triage',           desc: 'ps, ss, ip, last, lsmod, services, installed packages' },
  { key: 'memory',    label: 'Memory Dump',                  desc: 'Physical memory via avml or /dev/fmem — 4–64 GB, requires root + avml in PATH', warn: true },
]

const DC_EXTRA_ARTIFACTS = [
  { key: 'evtx',    label: 'Event Logs (EVTX)',             desc: 'Security, ADDS replication, Kerberos, NTDS audit events' },
  { key: 'registry',label: 'Registry Hives',               desc: 'SYSTEM, SOFTWARE, SAM, SECURITY, Group Policy state' },
  { key: 'triage',  label: 'Live AD Triage',               desc: 'nltest, netdom, Get-ADUser/Group/GPO snapshots, trust enumeration' },
]

const PROXY_ARTIFACTS = [
  { key: 'logs',    label: 'Proxy / Access Logs',           desc: '/var/log/squid, /var/log/nginx, /var/log/haproxy, /var/log/apache2' },
  { key: 'config',  label: 'Proxy / Firewall Config',      desc: '/etc/squid, /etc/nginx, /etc/haproxy, /etc/iptables, nftables rules' },
  { key: 'triage',  label: 'Live Network Triage',          desc: 'Active connections, routing table, ARP cache, loaded kernel modules' },
  { key: 'network', label: 'Live PCAP Snapshot',           desc: 'Short tcpdump capture on primary interfaces (5 min, 500 MB cap)' },
  { key: 'ssh',     label: 'SSH Artifacts',                desc: 'known_hosts, authorized_keys, sshd_config' },
]

const NS_ARTIFACTS = [
  { key: 'logs',    label: 'DNS Query Logs',               desc: '/var/log/named, /var/log/bind, /var/log/unbound, journalctl' },
  { key: 'config',  label: 'DNS Configuration',            desc: '/etc/named.conf, /etc/bind, zone files, resolv.conf' },
  { key: 'triage',  label: 'Live System Triage',           desc: 'Running processes, open ports, installed packages' },
  { key: 'ssh',     label: 'SSH Artifacts',                desc: 'known_hosts, authorized_keys, sshd_config' },
]

// ── Platform definitions ──────────────────────────────────────────────────────

const PLATFORMS = [
  {
    id: 'win',
    label: 'Windows',
    group: 'Endpoint',
    Icon: Monitor,
    color: 'text-blue-600',
    bg: 'bg-blue-50',
    border: 'border-blue-200',
    selectedBorder: 'border-blue-500',
    selectedBg: 'bg-blue-50',
    desc: 'Live system, mounted directory (--path), or external disk (--disk)',
    tip: 'Requires Python 3.8+ on target. Build a zero-dependency EXE with build.bat.',
    artifacts: WINDOWS_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Linux / macOS',
    group: 'Endpoint',
    Icon: Terminal,
    color: 'text-emerald-600',
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    selectedBorder: 'border-emerald-500',
    selectedBg: 'bg-emerald-50',
    desc: 'Workstation or server — run as root',
    tip: 'Requires Python 3.8+ on target. Build a zero-dependency binary with ./build.sh.',
    artifacts: LINUX_ARTIFACTS,
  },
  {
    id: 'win',
    label: 'Domain Controller',
    group: 'Endpoint',
    Icon: Monitor,
    color: 'text-indigo-600',
    bg: 'bg-indigo-50',
    border: 'border-indigo-200',
    selectedBorder: 'border-indigo-500',
    selectedBg: 'bg-indigo-50',
    desc: 'Windows — AD events, NTDS, GPO, trust info',
    tip: 'Run as Domain Admin. Collects AD-specific event channels and Group Policy state.',
    defaultCollect: ['evtx','registry','triage'],
    artifacts: DC_EXTRA_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Proxy / Firewall',
    group: 'Network',
    Icon: Terminal,
    color: 'text-orange-600',
    bg: 'bg-orange-50',
    border: 'border-orange-200',
    selectedBorder: 'border-orange-500',
    selectedBg: 'bg-orange-50',
    desc: 'Linux-based — Squid, Nginx, HAProxy, iptables',
    tip: 'Run as root on the proxy or firewall host. Collects access logs, config and a PCAP snapshot.',
    defaultCollect: ['logs','config','triage','network'],
    artifacts: PROXY_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Nameserver',
    group: 'Network',
    Icon: Terminal,
    color: 'text-cyan-600',
    bg: 'bg-cyan-50',
    border: 'border-cyan-200',
    selectedBorder: 'border-cyan-500',
    selectedBg: 'bg-cyan-50',
    desc: 'Linux-based — BIND, Unbound, PowerDNS',
    tip: 'Run as root on the DNS server. Captures query logs, zone files, and config.',
    defaultCollect: ['logs','config','triage'],
    artifacts: NS_ARTIFACTS,
  },
  {
    id: 'py',
    label: 'Generic (Python)',
    group: 'Other',
    Icon: FileCode,
    color: 'text-violet-600',
    bg: 'bg-violet-50',
    border: 'border-violet-200',
    selectedBorder: 'border-violet-500',
    selectedBg: 'bg-violet-50',
    desc: 'Auto-detects OS at runtime — Windows + Linux + macOS',
    tip: 'Best when the target already has Python 3.8+. Manually select artifacts below.',
    artifacts: [...WINDOWS_ARTIFACTS, ...LINUX_ARTIFACTS].filter(
      (a, i, arr) => arr.findIndex(b => b.key === a.key) === i
    ),
  },
]

const PLATFORM_GROUPS = ['Endpoint', 'Network', 'Other']

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Collector() {
  // ── shared state ──────────────────────────────────────────────────────────
  const [step, setStep]               = useState(1)
  const [platIdx, setPlatIdx]         = useState(null)
  const [cases, setCases]             = useState([])
  const [caseId, setCaseId]           = useState('')

  // Script-mode state
  const [selected, setSelected]       = useState(new Set())
  const [apiUrl, setApiUrl]           = useState('')
  const [netIps, setNetIps]           = useState([])
  const [inK8s, setInK8s]             = useState(false)
  const [netLoading, setNetLoading]   = useState(false)
  const [ipHint, setIpHint]           = useState(null)
  const [ingress, setIngress]         = useState(null)
  const [ingressBusy, setIngressBusy] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [downloaded, setDownloaded]   = useState(false)


  const platformDef = platIdx !== null ? PLATFORMS[platIdx] : null
  const artifacts   = platformDef?.artifacts || []

  // ── data loading ──────────────────────────────────────────────────────────
  useEffect(() => {
    api.cases.list().then(r => {
      const cs = r.cases || []
      setCases(cs)
      if (cs.length === 1) setCaseId(cs[0].case_id)
    }).catch(() => {})
  }, [])

  // Pre-select artifacts when platform chosen
  useEffect(() => {
    if (!platformDef) return
    const defaults = platformDef.defaultCollect
      ? new Set(platformDef.defaultCollect)
      : new Set(platformDef.artifacts.map(a => a.key))
    setSelected(defaults)
    setStep(1)
  }, [platIdx])

  // ── script handlers ───────────────────────────────────────────────────────
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
        const lbEntry  = candidates.find(c => c.k8s && c.label?.includes('LoadBalancer'))
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
    } catch { /* ignore */ } finally {
      setIngressBusy(false)
    }
  }

  async function removeIngress() {
    setIngressBusy(true)
    try {
      await api.collector.deleteIngress()
      setIngress(null)
    } catch { /* ignore */ } finally {
      setIngressBusy(false)
    }
  }

  function handleCaseSelect(id) {
    setCaseId(id)
    if (!apiUrl) detectIps()
  }

  function handleDownload() {
    setDownloading(true)
    setDownloaded(false)
    const url = api.collector.downloadUrl({
      platform: platformDef?.id,
      caseId:  caseId  || undefined,
      apiUrl:  apiUrl  || undefined,
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

  // ── derived / display ─────────────────────────────────────────────────────
  const stepLabels = ['Platform', 'Artifacts', 'Configure & Download']

  // ── render ────────────────────────────────────────────────────────────────
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
              Generate a pre-configured collection script — or trigger server-side harvest below
            </p>
          </div>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-0 mb-6 bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          {stepLabels.map((label, i) => {
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

        {/* ── Step 1: Platform ─────────────────────────────────────────── */}
        {step === 1 && (
          <div className="space-y-5">
            {PLATFORM_GROUPS.map(group => {
              const groupPlatforms = PLATFORMS.map((p, i) => ({ ...p, _idx: i })).filter(p => p.group === group)
              if (groupPlatforms.length === 0) return null
              return (
                <div key={group}>
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-widest mb-2">{group}</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {groupPlatforms.map(({ _idx, label, Icon, desc, tip, selectedBorder, selectedBg, bg, color, border }) => {
                      const active = platIdx === _idx
                      return (
                        <button
                          key={_idx}
                          onClick={() => { setPlatIdx(_idx); setStep(1) }}
                          className={`card flex flex-col items-start gap-2.5 p-4 text-left cursor-pointer
                                      border-2 transition-all hover:shadow-md ${
                            active ? `${selectedBorder} ${selectedBg}` : `border-transparent`
                          }`}
                        >
                          <div className="flex items-center gap-2.5 w-full">
                            <div className={`w-9 h-9 rounded-lg ${bg} border ${border} flex items-center justify-center flex-shrink-0`}>
                              <Icon size={18} className={color} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-semibold text-brand-text">{label}</div>
                              <div className="text-xs text-gray-500 truncate">{desc}</div>
                            </div>
                            {active && <Check size={14} className="text-brand-accent flex-shrink-0" />}
                          </div>
                          <div className="text-[11px] text-gray-400 leading-relaxed">{tip}</div>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {/* ── Step 2: Artifacts ─────────────────────────────────────── */}
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
                        ? a.warn ? 'border-amber-400 bg-amber-50' : 'border-brand-accent/40 bg-brand-accentlight'
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
            {selected.has('memory') && (
              <div className="mt-3 flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
                <AlertTriangle size={13} className="flex-shrink-0 mt-0.5 text-amber-500" />
                <div>
                  <strong>Memory dumps are 4–64 GB and take 15–60 minutes.</strong>{' '}
                  Ensure storage is sufficient and upload timeouts are generous.
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Step 3: Configure & Download ─────────────────────────── */}
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

            {/* Case selector */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Upload target <span className="text-gray-300 normal-case font-normal">— optional</span>
              </h3>
              <p className="text-xs text-gray-500 mb-3">
                Link the collector to a case so artifacts upload automatically when it runs.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Case</label>
                  <select className="input text-sm" value={caseId} onChange={e => handleCaseSelect(e.target.value)}>
                    <option value="">— No case (save locally) —</option>
                    {cases.map(c => <option key={c.case_id} value={c.case_id}>{c.name}</option>)}
                  </select>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-medium text-gray-600">API URL</label>
                    <button className="btn-ghost text-xs py-0.5 gap-1" onClick={detectIps}>
                      {netLoading ? <RefreshCw size={10} className="animate-spin" /> : <Wifi size={10} />}
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

              {ipHint && (
                <div className="mt-3 flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
                  <AlertTriangle size={13} className="flex-shrink-0 mt-0.5 text-amber-500" />
                  <div>
                    <strong>Only Docker-internal IPs detected.</strong>{' '}
                    Set <code className="bg-amber-100 px-1 rounded">FO_PUBLIC_URL</code> in your docker-compose.yml.
                  </div>
                </div>
              )}

              {netIps.length > 0 && (
                <div className="mt-3">
                  <p className="text-[11px] text-gray-400 mb-2 flex items-center gap-1">
                    <Wifi size={10} /> Detected addresses — click to use
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {netIps.map(c => {
                      const isInternal = c.ip.startsWith('172.') || c.label === 'docker bridge'
                      return (
                        <button
                          key={c.url}
                          onClick={() => setApiUrl(c.url)}
                          title={`Interface: ${c.iface}`}
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-mono transition-all ${
                            apiUrl === c.url
                              ? 'border-brand-accent bg-brand-accentlight text-brand-accent'
                              : isInternal
                              ? 'border-gray-200 bg-gray-50 text-gray-400 hover:border-amber-300'
                              : 'border-gray-200 bg-white text-gray-600 hover:border-brand-accent/50'
                          }`}
                        >
                          {c.k8s ? <Globe size={10} /> : isInternal ? <AlertTriangle size={10} className="text-amber-400" /> : <Wifi size={10} />}
                          <span>{c.ip}</span>
                          {c.label && <span className="text-gray-400 font-sans text-[10px]">({c.label})</span>}
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}

              {inK8s && (
                <div className="mt-4 pt-4 border-t border-gray-100">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-1.5">
                      <Globe size={12} className="text-brand-accent" />
                      <span className="text-xs font-medium text-gray-600">Kubernetes LoadBalancer</span>
                      {ingress?.status === 'ready'   && <span className="badge bg-green-100 text-green-700 border border-green-200 text-[10px]">ready</span>}
                      {ingress?.status === 'pending' && <span className="badge bg-amber-100 text-amber-700 border border-amber-200 text-[10px]">pending IP…</span>}
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
                        <button className="btn-primary text-xs py-0.5 gap-1" onClick={createIngress} disabled={ingressBusy || !caseId}>
                          {ingressBusy ? <Loader2 size={10} className="animate-spin" /> : <Globe size={10} />} Create LoadBalancer
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
                  {ingress?.status === 'error' && <RbacErrorBanner error={ingress.error} />}
                </div>
              )}
            </div>

            {/* Download */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Download</h3>
              <button
                className={`btn-primary w-full justify-center h-10 gap-2 ${downloaded ? '!bg-green-600' : ''}`}
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
                  {platformDef?.id === 'win'
                    ? 'python fo-collector.py     # as Administrator'
                    : 'python3 fo-collector.py   # as root'
                  }
                  {caseId && apiUrl && (<>{'\n\n'}<span className="text-gray-500"># Artifacts auto-upload to case </span><span className="text-brand-accent">{caseId}</span></>)}
                  {!caseId && (<>{'\n\n'}<span className="text-amber-400">⚠ No case linked — ZIP saved locally.</span></>)}
                </div>
              )}

              <p className="text-[11px] text-gray-400 mt-3 leading-relaxed">
                Requires <strong className="text-gray-500">Python 3.8+</strong> on the target.
                Build zero-dependency binary:{' '}
                <code className="text-[10px] bg-gray-100 px-1 py-0.5 rounded">build.bat</code> (Windows) or{' '}
                <code className="text-[10px] bg-gray-100 px-1 py-0.5 rounded">./build.sh</code> (Linux).
              </p>
            </div>
          </div>
        )}

        {/* ── Navigation ────────────────────────────────────────────── */}
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
              disabled={step === 1 && platIdx === null}
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

// ── RbacErrorBanner ───────────────────────────────────────────────────────────
function RbacErrorBanner({ error }) {
  const [yaml, setYaml]     = useState(null)
  const [copied, setCopied] = useState(false)
  const is403 = error?.includes('403') || error?.toLowerCase().includes('forbidden')

  useEffect(() => {
    if (!is403) return
    api.collector.getRbacYaml().then(text => setYaml(text)).catch(() => {})
  }, [is403])

  function copyYaml() {
    if (!yaml) return
    navigator.clipboard.writeText(yaml).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })
  }

  return (
    <div className="mt-2 space-y-1.5">
      <p className="text-[11px] text-red-500">{error}</p>
      {is403 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-[11px] text-amber-800 space-y-2">
          <p className="font-semibold flex items-center gap-1.5"><Info size={11} /> RBAC setup required</p>
          <p>Download and apply from a machine with kubectl access:</p>
          <div className="flex items-center gap-2">
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
          {yaml && <pre className="bg-gray-900 text-green-300 rounded p-2 text-[10px] font-mono overflow-x-auto max-h-40">{`kubectl apply -f fo-rbac.yaml`}</pre>}
        </div>
      )}
    </div>
  )
}
