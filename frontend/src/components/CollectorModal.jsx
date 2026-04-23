import { useState, useEffect, useRef, useCallback } from 'react'
import {
  X, Monitor, Terminal, FileCode, Download,
  ChevronRight, ChevronLeft, Check, Wifi, RefreshCw,
  Globe, Loader2, Trash2, Info, Copy, ExternalLink,
  AlertTriangle,
} from 'lucide-react'
import { api } from '../api/client'

// ── Artifact definitions (script mode) ───────────────────────────────────────

const WINDOWS_ARTIFACTS = [
  // ── Core ────────────────────────────────────────────────────────────────────
  { key: 'evtx',              label: 'Event Logs (EVTX)',               desc: 'Security, System, Application, PowerShell, Sysmon and more' },
  { key: 'registry',          label: 'Registry Hives',                  desc: 'SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat' },
  { key: 'prefetch',          label: 'Prefetch Files',                  desc: 'Program execution evidence (up to 500 .pf files)' },
  { key: 'mft',               label: 'Master File Table ($MFT)',        desc: 'Raw NTFS MFT — requires Administrator or dead-box access' },
  { key: 'execution',         label: 'Execution Evidence',              desc: 'SRUM database, Amcache.hve, Prefetch — comprehensive execution history' },
  { key: 'persistence',       label: 'Persistence (Tasks + WMI)',       desc: 'Scheduled Tasks XML from System32/SysWOW64, WMI repository (OBJECTS.DATA)' },
  { key: 'filesystem',        label: 'NTFS Metadata',                   desc: '$MFT, $LogFile, $Boot — full NTFS journal and boot sector' },
  // ── Network & USB ────────────────────────────────────────────────────────────
  { key: 'network_cfg',       label: 'Network Config',                  desc: 'Hosts file, WLAN profiles (.xml), Windows Firewall logs' },
  { key: 'usb_devices',       label: 'USB Device History',              desc: 'setupapi.dev.log / setupapi.setup.log — device plug-in timeline' },
  // ── Credentials & Security ───────────────────────────────────────────────────
  { key: 'credentials',       label: 'Credentials (DPAPI)',             desc: 'SAM, SECURITY hives, Credential Manager stores, DPAPI Protect folders' },
  { key: 'antivirus',         label: 'Windows Defender',                desc: 'Quarantine, support logs — detection history and threat actions' },
  { key: 'wer_crashes',       label: 'WER Crash Dumps',                 desc: 'Windows Error Reporting crash dumps and report archives' },
  { key: 'win_logs',          label: 'Windows Logs',                    desc: 'CBS.log, DISM, WindowsUpdate.log, Panther setup logs' },
  { key: 'boot_uefi',         label: 'Boot Config (BCD / EFI)',         desc: 'BCD store, bootstat.dat — boot persistence indicators' },
  { key: 'encryption',        label: 'Encryption Metadata',             desc: 'BitLocker FVE recovery info, EFS metadata' },
  { key: 'etw_diagnostics',   label: 'ETW Diagnostic Traces',           desc: 'Windows/System32/LogFiles/WMI — .etl trace files' },
  // ── Browsers ─────────────────────────────────────────────────────────────────
  { key: 'browser',           label: 'All Browsers',                    desc: 'Chrome, Edge, Firefox, Brave, Opera, Vivaldi — history, cookies, logins' },
  { key: 'browser_chrome',    label: 'Chrome',                          desc: 'History, Cookies, Login Data, Bookmarks, Web Data for all users' },
  { key: 'browser_edge',      label: 'Microsoft Edge',                  desc: 'History, Cookies, Login Data, Web Data for all users' },
  { key: 'browser_ie',        label: 'Internet Explorer',               desc: 'WebCacheV01.dat / WebCacheV24.dat — legacy IE cache database' },
  // ── Email ────────────────────────────────────────────────────────────────────
  { key: 'email_outlook',     label: 'Outlook Email',                   desc: '.pst / .ost mailbox databases', warn: true },
  { key: 'email_thunderbird', label: 'Thunderbird Email',               desc: 'Thunderbird profile SQLite databases and .msf index files' },
  // ── Messaging ────────────────────────────────────────────────────────────────
  { key: 'teams',             label: 'Microsoft Teams',                 desc: 'Teams logs.txt, IndexedDB, Local Storage — chat history traces' },
  { key: 'slack',             label: 'Slack',                           desc: 'Slack AppData/Roaming/Slack/logs' },
  { key: 'discord',           label: 'Discord',                         desc: 'Discord Local Storage — message and user data artifacts' },
  { key: 'signal',            label: 'Signal Desktop',                  desc: 'Signal databases/db.sqlite — encrypted message store' },
  { key: 'whatsapp',          label: 'WhatsApp Desktop',                desc: 'WhatsApp Desktop UWP package databases' },
  { key: 'telegram',          label: 'Telegram Desktop',                desc: 'Telegram tdata folder — session and message cache' },
  // ── Cloud ─────────────────────────────────────────────────────────────────────
  { key: 'cloud_onedrive',    label: 'OneDrive',                        desc: 'OneDrive sync databases and activity logs' },
  { key: 'cloud_google_drive',label: 'Google Drive',                    desc: 'Google DriveFS sync databases' },
  { key: 'cloud_dropbox',     label: 'Dropbox',                         desc: 'Dropbox sync metadata and activity JSON' },
  // ── Remote access ────────────────────────────────────────────────────────────
  { key: 'remote_access',     label: 'Remote Access Tools',             desc: 'AnyDesk traces/config, TeamViewer logs' },
  { key: 'rdp',               label: 'RDP / Terminal Services',         desc: 'Terminal Server Client cache — bitmap tiles from past RDP sessions' },
  { key: 'ssh_ftp',           label: 'SSH / FTP Clients',               desc: 'known_hosts, PuTTY sessions, WinSCP.ini' },
  // ── Applications & user data ─────────────────────────────────────────────────
  { key: 'lnk',               label: 'LNK / Recent Items',              desc: 'Shell link files from all user Recent folders' },
  { key: 'office',            label: 'Office MRU',                      desc: 'Office Recent Documents list and trusted document registry' },
  { key: 'dev_tools',         label: 'Dev Tools',                       desc: '.gitconfig, PowerShell history, .aws/credentials, .azure tokens' },
  { key: 'password_managers', label: 'Password Managers',               desc: 'KeePass .kdbx databases found in user directories' },
  { key: 'database_clients',  label: 'Database Clients',                desc: 'SSMS connection configs, DBeaver workspace files' },
  { key: 'gaming',            label: 'Gaming Platforms',                desc: 'Steam .vdf files, Epic Games Launcher logs' },
  { key: 'windows_apps',      label: 'Windows Apps (UWP)',              desc: 'Sticky Notes, Cortana — UWP package SQLite stores' },
  { key: 'wsl',               label: 'WSL',                             desc: 'Ubuntu/Debian WSL rootfs /etc — passwd, shadow, bashrc' },
  // ── Infrastructure ───────────────────────────────────────────────────────────
  { key: 'vpn',               label: 'VPN Config',                      desc: 'OpenVPN .ovpn profiles, WireGuard .conf files' },
  { key: 'iis_web',           label: 'IIS Web Server',                  desc: 'inetpub/logs .log files, applicationHost.config' },
  { key: 'active_directory',  label: 'Active Directory',                desc: 'Windows/NTDS/ntds.dit + edb.log — full AD database', warn: true },
  { key: 'virtualization',    label: 'Virtualization',                  desc: 'Hyper-V .vhd / .vhdx inventory from ProgramData' },
  { key: 'recovery',          label: 'Recovery / VSS',                  desc: 'System Volume Information — VSS snapshot metadata' },
  { key: 'printing',          label: 'Print Spool',                     desc: 'Windows/System32/spool/PRINTERS — spooled print jobs' },
  // ── Live-only ────────────────────────────────────────────────────────────────
  { key: 'triage',            label: 'Live System Triage',              desc: 'systeminfo, netstat, tasklist, services, installed software — live OS only' },
  // ── Heavy / opt-in ───────────────────────────────────────────────────────────
  { key: 'pe',                label: 'PE / Executable Binaries',        desc: 'EXE/DLL/PS1 from Temp, Downloads, AppData — feeds PE Analysis, YARA', warn: true },
  { key: 'documents',         label: 'Office Documents & PDFs',         desc: 'DOCX, XLSX, PPTX, PDF from Documents/Downloads/Desktop', warn: true },
  { key: 'memory',            label: 'Live Memory Dump',                desc: 'Physical memory via WinPmem — requires winpmem_mini_x64_rc2.exe beside the script', warn: true },
  { key: 'memory_artifacts',  label: 'Memory Artifacts (dead-box)',     desc: 'pagefile.sys, hiberfil.sys, swapfile.sys — from mounted/external volume', warn: true },
]

const LINUX_ARTIFACTS = [
  { key: 'logs',      label: 'System Logs',          desc: '/var/log — auth.log, syslog, kern.log, audit, journalctl export' },
  { key: 'history',   label: 'Shell Histories',      desc: '.bash_history, .zsh_history for root and all users' },
  { key: 'config',    label: 'System Configuration', desc: '/etc/passwd, shadow, sudoers, hosts, ssh/sshd_config' },
  { key: 'cron',      label: 'Cron Jobs',            desc: 'cron.d, cron.daily, crontabs, systemd timers' },
  { key: 'ssh',       label: 'SSH Artifacts',        desc: 'known_hosts, authorized_keys, config (no private keys)' },
  { key: 'services',  label: 'System Services',      desc: 'Systemd units (/lib/systemd/system/, /etc/systemd/system/) and init.d scripts' },
  { key: 'network',   label: 'Network Captures',     desc: 'PCAP/PCAPNG from /var/log, /tmp — live tcpdump if none found' },
  { key: 'suricata',  label: 'Suricata IDS Logs',    desc: 'EVE JSON alerts from /var/log/suricata' },
  { key: 'edr',       label: 'EDR / AV Logs',        desc: 'auditd, Falco, osquery, CrowdStrike Falcon, SentinelOne, Wazuh alerts' },
  { key: 'triage',    label: 'Live System Triage',   desc: 'ps, ss, ip, last, lsmod, installed packages' },
  { key: 'pe',        label: 'ELF / Binaries',       desc: 'Suspicious binaries from /tmp, /var/tmp, ~/Downloads — feeds PE Analysis, YARA', warn: true },
  { key: 'documents', label: 'Office Documents & PDFs', desc: 'DOCX, XLSX, PPTX, PDF from home directories — feeds OLE analysis', warn: true },
  { key: 'memory',    label: 'Memory Dump',          desc: 'Physical memory via avml or /dev/fmem — 4–64 GB, requires root + avml in PATH', warn: true },
]

const MACOS_ARTIFACTS = [
  { key: 'logs',      label: 'System Logs',          desc: '/var/log, ASL, Unified Logging (log show export), system.log' },
  { key: 'history',   label: 'Shell Histories',      desc: '.bash_history, .zsh_history, fish_history for root and all users' },
  { key: 'config',    label: 'System Configuration', desc: '/etc/hosts, sudoers, ssh/sshd_config, /etc/passwd' },
  { key: 'cron',      label: 'Cron / launchd',       desc: 'User crontabs, /etc/cron.d, systemd timers — and launchd timer plists' },
  { key: 'ssh',       label: 'SSH Artifacts',        desc: 'known_hosts, authorized_keys, config (no private keys)' },
  { key: 'plist',     label: 'Preference Plists',    desc: '/Library/Preferences, ~/Library/Preferences — app prefs and hidden settings' },
  { key: 'services',  label: 'LaunchAgents/Daemons', desc: '/Library/LaunchAgents, /Library/LaunchDaemons, ~/Library/LaunchAgents — persistence' },
  { key: 'network',   label: 'Network Captures',     desc: 'PCAP/PCAPNG from /var/log, /tmp — live tcpdump if none found' },
  { key: 'browser',   label: 'Browsers',             desc: 'Safari History.db, Cookies, Bookmarks.plist; Chrome/Firefox if installed' },
  { key: 'edr',       label: 'EDR / AV Logs',        desc: 'CrowdStrike Falcon for Mac, Carbon Black, Jamf, Kandji, osquery' },
  { key: 'triage',    label: 'Live System Triage',   desc: 'ps, netstat, launchctl list, system_profiler, sw_vers' },
  { key: 'pe',        label: 'Mach-O Binaries',      desc: 'Suspicious binaries from /tmp, ~/Downloads — feeds YARA, strings', warn: true },
  { key: 'documents', label: 'Office Documents & PDFs', desc: 'DOCX, XLSX, PPTX, PDF from home directories — feeds OLE analysis', warn: true },
  { key: 'memory',    label: 'Memory Dump',          desc: 'Physical memory via osxpmem — requires root + osxpmem in PATH', warn: true },
]

// ── Platform definitions ──────────────────────────────────────────────────────

const PLATFORMS = [
  {
    id: 'win',
    label: 'Windows',
    Icon: Monitor,
    desc: 'Live system, mounted dir (--path), or external disk (--disk)',
    tip: 'Requires Python 3.8+ on target. Build a zero-dependency EXE with: build.bat',
    artifacts: WINDOWS_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Linux',
    Icon: Terminal,
    desc: 'Self-contained Python script — run as root',
    tip: 'Requires Python 3.8+ on target. Build a zero-dependency ELF with: ./build.sh',
    artifacts: LINUX_ARTIFACTS,
  },
  {
    id: 'macos',
    label: 'macOS',
    Icon: Terminal,
    desc: 'Self-contained Python script — run as root or with sudo',
    tip: 'Requires Python 3.8+ on target. SIP must allow /var/log access for full coverage.',
    artifacts: MACOS_ARTIFACTS,
  },
  {
    id: 'py',
    label: 'Python Script (auto-detect)',
    Icon: FileCode,
    desc: 'Platform-agnostic — auto-detects OS at runtime',
    tip: 'Works on Windows, Linux & macOS. Use this when the target already has Python 3.8+.',
    artifacts: [...WINDOWS_ARTIFACTS, ...LINUX_ARTIFACTS, ...MACOS_ARTIFACTS].filter(
      (a, i, arr) => arr.findIndex(b => b.key === a.key) === i
    ),
  },
]

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

  const platformDef = PLATFORMS.find(p => p.id === platform)
  const artifacts   = platformDef?.artifacts || []

  // Pre-select non-warn artifacts when platform chosen; warn=true items (binaries, docs, memory) default OFF
  useEffect(() => {
    if (!platformDef) return
    setSelected(new Set(platformDef.artifacts.filter(a => !a.warn).map(a => a.key)))
  }, [platform])

  // Fetch detected IPs + K8s status when script mode reaches step 3
  useEffect(() => {
    if (step !== 3) return
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

  // ── Step labels ───────────────────────────────────────────────────────────

  const stepLabels = ['Platform', 'Artifacts', 'Download']

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box" style={{ maxWidth: 580 }}>

        {/* Header */}
        <div className="modal-header">
          <div>
            <h2 className="text-sm font-semibold text-brand-text">
              Download Artifact Collector
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">
              {caseId
                ? `Case ${caseId} — artifacts auto-upload on completion`
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
              {PLATFORMS.map(({ id, label, Icon, desc, tip }) => {
                const active = platform === id
                return (
                  <button
                    key={id}
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
                      <div className="text-sm font-semibold text-brand-text mb-0.5">{label}</div>
                      <div className="text-xs text-gray-500 mb-1">{desc}</div>
                      <div className="text-[11px] text-gray-400">{tip}</div>
                    </div>
                    {active && <Check size={15} className="text-brand-accent flex-shrink-0 mt-1" />}
                  </button>
                )
              })}
            </div>
          )}

          {/* Step 2 — Artifacts */}
          {step === 2 && platformDef && (
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

          {/* Step 3 — Download */}
          {step === 3 && (
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
