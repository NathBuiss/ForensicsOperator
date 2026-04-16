/**
 * Collector page — artifact collection script wizard.
 *
 * Generates a pre-configured Python script for live systems,
 * mounted directories (--path), or external drives (--disk).
 * Server-side harvest is available inside the ingestion panel of each case.
 */
import { useState, useEffect } from 'react'
import {
  Monitor, Terminal, FileCode, Download, Check,
  ChevronRight, ChevronLeft,
  PackageOpen, AlertTriangle,
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
  { key: 'network_cfg',       label: 'Network Config',                  desc: 'Hosts file, WLAN profiles (.xml), Windows Firewall logs (pfirewall.log)' },
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
  { key: 'email_outlook',     label: 'Outlook Email',                   desc: '.pst / .ost mailbox databases from Documents/Outlook Files and AppData', warn: true },
  { key: 'email_thunderbird', label: 'Thunderbird Email',               desc: 'Thunderbird profile SQLite databases and .msf index files' },
  // ── Messaging ────────────────────────────────────────────────────────────────
  { key: 'teams',             label: 'Microsoft Teams',                 desc: 'Teams logs.txt, IndexedDB, Local Storage — chat history traces' },
  { key: 'slack',             label: 'Slack',                           desc: 'Slack AppData/Roaming/Slack/logs — workspace activity logs' },
  { key: 'discord',           label: 'Discord',                         desc: 'Discord Local Storage — message and user data artifacts' },
  { key: 'signal',            label: 'Signal Desktop',                  desc: 'Signal databases/db.sqlite — encrypted message store' },
  { key: 'whatsapp',          label: 'WhatsApp Desktop',                desc: 'WhatsApp Desktop UWP package databases' },
  { key: 'telegram',          label: 'Telegram Desktop',                desc: 'Telegram tdata folder — session and message cache' },
  // ── Cloud ─────────────────────────────────────────────────────────────────────
  { key: 'cloud_onedrive',    label: 'OneDrive',                        desc: 'OneDrive sync databases and activity logs' },
  { key: 'cloud_google_drive',label: 'Google Drive',                    desc: 'Google DriveFS sync databases' },
  { key: 'cloud_dropbox',     label: 'Dropbox',                         desc: 'Dropbox sync metadata and activity JSON' },
  // ── Remote access ────────────────────────────────────────────────────────────
  { key: 'remote_access',     label: 'Remote Access Tools',             desc: 'AnyDesk traces/config, TeamViewer logs — lateral movement indicators' },
  { key: 'rdp',               label: 'RDP / Terminal Services',         desc: 'Terminal Server Client cache — bitmap tiles from past RDP sessions' },
  { key: 'ssh_ftp',           label: 'SSH / FTP Clients',               desc: 'known_hosts, PuTTY sessions, WinSCP.ini — remote connection history' },
  // ── Applications & user data ─────────────────────────────────────────────────
  { key: 'lnk',               label: 'LNK / Recent Items',              desc: 'Shell link files from all user Recent folders' },
  { key: 'tasks',             label: 'Scheduled Tasks (legacy key)',     desc: 'Alias for persistence — kept for backwards compatibility' },
  { key: 'office',            label: 'Office MRU',                      desc: 'Office Recent Documents list and trusted document registry' },
  { key: 'dev_tools',         label: 'Dev Tools',                       desc: '.gitconfig, .git-credentials, PowerShell history, .aws/credentials, .azure tokens' },
  { key: 'password_managers', label: 'Password Managers',               desc: 'KeePass .kdbx databases found in user directories' },
  { key: 'database_clients',  label: 'Database Clients',                desc: 'SSMS connection configs, DBeaver workspace files' },
  { key: 'gaming',            label: 'Gaming Platforms',                desc: 'Steam .vdf files, Epic Games Launcher logs' },
  { key: 'windows_apps',      label: 'Windows Apps (UWP)',              desc: 'Sticky Notes, Cortana — UWP package SQLite stores' },
  { key: 'wsl',               label: 'WSL',                             desc: 'Ubuntu/Debian WSL rootfs /etc — passwd, shadow, bashrc' },
  // ── Infrastructure ───────────────────────────────────────────────────────────
  { key: 'vpn',               label: 'VPN Config',                      desc: 'OpenVPN .ovpn profiles, WireGuard .conf files from ProgramData' },
  { key: 'iis_web',           label: 'IIS Web Server',                  desc: 'inetpub/logs .log files, applicationHost.config — web server forensics' },
  { key: 'active_directory',  label: 'Active Directory',                desc: 'Windows/NTDS/ntds.dit + edb.log — full AD database', warn: true },
  { key: 'virtualization',    label: 'Virtualization',                  desc: 'Hyper-V .vhd / .vhdx inventory from ProgramData' },
  { key: 'recovery',          label: 'Recovery / VSS',                  desc: 'System Volume Information — VSS snapshot metadata' },
  { key: 'printing',          label: 'Print Spool',                     desc: 'Windows/System32/spool/PRINTERS — spooled print jobs' },
  // ── Live-only ────────────────────────────────────────────────────────────────
  { key: 'triage',            label: 'Live System Triage',              desc: 'systeminfo, netstat, tasklist, services, installed software — live OS only' },
  // ── Heavy / opt-in ───────────────────────────────────────────────────────────
  { key: 'pe',                label: 'PE / Executable Binaries',        desc: 'EXE/DLL/PS1 from Temp, Downloads, AppData — feeds PE Analysis, YARA, strings', warn: true },
  { key: 'documents',         label: 'Office Documents & PDFs',         desc: 'DOCX, XLSX, PPTX, PDF from Documents/Downloads/Desktop — feeds OLE analysis', warn: true },
  { key: 'memory',            label: 'Live Memory Dump',                desc: 'Physical memory via WinPmem — 4–64 GB, requires winpmem_mini_x64_rc2.exe beside the script', warn: true },
  { key: 'memory_artifacts',  label: 'Memory Artifacts (dead-box)',     desc: 'pagefile.sys, hiberfil.sys, swapfile.sys — from mounted/external volume', warn: true },
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
  const [step, setStep]           = useState(1)
  const [platIdx, setPlatIdx]     = useState(null)
  const [selected, setSelected]   = useState(new Set())
  const [caseName, setCaseName]   = useState('')
  const [downloading, setDownloading] = useState(false)
  const [downloaded, setDownloaded]   = useState(false)

  const platformDef = platIdx !== null ? PLATFORMS[platIdx] : null
  const artifacts   = platformDef?.artifacts || []

  // Pre-select artifacts when platform chosen
  useEffect(() => {
    if (!platformDef) return
    const defaults = platformDef.defaultCollect
      ? new Set(platformDef.defaultCollect)
      : new Set(platformDef.artifacts.map(a => a.key))
    setSelected(defaults)
    setStep(1)
  }, [platIdx])

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

  function handleDownload() {
    setDownloading(true)
    setDownloaded(false)
    const url = api.collector.packageUrl({
      categories: [...selected],
      caseName:   caseName.trim() || undefined,
    })
    const a = document.createElement('a')
    a.href = url
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setTimeout(() => { setDownloading(false); setDownloaded(true) }, 1200)
  }

  const stepLabels = ['Platform', 'Artifacts', 'Download']

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
              Generate a pre-configured collection script for live systems, mounted directories, or external drives
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
              <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm mb-4">
                <SummaryRow label="Platform"  value={platformDef?.label} />
                <SummaryRow label="Artifacts" value={`${selected.size} types`} />
                {caseName.trim() && <SummaryRow label="Case name" value={caseName.trim()} mono />}
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-500 mb-1">
                  Case name <span className="text-gray-400 font-normal">(optional — used in output ZIP filename)</span>
                </label>
                <input
                  type="text"
                  value={caseName}
                  onChange={e => setCaseName(e.target.value)}
                  placeholder="e.g. ACME-2024-IR01"
                  className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2
                             focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent
                             placeholder:text-gray-300"
                />
              </div>
            </div>

            {/* Download package */}
            <div className="card p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Download Package
              </h3>
              <p className="text-xs text-gray-500 mb-4 leading-relaxed">
                Downloads <code className="text-[10px] bg-gray-100 px-1 py-0.5 rounded">fo-harvester.zip</code> — a self-contained collector
                with your pre-selected artifact categories baked into <code className="text-[10px] bg-gray-100 px-1 py-0.5 rounded">config.json</code>. Requires{' '}
                <strong className="text-gray-500">Python 3.8+</strong> on the target — no extra packages needed.
              </p>

              <button
                className={`btn-primary w-full justify-center h-10 gap-2 ${downloaded ? '!bg-green-600' : ''}`}
                onClick={handleDownload}
                disabled={selected.size === 0 || downloading}
              >
                {downloading
                  ? 'Preparing…'
                  : downloaded
                  ? <><Check size={14} /> fo-harvester.zip downloaded</>
                  : <><Download size={14} /> Download fo-harvester.zip</>
                }
              </button>

              {downloaded && (
                <div className="mt-4 bg-gray-950 rounded-lg p-4 text-[11px] font-mono leading-relaxed space-y-2">
                  <div className="text-gray-500"># Extract fo-harvester.zip then run on the target machine</div>
                  {platformDef?.id === 'win' ? <>
                    <div>
                      <span className="text-gray-500"># Live OS (run as Administrator):</span>{'\n'}
                      <span className="text-green-400">python fo-harvester.py</span>
                    </div>
                    <div>
                      <span className="text-gray-500"># Dead-box — mounted directory:</span>{'\n'}
                      <span className="text-green-400">{'python fo-harvester.py --path D:\\'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500"># BitLocker — key stays local, never in config.json:</span>{'\n'}
                      <span className="text-green-400">{'python fo-harvester.py --path E:\\ ^'}</span>{'\n'}
                      <span className="text-green-400">{'  --bitlocker-key 123456-123456-...'}</span>
                    </div>
                  </> : <>
                    <div>
                      <span className="text-gray-500"># Live OS (run as root):</span>{'\n'}
                      <span className="text-green-400">python3 fo-harvester.py</span>
                    </div>
                    <div>
                      <span className="text-gray-500"># Dead-box — mounted directory:</span>{'\n'}
                      <span className="text-green-400">python3 fo-harvester.py --path /mnt/windows</span>
                    </div>
                    <div>
                      <span className="text-gray-500"># Dead-box — raw device + BitLocker:</span>{'\n'}
                      <span className="text-green-400">python3 fo-harvester.py --disk /dev/sdb1 \</span>{'\n'}
                      <span className="text-green-400">{'  --bitlocker-key 123456-123456-...'}</span>
                    </div>
                  </>}
                  <div className="text-gray-500 pt-1"># Output ZIP is created in ./output/ — upload via Case → Ingest</div>
                </div>
              )}
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

