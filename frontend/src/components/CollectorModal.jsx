import { useState, useEffect } from 'react'
import { X, Monitor, Terminal, FileCode, Download, ChevronRight, ChevronLeft, Check } from 'lucide-react'
import { api } from '../api/client'

// ── Artifact definitions ─────────────────────────────────────────────────────

const WINDOWS_ARTIFACTS = [
  { key: 'evtx',     label: 'Event Logs (EVTX)',      desc: 'Security, System, Application, PowerShell, Sysmon and more' },
  { key: 'registry', label: 'Registry Hives',          desc: 'SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat' },
  { key: 'prefetch', label: 'Prefetch Files',           desc: 'Program execution evidence (up to 500 .pf files)' },
  { key: 'lnk',      label: 'LNK / Recent Items',       desc: 'Shell link files from all user Recent folders' },
  { key: 'browser',  label: 'Browser Artifacts',        desc: 'Chrome, Edge, Firefox — history, cookies, login data' },
  { key: 'tasks',    label: 'Scheduled Tasks',          desc: 'Windows Task Scheduler XML files from System32\\Tasks' },
  { key: 'triage',   label: 'Live System Triage',       desc: 'systeminfo, netstat, tasklist, services, installed software' },
]

const LINUX_ARTIFACTS = [
  { key: 'logs',     label: 'System Logs',             desc: '/var/log — auth.log, syslog, audit, journalctl export' },
  { key: 'history',  label: 'Shell Histories',         desc: '.bash_history, .zsh_history for root and all users' },
  { key: 'config',   label: 'System Configuration',    desc: '/etc/passwd, sudoers, hosts, ssh/sshd_config and more' },
  { key: 'cron',     label: 'Cron Jobs',               desc: 'cron.d, cron.daily, crontabs, systemd timers' },
  { key: 'ssh',      label: 'SSH Artifacts',           desc: 'known_hosts, authorized_keys, config (no private keys)' },
  { key: 'triage',   label: 'Live System Triage',      desc: 'ps, ss, ip, last, lsmod, services, installed packages' },
]

// ── Platform cards ────────────────────────────────────────────────────────────

const PLATFORMS = [
  {
    id: 'win',
    label: 'Windows',
    icon: Monitor,
    desc: 'Self-contained Python script — run as Administrator',
    tip: 'Requires Python 3.8+ on target. For a zero-dependency EXE, build with PyInstaller.',
    artifacts: WINDOWS_ARTIFACTS,
  },
  {
    id: 'linux',
    label: 'Linux / macOS',
    icon: Terminal,
    desc: 'Self-contained Python script — run as root',
    tip: 'Requires Python 3.8+ on target. For a zero-dependency ELF, build with PyInstaller.',
    artifacts: LINUX_ARTIFACTS,
  },
  {
    id: 'py',
    label: 'Python Script',
    icon: FileCode,
    desc: 'Platform-agnostic — runs on Windows, Linux & macOS',
    tip: 'Auto-detects the OS at runtime. Identical to the platform-specific scripts.',
    artifacts: [...WINDOWS_ARTIFACTS, ...LINUX_ARTIFACTS],
  },
]

// ── Main component ────────────────────────────────────────────────────────────

export default function CollectorModal({ onClose, caseId, apiUrl: propApiUrl }) {
  const [step, setStep] = useState(1)            // 1=platform, 2=artifacts, 3=config+download
  const [platform, setPlatform] = useState(null)
  const [selected, setSelected] = useState(new Set())
  const [apiUrl, setApiUrl] = useState(propApiUrl || window.location.origin)
  const [downloading, setDownloading] = useState(false)

  // Derive artifact list from selected platform
  const platformDef = PLATFORMS.find(p => p.id === platform)
  const artifacts = platformDef?.artifacts || []

  // Pre-select all artifacts when platform is chosen
  useEffect(() => {
    if (platformDef) {
      setSelected(new Set(platformDef.artifacts.map(a => a.key)))
    }
  }, [platform])

  function toggleArtifact(key) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  function toggleAll() {
    if (selected.size === artifacts.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(artifacts.map(a => a.key)))
    }
  }

  function handleDownload() {
    setDownloading(true)
    const url = api.collector.downloadUrl({
      platform,
      caseId: caseId || undefined,
      apiUrl: (apiUrl && (caseId || propApiUrl)) ? apiUrl : undefined,
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

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box" style={{ maxWidth: 640, width: '95vw' }}>

        {/* Header */}
        <div className="modal-header">
          <div>
            <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>
              Download Artifact Collector
            </h2>
            <p style={{ margin: '2px 0 0', fontSize: 12, color: 'var(--text-muted)' }}>
              {caseId
                ? `Configured for case ${caseId} — auto-uploads on completion`
                : 'Standalone collector — upload manually or configure a case below'}
            </p>
          </div>
          <button className="icon-btn" onClick={onClose}><X size={16} /></button>
        </div>

        {/* Step indicator */}
        <div style={{
          display: 'flex', gap: 8, padding: '12px 20px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
        }}>
          {['Platform', 'Artifacts', 'Download'].map((label, i) => {
            const num = i + 1
            const active = step === num
            const done   = step > num
            return (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {i > 0 && <span style={{ color: 'var(--border)', fontSize: 12 }}>›</span>}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  color: active ? 'var(--accent)' : done ? 'var(--text-muted)' : 'var(--text-muted)',
                  fontWeight: active ? 600 : 400,
                  fontSize: 12,
                  cursor: done ? 'pointer' : 'default',
                }} onClick={() => done && setStep(num)}>
                  <div style={{
                    width: 20, height: 20, borderRadius: '50%',
                    background: active ? 'var(--accent)' : done ? 'var(--success, #22c55e)' : 'var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    color: (active || done) ? '#fff' : 'var(--text-muted)',
                    fontSize: 10, fontWeight: 700, flexShrink: 0,
                  }}>
                    {done ? <Check size={11} /> : num}
                  </div>
                  {label}
                </div>
              </div>
            )
          })}
        </div>

        {/* Step 1 — Platform */}
        {step === 1 && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {PLATFORMS.map(p => {
              const Icon = p.icon
              const isSelected = platform === p.id
              return (
                <div
                  key={p.id}
                  onClick={() => setPlatform(p.id)}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: 14,
                    padding: '14px 16px',
                    border: `2px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                    borderRadius: 8,
                    cursor: 'pointer',
                    background: isSelected ? 'var(--accent-subtle, rgba(99,102,241,.08))' : 'var(--bg-secondary)',
                    transition: 'border-color .15s, background .15s',
                  }}
                >
                  <div style={{
                    width: 38, height: 38, borderRadius: 8,
                    background: isSelected ? 'var(--accent)' : 'var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    color: isSelected ? '#fff' : 'var(--text-muted)',
                    flexShrink: 0,
                  }}>
                    <Icon size={18} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 2 }}>{p.label}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{p.desc}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, opacity: .7 }}>{p.tip}</div>
                  </div>
                  {isSelected && (
                    <Check size={16} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 2 }} />
                  )}
                </div>
              )
            })}
          </div>
        )}

        {/* Step 2 — Artifacts */}
        {step === 2 && platformDef && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {/* Select-all row */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              marginBottom: 4,
            }}>
              <span style={{ fontSize: 13, fontWeight: 600 }}>
                {platformDef.label} artifacts ({selected.size}/{artifacts.length} selected)
              </span>
              <button
                className="btn-ghost"
                style={{ fontSize: 12 }}
                onClick={toggleAll}
              >
                {selected.size === artifacts.length ? 'Deselect all' : 'Select all'}
              </button>
            </div>

            {artifacts.map(a => {
              const checked = selected.has(a.key)
              return (
                <label
                  key={a.key}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: 12,
                    padding: '10px 14px',
                    border: `1px solid ${checked ? 'var(--accent)' : 'var(--border)'}`,
                    borderRadius: 7,
                    cursor: 'pointer',
                    background: checked ? 'var(--accent-subtle, rgba(99,102,241,.06))' : 'var(--bg-secondary)',
                    transition: 'border-color .12s, background .12s',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleArtifact(a.key)}
                    style={{ marginTop: 2, accentColor: 'var(--accent)', cursor: 'pointer' }}
                  />
                  <div>
                    <div style={{ fontWeight: 500, fontSize: 13, marginBottom: 2 }}>{a.label}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{a.desc}</div>
                  </div>
                </label>
              )
            })}
          </div>
        )}

        {/* Step 3 — Config + Download */}
        {step === 3 && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* Summary */}
            <div style={{
              padding: '12px 14px',
              background: 'var(--bg-secondary)',
              borderRadius: 8,
              border: '1px solid var(--border)',
              display: 'flex', flexDirection: 'column', gap: 6,
            }}>
              <Row label="Platform"  value={platformDef?.label} />
              <Row label="Artifacts" value={[...selected].join(', ') || 'none'} />
              {caseId && <Row label="Case ID"   value={caseId} mono />}
            </div>

            {/* API URL (only relevant when a case is configured) */}
            {caseId && (
              <div>
                <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 6 }}>
                  ForensicsOperator API URL
                  <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 6 }}>
                    — embedded in the script for direct upload
                  </span>
                </label>
                <input
                  type="text"
                  className="input"
                  value={apiUrl}
                  onChange={e => setApiUrl(e.target.value)}
                  placeholder="http://fo-api:8000/api/v1"
                  style={{ width: '100%', fontFamily: 'monospace', fontSize: 12 }}
                />
              </div>
            )}

            {/* Download button */}
            <button
              className="btn-primary"
              onClick={handleDownload}
              disabled={selected.size === 0 || downloading}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, height: 40 }}
            >
              {downloading
                ? 'Downloading…'
                : <><Download size={15} /> Download fo-collector.py</>}
            </button>

            {/* Usage hint */}
            <div style={{
              fontSize: 11, color: 'var(--text-muted)',
              background: 'var(--bg-secondary)',
              borderRadius: 7,
              padding: '10px 12px',
              fontFamily: 'monospace',
              lineHeight: 1.6,
            }}>
              {platform === 'win'
                ? <>Run as Administrator:<br /><code>python fo-collector.py</code><br />or build EXE: <code>build.bat</code></>
                : <>Run as root:<br /><code>python3 fo-collector.py</code><br />or build ELF: <code>./build.sh</code></>}
              {caseId && (
                <><br /><br />Artifacts will upload automatically to case <strong>{caseId}</strong>.</>
              )}
            </div>
          </div>
        )}

        {/* Footer nav */}
        <div style={{
          display: 'flex', justifyContent: 'space-between',
          padding: '12px 20px',
          borderTop: '1px solid var(--border)',
        }}>
          <button
            className="btn-ghost"
            onClick={() => step > 1 ? setStep(s => s - 1) : onClose()}
            style={{ display: 'flex', alignItems: 'center', gap: 4 }}
          >
            {step > 1 ? <><ChevronLeft size={14} /> Back</> : 'Cancel'}
          </button>
          {step < 3 && (
            <button
              className="btn-primary"
              onClick={() => setStep(s => s + 1)}
              disabled={step === 1 && !platform}
              style={{ display: 'flex', alignItems: 'center', gap: 4 }}
            >
              Next <ChevronRight size={14} />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// Small helper
function Row({ label, value, mono }) {
  return (
    <div style={{ display: 'flex', gap: 8, fontSize: 12 }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 70 }}>{label}</span>
      <span style={{ fontFamily: mono ? 'monospace' : undefined, wordBreak: 'break-all' }}>{value}</span>
    </div>
  )
}
