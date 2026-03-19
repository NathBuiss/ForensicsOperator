import { useEffect, useState } from 'react'
import {
  Cpu, CheckCircle, XCircle, ChevronDown,
  Copy, Check, Code2, BookOpen, AlertCircle, X,
  PackageOpen, Terminal, Download,
} from 'lucide-react'
import { api } from '../api/client'

// ── Code templates shown in the documentation modal ──────────────────────────

const RUNNER_TEMPLATE = `# processor/tasks/module_task.py
# ─────────────────────────────────────────────────────────
# 1. Add your runner function

def _run_my_module(run_id: str, work_dir: Path, sources_dir: Path) -> list[dict]:
    """
    Execute the module against the downloaded source files.

    Args:
        run_id      — unique run identifier (use for logging)
        work_dir    — temporary working directory (cleaned up automatically)
        sources_dir — directory containing downloaded source files

    Returns:
        list of hit dicts — each hit must contain at least:
          {
            "id":          str(uuid.uuid4()),
            "timestamp":   "",          # ISO-8601 string or ""
            "level":       "informational",  # critical/high/medium/low/informational
            "level_int":   1,           # 5/4/3/2/1  (matches level)
            "rule_title":  "...",       # short label shown in the results panel
            "computer":    "...",       # hostname or source filename
            "details_raw": "...",       # detail text shown below the title
          }
    """
    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue

        logger.info("[%s] Processing %s", run_id, file_path.name)

        # --- your analysis logic here ---
        hits = _analyse_file(file_path)

        for h in hits:
            results.append({
                "id":          str(uuid.uuid4()),
                "timestamp":   h.get("ts", ""),
                "level":       h.get("severity", "informational"),
                "level_int":   LEVEL_INT.get(h.get("severity", "informational"), 1),
                "rule_title":  h.get("name", ""),
                "computer":    file_path.name,
                "details_raw": h.get("detail", ""),
            })

    return results


# 2. Register the runner in the dispatch table (same file, ~line 99)

RUNNERS = {
    "hayabusa":   _run_hayabusa,
    "strings":    _run_strings,
    "hindsight":  _run_hindsight,
    "regripper":  _run_regripper,
    "my_module":  _run_my_module,   # ← add this line
}
`

const REGISTRY_TEMPLATE = `# api/routers/modules.py  — add an entry to MODULES

{
    "id":               "my_module",          # must match the RUNNERS key above
    "name":             "My Module",          # display name
    "description":      "One-line description shown in the launch modal",
    "input_extensions": [".bin", ".exe"],     # file extensions to match
    "input_filenames":  ["config.dat"],       # exact basenames to match (optional)
    # Both lists empty → accept every uploaded file (like "strings")
    "available":        True,
},
`

// ── DocsModal ─────────────────────────────────────────────────────────────────
function DocsModal({ onClose }) {
  const [tab, setTab]     = useState('runner')  // 'runner' | 'registry'
  const [copied, setCopied] = useState(false)

  const content = tab === 'runner' ? RUNNER_TEMPLATE : REGISTRY_TEMPLATE

  function copy() {
    navigator.clipboard.writeText(content)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div
      className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      <div className="bg-white border border-gray-200 rounded-xl w-full max-w-3xl shadow-2xl flex flex-col max-h-[90vh]">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <BookOpen size={16} className="text-brand-accent" />
            <span className="text-sm font-semibold text-brand-text">How to Add a Module</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={copy} className="btn-ghost text-xs">
              {copied
                ? <><Check size={13} className="text-green-600" /> Copied!</>
                : <><Copy size={13} /> Copy</>}
            </button>
            <button onClick={onClose} className="btn-ghost p-1.5">
              <X size={14} />
            </button>
          </div>
        </div>

        {/* Intro */}
        <div className="px-5 pt-4 flex-shrink-0">
          <p className="text-xs text-gray-500 leading-relaxed mb-4">
            Modules are on-demand analysis tools that run against files already uploaded to a case.
            Adding a module requires two code changes and a processor image rebuild:
          </p>
          <ol className="text-xs text-gray-600 space-y-1 list-decimal list-inside mb-4">
            <li>Write a <strong>runner function</strong> in <code className="text-brand-accent bg-brand-accentlight px-1 rounded">processor/tasks/module_task.py</code></li>
            <li>Register it in the <strong>module registry</strong> in <code className="text-brand-accent bg-brand-accentlight px-1 rounded">api/routers/modules.py</code></li>
            <li>Rebuild and redeploy — <code className="text-gray-500">python3 deploy.py</code></li>
          </ol>
        </div>

        {/* Tabs */}
        <div className="px-5 flex gap-1 flex-shrink-0">
          {[
            { id: 'runner',   label: 'Step 1 — Runner function' },
            { id: 'registry', label: 'Step 2 — Registry entry' },
          ].map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-3 py-1.5 text-xs rounded-t-lg border-b-2 transition-colors ${
                tab === t.id
                  ? 'border-brand-accent text-brand-accent font-medium'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Code block */}
        <div className="px-5 pb-5 flex-1 overflow-y-auto">
          <pre className="code-block text-[11px] leading-relaxed overflow-x-auto mt-0 rounded-t-none">
            {content}
          </pre>

          {tab === 'runner' && (
            <div className="mt-3 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
              <strong>Tip:</strong> Install any required binary in the{' '}
              <code className="bg-amber-100 px-1 rounded">processor/Dockerfile</code> and check for it with{' '}
              <code className="bg-amber-100 px-1 rounded">shutil.which()</code> at the start of your runner —
              raise a <code className="bg-amber-100 px-1 rounded">RuntimeError</code> with a clear message if it's missing.
            </div>
          )}
          {tab === 'registry' && (
            <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded-lg text-xs text-blue-800">
              <strong>Tip:</strong> Set <code className="bg-blue-100 px-1 rounded">"available": False</code> with an{' '}
              <code className="bg-blue-100 px-1 rounded">"unavailable_reason"</code> string while the module is under
              development — it will appear greyed-out in the launch modal with the reason as a tooltip.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── CollectorSection ─────────────────────────────────────────────────────────

const COLLECTOR_STEPS = `# 1 — Build the binary on the target platform
#   Linux  (produces dist/fo-collector  — self-contained ELF)
cd collector && ./build.sh

#   Windows  (produces dist\\fo-collector.exe — self-contained EXE)
cd collector && build.bat

# 2 — Deploy & run on the target host
#   Linux / macOS (run as root for full collection)
scp dist/fo-collector root@target:/tmp/
ssh root@target '/tmp/fo-collector --verbose'

#   Windows (run as Administrator)
#   Copy fo-collector.exe to the target and double-click,
#   or from an elevated prompt:
fo-collector.exe --verbose

# 3 — Upload the produced ZIP to ForensicsOperator
fo-collector.exe --api-url http://FO_HOST/api/v1 --case-id CASE_ID
# The ZIP is also saved locally for manual upload via the Ingest panel.`

function CollectorSection() {
  const [open, setOpen]     = useState(false)
  const [copied, setCopied] = useState(false)

  function copy() {
    navigator.clipboard.writeText(COLLECTOR_STEPS)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <section className="mb-8">
      <h2 className="section-title mb-3">Artifact Collector</h2>
      <div className="card overflow-hidden">
        {/* Summary row */}
        <button
          className="w-full flex items-start gap-3 p-4 text-left hover:bg-gray-50 transition-colors"
          onClick={() => setOpen(v => !v)}
        >
          <div className="w-8 h-8 rounded-lg bg-brand-accentlight border border-brand-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
            <PackageOpen size={14} className="text-brand-accent" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-sm font-semibold text-brand-text">fo-collector</span>
              <span className="badge bg-blue-50 text-blue-700 border border-blue-200">Windows</span>
              <span className="badge bg-gray-100 text-gray-600 border border-gray-200">Linux</span>
            </div>
            <p className="text-xs text-gray-500">
              Standalone EXE / ELF binary that collects forensic artifacts from a live system
              and packages them as a ZIP for direct upload to a ForensicsOperator case.
            </p>
          </div>
          <ChevronDown size={14} className={`text-gray-400 flex-shrink-0 mt-1 transition-transform ${open ? 'rotate-180' : ''}`} />
        </button>

        {open && (
          <div className="border-t border-gray-100 bg-gray-50 p-4 space-y-4">

            {/* What it collects */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div>
                <p className="section-title mb-2 flex items-center gap-1.5">
                  <Terminal size={11} /> Windows artifacts
                </p>
                <ul className="space-y-1 text-gray-500">
                  {[
                    'EVTX event logs (Security, System, PowerShell, Sysmon…)',
                    'Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT…)',
                    'Prefetch files (.pf)',
                    'LNK / Recent Items',
                    'Browser history (Chrome, Edge, Firefox)',
                    'Scheduled Tasks XML',
                    'Live triage: processes, services, netstat, users',
                  ].map(item => (
                    <li key={item} className="flex items-start gap-1.5">
                      <CheckCircle size={10} className="text-green-500 flex-shrink-0 mt-0.5" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="section-title mb-2 flex items-center gap-1.5">
                  <Terminal size={11} /> Linux artifacts
                </p>
                <ul className="space-y-1 text-gray-500">
                  {[
                    'System logs (/var/log + systemd journal)',
                    'Shell histories (.bash_history, .zsh_history…)',
                    'Auth / SSH artifacts (authorized_keys, known_hosts)',
                    'Cron jobs (system + user crontabs)',
                    'System config (/etc/passwd, sudoers, sshd_config…)',
                    'Live triage: processes, sockets, mounts, env',
                    'Installed packages (dpkg / rpm)',
                  ].map(item => (
                    <li key={item} className="flex items-start gap-1.5">
                      <CheckCircle size={10} className="text-green-500 flex-shrink-0 mt-0.5" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Build & usage */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <p className="section-title flex items-center gap-1.5">
                  <Download size={11} /> Build &amp; Deploy
                </p>
                <button onClick={copy} className="btn-ghost text-xs">
                  {copied
                    ? <><Check size={12} className="text-green-600" /> Copied</>
                    : <><Copy size={12} /> Copy</>}
                </button>
              </div>
              <pre className="code-block text-[11px] leading-relaxed overflow-x-auto">
                {COLLECTOR_STEPS}
              </pre>
            </div>

            {/* Notes */}
            <div className="flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
              <BookOpen size={13} className="flex-shrink-0 mt-0.5" />
              <div>
                <strong>Requirements:</strong> Python 3.8+ and PyInstaller on the build machine.
                The resulting binary has <strong>no runtime dependencies</strong> — copy a single file to the target.
                Windows collection requires <strong>Administrator</strong> privileges for registry
                hives (reg.exe SAVE) and locked files. Linux collection requires <strong>root</strong>
                for /etc/shadow, audit logs, and other privileged paths.
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}

// ── ModuleCard ────────────────────────────────────────────────────────────────
function ModuleCard({ mod }) {
  const [open, setOpen] = useState(false)

  const acceptsAll = mod.input_extensions.length === 0 && mod.input_filenames.length === 0
  const allTags    = [...(mod.input_extensions || []), ...(mod.input_filenames || [])]

  return (
    <div className="card overflow-hidden">
      <button
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        {/* Icon */}
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
          mod.available
            ? 'bg-brand-accentlight border border-brand-accent/20'
            : 'bg-gray-100 border border-gray-200'
        }`}>
          <Cpu size={14} className={mod.available ? 'text-brand-accent' : 'text-gray-400'} />
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-0.5">
            <span className={`text-sm font-semibold ${mod.available ? 'text-brand-text' : 'text-gray-400'}`}>
              {mod.name}
            </span>
            {mod.available
              ? (
                <span className="badge bg-green-50 text-green-700 border border-green-200">
                  <CheckCircle size={9} className="mr-1" /> available
                </span>
              ) : (
                <span className="badge bg-gray-100 text-gray-400 border border-gray-200">
                  <XCircle size={9} className="mr-1" /> unavailable
                </span>
              )
            }
          </div>
          <p className={`text-xs ${mod.available ? 'text-gray-500' : 'text-gray-400'}`}>
            {mod.description}
          </p>
          {!mod.available && mod.unavailable_reason && (
            <p className="text-[10px] text-gray-400 italic mt-0.5">{mod.unavailable_reason}</p>
          )}
        </div>

        {/* Tags + chevron */}
        <div className="flex items-center gap-2 flex-shrink-0 ml-2">
          {acceptsAll && (
            <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">
              any file
            </span>
          )}
          {!acceptsAll && allTags.slice(0, 2).map(t => (
            <span key={t} className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono hidden sm:inline-flex">
              {t}
            </span>
          ))}
          {!acceptsAll && allTags.length > 2 && (
            <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
              +{allTags.length - 2}
            </span>
          )}
          <ChevronDown size={14} className={`text-gray-400 transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>

      {/* Expanded detail */}
      {open && (
        <div className="border-t border-gray-100 bg-gray-50 px-4 py-3">
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">

            {/* Accepted inputs */}
            <div>
              <p className="section-title mb-1.5">Accepted inputs</p>
              {acceptsAll ? (
                <span className="text-gray-500 italic">All file types</span>
              ) : (
                <div className="flex flex-wrap gap-1">
                  {allTags.map(t => (
                    <span key={t} className="badge bg-white border border-gray-200 text-gray-600 font-mono">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Module ID */}
            <div>
              <p className="section-title mb-1.5">Module ID</p>
              <code className="text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded text-[11px]">
                {mod.id}
              </code>
            </div>

          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Modules() {
  const [modules, setModules]       = useState([])
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState(null)
  const [showDocs, setShowDocs]     = useState(false)

  useEffect(() => {
    api.modules.list()
      .then(r => setModules(r.modules || []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const available   = modules.filter(m => m.available)
  const unavailable = modules.filter(m => !m.available)

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {showDocs && <DocsModal onClose={() => setShowDocs(false)} />}

      {/* Page header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-brand-text flex items-center gap-2">
            <Cpu size={18} className="text-brand-accent" /> Modules
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            On-demand analysis tools — run against ingested source files within a case
          </p>
        </div>
        <button onClick={() => setShowDocs(true)} className="btn-ghost text-xs">
          <Code2 size={13} /> Add a Module
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 flex items-center gap-2 text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          <AlertCircle size={13} /> Failed to load modules: {error}
        </div>
      )}

      {/* Skeleton */}
      {loading && (
        <div className="space-y-3">
          {[1, 2, 3, 4].map(i => <div key={i} className="skeleton h-16 w-full" />)}
        </div>
      )}

      {!loading && !error && (
        <>
          {/* ── Available ──────────────────────────────────────────────────── */}
          <section className="mb-8">
            <div className="flex items-center gap-2 mb-3">
              <h2 className="section-title">Available</h2>
              <span className="badge bg-green-50 text-green-700 border border-green-200">
                {available.length}
              </span>
            </div>
            {available.length === 0 ? (
              <p className="text-xs text-gray-400 italic">No modules available yet.</p>
            ) : (
              <div className="space-y-2">
                {available.map(mod => <ModuleCard key={mod.id} mod={mod} />)}
              </div>
            )}
          </section>

          {/* ── Coming soon ─────────────────────────────────────────────────── */}
          {unavailable.length > 0 && (
            <section className="mb-8">
              <div className="flex items-center gap-2 mb-3">
                <h2 className="section-title">Coming Soon</h2>
                <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
                  {unavailable.length}
                </span>
              </div>
              <div className="space-y-2">
                {unavailable.map(mod => <ModuleCard key={mod.id} mod={mod} />)}
              </div>
            </section>
          )}

          {/* ── Artifact Collector ──────────────────────────────────────────── */}
          <CollectorSection />

          {/* ── How modules work ─────────────────────────────────────────────── */}
          <section>
            <h2 className="section-title mb-3">How Modules Work</h2>
            <div className="card p-5 space-y-4">

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                {/* Step 1 */}
                <div className="flex gap-3">
                  <div className="w-6 h-6 rounded-full bg-brand-accent text-white flex items-center justify-center text-[11px] font-bold flex-shrink-0 mt-0.5">
                    1
                  </div>
                  <div>
                    <p className="font-semibold text-brand-text mb-1">Ingest your files</p>
                    <p className="text-gray-500">
                      Upload evidence files to a case via <strong>Add Evidence</strong>.
                      Each file is stored in MinIO and available as a module source.
                    </p>
                  </div>
                </div>

                {/* Step 2 */}
                <div className="flex gap-3">
                  <div className="w-6 h-6 rounded-full bg-brand-accent text-white flex items-center justify-center text-[11px] font-bold flex-shrink-0 mt-0.5">
                    2
                  </div>
                  <div>
                    <p className="font-semibold text-brand-text mb-1">Launch a module</p>
                    <p className="text-gray-500">
                      Open a case → click <strong>Modules</strong> in the header →
                      select a module → choose the source files → click <strong>Run</strong>.
                    </p>
                  </div>
                </div>

                {/* Step 3 */}
                <div className="flex gap-3">
                  <div className="w-6 h-6 rounded-full bg-brand-accent text-white flex items-center justify-center text-[11px] font-bold flex-shrink-0 mt-0.5">
                    3
                  </div>
                  <div>
                    <p className="font-semibold text-brand-text mb-1">Review results</p>
                    <p className="text-gray-500">
                      Results appear in the <strong>Module Runs</strong> panel, grouped by
                      severity. Full output is also stored in MinIO for long-term retention.
                    </p>
                  </div>
                </div>
              </div>

              <div className="border-t border-gray-100 pt-4 flex items-start gap-3 text-xs">
                <div className="w-5 h-5 rounded-full bg-amber-100 text-amber-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <BookOpen size={11} />
                </div>
                <p className="text-gray-500">
                  Modules are different from <strong>Ingesters</strong>.
                  Ingesters parse raw files into timeline events (run automatically on upload).
                  Modules are launched manually, run external analysis tools against
                  already-ingested source files, and display results in their own panel —
                  they do not affect the main event timeline.
                  <button
                    onClick={() => setShowDocs(true)}
                    className="ml-1.5 text-brand-accent hover:underline font-medium"
                  >
                    Learn how to add a custom module →
                  </button>
                </p>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  )
}
