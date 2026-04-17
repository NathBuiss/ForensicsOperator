/**
 * Docs — platform documentation.
 *
 * Structured reference for:
 *   1. Architecture overview
 *   2. Creating custom ingesters
 *   3. Creating custom modules
 *   4. Writing alert rules
 *   5. API reference
 */
import { useState } from 'react'
import {
  BookOpen, Puzzle, Cpu, Bell, Server, ChevronRight,
  Code2, Copy, Check, AlertCircle, CheckCircle, Zap,
  FileCode2, Database, GitBranch, Terminal,
} from 'lucide-react'

// ── Code block ────────────────────────────────────────────────────────────────

function CodeBlock({ code, language = 'python' }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div className="relative group rounded-xl overflow-hidden border border-gray-800 my-4">
      <div className="flex items-center justify-between bg-gray-900 px-4 py-2 border-b border-gray-800">
        <span className="text-[10px] text-gray-500 font-mono uppercase tracking-wider">{language}</span>
        <button
          onClick={copy}
          className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300 transition-colors"
        >
          {copied ? <><Check size={10} className="text-green-400" /> Copied</> : <><Copy size={10} /> Copy</>}
        </button>
      </div>
      <pre className="bg-gray-950 text-gray-200 font-mono text-[12px] leading-relaxed p-4 overflow-x-auto">
        {code}
      </pre>
    </div>
  )
}

// ── Info box ──────────────────────────────────────────────────────────────────

function InfoBox({ type = 'info', children }) {
  const styles = {
    info:    { cls: 'bg-blue-50 border-blue-200 text-blue-800', icon: <AlertCircle size={14} className="text-blue-500 flex-shrink-0 mt-0.5" /> },
    tip:     { cls: 'bg-green-50 border-green-200 text-green-800', icon: <CheckCircle size={14} className="text-green-500 flex-shrink-0 mt-0.5" /> },
    warning: { cls: 'bg-amber-50 border-amber-200 text-amber-800', icon: <AlertCircle size={14} className="text-amber-500 flex-shrink-0 mt-0.5" /> },
  }
  const s = styles[type] || styles.info
  return (
    <div className={`flex gap-2.5 border rounded-lg px-3.5 py-3 my-3 text-sm leading-relaxed ${s.cls}`}>
      {s.icon}
      <div>{children}</div>
    </div>
  )
}

// ── Section ───────────────────────────────────────────────────────────────────

function Section({ id, title, icon, children }) {
  return (
    <section id={id} className="mb-12 scroll-mt-4">
      <div className="flex items-center gap-2 mb-4 pb-2 border-b border-gray-200">
        <div className="w-7 h-7 rounded-lg bg-brand-accentlight border border-brand-accent/20 flex items-center justify-center flex-shrink-0">
          {icon}
        </div>
        <h2 className="text-base font-bold text-brand-text">{title}</h2>
      </div>
      <div className="prose-sm text-gray-700 space-y-3">
        {children}
      </div>
    </section>
  )
}

function H3({ children }) {
  return <h3 className="text-sm font-semibold text-gray-900 mt-5 mb-2">{children}</h3>
}

function P({ children }) {
  return <p className="text-sm text-gray-600 leading-relaxed">{children}</p>
}

function Li({ children }) {
  return (
    <li className="flex items-start gap-2 text-sm text-gray-600 leading-relaxed">
      <ChevronRight size={13} className="text-brand-accent flex-shrink-0 mt-0.5" />
      <span>{children}</span>
    </li>
  )
}

function Ul({ children }) {
  return <ul className="space-y-1.5 mt-1">{children}</ul>
}

function Field({ name, type, required, children }) {
  return (
    <div className="flex gap-3 py-2 border-b border-gray-100 last:border-0">
      <code className="text-[11px] font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded flex-shrink-0 h-fit">
        {name}
      </code>
      <div className="min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[10px] text-gray-400 font-mono">{type}</span>
          {required && (
            <span className="text-[10px] text-red-500 font-medium">required</span>
          )}
        </div>
        <p className="text-xs text-gray-500 leading-relaxed">{children}</p>
      </div>
    </div>
  )
}

// ── Navigation ────────────────────────────────────────────────────────────────

const SECTIONS = [
  { id: 'architecture', label: 'Architecture',        icon: <Server size={13} /> },
  { id: 'ingesters',    label: 'Custom Ingesters',    icon: <Puzzle size={13} /> },
  { id: 'modules',      label: 'Custom Modules',      icon: <Cpu size={13} /> },
  { id: 'alert-rules',  label: 'Alert Rules',         icon: <Bell size={13} /> },
  { id: 'query-syntax', label: 'Query Syntax',        icon: <Terminal size={13} /> },
  { id: 'search',       label: 'Investigation UI',    icon: <GitBranch size={13} /> },
  { id: 'api',          label: 'API Reference',       icon: <Code2 size={13} /> },
]

// ── Main ──────────────────────────────────────────────────────────────────────

export default function Docs() {
  const [active, setActive] = useState('architecture')

  function scrollTo(id) {
    setActive(id)
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="flex flex-1 overflow-hidden min-h-0">

      {/* Left nav */}
      <nav className="w-48 flex-shrink-0 flex flex-col border-r border-gray-200 bg-white overflow-y-auto">
        <div className="px-4 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <BookOpen size={15} className="text-brand-accent" />
            <span className="text-sm font-semibold text-brand-text">Documentation</span>
          </div>
        </div>
        <div className="flex-1 py-2">
          {SECTIONS.map(s => (
            <button
              key={s.id}
              onClick={() => scrollTo(s.id)}
              className={`w-full flex items-center gap-2 px-4 py-2 text-left text-xs transition-colors ${
                active === s.id
                  ? 'text-brand-accent bg-brand-accentlight font-medium'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              <span className="opacity-70">{s.icon}</span>
              {s.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto px-8 py-8">

          {/* ── Architecture ──────────────────────────────────────────────── */}
          <Section id="architecture" title="Architecture Overview" icon={<Server size={14} className="text-brand-accent" />}>
            <P>
              TraceX is a containerised digital forensics platform. Evidence files are
              uploaded to MinIO, parsed by the Processor service, stored in Elasticsearch, and
              surfaced through the React frontend.
            </P>

            <H3>Services</H3>
            <div className="space-y-2">
              {[
                { name: 'api', port: '8000', desc: 'FastAPI — REST API, case management, rule library, editor' },
                { name: 'processor', port: 'worker', desc: 'Celery — ingest tasks, module runs, analysis jobs' },
                { name: 'elasticsearch', port: '9200', desc: 'Event storage and full-text search' },
                { name: 'redis', port: '6379', desc: 'Celery broker, job state, alert/module run metadata' },
                { name: 'minio', port: '9000/9001', desc: 'Object storage for uploaded evidence files' },
                { name: 'frontend', port: '3000', desc: 'React + Vite — web UI' },
              ].map(s => (
                <div key={s.name} className="flex gap-3 items-start py-1.5 border-b border-gray-100 last:border-0">
                  <code className="text-[11px] font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded flex-shrink-0">
                    {s.name}
                  </code>
                  <span className="text-[10px] text-gray-400 font-mono flex-shrink-0 mt-0.5">:{s.port}</span>
                  <p className="text-xs text-gray-500">{s.desc}</p>
                </div>
              ))}
            </div>

            <H3>Data flow — ingest</H3>
            <CodeBlock language="text" code={`Upload file  →  POST /cases/{id}/ingest
                 →  MinIO  (raw file storage)
                 →  Celery ingest task
                 →  PluginLoader.get_plugin(filename, mime)
                 →  plugin.parse(file_path, context)  ← yields ParsedEvent objects
                 →  Elasticsearch  fo-case-{id}-{artifact_type} index`} />

            <H3>Data flow — module run</H3>
            <CodeBlock language="text" code={`Select module + source files  →  POST /cases/{id}/module-runs
                                    →  Redis run record  (PENDING)
                                    →  Celery module.run task
                                    →  download source files from MinIO → /tmp
                                    →  run built-in OR custom module
                                    →  upload results.json to MinIO
                                    →  update Redis run record  (COMPLETED + hits)`} />

            <H3>Custom extension points</H3>
            <Ul>
              <Li><strong>Custom Ingesters</strong> — files in <code className="text-brand-accent">ingester/*_ingester.py</code>, auto-loaded by PluginLoader alongside built-ins.</Li>
              <Li><strong>Custom Modules</strong> — files in <code className="text-brand-accent">modules/*_module.py</code>, dynamically loaded by the Celery worker at run time.</Li>
            </Ul>
            <InfoBox type="tip">
              Both directories are Docker volume-mounted and writable. Files you save via the <strong>Studio</strong> page are immediately available — no restart required.
            </InfoBox>
          </Section>

          {/* ── Ingesters ─────────────────────────────────────────────────── */}
          <Section id="ingesters" title="Creating a Custom Ingester" icon={<Puzzle size={14} className="text-brand-accent" />}>
            <P>
              An ingester is a Python class that parses an uploaded file into timeline events.
              Create one via <strong>Studio → Ingesters → New Ingester</strong>, or drop a
              file into <code className="text-gray-600">ingester/</code> at the repository root.
            </P>

            <InfoBox type="info">
              File name must end with <code>_ingester.py</code> and be placed in the
              <code> ingester/</code> directory.  The class must inherit from <code>BasePlugin</code>.
            </InfoBox>

            <H3>Minimal example</H3>
            <CodeBlock code={`from base_plugin import BasePlugin, PluginContext, ParsedEvent

class ApacheAccessIngester(BasePlugin):
    PLUGIN_NAME          = "apache-access"
    SUPPORTED_EXTENSIONS = [".log"]
    HANDLED_FILENAMES    = ["access.log", "access_log"]

    def parse(self, file_path: str, context: PluginContext):
        import re
        COMBINED = re.compile(
            r'(?P<host>\\S+) \\S+ \\S+ \\[(?P<time>[^\\]]+)\\] '
            r'"(?P<request>[^"]*)" (?P<status>\\d+) \\S+'
        )
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = COMBINED.match(line.strip())
                if not m:
                    continue
                yield ParsedEvent(
                    timestamp = self._parse_apache_time(m["time"]),
                    message   = m["request"],
                    artifact_type = self.PLUGIN_NAME,
                    host      = {"hostname": m["host"]},
                    extra     = {"status": int(m["status"])},
                )

    def _parse_apache_time(self, s: str) -> str:
        from datetime import datetime
        dt = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()`} />

            <H3>BasePlugin reference</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                <span className="text-xs font-semibold text-gray-600">Class attributes</span>
              </div>
              <div className="px-4">
                <Field name="PLUGIN_NAME" type="str" required>
                  Unique identifier. Used as <code>artifact_type</code> on every event and as the
                  Elasticsearch index name suffix: <code>fo-case-[case_id]-PLUGIN_NAME</code>.
                </Field>
                <Field name="SUPPORTED_EXTENSIONS" type="list[str]" required>
                  Lower-case extensions with leading dot, e.g. <code>[".log", ".txt"]</code>.
                  Leave empty to match by filename only.
                </Field>
                <Field name="HANDLED_FILENAMES" type="list[str]" required>
                  Exact filenames (case-insensitive) to match, e.g. <code>["$MFT", "NTUSER.DAT"]</code>.
                  Used for system files that have no extension.
                </Field>
              </div>
            </div>

            <H3>ParsedEvent fields</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="timestamp" type="str" required>ISO-8601 datetime string, e.g. <code>2024-01-15T09:30:00Z</code>.</Field>
                <Field name="message" type="str" required>Human-readable description of the event.</Field>
                <Field name="artifact_type" type="str">Defaults to <code>PLUGIN_NAME</code>. Override to sub-categorise events.</Field>
                <Field name="host" type="dict">Host fields — <code>{"{"}"hostname": "...", "ip": "..."{"}"}. </code>Indexed under <code>host.*</code>.</Field>
                <Field name="user" type="dict">User fields — <code>{"{"}"name": "...", "domain": "..."{"}"}. </code>Indexed under <code>user.*</code>.</Field>
                <Field name="process" type="dict">Process fields — <code>{"{"}"name": "...", "pid": 123, "cmdline": "..."{"}"}.</code></Field>
                <Field name="network" type="dict">Network fields — <code>{"{"}"src_ip": "...", "dest_ip": "...", "dest_port": 443{"}"}.</code></Field>
                <Field name="extra" type="dict">Any additional fields. Stored under their own keys in Elasticsearch.</Field>
              </div>
            </div>

            <H3>After saving</H3>
            <P>
              Go to <strong>Ingesters → Reload All</strong> (or restart the processor container)
              to activate your new ingester. You can then upload a matching file in any case and
              it will be parsed automatically.
            </P>
          </Section>

          {/* ── Modules ───────────────────────────────────────────────────── */}
          <Section id="modules" title="Creating a Custom Module" icon={<Cpu size={14} className="text-brand-accent" />}>
            <P>
              A module is a Python file exposing a <code>run()</code> function that performs
              deeper analysis on files already stored in a case. Modules run as Celery tasks
              and produce their own results panel — separate from the event timeline.
            </P>

            <InfoBox type="info">
              File name must end with <code>_module.py</code> and be placed in the
              <code> modules/</code> directory.  No restart needed — the worker loads the file
              at task execution time.
            </InfoBox>

            <H3>Minimal example</H3>
            <CodeBlock code={`MODULE_NAME        = "String Extractor"
MODULE_DESCRIPTION = "Extract printable strings from any file"
INPUT_EXTENSIONS   = []   # empty = accept all files

import os
from pathlib import Path

def run(run_id, case_id, source_files, params,
        minio_client, redis_client, tmp_dir):

    min_len = int(params.get("min_length", 8))
    hits = []

    for sf in source_files:
        local = tmp_dir / sf["filename"]
        minio_client.fget_object(
            os.getenv("MINIO_BUCKET", "forensics-cases"),
            sf["minio_key"],
            str(local),
        )

        # Extract printable ASCII strings
        strings = _extract_strings(local, min_len)
        hits.extend({
            "filename": sf["filename"],
            "string":   s,
            "level":    "info",
        } for s in strings)

    return {"hits": hits, "total_hits": len(hits)}


def _extract_strings(path: Path, min_len: int):
    result, buf = [], []
    with open(path, "rb") as fh:
        for byte in fh.read():
            if 0x20 <= byte < 0x7F:
                buf.append(chr(byte))
            elif len(buf) >= min_len:
                result.append("".join(buf))
                buf = []
            else:
                buf = []
    return result`} />

            <H3>Module metadata</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="MODULE_NAME" type="str" required>
                  Display name shown in the Modules selector, e.g. <code>"String Extractor"</code>.
                </Field>
                <Field name="MODULE_DESCRIPTION" type="str" required>Short description shown in the module card.</Field>
                <Field name="INPUT_EXTENSIONS" type="list[str]">
                  File extensions accepted as source input, e.g. <code>[".evtx", ".log"]</code>.
                  Leave empty to accept all files regardless of extension.
                </Field>
                <Field name="INPUT_FILENAMES" type="list[str]">
                  Exact filenames to match (like <code>HANDLED_FILENAMES</code> for ingesters).
                </Field>
              </div>
            </div>

            <H3>run() parameters</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="run_id" type="str">Unique ID for this run — pass to Redis for status updates.</Field>
                <Field name="case_id" type="str">Case the module is running against.</Field>
                <Field name="source_files" type="list[dict]">
                  List of <code>{"{"}"job_id", "filename", "minio_key"{"}"}</code> dicts — the files selected by the user.
                </Field>
                <Field name="params" type="dict">User-supplied parameters (arbitrary key/value pairs).</Field>
                <Field name="minio_client" type="Minio">Configured MinIO client. Use <code>fget_object(bucket, key, local_path)</code> to download.</Field>
                <Field name="redis_client" type="Redis">Redis client (<code>decode_responses=True</code>). Useful for streaming progress updates.</Field>
                <Field name="tmp_dir" type="Path">Clean temporary directory. Deleted automatically after the run completes.</Field>
              </div>
            </div>

            <H3>Return value</H3>
            <CodeBlock code={`return {
    "hits": [
        {
            "filename": "Security.evtx",   # str — source file
            "level":    "high",            # critical | high | medium | low | info
            "message":  "...",             # description
            # add any extra fields you want shown in the results panel
        },
    ],
    "total_hits": 1,  # optional — computed from len(hits) if omitted
}`} />
          </Section>

          {/* ── Alert Rules ───────────────────────────────────────────────── */}
          <Section id="alert-rules" title="Alert Rules" icon={<Bell size={14} className="text-brand-accent" />}>
            <P>
              Alert rules are Elasticsearch query_string queries stored in the global library.
              Run them against any case from the <strong>Alert Rules</strong> page or from
              within a case using the <strong>Run Alerts</strong> button.
            </P>

            <H3>Rule fields</H3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4">
                <Field name="name" type="str" required>Short, descriptive name shown in the rule list.</Field>
                <Field name="description" type="str">Explanation of what the rule detects and why it matters.</Field>
                <Field name="artifact_type" type="str">
                  Restrict the rule to a specific index, e.g. <code>evtx</code>, <code>suricata</code>.
                  Leave empty to search all indexes for the case.
                </Field>
                <Field name="query" type="str" required>
                  Lucene query_string syntax. See the Query Syntax section below.
                </Field>
                <Field name="threshold" type="int">
                  Minimum number of matching events to consider the rule "fired". Default: 1.
                </Field>
              </div>
            </div>

            <H3>Example rules</H3>
            <CodeBlock language="lucene" code={`# Event Log cleared (Security + System)
evtx.event_id:1102 OR evtx.event_id:104

# Brute-force (> 10 failures)
evtx.event_id:4625
threshold: 10

# PowerShell encoded command
evtx.event_id:4104 AND message:*-enc*

# Suricata malware category
suricata.event_type:alert AND message:*ET\\ MALWARE*

# Process spawned by Office app
evtx.event_id:4688 AND (message:*winword* OR message:*excel*)`} />

            <InfoBox type="tip">
              Use <strong>Load Default Rules</strong> to seed the built-in detection library.
              Rules are global — they apply to every case you run them against.
            </InfoBox>
          </Section>

          {/* ── Query Syntax ──────────────────────────────────────────────── */}
          <Section id="query-syntax" title="Query Syntax" icon={<Terminal size={14} className="text-brand-accent" />}>
            <P>
              The Timeline and Alert Rules use Elasticsearch <strong>Lucene query_string</strong> syntax.
              The search bar targets <code>message</code>, <code>host.hostname</code>, <code>user.name</code>,
              <code>process.name</code>, <code>process.cmdline</code>, and <code>process.args</code> by default.
              Prefix a term with a field name to search elsewhere.
            </P>

            <H3>Common patterns</H3>
            <div className="space-y-2">
              {[
                { q: 'evtx.event_id:4625',             desc: 'Field equals value' },
                { q: 'evtx.event_id:(4625 OR 4771)',   desc: 'OR group — failed auth' },
                { q: 'evtx.event_id:4688 AND message:*powershell*', desc: 'AND with wildcard' },
                { q: 'message:*encoded*',              desc: 'Wildcard (*) — any characters' },
                { q: 'NOT evtx.event_id:4672',         desc: 'NOT operator' },
                { q: 'evtx.event_id:[4600 TO 4700]',   desc: 'Range query' },
                { q: 'artifact_type:prefetch',         desc: 'Filter by ingester type' },
                { q: 'host.hostname:DESKTOP-*',        desc: 'Prefix match with wildcard' },
                { q: 'is_flagged:true',                desc: 'Only analyst-flagged events' },
                { q: 'tags:lateral-movement',          desc: 'Events with a specific tag' },
              ].map(r => (
                <div key={r.q} className="flex gap-3 items-start text-xs py-1.5 border-b border-gray-100 last:border-0">
                  <code className="font-mono text-brand-accent bg-brand-accentlight px-2 py-0.5 rounded text-[11px] flex-shrink-0">
                    {r.q}
                  </code>
                  <span className="text-gray-500 pt-0.5">{r.desc}</span>
                </div>
              ))}
            </div>

            <H3>Regexp mode</H3>
            <P>
              Enable the <strong>.*</strong> toggle in the search bar to match full event messages using
              Elasticsearch regexp syntax. This runs against the raw unanalyzed <code>message</code> field.
            </P>
            <InfoBox type="warning">
              ES regexp supports <code>. .* [a-z] (a|b) a+ a? a&#123;n,m&#125;</code> but <strong>NOT</strong>{' '}
              <code>\d \w \s</code>. Use <code>[0-9]</code>, <code>[a-zA-Z_]</code>, <code>[ \t]</code> instead.
            </InfoBox>
            <div className="space-y-2">
              {[
                { q: 'lateral.*movement',    desc: 'Any chars between words' },
                { q: 'cmd\\.exe',            desc: 'Escape literal dot' },
                { q: '4[6-9][0-9]{2}',       desc: 'Event ID range 4600-4999' },
                { q: '(mimikatz|sekurlsa)',   desc: 'Either word' },
              ].map(r => (
                <div key={r.q} className="flex gap-3 items-start text-xs py-1.5 border-b border-gray-100 last:border-0">
                  <code className="font-mono text-brand-accent bg-brand-accentlight px-2 py-0.5 rounded text-[11px] flex-shrink-0">
                    {r.q}
                  </code>
                  <span className="text-gray-500 pt-0.5">{r.desc}</span>
                </div>
              ))}
            </div>

            <H3>Indexed fields</H3>
            <Ul>
              <Li><code className="text-gray-600">timestamp</code> — ISO-8601 event time</Li>
              <Li><code className="text-gray-600">message</code> — human-readable description (full-text + keyword)</Li>
              <Li><code className="text-gray-600">artifact_type</code> — ingester that produced the event (evtx, prefetch, mft, registry, lnk, syslog, hayabusa, …)</Li>
              <Li><code className="text-gray-600">fo_id</code> — unique event ID</Li>
              <Li><code className="text-gray-600">host.*</code> — hostname, ip, os</Li>
              <Li><code className="text-gray-600">user.*</code> — name, domain, sid</Li>
              <Li><code className="text-gray-600">process.*</code> — name, pid, cmdline, args, path</Li>
              <Li><code className="text-gray-600">network.*</code> — src_ip, dst_ip, dst_port, protocol</Li>
              <Li><code className="text-gray-600">evtx.*</code> — event_id, channel, provider_name</Li>
              <Li><code className="text-gray-600">registry.*</code> — key_path, value_name, value_data</Li>
              <Li><code className="text-gray-600">prefetch.*</code> — executable, run_count, last_run</Li>
              <Li><code className="text-gray-600">lnk.*</code> — target_path, machine_id</Li>
              <Li><code className="text-gray-600">hayabusa.*</code> — level, rule_title</Li>
              <Li><code className="text-gray-600">is_flagged</code>, <code className="text-gray-600">tags</code>, <code className="text-gray-600">analyst_note</code> — analyst annotations</Li>
            </Ul>

            <InfoBox type="tip">
              Fields from the <code>extra</code> dict in custom ingesters are stored at the top level —
              search them directly by their key name. Use AI Search Assist (✦ button) to generate queries
              from plain English.
            </InfoBox>
          </Section>

          {/* ── Investigation UI ──────────────────────────────────────────── */}
          <Section id="search" title="Investigation UI" icon={<GitBranch size={14} className="text-brand-accent" />}>
            <P>
              The <strong>Timeline</strong> tab is the unified investigation workspace. It combines
              chronological event browsing, full-text search, facet filtering, saved searches, and
              AI-assisted query generation in a single view.
            </P>

            <H3>Search bar</H3>
            <Ul>
              <Li>Press <kbd className="px-1 bg-gray-100 rounded text-[10px] font-mono">/</kbd> to focus the search bar from anywhere</Li>
              <Li>Press <strong>Enter</strong> or click <strong>Search</strong> to apply the query</Li>
              <Li>Toggle <strong>.*</strong> for ES regexp mode (matches full message text)</Li>
              <Li>Click <strong>✦</strong> (Sparkles) to open AI Search Assist — describe what you want in plain English</Li>
            </Ul>

            <H3>Facet filter chips</H3>
            <P>
              The left sidebar shows Host, User, Event ID, and Channel facet chips auto-computed from
              the current result set. Click a chip to add it as an active filter — click again to remove.
              Active filters appear as dismissible badges below the search bar.
            </P>

            <H3>Saved searches</H3>
            <P>
              When a query or facet filter is active, click <strong>+ Save</strong> in the sidebar to
              name and persist the search for the current case. Saved searches restore both the query
              text and any active facet filters. Delete them by hovering and clicking the trash icon.
            </P>

            <H3>Sorting</H3>
            <P>
              Click any sortable column header (Timestamp ↑↓, Type, Host, User) to sort by that field.
              Click again to reverse the order. Default: newest first (timestamp descending).
            </P>

            <H3>Event deduplication</H3>
            <P>
              Events with identical timestamp, message, artifact type, host, and user are automatically
              deduplicated client-side. This prevents the same log event from appearing twice when an
              artifact was ingested from multiple sources (e.g. raw EVTX + Plaso processing).
            </P>

            <H3>AI Search Assist</H3>
            <P>
              The AI assistant uses the configured LLM (Settings → AI Analysis) to translate a plain
              English description into an Elasticsearch query_string. The model is aware of the full
              field schema including EVTX event IDs, registry paths, prefetch fields, and common
              forensic investigation patterns (lateral movement, credential dumping, persistence, …).
            </P>
            <InfoBox type="info">
              AI Assist requires an LLM to be configured in Settings. The generated query is editable
              before you apply it — always review before running against large datasets.
            </InfoBox>
          </Section>

          {/* ── API Reference ─────────────────────────────────────────────── */}
          <Section id="api" title="API Reference" icon={<Code2 size={14} className="text-brand-accent" />}>
            <P>
              The REST API is served at <code>http://localhost:8000/api/v1</code>.
              Interactive docs: <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer"
                className="text-brand-accent hover:underline">localhost:8000/docs</a> (Swagger UI).
            </P>

            <H3>Cases</H3>
            <CodeBlock language="http" code={`GET    /cases                            list all cases
POST   /cases                            create case  {name, description?}
GET    /cases/{id}                       get case
DELETE /cases/{id}                       delete case

POST   /cases/{id}/ingest                upload evidence file (multipart)
GET    /cases/{id}/jobs                  list ingest jobs
GET    /jobs/{job_id}                    get single job`} />

            <H3>Search</H3>
            <CodeBlock language="http" code={`GET /cases/{id}/timeline     timeline events  ?from=&to=&artifact=&page=
GET /cases/{id}/search       free-text search ?q=&page=&per_page=
GET /cases/{id}/search/facets           field facets for filters`} />

            <H3>Modules</H3>
            <CodeBlock language="http" code={`GET    /modules                          list all modules (built-in + custom)
GET    /cases/{id}/sources               source files available for a case
POST   /cases/{id}/module-runs           launch a module run  {module_id, job_ids[]}
GET    /cases/{id}/module-runs           list runs for a case
GET    /module-runs/{run_id}             get run with full results_preview
POST   /modules/yara/validate            validate YARA rule syntax  {rules}`} />

            <H3>Alert Rules</H3>
            <CodeBlock language="http" code={`GET    /alert-rules/library              list global rule library
POST   /alert-rules/library              create rule
PUT    /alert-rules/library/{id}         update rule
DELETE /alert-rules/library/{id}         delete rule
POST   /alert-rules/library/seed         seed default rules  ?replace=false
POST   /cases/{id}/alert-rules/run-library   run all rules against case
POST   /cases/{id}/alert-rules/library/{rule_id}/run  run single rule`} />

            <H3>Editor (Studio)</H3>
            <CodeBlock language="http" code={`GET    /editor/ingesters                 list ingester files
GET    /editor/ingesters/{name}          read file
PUT    /editor/ingesters/{name}          write file  {content}
DELETE /editor/ingesters/{name}          delete file

GET    /editor/modules                   list module files
GET    /editor/modules/{name}            read file
PUT    /editor/modules/{name}            write file  {content}
DELETE /editor/modules/{name}            delete file

POST   /editor/validate                  Python syntax check  {code}`} />

            <H3>Plugins (ingesters — loaded)</H3>
            <CodeBlock language="http" code={`GET  /plugins        list loaded plugin classes
POST /plugins/reload  reload plugin directory
POST /plugins/upload  upload a .py file (multipart)`} />
          </Section>

        </div>
      </div>
    </div>
  )
}
