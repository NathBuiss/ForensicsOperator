import { useState } from 'react'
import { api } from '../../api/client'

export default function EventDetail({ event: initialEvent, caseId, onClose }) {
  const [event, setEvent] = useState(initialEvent)
  const [note, setNote] = useState(event.analyst_note || '')
  const [tagInput, setTagInput] = useState('')
  const [saving, setSaving] = useState(false)

  async function toggleFlag() {
    const r = await api.search.flagEvent(caseId, event.fo_id)
    setEvent(prev => ({ ...prev, is_flagged: r.is_flagged }))
  }

  async function saveNote() {
    setSaving(true)
    await api.search.noteEvent(caseId, event.fo_id, note)
    setSaving(false)
  }

  async function addTag(e) {
    e.preventDefault()
    if (!tagInput.trim()) return
    const tags = [...(event.tags || []), tagInput.trim()]
    await api.search.tagEvent(caseId, event.fo_id, tags)
    setEvent(prev => ({ ...prev, tags }))
    setTagInput('')
  }

  async function removeTag(tag) {
    const tags = (event.tags || []).filter(t => t !== tag)
    await api.search.tagEvent(caseId, event.fo_id, tags)
    setEvent(prev => ({ ...prev, tags }))
  }

  const ts = event.timestamp
    ? new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 23)
    : '—'

  // Collect artifact-specific fields
  const artifactData = event[event.artifact_type] || {}

  return (
    <div className="w-96 flex-shrink-0 bg-gray-900 border-l border-gray-700 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-3 border-b border-gray-700 flex items-start justify-between">
        <div>
          <span className="badge bg-blue-900/40 text-blue-400 mb-1">{event.artifact_type}</span>
          <p className="text-xs text-gray-300 break-words">{event.message}</p>
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-300 ml-2 flex-shrink-0">✕</button>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3 text-xs">
        {/* Actions */}
        <div className="flex gap-2">
          <button onClick={toggleFlag}
            className={`btn text-xs ${event.is_flagged ? 'bg-red-900/50 text-red-300' : 'btn-ghost'}`}>
            {event.is_flagged ? '🚩 Flagged' : '🏳 Flag'}
          </button>
        </div>

        {/* Tags */}
        <div>
          <p className="text-gray-500 mb-1">Tags</p>
          <div className="flex flex-wrap gap-1 mb-1">
            {(event.tags || []).map(t => (
              <span key={t} className="badge bg-indigo-900/40 text-indigo-400 cursor-pointer"
                onClick={() => removeTag(t)}>{t} ×</span>
            ))}
          </div>
          <form onSubmit={addTag} className="flex gap-1">
            <input value={tagInput} onChange={e => setTagInput(e.target.value)}
              placeholder="Add tag..." className="input flex-1 text-xs" />
            <button type="submit" className="btn-ghost text-xs">+</button>
          </form>
        </div>

        {/* Analyst note */}
        <div>
          <p className="text-gray-500 mb-1">Analyst Note</p>
          <textarea value={note} onChange={e => setNote(e.target.value)}
            className="input w-full h-20 resize-none text-xs"
            placeholder="Add investigation notes..." />
          <button onClick={saveNote} disabled={saving}
            className="btn-primary text-xs mt-1">
            {saving ? 'Saving...' : 'Save Note'}
          </button>
        </div>

        {/* Base fields */}
        <FieldGroup title="Event" fields={{
          Timestamp: ts,
          Description: event.timestamp_desc,
          Host: event.host?.hostname || event.host?.fqdn,
          User: [event.user?.domain, event.user?.name].filter(Boolean).join('\\') || undefined,
          SID: event.user?.sid,
          Process: event.process?.path || event.process?.name,
          PID: event.process?.pid,
          'Src IP': event.network?.src_ip,
          'MITRE': event.mitre?.technique_id ? `${event.mitre.technique_id} – ${event.mitre.technique_name}` : undefined,
        }} />

        {/* Artifact-specific */}
        {Object.keys(artifactData).length > 0 && (
          <FieldGroup title={event.artifact_type?.toUpperCase()} fields={
            Object.fromEntries(
              Object.entries(artifactData)
                .filter(([, v]) => v !== null && v !== undefined && v !== '')
                .map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v, null, 2) : v])
            )
          } />
        )}

        {/* Job info */}
        <FieldGroup title="Metadata" fields={{
          'Ingest Job': event.ingest_job_id,
          'Source': event.source_file,
          'Ingested': event.ingested_at,
        }} />
      </div>
    </div>
  )
}

function FieldGroup({ title, fields }) {
  const entries = Object.entries(fields).filter(([, v]) => v !== null && v !== undefined && v !== '')
  if (!entries.length) return null
  return (
    <div>
      <p className="text-gray-500 uppercase tracking-wider text-xs mb-1">{title}</p>
      <div className="space-y-0.5">
        {entries.map(([k, v]) => (
          <div key={k} className="flex gap-2">
            <span className="text-gray-600 flex-shrink-0 w-24 truncate">{k}</span>
            <span className="text-gray-300 break-all font-mono text-xs">
              {typeof v === 'string' && v.includes('\n')
                ? <pre className="whitespace-pre-wrap">{v}</pre>
                : String(v)}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
