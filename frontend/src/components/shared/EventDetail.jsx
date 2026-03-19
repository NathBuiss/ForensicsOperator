import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { X, Flag, Tag, Plus, Save, Search, Shield, AlertTriangle } from 'lucide-react'
import { api } from '../../api/client'
import { extractIocs, iocSearchQuery } from '../../utils/ioc'
import { getMitre, TACTIC_COLORS } from '../../utils/mitre'

export default function EventDetail({ event: initialEvent, caseId, onClose }) {
  const [event, setEvent] = useState(initialEvent)
  const [note, setNote]   = useState(event.analyst_note || '')
  const [tagInput, setTagInput] = useState('')
  const [saving, setSaving]     = useState(false)
  const navigate = useNavigate()

  const mitre = getMitre(event)
  const iocs  = extractIocs(event.message)

  async function toggleFlag() {
    const r = await api.search.flagEvent(caseId, event.fo_id)
    setEvent(p => ({ ...p, is_flagged: r.is_flagged }))
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
    setEvent(p => ({ ...p, tags }))
    setTagInput('')
  }

  async function removeTag(tag) {
    const tags = (event.tags || []).filter(t => t !== tag)
    await api.search.tagEvent(caseId, event.fo_id, tags)
    setEvent(p => ({ ...p, tags }))
  }

  function pivot(query) {
    navigate('../search', { state: { pivotQuery: query } })
  }

  const ts = event.timestamp
    ? new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 23)
    : '—'

  const artifactData = event[event.artifact_type] || {}

  const ARTIFACT_COLOR = {
    evtx:     'badge-evtx',
    prefetch: 'badge-prefetch',
    mft:      'badge-mft',
    registry: 'badge-registry',
    lnk:      'badge-lnk',
    plaso:    'badge-plaso',
    hayabusa: 'badge-hayabusa',
  }

  return (
    <div className="w-96 flex-shrink-0 bg-white border-l border-gray-200 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-3 border-b border-gray-200 flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className={`badge ${ARTIFACT_COLOR[event.artifact_type] || 'badge-generic'}`}>
              {event.artifact_type}
            </span>
            {mitre && (
              <span className={`badge border text-[10px] ${TACTIC_COLORS[mitre.tactic] || 'bg-gray-100 text-gray-600 border-gray-200'}`}
                title={mitre.tactic}>
                <Shield size={9} className="mr-1" />
                {mitre.technique_id}
              </span>
            )}
          </div>
          <p className="text-xs text-brand-text break-words line-clamp-3">{event.message}</p>
        </div>
        <button onClick={onClose} className="btn-ghost p-1 flex-shrink-0">
          <X size={14} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-4 text-xs">
        {/* Actions */}
        <div className="flex gap-2">
          <button onClick={toggleFlag}
            className={`btn text-xs ${event.is_flagged ? 'bg-red-100 text-red-700 border border-red-200' : 'btn-ghost'}`}>
            <Flag size={12} />
            {event.is_flagged ? 'Flagged' : 'Flag'}
          </button>
        </div>

        {/* MITRE ATT&CK */}
        {mitre && (
          <div className="rounded-lg border border-gray-200 bg-gray-50 p-2.5">
            <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
              <Shield size={9} /> MITRE ATT&CK
            </p>
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="text-brand-text font-medium">{mitre.technique_name}</p>
                <p className="text-gray-500 text-[10px]">{mitre.tactic}</p>
              </div>
              <span className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono flex-shrink-0">
                {mitre.technique_id}
              </span>
            </div>
          </div>
        )}

        {/* IOC Panel */}
        {iocs.length > 0 && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-2.5">
            <p className="text-[10px] font-semibold text-amber-700 uppercase tracking-wider mb-2 flex items-center gap-1">
              <AlertTriangle size={9} /> IOCs Detected ({iocs.length})
            </p>
            <div className="space-y-1">
              {iocs.map((ioc, i) => (
                <div key={i} className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-[10px] text-gray-500 flex-shrink-0 w-12">{ioc.type}</span>
                    <span className={`font-mono text-[10px] truncate ${ioc.color}`}>{ioc.value}</span>
                  </div>
                  <button onClick={() => pivot(iocSearchQuery(ioc))}
                    className="flex-shrink-0 p-1 rounded hover:bg-amber-100 text-amber-500 hover:text-amber-700 transition-colors"
                    title="Find all events with this IOC">
                    <Search size={10} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tags */}
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
            <Tag size={9} /> Tags
          </p>
          <div className="flex flex-wrap gap-1 mb-1.5">
            {(event.tags || []).map(t => (
              <span key={t} className="badge bg-brand-accentlight text-brand-accent border border-brand-accent/20 cursor-pointer hover:bg-brand-accent/10 transition-colors"
                onClick={() => removeTag(t)}>{t} ×</span>
            ))}
          </div>
          <form onSubmit={addTag} className="flex gap-1">
            <input value={tagInput} onChange={e => setTagInput(e.target.value)}
              placeholder="Add tag…" className="input flex-1 py-1 text-xs" />
            <button type="submit" className="btn-ghost px-2 text-xs"><Plus size={12} /></button>
          </form>
        </div>

        {/* Analyst Note */}
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
            Analyst Note
          </p>
          <textarea value={note} onChange={e => setNote(e.target.value)}
            className="input w-full h-20 resize-none text-xs"
            placeholder="Investigation notes…" />
          <button onClick={saveNote} disabled={saving} className="btn-primary text-xs mt-1.5">
            <Save size={11} /> {saving ? 'Saving…' : 'Save Note'}
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
        }} pivotFields={['Host', 'User', 'Src IP']} onPivot={pivot} />

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

        {/* Metadata */}
        <FieldGroup title="Metadata" fields={{
          'Ingest Job': event.ingest_job_id,
          Source: event.source_file,
          Ingested: event.ingested_at,
        }} />
      </div>
    </div>
  )
}

function FieldGroup({ title, fields, pivotFields = [], onPivot }) {
  const entries = Object.entries(fields).filter(([, v]) => v !== null && v !== undefined && v !== '')
  if (!entries.length) return null
  return (
    <div>
      <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-1.5">{title}</p>
      <div className="space-y-1">
        {entries.map(([k, v]) => (
          <div key={k} className="flex gap-2 items-start">
            <span className="text-gray-400 flex-shrink-0 w-20 text-[10px] pt-0.5">{k}</span>
            <span className="text-gray-700 break-all font-mono text-[10px] flex-1">
              {typeof v === 'string' && v.includes('\n')
                ? <pre className="whitespace-pre-wrap">{v}</pre>
                : String(v)}
            </span>
            {pivotFields.includes(k) && onPivot && v && (
              <button onClick={() => onPivot(`"${v}"`)}
                className="flex-shrink-0 p-0.5 rounded hover:bg-gray-100 text-gray-400 hover:text-brand-accent transition-colors"
                title={`Search all events for: ${v}`}>
                <Search size={10} />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
