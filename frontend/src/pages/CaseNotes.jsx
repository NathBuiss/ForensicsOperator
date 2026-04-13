import { useEffect, useState, useCallback } from 'react'
import { Save, FileText } from 'lucide-react'
import { api } from '../api/client'

function relativeTime(iso) {
  if (!iso) return null
  const diff = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 10)   return 'just now'
  if (diff < 60)   return `${diff}s ago`
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  return `${Math.round(diff / 3600)}h ago`
}

export default function CaseNotes({ caseId }) {
  const [body,      setBody]      = useState('')
  const [savedBody, setSavedBody] = useState('')
  const [updatedAt, setUpdatedAt] = useState(null)
  const [saving,    setSaving]    = useState(false)
  const [, setTick] = useState(0)

  useEffect(() => {
    api.notes.get(caseId).then(d => {
      setBody(d.body || '')
      setSavedBody(d.body || '')
      setUpdatedAt(d.updated_at)
    })
  }, [caseId])

  // Tick every 30s so the "saved X ago" label stays fresh
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 30_000)
    return () => clearInterval(id)
  }, [])

  const save = useCallback(async () => {
    if (saving) return
    setSaving(true)
    try {
      const res = await api.notes.save(caseId, body)
      setSavedBody(body)
      setUpdatedAt(res.updated_at)
    } finally {
      setSaving(false)
    }
  }, [caseId, body, saving])

  // ⌘S / Ctrl+S
  useEffect(() => {
    const handler = e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault()
        save()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [save])

  const dirty = body !== savedBody

  return (
    <div className="p-6 max-w-3xl mx-auto flex flex-col h-full">
      <div className="flex items-center justify-between mb-3 flex-shrink-0">
        <div className="flex items-center gap-2">
          <FileText size={14} className="text-brand-accent" />
          <h2 className="text-sm font-semibold text-brand-text">Investigator Notes</h2>
        </div>
        <div className="flex items-center gap-3">
          {updatedAt && !dirty && (
            <span className="text-xs text-gray-400">saved {relativeTime(updatedAt)}</span>
          )}
          {dirty && (
            <span className="text-xs text-amber-500">unsaved changes</span>
          )}
          <button
            onClick={save}
            disabled={saving || !dirty}
            className="btn-primary text-xs flex items-center gap-1.5">
            <Save size={11} />
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      <textarea
        className="input w-full font-mono text-xs resize-none flex-1 leading-relaxed"
        style={{ minHeight: '420px' }}
        placeholder={
          'Investigation notes — ⌘S / Ctrl+S to save.\n\n' +
          '2026-04-13  Checked svchost.exe hash → clean. Suspicious parent process,\n' +
          '            pivot to process tree on dc01.\n\n' +
          '2026-04-13  Confirmed lateral movement dc01 → ws04 via RDP at 03:42 UTC.'
        }
        value={body}
        onChange={e => setBody(e.target.value)}
        spellCheck={false}
      />

      <p className="text-[11px] text-gray-400 mt-2 flex-shrink-0">
        Notes are private to this case and persist across sessions.
      </p>
    </div>
  )
}
