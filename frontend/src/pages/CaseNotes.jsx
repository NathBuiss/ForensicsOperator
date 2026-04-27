import { useEffect, useState, useCallback, useRef } from 'react'
import { Save, FileText, Printer } from 'lucide-react'
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
  const editorRef              = useRef(null)
  const [savedBody, setSavedBody]   = useState('')
  const [currentBody, setCurrentBody] = useState('')
  const [updatedAt,  setUpdatedAt]  = useState(null)
  const [saving,     setSaving]     = useState(false)
  const [, setTick] = useState(0)

  useEffect(() => {
    api.notes.get(caseId).then(d => {
      const body = d.body || ''
      setSavedBody(body)
      setCurrentBody(body)
      setUpdatedAt(d.updated_at)
      if (editorRef.current) {
        editorRef.current.innerHTML = body
      }
    })
  }, [caseId])

  // Keep "saved X ago" label fresh
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 30_000)
    return () => clearInterval(id)
  }, [])

  const save = useCallback(async () => {
    if (saving || !editorRef.current) return
    setSaving(true)
    const body = editorRef.current.innerHTML
    try {
      const res = await api.notes.save(caseId, body)
      setSavedBody(body)
      setCurrentBody(body)
      setUpdatedAt(res.updated_at)
    } finally {
      setSaving(false)
    }
  }, [caseId, saving])

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

  // Intercept image paste → embed as base64
  const handlePaste = useCallback(e => {
    const items = Array.from(e.clipboardData?.items || [])
    const imageItem = items.find(item => item.type.startsWith('image/'))
    if (!imageItem) return
    e.preventDefault()
    const file = imageItem.getAsFile()
    if (!file) return
    const reader = new FileReader()
    reader.onload = evt => {
      const img = document.createElement('img')
      img.src = evt.target.result
      img.style.cssText = 'max-width:100%;border-radius:4px;margin:4px 0;display:block;'
      const sel = window.getSelection()
      if (sel?.rangeCount) {
        const range = sel.getRangeAt(0)
        range.deleteContents()
        range.insertNode(document.createElement('br'))
        range.insertNode(img)
        range.collapse(false)
        sel.removeAllRanges()
        sel.addRange(range)
      } else {
        editorRef.current.appendChild(img)
      }
      setCurrentBody(editorRef.current.innerHTML)
    }
    reader.readAsDataURL(file)
  }, [])

  const handleExportPDF = useCallback(() => {
    const content = editorRef.current?.innerHTML || ''
    const win = window.open('', '_blank')
    if (!win) return
    win.document.write(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Notes — Case ${caseId}</title>
  <style>
    body { font-family: monospace; font-size: 13px; padding: 32px; line-height: 1.7;
           color: #111; white-space: pre-wrap; word-break: break-word; }
    img  { max-width: 100%; display: block; margin: 8px 0; }
    @media print { body { padding: 0; } }
  </style>
</head>
<body>${content}</body>
</html>`)
    win.document.close()
    win.focus()
    setTimeout(() => { win.print(); win.close() }, 250)
  }, [caseId])

  const dirty = currentBody !== savedBody

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
            onClick={handleExportPDF}
            className="btn-ghost text-xs flex items-center gap-1.5">
            <Printer size={11} />
            Export PDF
          </button>
          <button
            onClick={save}
            disabled={saving || !dirty}
            className="btn-primary text-xs flex items-center gap-1.5">
            <Save size={11} />
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      <div
        ref={editorRef}
        contentEditable
        suppressContentEditableWarning
        onInput={() => setCurrentBody(editorRef.current?.innerHTML || '')}
        onPaste={handlePaste}
        spellCheck={false}
        className="input font-mono text-xs leading-relaxed flex-1 overflow-auto outline-none cursor-text"
        style={{
          minHeight: '420px',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
        }}
      />

      <p className="text-[11px] text-gray-400 mt-2 flex-shrink-0">
        Paste screenshots directly into the editor. ⌘S / Ctrl+S to save.
      </p>
    </div>
  )
}
