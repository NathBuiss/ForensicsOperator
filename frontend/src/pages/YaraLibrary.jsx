import { useState, useEffect, useRef } from 'react'
import {
  FileCode, Plus, Trash2, Pencil, X, Upload, Download,
  Check, Loader2, AlertTriangle, Search, Code2, ChevronDown, ChevronUp, Sparkles,
} from 'lucide-react'
import { api } from '../api/client'

// ── Rule Modal ────────────────────────────────────────────────────────────────

function YaraRuleModal({ rule = null, onClose, onSaved, openAI = false }) {
  const isEdit   = !!(rule?.id)
  const fileRef  = useRef(null)

  const [name, setName]         = useState(rule?.name        || '')
  const [desc, setDesc]         = useState(rule?.description || '')
  const [tags, setTags]         = useState((rule?.tags || []).join(', '))
  const [content, setContent]   = useState(rule?.content     || '')
  const [saving, setSaving]     = useState(false)
  const [validating, setValid]  = useState(false)
  const [validResult, setVR]    = useState(null)
  const [error, setError]       = useState('')

  // AI generation state
  const [aiOpen, setAiOpen]         = useState(openAI)
  const [aiPrompt, setAiPrompt]     = useState('')
  const [aiContext, setAiContext]    = useState('')
  const [aiGenerating, setAiGen]    = useState(false)
  const [aiError, setAiError]       = useState('')
  const [aiModelUsed, setAiModel]   = useState('')

  async function generateWithAI() {
    if (!aiPrompt.trim()) return
    setAiGen(true)
    setAiError('')
    try {
      const r = await api.yaraRules.generateYara({ description: aiPrompt, context: aiContext })
      setContent(r.content || '')
      if (r.name && !name) setName(r.name)
      if (r.description && !desc) setDesc(r.description)
      if (r.tags?.length && !tags) setTags(r.tags.join(', '))
      setAiModel(r.model_used || '')
      setVR(null)
      setAiOpen(false)
    } catch (err) {
      setAiError(err.message)
    } finally {
      setAiGen(false)
    }
  }

  function handleFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      setContent(ev.target.result || '')
      if (!name) setName(file.name.replace(/\.yar(a)?$/i, ''))
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  async function validate() {
    if (!content.trim()) return
    setValid(true)
    setVR(null)
    try {
      const r = await api.modules.validateYara(content)
      setVR({ ok: r.valid, msg: r.message || (r.valid ? 'Syntax OK' : 'Invalid syntax') })
    } catch (err) {
      setVR({ ok: false, msg: err.message })
    } finally {
      setValid(false)
    }
  }

  async function save() {
    if (!name.trim())    { setError('Name is required'); return }
    if (!content.trim()) { setError('Rule content is required'); return }
    setSaving(true)
    setError('')
    try {
      const tagList = tags.split(',').map(t => t.trim()).filter(Boolean)
      const body    = { name: name.trim(), description: desc.trim(), tags: tagList, content }
      const saved   = isEdit
        ? await api.yaraRules.update(rule.id, body)
        : await api.yaraRules.create(body)
      onSaved(saved)
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl mx-4 flex flex-col max-h-[92vh]">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 flex-shrink-0">
          <div className="flex items-center gap-2">
            <FileCode size={16} className="text-brand-accent" />
            <h2 className="text-sm font-semibold">{isEdit ? 'Edit YARA Rule' : 'New YARA Rule'}</h2>
          </div>
          <button onClick={onClose} className="icon-btn"><X size={14} /></button>
        </div>

        <div className="overflow-y-auto flex-1 p-5 space-y-4">
          {/* Meta row */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-gray-600 mb-1 block">Rule name *</label>
              <input value={name} onChange={e => setName(e.target.value)}
                placeholder="e.g. Detect_Cobalt_Strike"
                className="input text-xs w-full" />
            </div>
            <div>
              <label className="text-xs font-medium text-gray-600 mb-1 block">Tags</label>
              <input value={tags} onChange={e => setTags(e.target.value)}
                placeholder="malware, apt, ransomware"
                className="input text-xs w-full" />
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-gray-600 mb-1 block">Description</label>
            <input value={desc} onChange={e => setDesc(e.target.value)}
              placeholder="What does this rule detect?"
              className="input text-xs w-full" />
          </div>

          {/* AI generation panel */}
          <div className="rounded-xl border border-brand-accent/30 bg-brand-soft/40 p-3">
            <button
              type="button"
              onClick={() => setAiOpen(o => !o)}
              className="flex items-center gap-2 w-full text-left"
            >
              <Sparkles size={13} className="text-brand-accent flex-shrink-0" />
              <span className="text-xs font-medium text-brand-accent">Generate with AI</span>
              <span className="text-[10px] text-gray-400 ml-1">— describe what you want to detect</span>
              <span className="ml-auto text-[10px] text-brand-accent">{aiOpen ? '▲' : '▼'}</span>
            </button>

            {aiOpen && (
              <div className="mt-3 space-y-2">
                <div>
                  <label className="text-[11px] font-medium text-gray-600 mb-1 block">What to detect *</label>
                  <input
                    value={aiPrompt}
                    onChange={e => setAiPrompt(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && !e.shiftKey && generateWithAI()}
                    placeholder="e.g. Cobalt Strike beacon in memory, ransomware dropping note files"
                    className="input text-xs w-full"
                    autoFocus
                  />
                </div>
                <div>
                  <label className="text-[11px] font-medium text-gray-600 mb-1 block">Hints (optional)</label>
                  <input
                    value={aiContext}
                    onChange={e => setAiContext(e.target.value)}
                    placeholder="known strings, hex patterns, file type, malware family…"
                    className="input text-xs w-full"
                  />
                </div>
                {aiError && (
                  <p className="text-xs text-red-600 flex items-center gap-1">
                    <AlertTriangle size={11} /> {aiError}
                  </p>
                )}
                <div className="flex items-center gap-2">
                  <button
                    onClick={generateWithAI}
                    disabled={aiGenerating || !aiPrompt.trim()}
                    className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50"
                  >
                    {aiGenerating
                      ? <><Loader2 size={11} className="animate-spin" /> Generating…</>
                      : <><Sparkles size={11} /> Generate rule</>
                    }
                  </button>
                  <button onClick={() => setAiOpen(false)} className="btn-outline text-xs">Cancel</button>
                </div>
              </div>
            )}

            {!aiOpen && aiModelUsed && (
              <p className="text-[10px] text-gray-400 mt-1.5 flex items-center gap-1">
                <Check size={10} className="text-green-500" /> Generated by {aiModelUsed} — review before saving
              </p>
            )}
          </div>

          {/* YARA content */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-medium text-gray-600">YARA Rule *</label>
              <div className="flex items-center gap-3">
                <button onClick={() => fileRef.current?.click()}
                  className="text-xs text-brand-accent hover:underline flex items-center gap-1">
                  <Upload size={11} /> Import .yar
                </button>
                <input ref={fileRef} type="file" accept=".yar,.yara" className="hidden" onChange={handleFile} />
                <button onClick={validate} disabled={validating || !content.trim()}
                  className="text-xs text-gray-500 hover:text-brand-accent flex items-center gap-1 disabled:opacity-40">
                  {validating ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />}
                  Validate
                </button>
              </div>
            </div>
            <textarea
              value={content}
              onChange={e => { setContent(e.target.value); setVR(null) }}
              className="w-full font-mono text-xs bg-gray-950 text-green-400 rounded-lg p-3 h-56 resize-none outline-none focus:ring-1 focus:ring-brand-accent/40 border border-gray-200"
              placeholder={`rule ExampleMalware {\n    meta:\n        description = "Detects example malware"\n        author = "analyst"\n    strings:\n        $s1 = "malicious_string" ascii\n        $b1 = { DE AD BE EF }\n    condition:\n        any of them\n}`}
              spellCheck={false}
            />
            {validResult && (
              <p className={`text-xs mt-1 flex items-center gap-1.5 ${validResult.ok ? 'text-green-600' : 'text-red-600'}`}>
                {validResult.ok ? <Check size={11} /> : <AlertTriangle size={11} />}
                {validResult.msg}
              </p>
            )}
          </div>

          {error && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {error}
            </p>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-gray-100 flex items-center justify-end gap-2 flex-shrink-0">
          <button onClick={onClose} className="btn-outline text-xs">Cancel</button>
          <button onClick={save} disabled={saving} className="btn-primary text-xs">
            {saving ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
            {isEdit ? 'Save changes' : 'Create rule'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Rule card ──────────────────────────────────────────────────────────────────

function RuleCard({ rule, onEdit, onDelete }) {
  const [expanded, setExpanded] = useState(false)
  const [deleting, setDeleting] = useState(false)

  async function confirmDelete() {
    if (!confirm(`Delete rule "${rule.name}"?`)) return
    setDeleting(true)
    try {
      await api.yaraRules.delete(rule.id)
      onDelete(rule.id)
    } catch (err) {
      alert('Delete failed: ' + err.message)
      setDeleting(false)
    }
  }

  return (
    <div className="card overflow-hidden">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-gray-50 transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <FileCode size={14} className="text-brand-accent flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold text-brand-text truncate">{rule.name}</p>
          {rule.description && (
            <p className="text-[11px] text-gray-500 truncate mt-0.5">{rule.description}</p>
          )}
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {(rule.tags || []).slice(0, 4).map(t => (
            <span key={t} className="badge-pill bg-brand-soft text-brand-accent text-[10px] px-1.5">{t}</span>
          ))}
          <button
            onClick={e => { e.stopPropagation(); onEdit(rule) }}
            className="icon-btn ml-1"
            title="Edit"
          >
            <Pencil size={12} />
          </button>
          <button
            onClick={e => { e.stopPropagation(); confirmDelete() }}
            disabled={deleting}
            className="icon-btn text-red-400 hover:text-red-600"
            title="Delete"
          >
            {deleting ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
          </button>
          {expanded ? <ChevronUp size={12} className="text-gray-400" /> : <ChevronDown size={12} className="text-gray-400" />}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-gray-100">
          <pre className="font-mono text-[11px] text-green-400 bg-gray-950 px-4 py-3 overflow-x-auto whitespace-pre-wrap max-h-72 leading-relaxed">
            {rule.content}
          </pre>
          <div className="px-4 py-2 bg-gray-50 border-t border-gray-100 flex items-center justify-between">
            <span className="text-[11px] text-gray-400">
              {rule.content.split('\n').length} lines
              {rule.updated_at && ` · Updated ${new Date(rule.updated_at).toLocaleDateString()}`}
            </span>
            <button
              onClick={e => { e.stopPropagation(); onEdit(rule) }}
              className="text-[11px] text-brand-accent hover:underline flex items-center gap-1"
            >
              <Pencil size={10} /> Edit
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function YaraLibrary() {
  const [rules, setRules]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [search, setSearch]       = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editRule, setEditRule]   = useState(null)   // null = create, object = edit/prefill
  const [modalOpenAI, setModalOpenAI] = useState(false)
  const importRef = useRef(null)

  useEffect(() => { load() }, [])

  async function load() {
    setLoading(true)
    try {
      const r = await api.yaraRules.list()
      setRules(r.rules || [])
    } catch (err) {
      console.error('Failed to load YARA rules:', err)
    } finally {
      setLoading(false)
    }
  }

  function openCreate() {
    setEditRule(null)
    setModalOpenAI(false)
    setShowModal(true)
  }

  function openCreateWithAI() {
    setEditRule(null)
    setModalOpenAI(true)
    setShowModal(true)
  }

  function openEdit(rule) {
    setEditRule(rule)
    setModalOpenAI(false)
    setShowModal(true)
  }

  function handleImportFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      // Open modal pre-filled with imported content (no id = create mode)
      setEditRule({
        name:        file.name.replace(/\.yar(a)?$/i, ''),
        description: '',
        tags:        [],
        content:     ev.target.result || '',
      })
      setShowModal(true)
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  const filtered = search.trim()
    ? rules.filter(r =>
        r.name.toLowerCase().includes(search.toLowerCase()) ||
        (r.description || '').toLowerCase().includes(search.toLowerCase()) ||
        (r.tags || []).some(t => t.toLowerCase().includes(search.toLowerCase()))
      )
    : rules

  return (
    <div className="p-6 max-w-4xl mx-auto">

      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2.5 mb-1">
          <FileCode size={20} className="text-brand-accent" />
          <h1 className="text-xl font-bold text-brand-text">YARA Rules Library</h1>
        </div>
        <p className="text-sm text-gray-500">
          Store and manage YARA rules. Rules are automatically available to the YARA Scanner module.
        </p>
      </div>

      {/* Toolbar */}
      <div className="card p-3 mb-4 flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-1 min-w-36">
          <Search size={13} className="text-gray-400 flex-shrink-0" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search rules, tags…"
            className="flex-1 text-xs outline-none bg-transparent placeholder-gray-400"
          />
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => importRef.current?.click()} className="btn-outline text-xs flex items-center gap-1.5">
            <Upload size={12} /> Import .yar
          </button>
          <input ref={importRef} type="file" accept=".yar,.yara" className="hidden" onChange={handleImportFile} />

          {rules.length > 0 && (
            <a
              href={api.yaraRules.exportUrl()}
              className="btn-outline text-xs flex items-center gap-1.5"
              download="yara_library.yar"
            >
              <Download size={12} /> Export all
            </a>
          )}

          <button onClick={openCreateWithAI} className="btn-ghost text-xs flex items-center gap-1.5">
            <Sparkles size={12} className="text-brand-accent" /> Generate with AI
          </button>
          <button onClick={openCreate} className="btn-primary text-xs flex items-center gap-1.5">
            <Plus size={12} /> New rule
          </button>
        </div>
      </div>

      {/* Count */}
      {!loading && rules.length > 0 && (
        <p className="text-xs text-gray-500 mb-3">
          <span className="font-medium text-brand-text">{rules.length}</span> rule{rules.length !== 1 ? 's' : ''} in library
          {search && <> · <span className="font-medium text-brand-text">{filtered.length}</span> matching</>}
        </p>
      )}

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center py-16 text-gray-400">
          <Loader2 size={18} className="animate-spin mr-2" /> Loading…
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 text-gray-400">
          <Code2 size={36} className="mx-auto mb-3 opacity-25" />
          {search ? (
            <p className="text-sm">No rules match "<span className="font-medium">{search}</span>"</p>
          ) : (
            <>
              <p className="text-sm font-medium mb-1">No YARA rules yet</p>
              <p className="text-xs text-gray-400 mb-4">Import an existing .yar file or write a rule from scratch.</p>
              <button onClick={openCreate} className="btn-primary text-xs mx-auto flex items-center gap-1.5">
                <Plus size={12} /> Create first rule
              </button>
            </>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(rule => (
            <RuleCard
              key={rule.id}
              rule={rule}
              onEdit={openEdit}
              onDelete={id => setRules(prev => prev.filter(r => r.id !== id))}
            />
          ))}
        </div>
      )}

      {/* Modal */}
      {showModal && (
        <YaraRuleModal
          rule={editRule}
          openAI={modalOpenAI}
          onClose={() => { setShowModal(false); setEditRule(null); setModalOpenAI(false) }}
          onSaved={saved => {
            if (editRule?.id) {
              setRules(prev => prev.map(r => r.id === saved.id ? saved : r))
            } else {
              setRules(prev => [saved, ...prev])
            }
          }}
        />
      )}
    </div>
  )
}
