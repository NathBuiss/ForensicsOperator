import { useState, useEffect } from 'react'
import { Settings2, Sparkles, Check, X, Loader2, Trash2, Eye, EyeOff, AlertCircle, Wifi } from 'lucide-react'
import { api } from '../api/client'

const PROVIDERS = [
  {
    id: 'openai',
    name: 'OpenAI',
    placeholder_model: 'gpt-4o',
    needs_key: true,
    default_url: '',
    hint: 'gpt-4o, gpt-4-turbo, gpt-4o-mini, gpt-3.5-turbo',
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    placeholder_model: 'claude-3-5-sonnet-20241022',
    needs_key: true,
    default_url: '',
    hint: 'claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5-20251001',
  },
  {
    id: 'ollama',
    name: 'Ollama (local)',
    placeholder_model: 'llama3',
    needs_key: false,
    default_url: 'http://localhost:11434',
    hint: 'llama3, mistral, gemma2, codellama — any model pulled in Ollama',
  },
  {
    id: 'custom',
    name: 'Custom (OpenAI-compatible)',
    placeholder_model: 'local-model',
    needs_key: true,
    key_optional: true,
    default_url: 'http://localhost:8000/v1',
    hint: 'LiteLLM, vLLM, LM Studio, LocalAI, Jan — any /chat/completions endpoint',
  },
]

export default function Settings() {
  const [config, setConfig]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)
  const [saved, setSaved]     = useState(false)
  const [error, setError]     = useState('')
  const [showKey, setShowKey]         = useState(false)
  const [testing, setTesting]         = useState(false)
  const [testResult, setTestResult]   = useState(null)  // null | {ok, response} | {error}

  const [form, setForm] = useState({
    provider: 'openai',
    model: '',
    api_key: '',
    base_url: '',
    enabled: true,
  })

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  useEffect(() => {
    api.llm.getConfig()
      .then(cfg => {
        setConfig(cfg)
        if (cfg.provider) {
          setForm({
            provider: cfg.provider,
            model:    cfg.model || '',
            api_key:  '',           // never pre-fill the key
            base_url: cfg.base_url || '',
            enabled:  cfg.enabled,
          })
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  async function save(e) {
    e.preventDefault()
    setSaving(true)
    setError('')
    setSaved(false)
    try {
      const updated = await api.llm.updateConfig({
        ...form,
        enabled: true,
      })
      setConfig(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  async function clearConfig() {
    if (!confirm('Remove LLM configuration?')) return
    try {
      await api.llm.clearConfig()
      setConfig({ provider: '', model: '', api_key_set: false, base_url: '', enabled: false })
      setForm({ provider: 'openai', model: '', api_key: '', base_url: '', enabled: true })
    } catch (err) {
      setError(err.message)
    }
  }

  async function testConnection() {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await api.llm.testConfig()
      setTestResult({ ok: true, response: res.response })
    } catch (err) {
      setTestResult({ ok: false, error: err.message })
    } finally {
      setTesting(false)
    }
  }

  const provider = PROVIDERS.find(p => p.id === form.provider) || PROVIDERS[0]

  return (
    <div className="p-6 max-w-2xl">
      <div className="mb-6">
        <div className="flex items-center gap-2.5 mb-1">
          <Settings2 size={20} className="text-brand-accent" />
          <h1 className="text-xl font-bold text-brand-text">Settings</h1>
        </div>
        <p className="text-sm text-gray-500">Platform configuration for administrators.</p>
      </div>

      {/* AI Analysis section */}
      <section className="card p-5 space-y-4">
        <div className="flex items-center gap-2">
          <Sparkles size={15} className="text-purple-500" />
          <h2 className="font-semibold text-brand-text">AI Analysis</h2>
          {!loading && config?.provider && (
            <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
              <Check size={10} /> Configured
            </span>
          )}
        </div>

        <p className="text-xs text-gray-500">
          Connect an LLM to enable the <strong className="text-brand-text">"Analyze with AI"</strong> button
          on module run results. The AI reads your detections and produces a structured forensic report
          (severity, timeline, IOCs, MITRE techniques, recommendations).
        </p>

        {loading ? (
          <div className="flex items-center gap-2 text-gray-400 py-4">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : (
          <form onSubmit={save} className="space-y-4">
            {/* Provider */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Provider</label>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {PROVIDERS.map(p => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => {
                      set('provider', p.id)
                      set('base_url', p.default_url || '')
                    }}
                    className={`relative text-xs py-2 px-3 rounded-lg border transition-colors text-left font-medium ${
                      form.provider === p.id
                        ? 'bg-brand-accent text-white border-brand-accent'
                        : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
                    }`}
                  >
                    {p.name}
                    {config?.provider === p.id && (
                      <span
                        className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-green-400 border-2 border-white"
                        title="Currently saved"
                      />
                    )}
                  </button>
                ))}
              </div>
              {provider.hint && (
                <p className="text-[10px] text-gray-400 mt-1">{provider.hint}</p>
              )}
            </div>

            {/* Model */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Model</label>
              <input
                className="input text-xs"
                placeholder={provider.placeholder_model}
                value={form.model}
                onChange={e => set('model', e.target.value)}
                required
              />
            </div>

            {/* API Key */}
            {provider.needs_key && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  API Key
                  {provider.key_optional && <span className="ml-1 text-gray-400 font-normal">(optional — for authenticated endpoints)</span>}
                  {!provider.key_optional && config?.api_key_set && (
                    <span className="ml-1 text-green-600 font-normal">(key already set — leave blank to keep)</span>
                  )}
                  {!provider.key_optional && !config?.api_key_set && null}
                  {provider.key_optional && config?.api_key_set && (
                    <span className="ml-1 text-green-600 font-normal">(key set — leave blank to keep)</span>
                  )}
                </label>
                <div className="relative">
                  <input
                    type={showKey ? 'text' : 'password'}
                    className="input text-xs pr-8"
                    placeholder={config?.api_key_set ? '••••••••••••••••' : 'sk-…'}
                    value={form.api_key}
                    onChange={e => set('api_key', e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showKey ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
              </div>
            )}

            {/* Base URL — required for Ollama / Custom; optional override for OpenAI / Anthropic */}
            {(provider.id === 'ollama' || provider.id === 'custom') && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Base URL</label>
                <input
                  className="input text-xs font-mono"
                  placeholder={provider.default_url}
                  value={form.base_url}
                  onChange={e => set('base_url', e.target.value)}
                  required
                />
              </div>
            )}
            {(provider.id === 'openai' || provider.id === 'anthropic') && form.base_url && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  Base URL
                  <span className="text-gray-400 font-normal ml-1">(optional — override default endpoint)</span>
                </label>
                <input
                  className="input text-xs font-mono"
                  placeholder="https://api.openai.com/v1"
                  value={form.base_url}
                  onChange={e => set('base_url', e.target.value)}
                />
              </div>
            )}

            {error && (
              <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                <AlertCircle size={12} /> {error}
              </p>
            )}

            <div className="flex items-center gap-2 flex-wrap">
              <button type="submit" disabled={saving} className="btn-primary text-xs">
                {saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                Save
              </button>
              {config?.provider && (
                <button
                  type="button"
                  onClick={testConnection}
                  disabled={testing}
                  className="btn-outline text-xs"
                >
                  {testing ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />}
                  Test Connection
                </button>
              )}
              {saved && (
                <span className="text-xs text-green-600 flex items-center gap-1">
                  <Check size={11} /> Saved
                </span>
              )}
              {config?.provider && (
                <button
                  type="button"
                  onClick={clearConfig}
                  className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto"
                >
                  <Trash2 size={12} /> Remove
                </button>
              )}
            </div>

            {testResult && (
              testResult.ok ? (
                <div className="text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                  <Check size={12} className="mt-0.5 flex-shrink-0" />
                  <span><strong>Connected.</strong> Model replied: <em className="font-mono">{testResult.response}</em></span>
                </div>
              ) : (
                <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                  <X size={12} className="mt-0.5 flex-shrink-0" />
                  <span><strong>Failed:</strong> {testResult.error}</span>
                </div>
              )
            )}
          </form>
        )}
      </section>
    </div>
  )
}
