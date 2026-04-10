import { useState, useEffect } from 'react'
import {
  Settings2, Sparkles, Check, X, Loader2, Trash2, Eye, EyeOff,
  AlertCircle, Wifi, HardDrive, FlaskConical, Cpu, Info,
  Shield, Lock,
} from 'lucide-react'
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

const S3_VENDORS = [
  { id: 'aws',       name: 'AWS S3' },
  { id: 'scaleway',  name: 'Scaleway' },
  { id: 'minio',     name: 'MinIO' },
  { id: 'wasabi',    name: 'Wasabi' },
  { id: 'gcs',       name: 'GCS' },
  { id: 'other',     name: 'Other' },
]

const SCALEWAY_REGIONS = [
  { region: 'nl-ams', endpoint: 's3.nl-ams.scw.cloud', label: 'Amsterdam (nl-ams)' },
  { region: 'fr-par', endpoint: 's3.fr-par.scw.cloud', label: 'Paris (fr-par)' },
  { region: 'pl-waw', endpoint: 's3.pl-waw.scw.cloud', label: 'Warsaw (pl-waw)' },
]

function scwEndpointPlaceholder(vendor) {
  if (vendor === 'aws')      return 's3.amazonaws.com'
  if (vendor === 'scaleway') return 's3.nl-ams.scw.cloud'
  if (vendor === 'wasabi')   return 's3.wasabisys.com'
  if (vendor === 'gcs')      return 'storage.googleapis.com'
  return 'minio.example.com:9000'
}

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

  // ── S3 Storage state ──────────────────────────────────────────────────────
  const [s3Config, setS3Config]       = useState(null)
  const [s3Loading, setS3Loading]     = useState(true)
  const [s3Saving, setS3Saving]       = useState(false)
  const [s3Saved, setS3Saved]         = useState(false)
  const [s3Error, setS3Error]         = useState('')
  const [s3ShowKey, setS3ShowKey]     = useState(false)
  const [s3Testing, setS3Testing]     = useState(false)
  const [s3TestResult, setS3TestResult] = useState(null)

  const [s3Form, setS3Form] = useState({
    vendor: 'aws',
    endpoint: '',
    access_key: '',
    secret_key: '',
    bucket: '',
    region: '',
    use_ssl: true,
  })

  const setS3 = (k, v) => setS3Form(f => ({ ...f, [k]: v }))

  // ── Triage Upload S3 state ─────────────────────────────────────────────────
  const [s3TriageConfig, setS3TriageConfig]         = useState(null)
  const [s3TriageLoading, setS3TriageLoading]       = useState(true)
  const [s3TriageSaving, setS3TriageSaving]         = useState(false)
  const [s3TriageSaved, setS3TriageSaved]           = useState(false)
  const [s3TriageError, setS3TriageError]           = useState('')
  const [s3TriageShowKey, setS3TriageShowKey]       = useState(false)
  const [s3TriageTesting, setS3TriageTesting]       = useState(false)
  const [s3TriageTestResult, setS3TriageTestResult] = useState(null)

  const [s3TriageForm, setS3TriageForm] = useState({
    vendor: 'scaleway',
    endpoint: '',
    access_key: '',
    secret_key: '',
    bucket: '',
    region: 'nl-ams',
    use_ssl: true,
  })

  const setS3Triage = (k, v) => setS3TriageForm(f => ({ ...f, [k]: v }))

  // ── Cuckoo Sandbox config state ────────────────────────────────────────────
  const [cuckooConfig, setCuckooConfig]         = useState(null)
  const [cuckooLoading, setCuckooLoading]       = useState(true)
  const [cuckooSaving, setCuckooSaving]         = useState(false)
  const [cuckooSaved, setCuckooSaved]           = useState(false)
  const [cuckooError, setCuckooError]           = useState('')
  const [showCuckooToken, setShowCuckooToken]   = useState(false)
  const [cuckooForm, setCuckooForm]             = useState({ api_url: '', api_token: '' })
  const setCuckoo = (k, v) => setCuckooForm(f => ({ ...f, [k]: v }))

  // ── VirusTotal / malwoverview config state ──────────────────────────────────
  const [vtConfig, setVtConfig]     = useState(null)
  const [vtLoading, setVtLoading]   = useState(true)
  const [vtSaving, setVtSaving]     = useState(false)
  const [vtSaved, setVtSaved]       = useState(false)
  const [vtError, setVtError]       = useState('')
  const [showVtKey, setShowVtKey]   = useState(false)
  const [vtForm, setVtForm]         = useState({ vt_api_key: '' })
  const setVt = (k, v) => setVtForm(f => ({ ...f, [k]: v }))

  // ── Worker metrics state ────────────────────────────────────────────────────
  const [workerMetrics, setWorkerMetrics] = useState(null)

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  useEffect(() => {
    // Load S3 import config
    api.s3.getConfig()
      .then(cfg => {
        setS3Config(cfg)
        if (cfg.endpoint) {
          setS3Form({
            vendor:     cfg.vendor || 'aws',
            endpoint:   cfg.endpoint || '',
            access_key: cfg.access_key || '',
            secret_key: '',
            bucket:     cfg.bucket || '',
            region:     cfg.region || '',
            use_ssl:    cfg.use_ssl !== false,
          })
        }
      })
      .catch(() => {})
      .finally(() => setS3Loading(false))

    // Load S3 triage config
    api.s3Triage.getConfig()
      .then(cfg => {
        setS3TriageConfig(cfg)
        if (cfg.endpoint) {
          setS3TriageForm({
            vendor:     cfg.vendor || 'scaleway',
            endpoint:   cfg.endpoint || '',
            access_key: cfg.access_key || '',
            secret_key: '',
            bucket:     cfg.bucket || '',
            region:     cfg.region || 'nl-ams',
            use_ssl:    cfg.use_ssl !== false,
          })
        }
      })
      .catch(() => {})
      .finally(() => setS3TriageLoading(false))

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

    // Load Cuckoo config
    api.cuckooConfig.get()
      .then(cfg => {
        setCuckooConfig(cfg)
        if (cfg.api_url) setCuckooForm(f => ({ ...f, api_url: cfg.api_url }))
      })
      .catch(() => {})
      .finally(() => setCuckooLoading(false))

    // Load VirusTotal / malwoverview config
    api.mwoConfig.get()
      .then(cfg => setVtConfig(cfg))
      .catch(() => {})
      .finally(() => setVtLoading(false))

    // Load worker metrics (from existing /metrics/dashboard)
    api.metrics.dashboard()
      .then(m => setWorkerMetrics(m))
      .catch(() => {})
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

  // ── S3 handlers ─────────────────────────────────────────────────────────
  async function saveS3(e) {
    e.preventDefault()
    setS3Saving(true)
    setS3Error('')
    setS3Saved(false)
    try {
      const updated = await api.s3.setConfig(s3Form)
      setS3Config(updated)
      setS3Saved(true)
      setTimeout(() => setS3Saved(false), 3000)
    } catch (err) {
      setS3Error(err.message)
    } finally {
      setS3Saving(false)
    }
  }

  async function clearS3() {
    if (!confirm('Remove S3 storage configuration?')) return
    try {
      await api.s3.clearConfig()
      setS3Config({ endpoint: '', access_key: '', secret_key_set: false, bucket: '', region: '', vendor: 'aws', use_ssl: true })
      setS3Form({ vendor: 'aws', endpoint: '', access_key: '', secret_key: '', bucket: '', region: '', use_ssl: true })
      setS3TestResult(null)
    } catch (err) {
      setS3Error(err.message)
    }
  }

  async function testS3() {
    setS3Testing(true)
    setS3TestResult(null)
    try {
      const res = await api.s3.testConfig()
      setS3TestResult({ ok: true, message: res.message })
    } catch (err) {
      setS3TestResult({ ok: false, error: err.message })
    } finally {
      setS3Testing(false)
    }
  }

  // ── Triage S3 handlers ───────────────────────────────────────────────────
  async function saveS3Triage(e) {
    e.preventDefault()
    setS3TriageSaving(true)
    setS3TriageError('')
    setS3TriageSaved(false)
    try {
      const updated = await api.s3Triage.setConfig(s3TriageForm)
      setS3TriageConfig(updated)
      setS3TriageSaved(true)
      setTimeout(() => setS3TriageSaved(false), 3000)
    } catch (err) {
      setS3TriageError(err.message)
    } finally {
      setS3TriageSaving(false)
    }
  }

  async function clearS3Triage() {
    if (!confirm('Remove Triage Upload Storage configuration?')) return
    try {
      await api.s3Triage.clearConfig()
      setS3TriageConfig({ endpoint: '', access_key: '', secret_key_set: false, bucket: '', region: '', vendor: 'scaleway', use_ssl: true })
      setS3TriageForm({ vendor: 'scaleway', endpoint: '', access_key: '', secret_key: '', bucket: '', region: 'nl-ams', use_ssl: true })
      setS3TriageTestResult(null)
    } catch (err) {
      setS3TriageError(err.message)
    }
  }

  async function testS3Triage() {
    setS3TriageTesting(true)
    setS3TriageTestResult(null)
    try {
      const res = await api.s3Triage.testConfig()
      setS3TriageTestResult({ ok: true, message: res.message })
    } catch (err) {
      setS3TriageTestResult({ ok: false, error: err.message })
    } finally {
      setS3TriageTesting(false)
    }
  }

  // ── Cuckoo handlers ────────────────────────────────────────────────────────
  async function saveCuckoo(e) {
    e.preventDefault()
    setCuckooSaving(true)
    setCuckooError('')
    setCuckooSaved(false)
    try {
      const updated = await api.cuckooConfig.set(cuckooForm)
      setCuckooConfig(updated)
      setCuckooSaved(true)
      setTimeout(() => setCuckooSaved(false), 3000)
    } catch (err) {
      setCuckooError(err.message)
    } finally {
      setCuckooSaving(false)
    }
  }

  async function clearCuckoo() {
    if (!confirm('Remove Cuckoo Sandbox configuration?')) return
    try {
      await api.cuckooConfig.clear()
      setCuckooConfig({ api_url: '', api_token_set: false, configured: false })
      setCuckooForm({ api_url: '', api_token: '' })
    } catch (err) {
      setCuckooError(err.message)
    }
  }

  // ── VirusTotal / malwoverview handlers ──────────────────────────────────────
  async function saveVt(e) {
    e.preventDefault()
    setVtSaving(true)
    setVtError('')
    setVtSaved(false)
    try {
      const updated = await api.mwoConfig.set(vtForm)
      setVtConfig(updated)
      setVtSaved(true)
      setTimeout(() => setVtSaved(false), 3000)
    } catch (err) {
      setVtError(err.message)
    } finally {
      setVtSaving(false)
    }
  }

  async function clearVt() {
    if (!confirm('Remove VirusTotal API key?')) return
    try {
      await api.mwoConfig.clear()
      setVtConfig({ vt_api_key_set: false, configured: false })
      setVtForm({ vt_api_key: '' })
    } catch (err) {
      setVtError(err.message)
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

      {/* Triage Upload Storage section */}
      <section className="card p-5 space-y-4 mt-6">
        <div className="flex items-center gap-2">
          <HardDrive size={15} className="text-orange-500" />
          <h2 className="font-semibold text-brand-text">Triage Upload Storage</h2>
          {!s3TriageLoading && s3TriageConfig?.endpoint && (
            <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
              <Check size={10} /> Configured
            </span>
          )}
        </div>

        <p className="text-xs text-gray-500">
          The bucket where <strong className="text-brand-text">collector agents push triage archives</strong> (ZIPs,
          memory dumps, disk images). Analysts browse this bucket from the case view and pull relevant archives
          into a case for processing. Supports Scaleway Object Storage, AWS S3, MinIO, and others.
        </p>

        {s3TriageLoading ? (
          <div className="flex items-center gap-2 text-gray-400 py-4">
            <Loader2 size={14} className="animate-spin" /> Loading...
          </div>
        ) : (
          <form onSubmit={saveS3Triage} className="space-y-4">
            {/* Vendor */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Vendor</label>
              <div className="flex flex-wrap gap-2">
                {S3_VENDORS.map(v => (
                  <button
                    key={v.id}
                    type="button"
                    onClick={() => setS3Triage('vendor', v.id)}
                    className={`text-xs py-2 px-3 rounded-lg border transition-colors font-medium ${
                      s3TriageForm.vendor === v.id
                        ? 'bg-brand-accent text-white border-brand-accent'
                        : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
                    }`}
                  >
                    {v.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Scaleway region selector (auto-fills endpoint) */}
            {s3TriageForm.vendor === 'scaleway' && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Region</label>
                <div className="flex flex-wrap gap-2">
                  {SCALEWAY_REGIONS.map(r => (
                    <button
                      key={r.region}
                      type="button"
                      onClick={() => {
                        setS3Triage('region', r.region)
                        setS3Triage('endpoint', r.endpoint)
                      }}
                      className={`text-xs py-2 px-3 rounded-lg border transition-colors font-medium ${
                        s3TriageForm.region === r.region
                          ? 'bg-blue-600 text-white border-blue-600'
                          : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
                      }`}
                    >
                      {r.label}
                    </button>
                  ))}
                </div>
                <p className="text-[10px] text-gray-400 mt-1">
                  Selecting a region auto-fills the endpoint below.
                </p>
              </div>
            )}

            {/* Endpoint URL */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Endpoint URL</label>
              <input
                className="input text-xs font-mono"
                placeholder={scwEndpointPlaceholder(s3TriageForm.vendor)}
                value={s3TriageForm.endpoint}
                onChange={e => setS3Triage('endpoint', e.target.value)}
                required
              />
            </div>

            {/* Access Key */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Access Key</label>
              <input
                className="input text-xs font-mono"
                placeholder="AKIAIOSFODNN7EXAMPLE"
                value={s3TriageForm.access_key}
                onChange={e => setS3Triage('access_key', e.target.value)}
                required
              />
            </div>

            {/* Secret Key */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                Secret Key
                {s3TriageConfig?.secret_key_set && (
                  <span className="ml-1 text-green-600 font-normal">(key set — leave blank to keep)</span>
                )}
              </label>
              <div className="relative">
                <input
                  type={s3TriageShowKey ? 'text' : 'password'}
                  className="input text-xs pr-8 font-mono"
                  placeholder={s3TriageConfig?.secret_key_set ? '••••••••••••••••' : 'wJalrXUtnFEMI/K7MDENG/bPxR...'}
                  value={s3TriageForm.secret_key}
                  onChange={e => setS3Triage('secret_key', e.target.value)}
                />
                <button
                  type="button"
                  onClick={() => setS3TriageShowKey(v => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {s3TriageShowKey ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
            </div>

            {/* Bucket + Region (non-Scaleway) */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Bucket Name</label>
                <input
                  className="input text-xs font-mono"
                  placeholder="triage-uploads"
                  value={s3TriageForm.bucket}
                  onChange={e => setS3Triage('bucket', e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  Region <span className="text-gray-400 font-normal">{s3TriageForm.vendor === 'scaleway' ? '(set above)' : '(optional)'}</span>
                </label>
                <input
                  className="input text-xs font-mono"
                  placeholder={s3TriageForm.vendor === 'scaleway' ? 'nl-ams' : 'us-east-1'}
                  value={s3TriageForm.region}
                  onChange={e => setS3Triage('region', e.target.value)}
                  readOnly={s3TriageForm.vendor === 'scaleway'}
                />
              </div>
            </div>

            {/* Use SSL */}
            <label className="flex items-center gap-2 text-xs text-gray-600 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={s3TriageForm.use_ssl}
                onChange={e => setS3Triage('use_ssl', e.target.checked)}
                className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
              />
              Use SSL / HTTPS
            </label>

            {s3TriageError && (
              <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                <AlertCircle size={12} /> {s3TriageError}
              </p>
            )}

            <div className="flex items-center gap-2 flex-wrap">
              <button type="submit" disabled={s3TriageSaving} className="btn-primary text-xs">
                {s3TriageSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                Save
              </button>
              {s3TriageConfig?.endpoint && (
                <button
                  type="button"
                  onClick={testS3Triage}
                  disabled={s3TriageTesting}
                  className="btn-outline text-xs"
                >
                  {s3TriageTesting ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />}
                  Test Connection
                </button>
              )}
              {s3TriageSaved && (
                <span className="text-xs text-green-600 flex items-center gap-1">
                  <Check size={11} /> Saved
                </span>
              )}
              {s3TriageConfig?.endpoint && (
                <button
                  type="button"
                  onClick={clearS3Triage}
                  className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto"
                >
                  <Trash2 size={12} /> Remove
                </button>
              )}
            </div>

            {s3TriageTestResult && (
              s3TriageTestResult.ok ? (
                <div className="text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                  <Check size={12} className="mt-0.5 flex-shrink-0" />
                  <span><strong>Connected.</strong> {s3TriageTestResult.message}</span>
                </div>
              ) : (
                <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                  <X size={12} className="mt-0.5 flex-shrink-0" />
                  <span><strong>Failed:</strong> {s3TriageTestResult.error}</span>
                </div>
              )
            )}
          </form>
        )}
      </section>

      {/* Case Data Import S3 section */}
      <section className="card p-5 space-y-4 mt-6">
        <div className="flex items-center gap-2">
          <HardDrive size={15} className="text-blue-500" />
          <h2 className="font-semibold text-brand-text">Case Data Import Storage</h2>
          {!s3Loading && s3Config?.endpoint && (
            <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
              <Check size={10} /> Configured
            </span>
          )}
        </div>

        <p className="text-xs text-gray-500">
          Browse an existing S3-compatible bucket and <strong className="text-brand-text">pull files directly into a case</strong> for
          parsing — useful when forensic images are already stored in cloud storage (AWS S3, Scaleway,
          MinIO, Wasabi, GCS). Files stream directly to internal storage with no RAM buffer.
        </p>

        {s3Loading ? (
          <div className="flex items-center gap-2 text-gray-400 py-4">
            <Loader2 size={14} className="animate-spin" /> Loading...
          </div>
        ) : (
          <form onSubmit={saveS3} className="space-y-4">
            {/* Vendor */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Vendor</label>
              <div className="flex flex-wrap gap-2">
                {S3_VENDORS.map(v => (
                  <button
                    key={v.id}
                    type="button"
                    onClick={() => setS3('vendor', v.id)}
                    className={`text-xs py-2 px-3 rounded-lg border transition-colors font-medium ${
                      s3Form.vendor === v.id
                        ? 'bg-brand-accent text-white border-brand-accent'
                        : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
                    }`}
                  >
                    {v.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Scaleway region selector (auto-fills endpoint) */}
            {s3Form.vendor === 'scaleway' && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Region</label>
                <div className="flex flex-wrap gap-2">
                  {SCALEWAY_REGIONS.map(r => (
                    <button
                      key={r.region}
                      type="button"
                      onClick={() => {
                        setS3('region', r.region)
                        setS3('endpoint', r.endpoint)
                      }}
                      className={`text-xs py-2 px-3 rounded-lg border transition-colors font-medium ${
                        s3Form.region === r.region
                          ? 'bg-blue-600 text-white border-blue-600'
                          : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
                      }`}
                    >
                      {r.label}
                    </button>
                  ))}
                </div>
                <p className="text-[10px] text-gray-400 mt-1">
                  Selecting a region auto-fills the endpoint below.
                </p>
              </div>
            )}

            {/* Endpoint URL */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Endpoint URL</label>
              <input
                className="input text-xs font-mono"
                placeholder={scwEndpointPlaceholder(s3Form.vendor)}
                value={s3Form.endpoint}
                onChange={e => setS3('endpoint', e.target.value)}
                required
              />
            </div>

            {/* Access Key */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Access Key</label>
              <input
                className="input text-xs font-mono"
                placeholder="AKIAIOSFODNN7EXAMPLE"
                value={s3Form.access_key}
                onChange={e => setS3('access_key', e.target.value)}
                required
              />
            </div>

            {/* Secret Key */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                Secret Key
                {s3Config?.secret_key_set && (
                  <span className="ml-1 text-green-600 font-normal">(key set — leave blank to keep)</span>
                )}
              </label>
              <div className="relative">
                <input
                  type={s3ShowKey ? 'text' : 'password'}
                  className="input text-xs pr-8 font-mono"
                  placeholder={s3Config?.secret_key_set ? '••••••••••••••••' : 'wJalrXUtnFEMI/K7MDENG/bPxR...'}
                  value={s3Form.secret_key}
                  onChange={e => setS3('secret_key', e.target.value)}
                />
                <button
                  type="button"
                  onClick={() => setS3ShowKey(v => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {s3ShowKey ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
            </div>

            {/* Bucket + Region */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Bucket Name</label>
                <input
                  className="input text-xs font-mono"
                  placeholder="my-forensics-bucket"
                  value={s3Form.bucket}
                  onChange={e => setS3('bucket', e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  Region <span className="text-gray-400 font-normal">{s3Form.vendor === 'scaleway' ? '(set above)' : '(optional)'}</span>
                </label>
                <input
                  className="input text-xs font-mono"
                  placeholder={s3Form.vendor === 'scaleway' ? 'nl-ams' : 'us-east-1'}
                  value={s3Form.region}
                  onChange={e => setS3('region', e.target.value)}
                  readOnly={s3Form.vendor === 'scaleway'}
                />
              </div>
            </div>

            {/* Use SSL */}
            <label className="flex items-center gap-2 text-xs text-gray-600 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={s3Form.use_ssl}
                onChange={e => setS3('use_ssl', e.target.checked)}
                className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
              />
              Use SSL / HTTPS
            </label>

            {s3Error && (
              <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                <AlertCircle size={12} /> {s3Error}
              </p>
            )}

            <div className="flex items-center gap-2 flex-wrap">
              <button type="submit" disabled={s3Saving} className="btn-primary text-xs">
                {s3Saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                Save
              </button>
              {s3Config?.endpoint && (
                <button
                  type="button"
                  onClick={testS3}
                  disabled={s3Testing}
                  className="btn-outline text-xs"
                >
                  {s3Testing ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />}
                  Test Connection
                </button>
              )}
              {s3Saved && (
                <span className="text-xs text-green-600 flex items-center gap-1">
                  <Check size={11} /> Saved
                </span>
              )}
              {s3Config?.endpoint && (
                <button
                  type="button"
                  onClick={clearS3}
                  className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto"
                >
                  <Trash2 size={12} /> Remove
                </button>
              )}
            </div>

            {s3TestResult && (
              s3TestResult.ok ? (
                <div className="text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                  <Check size={12} className="mt-0.5 flex-shrink-0" />
                  <span><strong>Connected.</strong> {s3TestResult.message}</span>
                </div>
              ) : (
                <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                  <X size={12} className="mt-0.5 flex-shrink-0" />
                  <span><strong>Failed:</strong> {s3TestResult.error}</span>
                </div>
              )
            )}
          </form>
        )}
      </section>

      {/* ── Cuckoo Sandbox ───────────────────────────────────────────────── */}
      <section className="card p-5 space-y-4 mt-6">
        <div className="flex items-center gap-2">
          <FlaskConical size={15} className="text-orange-500" />
          <h2 className="font-semibold text-brand-text">Cuckoo Sandbox</h2>
          {!cuckooLoading && cuckooConfig?.configured && (
            <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
              <Check size={10} /> Configured
            </span>
          )}
          {!cuckooLoading && cuckooConfig?.source === 'env' && (
            <span className="text-xs text-blue-600 bg-blue-50 border border-blue-200 rounded-full px-2 py-0.5 flex items-center gap-1">
              <Info size={10} /> Via env var
            </span>
          )}
        </div>

        {/* How Cuckoo isolation works */}
        <div className="rounded-lg bg-orange-50 border border-orange-200 p-3 space-y-2">
          <p className="text-xs font-semibold text-orange-800 flex items-center gap-1.5">
            <Shield size={12} /> Isolation model
          </p>
          <p className="text-xs text-orange-700 leading-relaxed">
            Files submitted to Cuckoo <strong>never execute on this server</strong>. Our processor
            sends the file bytes to Cuckoo's REST API via HTTP, then polls for the report.
            Cuckoo runs the sample inside a <strong>fresh VM snapshot</strong> (KVM/VirtualBox guest)
            that is reset to a clean state after each task — the malware is fully contained within
            Cuckoo's infrastructure.
          </p>
          <p className="text-xs text-orange-600 leading-relaxed">
            One VM task is created per submitted file. The VM monitors API calls, network connections,
            file writes, and registry changes, then generates a behavioral report with a severity score.
          </p>
        </div>

        <p className="text-xs text-gray-500">
          Enter the URL of your Cuckoo Sandbox API. Settings saved here are stored securely in Redis
          and take effect immediately — no pod restart needed.
          If you also set <code className="bg-gray-100 px-1 rounded font-mono">CUCKOO_API_URL</code> as
          an environment variable, the UI config takes priority.
        </p>

        {cuckooLoading ? (
          <div className="flex items-center gap-2 text-gray-400 py-4">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : (
          <form onSubmit={saveCuckoo} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Cuckoo API URL</label>
              <input
                className="input text-xs font-mono"
                placeholder="http://cuckoo.internal:8090"
                value={cuckooForm.api_url}
                onChange={e => setCuckoo('api_url', e.target.value)}
                required
              />
              <p className="text-[10px] text-gray-400 mt-1">
                Default Cuckoo API port is 8090. Include the scheme and host.
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                API Token
                <span className="ml-1 text-gray-400 font-normal">(optional — only if auth is enabled on Cuckoo)</span>
                {cuckooConfig?.api_token_set && (
                  <span className="ml-1 text-green-600 font-normal">(token set — leave blank to keep)</span>
                )}
              </label>
              <div className="relative">
                <input
                  type={showCuckooToken ? 'text' : 'password'}
                  className="input text-xs pr-8 font-mono"
                  placeholder={cuckooConfig?.api_token_set ? '••••••••••••••••' : '(leave blank if no auth)'}
                  value={cuckooForm.api_token}
                  onChange={e => setCuckoo('api_token', e.target.value)}
                />
                <button
                  type="button"
                  onClick={() => setShowCuckooToken(v => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showCuckooToken ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
            </div>

            {cuckooError && (
              <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                <AlertCircle size={12} /> {cuckooError}
              </p>
            )}

            <div className="flex items-center gap-2 flex-wrap">
              <button type="submit" disabled={cuckooSaving} className="btn-primary text-xs">
                {cuckooSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                Save
              </button>
              {cuckooSaved && (
                <span className="text-xs text-green-600 flex items-center gap-1">
                  <Check size={11} /> Saved — takes effect immediately
                </span>
              )}
              {cuckooConfig?.configured && (
                <button
                  type="button"
                  onClick={clearCuckoo}
                  className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto"
                >
                  <Trash2 size={12} /> Remove
                </button>
              )}
            </div>
          </form>
        )}
      </section>

      {/* ── VirusTotal / malwoverview ────────────────────────────────────────── */}
      <section className="card p-5 space-y-4 mt-6">
        <div className="flex items-center gap-2">
          <Shield size={15} className="text-purple-500" />
          <h2 className="font-semibold text-brand-text">VirusTotal</h2>
          {!vtLoading && vtConfig?.vt_api_key_set && (
            <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
              <Check size={10} /> Configured
            </span>
          )}
          {!vtLoading && vtConfig?.source === 'env' && (
            <span className="text-xs text-blue-600 bg-blue-50 border border-blue-200 rounded-full px-2 py-0.5 flex items-center gap-1">
              <Info size={10} /> Via env var
            </span>
          )}
        </div>

        <p className="text-xs text-gray-500">
          Required by the <strong className="text-brand-text">Malwoverview</strong> module for file hash
          lookups against the VirusTotal v3 API. Enter a public (free) or private key. Stored securely
          in Redis — takes effect immediately without a restart. You can also set{' '}
          <code className="bg-gray-100 px-1 rounded font-mono">VT_API_KEY</code> as an environment variable.
        </p>

        {vtLoading ? (
          <div className="flex items-center gap-2 text-gray-400 py-4">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : (
          <form onSubmit={saveVt} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                VirusTotal API Key
                {vtConfig?.vt_api_key_set && (
                  <span className="ml-1 text-green-600 font-normal">(key set — leave blank to keep)</span>
                )}
              </label>
              <div className="relative">
                <input
                  type={showVtKey ? 'text' : 'password'}
                  className="input text-xs pr-8 font-mono"
                  placeholder={vtConfig?.vt_api_key_set ? '••••••••••••••••••••••••••••••••' : 'Enter your VirusTotal API key'}
                  value={vtForm.vt_api_key}
                  onChange={e => setVt('vt_api_key', e.target.value)}
                />
                <button
                  type="button"
                  onClick={() => setShowVtKey(v => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showVtKey ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
              <p className="text-[10px] text-gray-400 mt-1">
                Get your key at{' '}
                <a
                  href="https://www.virustotal.com/gui/my-apikey"
                  target="_blank"
                  rel="noreferrer"
                  className="text-brand-accent hover:underline"
                >
                  virustotal.com/gui/my-apikey
                </a>
              </p>
            </div>

            {vtError && (
              <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                <AlertCircle size={12} /> {vtError}
              </p>
            )}

            <div className="flex items-center gap-2 flex-wrap">
              <button type="submit" disabled={vtSaving} className="btn-primary text-xs">
                {vtSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                Save
              </button>
              {vtSaved && (
                <span className="text-xs text-green-600 flex items-center gap-1">
                  <Check size={11} /> Saved — takes effect immediately
                </span>
              )}
              {vtConfig?.vt_api_key_set && (
                <button
                  type="button"
                  onClick={clearVt}
                  className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto"
                >
                  <Trash2 size={12} /> Remove
                </button>
              )}
            </div>
          </form>
        )}
      </section>

      {/* ── Worker Performance ───────────────────────────────────────────────── */}
      <section className="card p-5 space-y-4 mt-6">
        <div className="flex items-center gap-2">
          <Cpu size={15} className="text-brand-accent" />
          <h2 className="font-semibold text-brand-text">Worker Performance</h2>
        </div>

        {/* Live metrics */}
        {workerMetrics && (
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'Active Workers', value: workerMetrics.celery?.registered_workers ?? '—' },
              { label: 'Running Tasks',  value: workerMetrics.celery?.active_tasks ?? '—' },
              { label: 'Queued Tasks',   value: (
                (workerMetrics.celery?.queue_lengths?.ingest || 0) +
                (workerMetrics.celery?.queue_lengths?.modules || 0)
              )},
            ].map(({ label, value }) => (
              <div key={label} className="bg-gray-50 rounded-lg p-3 text-center border border-gray-200">
                <p className="text-lg font-bold text-brand-text">{value}</p>
                <p className="text-[10px] text-gray-400 mt-0.5">{label}</p>
              </div>
            ))}
          </div>
        )}

        {/* Isolation model explainer */}
        <div className="rounded-lg bg-brand-accentlight border border-brand-accent/20 p-3 space-y-2">
          <p className="text-xs font-semibold text-brand-accent flex items-center gap-1.5">
            <Lock size={12} /> Sandbox isolation for custom modules
          </p>
          <p className="text-xs text-gray-600 leading-relaxed">
            Python modules you write in <strong>Studio</strong> run in a double-sandboxed child process:
            Linux resource limits (CPU time, RAM, file size, max processes), a stripped environment
            (no MinIO or Redis credentials visible), and a wall-clock kill timer.
            Built-in analysis tools (Hayabusa, YARA, ExifTool, de4dot) run as trusted binaries with
            no access to server secrets in their subprocess environment.
          </p>
        </div>

        {/* How to scale */}
        <div className="space-y-3 text-xs">
          <p className="text-gray-500 font-medium">How to increase compute capacity</p>

          <div className="space-y-2">
            {[
              {
                label: 'CELERY_CONCURRENCY',
                desc:  'Number of parallel task processes per pod. Set to the number of vCPUs you allocate. Changing this + redeploying is all you need — no image rebuild.',
                default_: '4',
              },
              {
                label: 'SANDBOX_CPU_SECONDS',
                desc:  'Max CPU time (seconds) a custom Python module can use. Default 3600 (1 h). Raise for very large memory image analysis.',
                default_: '3600',
              },
              {
                label: 'SANDBOX_MEMORY_BYTES',
                desc:  'Max RSS memory a custom Python module can allocate. Default 2 GB. Match this to the pod memory limit.',
                default_: '2147483648',
              },
              {
                label: 'SANDBOX_TIMEOUT_SEC',
                desc:  'Wall-clock timeout for a custom module subprocess. Default 30 min. Volatility3 on large images may need 45–60 min.',
                default_: '1800',
              },
            ].map(({ label, desc, default_ }) => (
              <div key={label} className="flex gap-3 items-start">
                <code className="text-[10px] font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded flex-shrink-0 mt-0.5">
                  {label}
                </code>
                <div>
                  <p className="text-gray-600">{desc}</p>
                  <p className="text-gray-400 text-[10px]">Default: {default_}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="rounded-lg bg-gray-50 border border-gray-200 p-3">
            <p className="text-gray-500 font-medium mb-1.5">Set in your K8s deployment</p>
            <pre className="text-[10px] font-mono text-gray-600 whitespace-pre-wrap leading-relaxed">{`# k8s/processor/deployment.yaml
env:
  - name: CELERY_CONCURRENCY
    value: "8"          # match to CPU limit
  - name: SANDBOX_MEMORY_BYTES
    value: "4294967296" # 4 GB for Volatility3
resources:
  limits:
    cpu: "8"
    memory: "12Gi"`}</pre>
          </div>
        </div>
      </section>
    </div>
  )
}
