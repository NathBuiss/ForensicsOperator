const BASE = '/api/v1'

const TOKEN_KEY = 'fo_token'

export function getToken()           { return localStorage.getItem(TOKEN_KEY) }
export function setToken(t)          { localStorage.setItem(TOKEN_KEY, t) }
export function clearToken()         { localStorage.removeItem(TOKEN_KEY) }
export function isAuthenticated()    { return !!getToken() }

// Called by App when the server responds 401 — clears state and reloads to /login
function _handle401() {
  clearToken()
  // Hard reload so React router re-evaluates the auth gate cleanly
  window.location.href = '/login'
}

async function request(method, path, body, options = {}) {
  const url     = `${BASE}${path}`
  const token   = getToken()
  const headers = body instanceof FormData
    ? {}
    : { 'Content-Type': 'application/json' }

  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(url, {
    method,
    headers,
    body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
    ...options,
  })

  if (res.status === 401) {
    _handle401()
    // Return a never-resolving promise so callers don't continue after redirect
    return new Promise(() => {})
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  if (res.status === 204) return null
  return res.json()
}

// Cases
export const api = {
  cases: {
    list:   ()           => request('GET',    '/cases'),
    get:    (id)         => request('GET',    `/cases/${id}`),
    create: (data)       => request('POST',   '/cases', data),
    update: (id, data)   => request('PUT',    `/cases/${id}`, data),
    delete: (id)         => request('DELETE', `/cases/${id}`),
  },

  ingest: {
    upload:   (caseId, formData) => request('POST', `/cases/${caseId}/ingest`, formData),
    listJobs: (caseId)           => request('GET',  `/cases/${caseId}/jobs`),
    getJob:   (jobId)            => request('GET',  `/jobs/${jobId}`),
    retryJob: (jobId)            => request('POST', `/jobs/${jobId}/retry`),
  },

  search: {
    timeline: (caseId, params = {}) => {
      const q = new URLSearchParams(params).toString()
      return request('GET', `/cases/${caseId}/timeline${q ? '?' + q : ''}`)
    },
    search: (caseId, params = {}) => {
      const q = new URLSearchParams(params).toString()
      return request('GET', `/cases/${caseId}/search${q ? '?' + q : ''}`)
    },
    facets: (caseId, params = {}) => {
      const q = new URLSearchParams(params).toString()
      return request('GET', `/cases/${caseId}/search/facets${q ? '?' + q : ''}`)
    },
    getEvent:  (caseId, foId)        => request('GET', `/cases/${caseId}/events/${foId}`),
    tagEvent:  (caseId, foId, tags)  => request('PUT', `/cases/${caseId}/events/${foId}/tag`,  { tags }),
    flagEvent: (caseId, foId)        => request('PUT', `/cases/${caseId}/events/${foId}/flag`),
    noteEvent: (caseId, foId, note)  => request('PUT', `/cases/${caseId}/events/${foId}/note`, { note }),
  },

  plugins: {
    list:   ()         => request('GET',  '/plugins'),
    reload: ()         => request('POST', '/plugins/reload'),
    upload: (formData) => request('POST', '/plugins/upload', formData),
  },

  health: {
    ready: () => request('GET', '/health/ready'),
  },

  auth: {
    me:             ()               => request('GET',    '/auth/me'),
    login:          (data)           => request('POST',   '/auth/login', data),
    listUsers:      ()               => request('GET',    '/auth/users'),
    createUser:     (data)           => request('POST',   '/auth/users', data),
    updateUser:     (username, data)  => request('PUT',    `/auth/users/${username}`, data),
    deleteUser:     (username)        => request('DELETE', `/auth/users/${username}`),
    changePassword: (data)           => request('PUT',    '/auth/me/password', data),
  },

  savedSearches: {
    list:   (caseId)       => request('GET',    `/cases/${caseId}/saved-searches`),
    create: (caseId, data) => request('POST',   `/cases/${caseId}/saved-searches`, data),
    delete: (caseId, id)   => request('DELETE', `/cases/${caseId}/saved-searches/${id}`),
  },

  alertRules: {
    list:            (caseId)         => request('GET',    `/cases/${caseId}/alert-rules`),
    create:          (caseId, data)   => request('POST',   `/cases/${caseId}/alert-rules`, data),
    delete:          (caseId, id)     => request('DELETE', `/cases/${caseId}/alert-rules/${id}`),
    check:           (caseId)         => request('POST',   `/cases/${caseId}/alert-rules/check`),
    listLibrary:     ()               => request('GET',    '/alert-rules/library'),
    createLibraryRule: (data)         => request('POST',   '/alert-rules/library', data),
    updateLibraryRule: (id, data)     => request('PUT',    `/alert-rules/library/${id}`, data),
    deleteLibraryRule: (id)           => request('DELETE', `/alert-rules/library/${id}`),
    seedLibrary:     (replace=false)  => request('POST',   `/alert-rules/library/seed?replace=${replace}`),
    runLibrary:      (caseId)         => request('POST',   `/cases/${caseId}/alert-rules/run-library`),
    runSingleRule:   (caseId, ruleId) => request('POST',   `/cases/${caseId}/alert-rules/library/${ruleId}/run`),
    importSigma:     (data)           => request('POST',   '/alert-rules/library/sigma', data),
    getLibraryRule:  (id)             => request('GET',    `/alert-rules/library/${id}`),
    generateRule:    (data)           => request('POST',   '/alert-rules/generate', data),
    analyzeResult:   (data)           => request('POST',   '/alert-rules/analyze', data),
    parseSigma:      (data)           => request('POST',   '/alert-rules/sigma/parse', data),
  },

  export: {
    csv: (caseId, params = {}) => {
      const q     = new URLSearchParams(params).toString()
      const token = getToken()
      // Append token as query param since this opens in a new tab (no headers)
      const auth  = token ? `&_token=${encodeURIComponent(token)}` : ''
      return `/api/v1/cases/${caseId}/export/csv${q ? '?' + q : ''}${auth}`
    },
  },

  modules: {
    list:         ()             => request('GET',  '/modules'),
    listSources:  (caseId)       => request('GET',  `/cases/${caseId}/sources`),
    createRun:    (caseId, data) => request('POST', `/cases/${caseId}/module-runs`, data),
    listRuns:     (caseId)       => request('GET',  `/cases/${caseId}/module-runs`),
    getRun:       (runId)        => request('GET',  `/module-runs/${runId}`),
    validateYara: (rules)        => request('POST', '/modules/yara/validate', { rules }),
    analyze:      (runId)        => request('POST', `/module-runs/${runId}/analyze`),
  },

  llm: {
    getConfig:         ()     => request('GET',    '/admin/llm-config'),
    updateConfig:      (data) => request('PUT',    '/admin/llm-config', data),
    clearConfig:       ()     => request('DELETE', '/admin/llm-config'),
    testConfig:        ()     => request('POST',   '/admin/llm-config/test'),
    analyzeModuleRun:  (runId)     => request('POST', `/module-runs/${runId}/analyze`),
    analyzeAlertRule:  (data)      => request('POST', '/alert-rules/analyze', data),
    explainEvents:     (data)      => request('POST', '/events/explain', data),
    generateRule:      (data)      => request('POST', '/alert-rules/generate', data),
    searchAssist:      (data)      => request('POST', '/search/ai-assist', data),
  },

  editor: {
    listIngesters:        ()            => request('GET',    '/editor/ingesters'),
    getIngester:          (name)        => request('GET',    `/editor/ingesters/${name}`),
    saveIngester:         (name, data)  => request('PUT',    `/editor/ingesters/${name}`, data),
    deleteIngester:       (name)        => request('DELETE', `/editor/ingesters/${name}`),
    listModules:          ()            => request('GET',    '/editor/modules'),
    getModule:            (name)        => request('GET',    `/editor/modules/${name}`),
    saveModule:           (name, data)  => request('PUT',    `/editor/modules/${name}`, data),
    deleteModule:         (name)        => request('DELETE', `/editor/modules/${name}`),
    validate:             (code)        => request('POST',   '/editor/validate', { code }),
    // Built-in ingester plugin files (editable)
    listBuiltinIngesters: ()            => request('GET',    '/editor/builtin-ingesters'),
    getBuiltinIngester:   (name)        => request('GET',    `/editor/builtin-ingesters/${name}`),
    saveBuiltinIngester:  (name, data)  => request('PUT',    `/editor/builtin-ingesters/${name}`, data),
    deleteBuiltinIngester:(name)        => request('DELETE', `/editor/builtin-ingesters/${name}`),
    // Built-in module YAML registry files (editable)
    listBuiltinModules:   ()            => request('GET',    '/editor/builtin-modules'),
    getBuiltinModule:     (name)        => request('GET',    `/editor/builtin-modules/${name}`),
    saveBuiltinModule:    (name, data)  => request('PUT',    `/editor/builtin-modules/${name}`, data),
    deleteBuiltinModule:  (name)        => request('DELETE', `/editor/builtin-modules/${name}`),
  },

  s3: {
    getConfig:    ()             => request('GET',    '/admin/s3-config'),
    setConfig:    (data)         => request('PUT',    '/admin/s3-config', data),
    clearConfig:  ()             => request('DELETE', '/admin/s3-config'),
    testConfig:   ()             => request('POST',   '/admin/s3-config/test'),
    browse:       (prefix = '', delimiter = '/') => request('GET', `/s3/browse?prefix=${encodeURIComponent(prefix)}&delimiter=${encodeURIComponent(delimiter)}`),
    importToCase: (caseId, data) => request('POST',   `/cases/${caseId}/s3-import`, data),
  },

  metrics: {
    dashboard: () => request('GET', '/metrics/dashboard'),
  },

  cti: {
    listFeeds:    () => request('GET', '/cti/feeds'),
    addFeed:      (data) => request('POST', '/cti/feeds', data),
    updateFeed:   (id, data) => request('PUT', `/cti/feeds/${id}`, data),
    deleteFeed:   (id) => request('DELETE', `/cti/feeds/${id}`),
    pullFeed:     (id) => request('POST', `/cti/feeds/${id}/pull`),
    importBundle: (data) => request('POST', '/cti/import', data),
    listIOCs:     (params = {}) => { const q = new URLSearchParams(params).toString(); return request('GET', `/cti/iocs${q ? '?' + q : ''}`) },
    iocStats:     () => request('GET', '/cti/iocs/stats'),
    clearIOCs:    () => request('DELETE', '/cti/iocs'),
    matchCase:    (caseId) => request('POST', `/cases/${caseId}/cti/match`),
  },

  malware: {
    uploadFile: (formData) => request('POST', '/malware-analysis/upload', formData),
    createRun:  (data)     => request('POST', '/malware-analysis/runs', data),
    listRuns:   ()         => request('GET',  '/malware-analysis/runs'),
  },

  cuckooConfig: {
    get:   ()     => request('GET',    '/admin/cuckoo-config'),
    set:   (data) => request('PUT',    '/admin/cuckoo-config', data),
    clear: ()     => request('DELETE', '/admin/cuckoo-config'),
  },

  mwoConfig: {
    get:   ()     => request('GET',    '/admin/malwoverview-config'),
    set:   (data) => request('PUT',    '/admin/malwoverview-config', data),
    clear: ()     => request('DELETE', '/admin/malwoverview-config'),
  },

  collector: {
    downloadUrl: ({ platform = 'py', caseId, apiUrl, collect } = {}) => {
      const params = new URLSearchParams({ platform })
      if (caseId)  params.set('case_id',  caseId)
      if (apiUrl)  params.set('api_url',  apiUrl)
      if (collect && collect.length > 0) params.set('collect', collect.join(','))
      // _token  → authenticates the download request (read by auth dependency)
      // api_token → embedded in the script so it can upload artifacts without prompting
      const token = getToken()
      if (token) {
        params.set('_token',    token)
        params.set('api_token', token)
      }
      return `/api/v1/collector/download?${params.toString()}`
    },
    networkInterfaces: () => request('GET',    '/network/interfaces'),
    createIngress:     () => request('POST',   '/collector/ingress'),
    getIngress:        () => request('GET',    '/collector/ingress'),
    deleteIngress:     () => request('DELETE', '/collector/ingress'),
    rbacUrl:           () => `${window.location.origin}${BASE}/collector/ingress/rbac`,
    getRbacYaml:       () => fetch(`${BASE}/collector/ingress/rbac`).then(r => r.text()),
  },
}
