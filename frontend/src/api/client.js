const BASE = '/api/v1'

async function request(method, path, body, options = {}) {
  const url = `${BASE}${path}`
  const res = await fetch(url, {
    method,
    headers: body instanceof FormData ? {} : { 'Content-Type': 'application/json' },
    body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
    ...options,
  })
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
    list: () => request('GET', '/cases'),
    get: (id) => request('GET', `/cases/${id}`),
    create: (data) => request('POST', '/cases', data),
    update: (id, data) => request('PUT', `/cases/${id}`, data),
    delete: (id) => request('DELETE', `/cases/${id}`),
  },

  ingest: {
    upload: (caseId, formData) => request('POST', `/cases/${caseId}/ingest`, formData),
    listJobs: (caseId) => request('GET', `/cases/${caseId}/jobs`),
    getJob: (jobId) => request('GET', `/jobs/${jobId}`),
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
    getEvent: (caseId, foId) => request('GET', `/cases/${caseId}/events/${foId}`),
    tagEvent: (caseId, foId, tags) =>
      request('PUT', `/cases/${caseId}/events/${foId}/tag`, { tags }),
    flagEvent: (caseId, foId) =>
      request('PUT', `/cases/${caseId}/events/${foId}/flag`),
    noteEvent: (caseId, foId, note) =>
      request('PUT', `/cases/${caseId}/events/${foId}/note`, { note }),
  },

  plugins: {
    list: () => request('GET', '/plugins'),
    reload: () => request('POST', '/plugins/reload'),
    upload: (formData) => request('POST', '/plugins/upload', formData),
  },

  health: {
    ready: () => request('GET', '/health/ready'),
  },

  savedSearches: {
    list: (caseId) => request('GET', `/cases/${caseId}/saved-searches`),
    create: (caseId, data) => request('POST', `/cases/${caseId}/saved-searches`, data),
    delete: (caseId, id) => request('DELETE', `/cases/${caseId}/saved-searches/${id}`),
  },

  alertRules: {
    // Per-case rules (legacy)
    list: (caseId) => request('GET', `/cases/${caseId}/alert-rules`),
    create: (caseId, data) => request('POST', `/cases/${caseId}/alert-rules`, data),
    delete: (caseId, id) => request('DELETE', `/cases/${caseId}/alert-rules/${id}`),
    check: (caseId) => request('POST', `/cases/${caseId}/alert-rules/check`),
    // Global library
    listLibrary: () => request('GET', '/alert-rules/library'),
    createLibraryRule: (data) => request('POST', '/alert-rules/library', data),
    updateLibraryRule: (id, data) => request('PUT', `/alert-rules/library/${id}`, data),
    deleteLibraryRule: (id) => request('DELETE', `/alert-rules/library/${id}`),
    // Run global library (all rules) against a specific case
    runLibrary: (caseId) => request('POST', `/cases/${caseId}/alert-rules/run-library`),
    // Run a single rule against a specific case
    runSingleRule: (caseId, ruleId) => request('POST', `/cases/${caseId}/alert-rules/library/${ruleId}/run`),
  },

  export: {
    csv: (caseId, params = {}) => {
      const q = new URLSearchParams(params).toString()
      return `/api/v1/cases/${caseId}/export/csv${q ? '?' + q : ''}`
    },
  },

  modules: {
    list:        ()             => request('GET', '/modules'),
    listSources: (caseId)       => request('GET', `/cases/${caseId}/sources`),
    createRun:   (caseId, data) => request('POST', `/cases/${caseId}/module-runs`, data),
    listRuns:    (caseId)       => request('GET', `/cases/${caseId}/module-runs`),
    getRun:      (runId)        => request('GET', `/module-runs/${runId}`),
  },

  collector: {
    /**
     * Returns the download URL for the configured collector script.
     * Use with an <a href> or trigger via document.createElement('a').
     */
    downloadUrl: ({ platform = 'py', caseId, apiUrl, collect } = {}) => {
      const params = new URLSearchParams({ platform })
      if (caseId)  params.set('case_id',  caseId)
      if (apiUrl)  params.set('api_url',  apiUrl)
      if (collect && collect.length > 0) params.set('collect', collect.join(','))
      return `/api/v1/collector/download?${params.toString()}`
    },
    /** Detect candidate API URLs from server network interfaces. */
    networkInterfaces: () => request('GET', '/network/interfaces'),
    /** Kubernetes LoadBalancer ingress management */
    createIngress:  () => request('POST', '/collector/ingress'),
    getIngress:     () => request('GET',  '/collector/ingress'),
    deleteIngress:  () => request('DELETE', '/collector/ingress'),
  },
}
