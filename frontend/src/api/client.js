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
  },

  health: {
    ready: () => request('GET', '/health/ready'),
  },
}
