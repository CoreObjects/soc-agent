import axios from 'axios'

const TOKEN_KEY = 'soc_token'

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY) || ''
  } catch {
    return ''
  }
}

export function setToken(t) {
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t)
    else localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* localStorage 不可用(如 SSR)→ 忽略 */
  }
}

// 纯拦截器逻辑(便于单测)
export function requestInterceptor(cfg) {
  const t = getToken()
  if (t) cfg.headers = { ...(cfg.headers || {}), Authorization: `Bearer ${t}` }
  return cfg
}

export function makeResponseErrorHandler(onUnauthorized) {
  return (err) => {
    if (err && err.response && err.response.status === 401) {
      setToken('')
      if (onUnauthorized) onUnauthorized()
    }
    return Promise.reject(err)
  }
}

export function attachInterceptors(instance, { onUnauthorized } = {}) {
  instance.interceptors.request.use(requestInterceptor)
  instance.interceptors.response.use((r) => r, makeResponseErrorHandler(onUnauthorized))
  return instance
}

const http = attachInterceptors(axios.create({ baseURL: '/' }), {
  onUnauthorized: () => {
    if (typeof window !== 'undefined') window.location.hash = '#/login'
  },
})

export const api = {
  alerts: (params) => http.get('/api/alerts', { params }).then((r) => r.data),
  alert: (uid) => http.get(`/api/alerts/${encodeURIComponent(uid)}`).then((r) => r.data),
  plans: (status) => http.get('/api/plans', { params: { status } }).then((r) => r.data),
  approve: (id, by) => http.post(`/api/plans/${id}/approve`, { by }).then((r) => r.data),
  reject: (id, reason) => http.post(`/api/plans/${id}/reject`, { reason }).then((r) => r.data),
  execute: (id) => http.post(`/api/plans/${id}/execute`).then((r) => r.data),
  rollback: (id) => http.post(`/api/plans/${id}/rollback`).then((r) => r.data),
  stats: () => http.get('/api/stats').then((r) => r.data),
  experience: (params) => http.get('/api/experience', { params }).then((r) => r.data),
  getMode: () => http.get('/api/config/response-mode').then((r) => r.data),
  setMode: (mode) => http.put('/api/config/response-mode', { mode }).then((r) => r.data),
  chat: (uid, messages) =>
    http.post(`/api/alerts/${encodeURIComponent(uid)}/chat`, { messages }).then((r) => r.data),
}

export default http
