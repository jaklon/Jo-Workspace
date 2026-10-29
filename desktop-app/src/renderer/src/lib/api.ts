import { apiErrorDetail } from './errors'
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ||
  (window.location.protocol === 'file:' ? 'http://127.0.0.1:8010' : window.location.origin)
let accessToken = '' // Electron bearer fallback: memory only, never localStorage.
export const apiUrl = (path: string): string => `${API_BASE_URL}${path}`

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const headers = new Headers(options.headers)
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`)
  const response = await fetch(apiUrl(path), { ...options, headers, credentials: 'include' })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const detail = apiErrorDetail(body.detail, response.status)
    if (response.status === 401) window.dispatchEvent(new Event('agent-auth-required'))
    throw new Error(detail)
  }
  return response
}

export async function connect(token: string): Promise<void> {
  const response = await fetch(apiUrl('/api/session'), {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(typeof body.detail === 'string' ? body.detail : 'Token tidak valid.')
  }
  if (window.location.protocol === 'file:') accessToken = token
}

export async function disconnect(): Promise<void> {
  try {
    await apiFetch('/api/session', { method: 'DELETE' })
  } finally {
    accessToken = ''
  }
}

export { consumeStream } from './stream'
