import type { SecurityEvent, Run, Agent, Model } from './types'
import { useAuthStore } from '@/store/auth'

const BASE = process.env.NEXT_PUBLIC_GATEWAY_URL ?? 'http://localhost:8080'

function authHeaders(): HeadersInit {
  const token = useAuthStore.getState().accessToken
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
}

async function tryRefresh(): Promise<boolean> {
  const { refreshToken, email, setTokens, clearTokens } = useAuthStore.getState()
  if (!refreshToken) return false
  try {
    const res = await fetch(`${BASE}/api/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!res.ok) { clearTokens(); return false }
    const { access_token, refresh_token } = await res.json()
    setTokens(access_token, refresh_token, email ?? '')
    return true
  } catch { clearTokens(); return false }
}

async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(url, { ...init, headers: authHeaders() })
  if (res.status === 401) {
    if (await tryRefresh()) {
      return fetch(url, { ...init, headers: authHeaders() })
    }
    useAuthStore.getState().clearTokens()
    if (typeof window !== 'undefined') window.location.href = '/login'
  }
  return res
}

export interface EventsParams {
  run_id?: string
  severity?: string
  event_type?: string
  decision?: string
}

export async function fetchEvents(params?: EventsParams): Promise<SecurityEvent[]> {
  const qs = new URLSearchParams()
  if (params?.run_id)    qs.set('run_id', params.run_id)
  if (params?.severity)  qs.set('severity', params.severity)
  const url = `${BASE}/api/events${qs.toString() ? '?' + qs.toString() : ''}`
  const res = await apiFetch(url)
  if (!res.ok) throw new Error('Failed to fetch events')
  return res.json()
}

export async function fetchRuns(): Promise<Run[]> {
  const res = await apiFetch(`${BASE}/api/runs`)
  if (!res.ok) throw new Error('Failed to fetch runs')
  return res.json()
}

export async function fetchRun(id: string): Promise<Run> {
  const res = await apiFetch(`${BASE}/api/runs/${id}`)
  if (!res.ok) throw new Error('Run not found')
  return res.json()
}

export async function fetchAgents(): Promise<Agent[]> {
  const res = await apiFetch(`${BASE}/api/agents`)
  if (!res.ok) throw new Error('Failed to fetch agents')
  return res.json()
}

export async function fetchModels(): Promise<Model[]> {
  const res = await apiFetch(`${BASE}/api/models`)
  if (!res.ok) throw new Error('Failed to fetch models')
  return res.json()
}

export interface SubmitRunBody {
  agent_type: string
  model: string
  task: string
}

// Returns the raw Response so callers can check status (403 = blocked, 201 = success).
export async function submitRun(body: SubmitRunBody): Promise<Response> {
  return apiFetch(`${BASE}/api/runs`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}
