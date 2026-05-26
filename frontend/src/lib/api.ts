import type {
  SecurityEvent, Run, Agent, Model,
  ShellRule, DlpPolicy, NetworkPolicy, FilesystemPolicy, ThreatSignature, YaraRule,
  RedteamRun, RedteamRunDetail, SecuritySettings,
} from './types'
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
  if (params?.run_id)     qs.set('run_id',     params.run_id)
  if (params?.severity)   qs.set('severity',   params.severity)
  if (params?.event_type) qs.set('event_type', params.event_type)
  if (params?.decision)   qs.set('decision',   params.decision)
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

// ─── Shell Rules ──────────────────────────────────────────────────────────────

export async function fetchShellRules(params?: { category?: string; active?: string }): Promise<ShellRule[]> {
  const qs = new URLSearchParams()
  if (params?.category) qs.set('category', params.category)
  if (params?.active)   qs.set('active', params.active)
  const res = await apiFetch(`${BASE}/api/policies/shell${qs.toString() ? '?' + qs.toString() : ''}`)
  if (!res.ok) throw new Error('Failed to fetch shell rules')
  return res.json()
}

export async function createShellRule(body: { pattern: string; reason: string; category: string }): Promise<ShellRule> {
  const res = await apiFetch(`${BASE}/api/policies/shell`, { method: 'POST', body: JSON.stringify(body) })
  if (!res.ok) throw new Error('Failed to create shell rule')
  return res.json()
}

export async function toggleShellRule(id: string, active: boolean): Promise<ShellRule> {
  const res = await apiFetch(`${BASE}/api/policies/shell/${id}`, { method: 'PATCH', body: JSON.stringify({ active }) })
  if (!res.ok) throw new Error('Failed to toggle shell rule')
  return res.json()
}

export async function deleteShellRule(id: string): Promise<void> {
  const res = await apiFetch(`${BASE}/api/policies/shell/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete shell rule')
}

// ─── DLP Policies ─────────────────────────────────────────────────────────────

export async function fetchDlpPolicies(params?: { category?: string; active?: string }): Promise<DlpPolicy[]> {
  const qs = new URLSearchParams()
  if (params?.category) qs.set('category', params.category)
  if (params?.active)   qs.set('active', params.active)
  const res = await apiFetch(`${BASE}/api/policies/dlp${qs.toString() ? '?' + qs.toString() : ''}`)
  if (!res.ok) throw new Error('Failed to fetch DLP policies')
  return res.json()
}

export async function createDlpPolicy(body: {
  category: string; pattern: string; label: string; action?: string; severity?: string
}): Promise<DlpPolicy> {
  const res = await apiFetch(`${BASE}/api/policies/dlp`, { method: 'POST', body: JSON.stringify(body) })
  if (!res.ok) throw new Error('Failed to create DLP policy')
  return res.json()
}

export async function toggleDlpPolicy(id: string, active: boolean): Promise<DlpPolicy> {
  const res = await apiFetch(`${BASE}/api/policies/dlp/${id}`, { method: 'PATCH', body: JSON.stringify({ active }) })
  if (!res.ok) throw new Error('Failed to toggle DLP policy')
  return res.json()
}

export async function deleteDlpPolicy(id: string): Promise<void> {
  const res = await apiFetch(`${BASE}/api/policies/dlp/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete DLP policy')
}

// ─── Network Policies ─────────────────────────────────────────────────────────

export async function fetchNetworkPolicies(params?: { type?: string; category?: string; active?: string }): Promise<NetworkPolicy[]> {
  const qs = new URLSearchParams()
  if (params?.type)     qs.set('type', params.type)
  if (params?.category) qs.set('category', params.category)
  if (params?.active)   qs.set('active', params.active)
  const res = await apiFetch(`${BASE}/api/policies/network${qs.toString() ? '?' + qs.toString() : ''}`)
  if (!res.ok) throw new Error('Failed to fetch network policies')
  return res.json()
}

export async function createNetworkPolicy(body: { domain: string; category: string; reason?: string }): Promise<NetworkPolicy> {
  const res = await apiFetch(`${BASE}/api/policies/network/allow`, { method: 'POST', body: JSON.stringify(body) })
  if (!res.ok) throw new Error('Failed to create network policy')
  return res.json()
}

export async function toggleNetworkPolicy(id: string, active: boolean): Promise<NetworkPolicy> {
  const res = await apiFetch(`${BASE}/api/policies/network/${id}`, { method: 'PATCH', body: JSON.stringify({ active }) })
  if (!res.ok) throw new Error('Failed to toggle network policy')
  return res.json()
}

export async function deleteNetworkPolicy(id: string): Promise<void> {
  const res = await apiFetch(`${BASE}/api/policies/network/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete network policy')
}

// ─── Filesystem Policies ──────────────────────────────────────────────────────

export async function fetchFilesystemPolicies(params?: { category?: string; active?: string }): Promise<FilesystemPolicy[]> {
  const qs = new URLSearchParams()
  if (params?.category) qs.set('category', params.category)
  if (params?.active)   qs.set('active', params.active)
  const res = await apiFetch(`${BASE}/api/policies/filesystem${qs.toString() ? '?' + qs.toString() : ''}`)
  if (!res.ok) throw new Error('Failed to fetch filesystem policies')
  return res.json()
}

export async function createFilesystemPolicy(body: {
  path_pattern: string; category: string; operation?: string; decision?: string; severity?: string
}): Promise<FilesystemPolicy> {
  const res = await apiFetch(`${BASE}/api/policies/filesystem`, { method: 'POST', body: JSON.stringify(body) })
  if (!res.ok) throw new Error('Failed to create filesystem policy')
  return res.json()
}

export async function toggleFilesystemPolicy(id: string, active: boolean): Promise<FilesystemPolicy> {
  const res = await apiFetch(`${BASE}/api/policies/filesystem/${id}`, { method: 'PATCH', body: JSON.stringify({ active }) })
  if (!res.ok) throw new Error('Failed to toggle filesystem policy')
  return res.json()
}

export async function deleteFilesystemPolicy(id: string): Promise<void> {
  const res = await apiFetch(`${BASE}/api/policies/filesystem/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete filesystem policy')
}

// ─── Threat Signatures ────────────────────────────────────────────────────────

export interface ListSignaturesResponse {
  total: number
  page: number
  page_size: number
  items: ThreatSignature[]
}

export async function fetchSignatures(params?: { category?: string; active?: string; page?: number; limit?: number }): Promise<ListSignaturesResponse> {
  const qs = new URLSearchParams()
  if (params?.category) qs.set('category', params.category)
  if (params?.active)   qs.set('active', params.active)
  if (params?.page)     qs.set('page', String(params.page))
  if (params?.limit)    qs.set('limit', String(params.limit))
  const res = await apiFetch(`${BASE}/api/intelligence/signatures${qs.toString() ? '?' + qs.toString() : ''}`)
  if (!res.ok) throw new Error('Failed to fetch signatures')
  return res.json()
}

export async function createSignature(body: {
  category: string; pattern: string; pattern_type?: string; severity?: string; description?: string
}): Promise<ThreatSignature> {
  const res = await apiFetch(`${BASE}/api/intelligence/signatures`, { method: 'POST', body: JSON.stringify(body) })
  if (!res.ok) throw new Error('Failed to create signature')
  return res.json()
}

export async function toggleSignature(id: string, active: boolean): Promise<ThreatSignature> {
  const res = await apiFetch(`${BASE}/api/intelligence/signatures/${id}`, { method: 'PATCH', body: JSON.stringify({ active }) })
  if (!res.ok) throw new Error('Failed to toggle signature')
  return res.json()
}

export async function deleteSignature(id: string): Promise<void> {
  const res = await apiFetch(`${BASE}/api/intelligence/signatures/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete signature')
}

// ─── YARA Rules ───────────────────────────────────────────────────────────────

export interface ListYaraRulesResponse {
  total: number
  page: number
  page_size: number
  items: YaraRule[]
}

export async function fetchYaraRules(params?: { category?: string; active?: string; page?: number; limit?: number }): Promise<ListYaraRulesResponse> {
  const qs = new URLSearchParams()
  if (params?.category) qs.set('category', params.category)
  if (params?.active)   qs.set('active', params.active)
  if (params?.page)     qs.set('page', String(params.page))
  if (params?.limit)    qs.set('limit', String(params.limit))
  const res = await apiFetch(`${BASE}/api/intelligence/yara-rules${qs.toString() ? '?' + qs.toString() : ''}`)
  if (!res.ok) throw new Error('Failed to fetch YARA rules')
  return res.json()
}

export async function createYaraRule(body: {
  name: string; category: string; rule_text: string; severity?: string; description?: string
}): Promise<YaraRule> {
  const res = await apiFetch(`${BASE}/api/intelligence/yara-rules`, { method: 'POST', body: JSON.stringify(body) })
  if (!res.ok) throw new Error('Failed to create YARA rule')
  return res.json()
}

export async function toggleYaraRule(id: string, active: boolean): Promise<YaraRule> {
  const res = await apiFetch(`${BASE}/api/intelligence/yara-rules/${id}`, { method: 'PATCH', body: JSON.stringify({ active }) })
  if (!res.ok) throw new Error('Failed to toggle YARA rule')
  return res.json()
}

export async function deleteYaraRule(id: string): Promise<void> {
  const res = await apiFetch(`${BASE}/api/intelligence/yara-rules/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete YARA rule')
}

// ─── Security Settings ────────────────────────────────────────────────────────

export async function getSecuritySettings(): Promise<SecuritySettings> {
  const res = await apiFetch(`${BASE}/api/settings/security`)
  if (!res.ok) throw new Error('Failed to load security settings')
  return res.json()
}

export async function updateSecuritySettings(s: Partial<SecuritySettings>): Promise<SecuritySettings> {
  const res = await apiFetch(`${BASE}/api/settings/security`, {
    method: 'PUT',
    body: JSON.stringify(s),
  })
  if (!res.ok) throw new Error('Failed to save security settings')
  return res.json()
}

// ─── Red Team ─────────────────────────────────────────────────────────────────

export async function triggerRedteamRun(): Promise<RedteamRun> {
  const res = await apiFetch(`${BASE}/api/redteam/run`, { method: 'POST' })
  if (!res.ok) throw new Error('Failed to trigger red-team run')
  return res.json()
}

export async function fetchRedteamRuns(): Promise<RedteamRun[]> {
  const res = await apiFetch(`${BASE}/api/redteam/results`)
  if (!res.ok) throw new Error('Failed to fetch red-team runs')
  return res.json()
}

export async function fetchRedteamRun(id: string): Promise<RedteamRunDetail> {
  const res = await apiFetch(`${BASE}/api/redteam/results/${id}`)
  if (!res.ok) throw new Error('Red-team run not found')
  return res.json()
}
