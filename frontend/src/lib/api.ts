import type { SecurityEvent, Run, Agent, Model } from './types'

const BASE = process.env.NEXT_PUBLIC_GATEWAY_URL ?? 'http://localhost:8080'

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
  const res = await fetch(url)
  if (!res.ok) throw new Error('Failed to fetch events')
  return res.json()
}

export async function fetchRuns(): Promise<Run[]> {
  const res = await fetch(`${BASE}/api/runs`)
  if (!res.ok) throw new Error('Failed to fetch runs')
  return res.json()
}

export async function fetchRun(id: string): Promise<Run> {
  const res = await fetch(`${BASE}/api/runs/${id}`)
  if (!res.ok) throw new Error('Run not found')
  return res.json()
}

export async function fetchAgents(): Promise<Agent[]> {
  const res = await fetch(`${BASE}/api/agents`)
  if (!res.ok) throw new Error('Failed to fetch agents')
  return res.json()
}

export async function fetchModels(): Promise<Model[]> {
  const res = await fetch(`${BASE}/api/models`)
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
  return fetch(`${BASE}/api/runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
