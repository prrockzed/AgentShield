export type EventType =
  | 'PROMPT_SCAN'
  | 'TOOL_INTERCEPT'
  | 'OUTPUT_SCAN'
  | 'NETWORK_INTERCEPT'
  | 'FILESYSTEM_INTERCEPT'
  | 'BEHAVIORAL_ALERT'
  | 'HALLUCINATION_DETECTION'
  | 'BROWSER_INTERCEPT'
  | 'CODE_SCAN'

export type Decision = 'ALLOWED' | 'BLOCKED' | 'FLAGGED' | 'REDACTED'
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface SecurityEvent {
  id: string
  run_id: string | null
  event_type: EventType
  source: string
  payload: Record<string, unknown> | null
  decision: Decision
  reason: string | null
  severity: Severity
  matched_signature_id: string | null
  timestamp: string
}

export interface Run {
  id: string
  task: string | null
  status: string
  agent_type: string
  model: string
  output: string | null
  steps: unknown[]
  created_at: string
}

export interface Agent {
  name: string
  description: string
  tools: string[]
}

export interface Model {
  name: string
  provider: string
}
