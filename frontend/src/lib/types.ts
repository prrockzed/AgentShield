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
  | 'POLICY_CHANGE'

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

export interface ShellRule {
  id: string
  pattern: string
  reason: string
  category: string
  source: string
  active: boolean
  created_at: string
}

export interface DlpPolicy {
  id: string
  category: string
  pattern: string
  label: string
  action: string
  severity: string
  active: boolean
  source: string
  created_at: string
}

export interface NetworkPolicy {
  id: string
  type: string
  domain: string
  category: string
  reason: string | null
  source: string
  active: boolean
  created_at: string
}

export interface FilesystemPolicy {
  id: string
  path_pattern: string
  operation: string
  decision: string
  severity: string
  category: string
  reason: string | null
  source: string
  active: boolean
  created_at: string
}

export interface ThreatSignature {
  id: string
  category: string
  pattern: string
  pattern_type: string
  severity: string
  description: string | null
  source: string
  version: number
  active: boolean
  created_at: string
  updated_at: string
}

export interface YaraRule {
  id: string
  name: string
  category: string
  rule_text: string
  severity: string
  description: string | null
  active: boolean
  created_at: string
}
