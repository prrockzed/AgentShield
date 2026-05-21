import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import type { Severity, Decision } from './types'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export const SEVERITY_STYLES: Record<Severity, string> = {
  INFO:     'border-gray-500 text-gray-400',
  LOW:      'border-blue-500 text-blue-400',
  MEDIUM:   'border-yellow-500 text-yellow-400',
  HIGH:     'border-orange-500 text-orange-400',
  CRITICAL: 'border-red-500 text-red-400',
}

export const DECISION_STYLES: Record<Decision, string> = {
  ALLOWED:  'border-green-500 text-green-400',
  BLOCKED:  'border-red-500 text-red-400',
  FLAGGED:  'border-yellow-500 text-yellow-400',
  REDACTED: 'border-purple-500 text-purple-400',
}

export function fmtTime(ts: string): string {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function fmtDate(ts: string): string {
  return new Date(ts).toLocaleString([], {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export function shortID(id: string): string {
  return id.slice(0, 8)
}
