'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import EventTable from '@/components/events/EventTable'
import LiveEventFeed from '@/components/events/LiveEventFeed'
import { useEventStore } from '@/store/events'
import { useEvents } from '@/hooks/useGateway'
import type { Severity, Decision, EventType } from '@/lib/types'

const SEVERITIES: Severity[]  = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const DECISIONS:  Decision[]  = ['ALLOWED', 'BLOCKED', 'FLAGGED', 'REDACTED']
const EVENT_TYPES: EventType[] = [
  'PROMPT_SCAN', 'TOOL_INTERCEPT', 'OUTPUT_SCAN',
  'NETWORK_INTERCEPT', 'FILESYSTEM_INTERCEPT', 'BEHAVIORAL_ALERT',
  'HALLUCINATION_DETECTION',
  'BROWSER_INTERCEPT',
  'CODE_SCAN',
]

export default function EventsPage() {
  const [severity,   setSeverity]   = useState('')
  const [eventType,  setEventType]  = useState('')
  const [decision,   setDecision]   = useState('')

  const { data: events, isLoading } = useEvents({
    severity:   severity   || undefined,
    event_type: eventType  || undefined,
    decision:   decision   || undefined,
  })

  const liveEvents = useEventStore((s) => s.events)
  const liveFiltered = liveEvents.filter((e) => {
    if (severity   && e.severity   !== severity)   return false
    if (eventType  && e.event_type !== eventType)  return false
    if (decision   && e.decision   !== decision)   return false
    return true
  })

  const combined = [
    ...liveFiltered.filter(
      (le) => !(events ?? []).some((e) => e.id === le.id)
    ),
    ...(events ?? []),
  ]

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-foreground">Events</h1>

      <div className="flex gap-3 flex-wrap">
        <Select onValueChange={(v) => setSeverity(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {SEVERITIES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>

        <Select onValueChange={(v) => setEventType(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-52">
            <SelectValue placeholder="Event type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {EVENT_TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
          </SelectContent>
        </Select>

        <Select onValueChange={(v) => setDecision(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Decision" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All decisions</SelectItem>
            {DECISIONS.map((d) => <SelectItem key={d} value={d}>{d}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Security Events ({combined.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-2">
              {[1,2,3,4,5].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : (
            <EventTable events={combined} showRunLink />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Live Feed</CardTitle>
        </CardHeader>
        <CardContent>
          <LiveEventFeed />
        </CardContent>
      </Card>
    </div>
  )
}
