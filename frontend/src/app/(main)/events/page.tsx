'use client'

import { useState, useEffect, useMemo } from 'react'
import { Search } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import EventTable from '@/components/events/EventTable'
import LiveEventFeed from '@/components/events/LiveEventFeed'
import Pagination from '@/components/ui/Pagination'
import { useEventStore } from '@/store/events'
import { useEvents } from '@/hooks/useGateway'
import type { Severity, Decision, EventType } from '@/lib/types'

const SEVERITIES: Severity[]   = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const DECISIONS:  Decision[]   = ['ALLOWED', 'BLOCKED', 'FLAGGED', 'REDACTED']
const EVENT_TYPES: EventType[] = [
  'PROMPT_SCAN', 'TOOL_INTERCEPT', 'OUTPUT_SCAN',
  'NETWORK_INTERCEPT', 'FILESYSTEM_INTERCEPT', 'BEHAVIORAL_ALERT',
  'HALLUCINATION_DETECTION', 'BROWSER_INTERCEPT', 'CODE_SCAN',
  'POLICY_CHANGE', 'RED_TEAM_RUN',
]
const TIME_RANGES = [
  { value: '1h',  label: 'Last hour' },
  { value: '24h', label: 'Last 24h' },
  { value: '7d',  label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

function withinTime(dateStr: string, range: string): boolean {
  if (!range) return true
  const ms = ({ '1h': 3_600_000, '24h': 86_400_000, '7d': 604_800_000, '30d': 2_592_000_000 } as Record<string, number>)[range]
  return ms ? (Date.now() - new Date(dateStr).getTime()) <= ms : true
}

export default function EventsPage() {
  // Server-side filters (sent to API)
  const [severity,  setSeverity]  = useState('')
  const [eventType, setEventType] = useState('')
  const [decision,  setDecision]  = useState('')
  // Client-side filters (applied after fetch)
  const [runIdSearch, setRunIdSearch] = useState('')
  const [timeRange,   setTimeRange]   = useState('')

  const [page, setPage]           = useState(1)
  const [pageSize, setPageSize]   = useState(10)

  useEffect(() => { setPage(1) }, [severity, eventType, decision, runIdSearch, timeRange])

  const { data: events, isLoading } = useEvents({
    severity:   severity   || undefined,
    event_type: eventType  || undefined,
    decision:   decision   || undefined,
  })

  const liveEvents = useEventStore((s) => s.events)
  const liveFiltered = liveEvents.filter((e) => {
    if (severity  && e.severity   !== severity)  return false
    if (eventType && e.event_type !== eventType) return false
    if (decision  && e.decision   !== decision)  return false
    return true
  })

  const combined = [
    ...liveFiltered.filter(
      (le) => !(events ?? []).some((e) => e.id === le.id)
    ),
    ...(events ?? []),
  ]

  const filtered = useMemo(() => {
    const q = runIdSearch.toLowerCase()
    return combined.filter((e) => {
      if (q && !(e.run_id ?? '').toLowerCase().includes(q)) return false
      if (!withinTime(e.timestamp, timeRange)) return false
      return true
    })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [combined.length, runIdSearch, timeRange])

  const total     = filtered.length
  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize)

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-foreground">Events</h1>

      <div className="flex gap-3 flex-wrap">
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search run ID…"
            value={runIdSearch}
            onChange={(e) => setRunIdSearch(e.target.value)}
            className="pl-8 w-44"
          />
        </div>

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

        <Select onValueChange={(v) => setTimeRange(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Time range" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All time</SelectItem>
            {TIME_RANGES.map(({ value, label }) => (
              <SelectItem key={value} value={value}>{label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Security Events ({total})</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-2">
              {[1,2,3,4,5].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : (
            <>
              <EventTable events={paginated} showRunLink />
              <Pagination
                total={total}
                page={page}
                pageSize={pageSize}
                onPageChange={setPage}
                onPageSizeChange={(s) => { setPageSize(s); setPage(1) }}
              />
            </>
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
