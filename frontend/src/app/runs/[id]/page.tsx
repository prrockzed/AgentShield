'use client'

import dynamic from 'next/dynamic'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import TraceTimeline from '@/components/runs/TraceTimeline'
import EventTable from '@/components/events/EventTable'
import LiveEventFeed from '@/components/events/LiveEventFeed'
import { useRun, useEvents } from '@/hooks/useGateway'
import { fmtDate } from '@/lib/utils'

const AgentTerminal = dynamic(
  () => import('@/components/runs/AgentTerminal'),
  { ssr: false, loading: () => <Skeleton className="h-64 w-full" /> }
)

interface Props {
  params: { id: string }
}

export default function RunDetailPage({ params }: Props) {
  const { data: run,    isLoading: runLoading    } = useRun(params.id)
  const { data: events, isLoading: eventsLoading } = useEvents({ run_id: params.id })

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <h1 className="text-2xl font-bold text-foreground">Run</h1>
        {runLoading ? (
          <Skeleton className="h-6 w-32" />
        ) : run ? (
          <>
            <span className="font-mono text-sm text-muted-foreground">{run.id}</span>
            <Badge variant={run.status === 'completed' ? 'default' : 'secondary'}>
              {run.status}
            </Badge>
            <span className="text-sm text-muted-foreground ml-auto">{fmtDate(run.created_at)}</span>
          </>
        ) : (
          <span className="text-muted-foreground">Not found</span>
        )}
      </div>

      {run?.task && (
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-muted-foreground font-medium mb-1">Task</p>
            <p className="text-sm text-foreground">{run.task}</p>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Trace Timeline</CardTitle>
          </CardHeader>
          <CardContent>
            <TraceTimeline steps={runLoading ? undefined : (run?.steps as unknown[] ?? [])} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Security Events</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {eventsLoading ? (
              <div className="space-y-2">
                {[1,2,3].map((i) => <Skeleton key={i} className="h-8 w-full" />)}
              </div>
            ) : (
              <EventTable events={events ?? []} />
            )}
            <div className="border-t border-border pt-3">
              <p className="text-xs text-muted-foreground mb-2">Live</p>
              <LiveEventFeed filterRunId={params.id} />
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Agent Output</CardTitle>
        </CardHeader>
        <CardContent>
          <AgentTerminal output={run?.output ?? null} />
        </CardContent>
      </Card>
    </div>
  )
}
