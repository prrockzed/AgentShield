'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import EventTable from '@/components/events/EventTable'
import LiveEventFeed from '@/components/events/LiveEventFeed'
import { useEvents, useRuns } from '@/hooks/useGateway'
import { Radio, ShieldX, AlertTriangle, Play } from 'lucide-react'

export default function DashboardPage() {
  const { data: events, isLoading: eventsLoading } = useEvents()
  const { data: runs,   isLoading: runsLoading   } = useRuns()

  const totalEvents = events?.length ?? 0
  const blocked     = events?.filter((e) => e.decision === 'BLOCKED').length ?? 0
  const critical    = events?.filter((e) => e.severity === 'CRITICAL').length ?? 0
  const totalRuns   = runs?.length ?? 0
  const last10      = events?.slice(0, 10) ?? []

  const stats = [
    { label: 'Total Events', value: totalEvents, icon: Radio,         color: 'text-blue-400'   },
    { label: 'Blocked',      value: blocked,     icon: ShieldX,       color: 'text-red-400'    },
    { label: 'Critical',     value: critical,    icon: AlertTriangle, color: 'text-orange-400' },
    { label: 'Runs',         value: totalRuns,   icon: Play,          color: 'text-green-400'  },
  ]

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {stats.map(({ label, value, icon: Icon, color }) => (
          <Card key={label}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
                <Icon className={`h-4 w-4 ${color}`} />
              </div>
            </CardHeader>
            <CardContent>
              {eventsLoading || runsLoading ? (
                <Skeleton className="h-8 w-16" />
              ) : (
                <span className="text-3xl font-bold text-foreground">{value}</span>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent Security Events</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {eventsLoading ? (
              <div className="p-4 space-y-2">
                {[1,2,3].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
            ) : (
              <EventTable events={last10} showRunLink />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Live Event Feed</CardTitle>
          </CardHeader>
          <CardContent>
            <LiveEventFeed />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
