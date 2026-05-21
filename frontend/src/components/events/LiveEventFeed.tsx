'use client'

import { useEventStore } from '@/store/events'
import SeverityBadge from './SeverityBadge'
import DecisionBadge from './DecisionBadge'
import { fmtTime } from '@/lib/utils'

interface Props {
  filterRunId?: string
}

export default function LiveEventFeed({ filterRunId }: Props) {
  const events = useEventStore((s) => s.events)
  const visible = filterRunId
    ? events.filter((e) => e.run_id === filterRunId)
    : events

  const recent = visible.slice(0, 20)

  return (
    <div className="space-y-1 overflow-y-auto max-h-80">
      {recent.length === 0 && (
        <p className="text-sm text-muted-foreground text-center py-6">
          Waiting for live events…
        </p>
      )}
      {recent.map((evt) => (
        <div
          key={evt.id}
          className="flex items-center gap-2 rounded px-2 py-1.5 text-xs animate-in fade-in duration-200 hover:bg-muted/40"
        >
          <span className="font-mono text-muted-foreground whitespace-nowrap">
            {fmtTime(evt.timestamp)}
          </span>
          <SeverityBadge severity={evt.severity} />
          <DecisionBadge decision={evt.decision} />
          <span className="text-foreground truncate flex-1">{evt.event_type}</span>
          <span className="text-muted-foreground truncate max-w-[200px]">
            {evt.reason ?? evt.source}
          </span>
        </div>
      ))}
    </div>
  )
}
