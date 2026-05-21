'use client'

import { Fragment, useState } from 'react'
import Link from 'next/link'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/table'
import SeverityBadge from './SeverityBadge'
import DecisionBadge from './DecisionBadge'
import { fmtTime, shortID } from '@/lib/utils'
import type { SecurityEvent } from '@/lib/types'

interface Props {
  events: SecurityEvent[]
  showRunLink?: boolean
}

export default function EventTable({ events, showRunLink = false }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null)

  return (
    <Table>
      <Thead>
        <Tr>
          <Th>Time</Th>
          <Th>Event Type</Th>
          <Th>Decision</Th>
          <Th>Severity</Th>
          <Th>Source</Th>
          {showRunLink && <Th>Run ID</Th>}
          <Th>Reason</Th>
        </Tr>
      </Thead>
      <Tbody>
        {events.map((evt) => (
          <Fragment key={evt.id}>
            <Tr
              className="cursor-pointer"
              onClick={() => setExpanded(expanded === evt.id ? null : evt.id)}
            >
              <Td className="font-mono text-xs text-muted-foreground whitespace-nowrap">
                {fmtTime(evt.timestamp)}
              </Td>
              <Td className="text-xs">{evt.event_type}</Td>
              <Td><DecisionBadge decision={evt.decision} /></Td>
              <Td><SeverityBadge severity={evt.severity} /></Td>
              <Td className="text-xs text-muted-foreground">{evt.source}</Td>
              {showRunLink && (
                <Td className="font-mono text-xs">
                  {evt.run_id ? (
                    <Link
                      href={`/runs/${evt.run_id}`}
                      className="text-primary hover:underline"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {shortID(evt.run_id)}
                    </Link>
                  ) : '—'}
                </Td>
              )}
              <Td className="text-xs text-muted-foreground max-w-xs truncate">
                {evt.reason ?? '—'}
              </Td>
            </Tr>
            {expanded === evt.id && evt.payload && (
              <Tr>
                <Td colSpan={showRunLink ? 7 : 6} className="bg-muted/30">
                  <pre className="text-xs text-foreground overflow-auto max-h-48 p-2">
                    {JSON.stringify(evt.payload, null, 2)}
                  </pre>
                </Td>
              </Tr>
            )}
          </Fragment>
        ))}
        {events.length === 0 && (
          <Tr>
            <Td colSpan={showRunLink ? 7 : 6} className="text-center text-muted-foreground text-sm py-8">
              No events
            </Td>
          </Tr>
        )}
      </Tbody>
    </Table>
  )
}
