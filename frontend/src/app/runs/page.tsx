'use client'

import Link from 'next/link'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useRuns } from '@/hooks/useGateway'
import { fmtDate, shortID } from '@/lib/utils'

function statusVariant(status: string) {
  if (status === 'completed') return 'default'
  if (status === 'failed')    return 'outline'
  return 'secondary'
}

export default function RunsPage() {
  const { data: runs, isLoading } = useRuns()

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-foreground">Runs</h1>
        <Link href="/runs/new" className="text-sm text-primary hover:underline">
          + New Run
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Agent Run History</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-2">
              {[1,2,3,4,5].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : (
            <Table>
              <Thead>
                <Tr>
                  <Th>ID</Th>
                  <Th>Status</Th>
                  <Th>Agent</Th>
                  <Th>Model</Th>
                  <Th>Task</Th>
                  <Th>Created</Th>
                </Tr>
              </Thead>
              <Tbody>
                {runs?.map((run) => (
                  <Tr key={run.id}>
                    <Td className="font-mono text-xs">
                      <Link href={`/runs/${run.id}`} className="text-primary hover:underline">
                        {shortID(run.id)}
                      </Link>
                    </Td>
                    <Td>
                      <Badge variant={statusVariant(run.status)}>{run.status}</Badge>
                    </Td>
                    <Td className="text-sm">{run.agent_type}</Td>
                    <Td className="text-xs text-muted-foreground">{run.model}</Td>
                    <Td className="text-sm text-muted-foreground max-w-xs truncate">
                      {run.task ? run.task.slice(0, 50) + (run.task.length > 50 ? '…' : '') : '—'}
                    </Td>
                    <Td className="text-xs text-muted-foreground whitespace-nowrap">
                      {fmtDate(run.created_at)}
                    </Td>
                  </Tr>
                ))}
                {(!runs || runs.length === 0) && (
                  <Tr>
                    <Td colSpan={6} className="text-center text-muted-foreground py-8">
                      No runs yet.{' '}
                      <Link href="/runs/new" className="text-primary hover:underline">
                        Submit one.
                      </Link>
                    </Td>
                  </Tr>
                )}
              </Tbody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
