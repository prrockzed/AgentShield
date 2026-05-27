'use client'

import { useState, useEffect, useMemo } from 'react'
import Link from 'next/link'
import { Search } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import Pagination from '@/components/ui/Pagination'
import { useRuns } from '@/hooks/useGateway'
import { fmtDate, shortID } from '@/lib/utils'

const STATUSES = ['completed', 'blocked', 'failed', 'running']
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

function statusVariant(status: string) {
  if (status === 'completed') return 'default'
  if (status === 'blocked')   return 'destructive'
  if (status === 'failed')    return 'outline'
  return 'secondary'
}

export default function RunsPage() {
  const { data: runs, isLoading } = useRuns()
  const [search,    setSearch]    = useState('')
  const [status,    setStatus]    = useState('')
  const [agent,     setAgent]     = useState('')
  const [model,     setModel]     = useState('')
  const [timeRange, setTimeRange] = useState('')
  const [page, setPage]           = useState(1)
  const [pageSize, setPageSize]   = useState(10)

  useEffect(() => { setPage(1) }, [search, status, agent, model, timeRange])

  const agents = useMemo(() => [...new Set(runs?.map((r) => r.agent_type) ?? [])], [runs])
  const models = useMemo(() => [...new Set(runs?.map((r) => r.model) ?? [])],      [runs])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return (runs ?? []).filter((r) => {
      if (q && !r.id.toLowerCase().includes(q) && !(r.task ?? '').toLowerCase().includes(q)) return false
      if (status    && r.status     !== status)    return false
      if (agent     && r.agent_type !== agent)     return false
      if (model     && r.model      !== model)     return false
      if (!withinTime(r.created_at, timeRange))    return false
      return true
    })
  }, [runs, search, status, agent, model, timeRange])

  const total     = filtered.length
  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-foreground">Runs</h1>
        <Link href="/runs/new" className="text-sm text-primary hover:underline">
          + New Run
        </Link>
      </div>

      <div className="flex gap-3 flex-wrap">
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search ID or task…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 w-56"
          />
        </div>

        <Select onValueChange={(v) => setStatus(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {STATUSES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>

        <Select onValueChange={(v) => setAgent(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Agent" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All agents</SelectItem>
            {agents.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}
          </SelectContent>
        </Select>

        <Select onValueChange={(v) => setModel(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Model" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All models</SelectItem>
            {models.map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}
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
          <CardTitle className="text-base">Agent Run History</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-2">
              {[1,2,3,4,5].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : (
            <>
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
                  {paginated.map((run) => (
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
                  {paginated.length === 0 && (
                    <Tr>
                      <Td colSpan={6} className="text-center text-muted-foreground py-8">
                        {(runs?.length ?? 0) > 0
                          ? 'No runs match the current filters.'
                          : <>No runs yet.{' '}<Link href="/runs/new" className="text-primary hover:underline">Submit one.</Link></>
                        }
                      </Td>
                    </Tr>
                  )}
                </Tbody>
              </Table>
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
    </div>
  )
}
