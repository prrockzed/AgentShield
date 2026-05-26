'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useRedteamRuns, useRedteamRun, useTriggerRedteamRun } from '@/hooks/useGateway'
import type { RedteamRun } from '@/lib/types'

function PassRateBadge({ rate }: { rate: number }) {
  const pct = Math.round(rate * 100)
  if (pct >= 90) return <Badge className="bg-green-700 text-green-100">{pct}%</Badge>
  if (pct >= 70) return <Badge className="bg-yellow-700 text-yellow-100">{pct}%</Badge>
  return <Badge variant="destructive">{pct}%</Badge>
}

function RunRow({ run, selected, onClick }: { run: RedteamRun; selected: boolean; onClick: () => void }) {
  return (
    <tr
      className={`border-b border-gray-800 cursor-pointer hover:bg-gray-800/50 transition-colors ${selected ? 'bg-gray-800' : ''}`}
      onClick={onClick}
    >
      <td className="px-4 py-2 font-mono text-xs text-gray-400">{run.id.slice(0, 8)}…</td>
      <td className="px-4 py-2 text-xs text-gray-400">{new Date(run.created_at).toLocaleString()}</td>
      <td className="px-4 py-2 text-xs text-gray-300">{run.total}</td>
      <td className="px-4 py-2 text-xs text-green-400 font-medium">{run.passed}</td>
      <td className="px-4 py-2 text-xs text-red-400 font-medium">{run.failed}</td>
      <td className="px-4 py-2"><PassRateBadge rate={run.pass_rate} /></td>
    </tr>
  )
}

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 flex flex-col gap-1">
      <span className="text-xs text-gray-400">{label}</span>
      <span className={`text-2xl font-bold ${color}`}>{value}</span>
    </div>
  )
}

function RunDetail({ runId }: { runId: string }) {
  const { data: run, isLoading } = useRedteamRun(runId)
  const [expandedRow, setExpandedRow] = useState<string | null>(null)

  if (isLoading) return <Skeleton className="h-40 w-full" />
  if (!run) return null

  return (
    <Card className="bg-gray-900 border-gray-800">
      <CardHeader>
        <CardTitle className="text-sm text-gray-300">
          Run <span className="font-mono text-gray-400">{run.id.slice(0, 8)}…</span> detail
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-4 gap-3">
          <StatCard label="Total"     value={run.total}                         color="text-white" />
          <StatCard label="Passed"    value={run.passed}                        color="text-green-400" />
          <StatCard label="Failed"    value={run.failed}                        color="text-red-400" />
          <StatCard label="Pass Rate" value={`${Math.round(run.pass_rate * 100)}%`} color="text-blue-400" />
        </div>

        <div className="overflow-x-auto rounded border border-gray-800">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-800/60">
                <th className="px-4 py-2 text-left text-xs text-gray-400"></th>
                <th className="px-4 py-2 text-left text-xs text-gray-400">Result</th>
                <th className="px-4 py-2 text-left text-xs text-gray-400">Category</th>
                <th className="px-4 py-2 text-left text-xs text-gray-400">Description</th>
                <th className="px-4 py-2 text-left text-xs text-gray-400">Expected</th>
                <th className="px-4 py-2 text-left text-xs text-gray-400">Actual</th>
                <th className="px-4 py-2 text-right text-xs text-gray-400">ms</th>
              </tr>
            </thead>
            <tbody>
              {run.results.map((r) => {
                const isExpanded = expandedRow === r.case_id
                return (
                  <>
                    <tr
                      key={r.case_id}
                      className="border-b border-gray-800 cursor-pointer hover:bg-gray-800/40"
                      onClick={() => setExpandedRow(isExpanded ? null : r.case_id)}
                    >
                      <td className="px-4 py-2 text-gray-500 text-xs">{isExpanded ? '▼' : '▶'}</td>
                      <td className="px-4 py-2">
                        {r.passed
                          ? <Badge className="bg-green-900 text-green-300">PASS</Badge>
                          : <Badge variant="destructive">FAIL</Badge>
                        }
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-400 font-mono">{r.category}</td>
                      <td className="px-4 py-2 text-xs text-gray-300 max-w-xs truncate">{r.description}</td>
                      <td className="px-4 py-2 text-xs text-gray-400 font-mono">{r.expected.join(' | ')}</td>
                      <td className="px-4 py-2 text-xs font-mono font-medium"
                        style={{ color: r.passed ? '#86efac' : '#f87171' }}>
                        {r.actual || (r.error ? 'ERROR' : '—')}
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-500 text-right">{r.duration_ms.toFixed(1)}</td>
                    </tr>
                    {isExpanded && (
                      <tr key={`${r.case_id}-detail`} className="bg-gray-950">
                        <td colSpan={7} className="px-6 py-3">
                          {r.error && (
                            <p className="text-xs text-red-400 mb-2">Error: {r.error}</p>
                          )}
                          <pre className="text-xs text-gray-400 bg-gray-900 rounded p-3 overflow-x-auto">
                            {JSON.stringify(r.actual_response, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}

export default function RedteamPage() {
  const { data: runs, isLoading } = useRedteamRuns()
  const trigger = useTriggerRedteamRun()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Red Team Suite</h1>
        <Button
          onClick={() => trigger.mutate(undefined, { onSuccess: (run) => setSelectedId(run.id) })}
          disabled={trigger.isPending}
          className="bg-red-700 hover:bg-red-600 text-white"
        >
          {trigger.isPending ? 'Running…' : 'Run Red Team Suite'}
        </Button>
      </div>

      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-sm text-gray-300">
            Past Runs ({runs?.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-2">
              {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
            </div>
          ) : !runs?.length ? (
            <p className="px-4 py-6 text-sm text-gray-500">No runs yet. Click "Run Red Team Suite" to start.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 bg-gray-800/60">
                    <th className="px-4 py-2 text-left text-xs text-gray-400">Run ID</th>
                    <th className="px-4 py-2 text-left text-xs text-gray-400">Date</th>
                    <th className="px-4 py-2 text-left text-xs text-gray-400">Total</th>
                    <th className="px-4 py-2 text-left text-xs text-gray-400">Passed</th>
                    <th className="px-4 py-2 text-left text-xs text-gray-400">Failed</th>
                    <th className="px-4 py-2 text-left text-xs text-gray-400">Pass Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run) => (
                    <RunRow
                      key={run.id}
                      run={run}
                      selected={run.id === selectedId}
                      onClick={() => setSelectedId(run.id === selectedId ? null : run.id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {selectedId && <RunDetail runId={selectedId} />}
    </div>
  )
}
