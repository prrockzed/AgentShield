import { ShieldX, ShieldCheck } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'

interface Step {
  type?: string
  status?: string
  tool?: string
  input?: unknown
  output?: unknown
  blocked?: boolean
  [key: string]: unknown
}

interface Props {
  // undefined = run not yet loaded (show skeletons)
  // []        = run loaded, agent made no tool calls
  // [...]     = render timeline entries
  steps: unknown[] | undefined
}

export default function TraceTimeline({ steps }: Props) {
  if (steps === undefined) {
    return (
      <div className="space-y-3">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    )
  }

  if (steps.length === 0) {
    return (
      <p className="text-sm text-muted-foreground py-4 text-center">
        No tool calls — agent answered directly without using tools.
      </p>
    )
  }

  return (
    <div className="relative space-y-4">
      <div className="absolute left-4 top-0 bottom-0 w-px bg-border" />
      {(steps as Step[]).map((step, idx) => {
        const isBlocked = step.blocked || step.status === 'BLOCKED'
        return (
          <div key={idx} className="relative pl-10">
            <div
              className={`absolute left-2.5 top-3 h-3 w-3 rounded-full border-2 ${
                isBlocked
                  ? 'border-red-500 bg-red-950'
                  : 'border-green-500 bg-green-950'
              }`}
            />
            <div
              className={`rounded-md border p-3 text-sm ${
                isBlocked
                  ? 'border-red-800 bg-red-950/30'
                  : 'border-green-800 bg-green-950/30'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                {isBlocked ? (
                  <ShieldX className="h-4 w-4 text-red-400" />
                ) : (
                  <ShieldCheck className="h-4 w-4 text-green-400" />
                )}
                <span className="font-medium text-foreground">
                  {step.type ?? step.tool ?? `Step ${idx + 1}`}
                </span>
                {step.status && (
                  <span className={`text-xs ml-auto ${isBlocked ? 'text-red-400' : 'text-green-400'}`}>
                    {step.status}
                  </span>
                )}
              </div>
              {step.input !== undefined && (
                <pre className="mt-1 text-xs text-muted-foreground overflow-auto max-h-24">
                  {typeof step.input === 'string' ? step.input : JSON.stringify(step.input, null, 2)}
                </pre>
              )}
              {step.output !== undefined && (
                <pre className="mt-1 text-xs text-muted-foreground overflow-auto max-h-24">
                  {typeof step.output === 'string' ? step.output : JSON.stringify(step.output, null, 2)}
                </pre>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
