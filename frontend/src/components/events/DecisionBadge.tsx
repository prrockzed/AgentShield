import { DECISION_STYLES } from '@/lib/utils'
import type { Decision } from '@/lib/types'

export default function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${DECISION_STYLES[decision]}`}>
      {decision}
    </span>
  )
}
