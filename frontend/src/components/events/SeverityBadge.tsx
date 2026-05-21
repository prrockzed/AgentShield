import { SEVERITY_STYLES } from '@/lib/utils'
import type { Severity } from '@/lib/types'

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${SEVERITY_STYLES[severity]}`}>
      {severity}
    </span>
  )
}
