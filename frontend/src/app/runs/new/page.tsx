import RunForm from '@/components/runs/RunForm'

export default function NewRunPage() {
  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold text-foreground">Submit Agent Task</h1>
      <RunForm />
    </div>
  )
}
