'use client'

import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from '@/components/ui/select'
import { useAgents, useModels, useSubmitRun } from '@/hooks/useGateway'
import type { Run } from '@/lib/types'

const schema = z.object({
  agent_type: z.string().min(1, 'Select an agent'),
  model:      z.string().min(1, 'Select a model'),
  task:       z.string().min(10, 'Task must be at least 10 characters'),
})

type FormData = z.infer<typeof schema>

export default function RunForm() {
  const router   = useRouter()
  const { data: agents } = useAgents()
  const { data: models } = useModels()
  const mutation = useSubmitRun()
  const [blockedMsg, setBlockedMsg] = useState<string | null>(null)

  const { register, handleSubmit, setValue, formState: { errors, isSubmitting } } = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { agent_type: '', model: '', task: '' },
  })

  const onSubmit = async (data: FormData) => {
    setBlockedMsg(null)
    const resp = await mutation.mutateAsync(data as Parameters<typeof mutation.mutateAsync>[0])

    if (resp.status === 403) {
      const body = await resp.json()
      if (body.run_id) {
        router.push(`/runs/${body.run_id}`)
      } else {
        setBlockedMsg(body.detail ?? JSON.stringify(body))
      }
      return
    }

    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      setBlockedMsg(body.error ?? 'Submission failed')
      return
    }

    const run: Run = await resp.json()
    router.push(`/runs/${run.id}`)
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      {blockedMsg && (
        <div className="rounded-md border border-red-500 bg-red-950/40 p-4">
          <p className="text-sm font-semibold text-red-400">Blocked by security policy</p>
          <p className="mt-1 text-xs text-red-300 font-mono">{blockedMsg}</p>
        </div>
      )}

      <div className="space-y-1">
        <label className="text-sm font-medium text-foreground">Agent Type</label>
        <Select onValueChange={(v) => setValue('agent_type', v)}>
          <SelectTrigger>
            <SelectValue placeholder="Select agent…" />
          </SelectTrigger>
          <SelectContent>
            {agents?.map((a) => (
              <SelectItem key={a.name} value={a.name}>{a.name}</SelectItem>
            ))}
            {!agents && <SelectItem value="direct_agent">direct_agent</SelectItem>}
          </SelectContent>
        </Select>
        {errors.agent_type && (
          <p className="text-xs text-red-400">{errors.agent_type.message}</p>
        )}
      </div>

      <div className="space-y-1">
        <label className="text-sm font-medium text-foreground">Model</label>
        <Select onValueChange={(v) => setValue('model', v)}>
          <SelectTrigger>
            <SelectValue placeholder="Select model…" />
          </SelectTrigger>
          <SelectContent>
            {models?.map((m) => (
              <SelectItem key={m.name} value={m.name}>{m.name}</SelectItem>
            ))}
            {!models && (
              <SelectItem value="groq/llama-3.3-70b-versatile">groq/llama-3.3-70b-versatile</SelectItem>
            )}
          </SelectContent>
        </Select>
        {errors.model && (
          <p className="text-xs text-red-400">{errors.model.message}</p>
        )}
      </div>

      <div className="space-y-1">
        <label className="text-sm font-medium text-foreground">Task</label>
        <Textarea
          {...register('task')}
          rows={5}
          placeholder="Describe the task for the agent…"
        />
        {errors.task && (
          <p className="text-xs text-red-400">{errors.task.message}</p>
        )}
      </div>

      <Button type="submit" disabled={isSubmitting || mutation.isPending} size="lg" className="w-full">
        {isSubmitting || mutation.isPending ? 'Running…' : 'Submit Task'}
      </Button>
    </form>
  )
}
