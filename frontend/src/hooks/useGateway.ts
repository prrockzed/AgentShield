import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchEvents, fetchRuns, fetchRun, fetchAgents, fetchModels, submitRun } from '@/lib/api'
import type { EventsParams } from '@/lib/api'

export function useEvents(params?: EventsParams) {
  return useQuery({
    queryKey: ['events', params],
    queryFn: () => fetchEvents(params),
    refetchInterval: 30_000,
  })
}

export function useRuns() {
  return useQuery({
    queryKey: ['runs'],
    queryFn: fetchRuns,
    refetchInterval: 30_000,
  })
}

export function useRun(id: string) {
  return useQuery({
    queryKey: ['runs', id],
    queryFn: () => fetchRun(id),
    refetchInterval: 30_000,
    enabled: !!id,
  })
}

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: fetchAgents,
    staleTime: Infinity,
  })
}

export function useModels() {
  return useQuery({
    queryKey: ['models'],
    queryFn: fetchModels,
    staleTime: Infinity,
  })
}

export function useSubmitRun() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: submitRun,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['runs'] }),
  })
}
