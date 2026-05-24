import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  fetchEvents, fetchRuns, fetchRun, fetchAgents, fetchModels, submitRun,
  fetchShellRules, createShellRule, toggleShellRule, deleteShellRule,
  fetchDlpPolicies, createDlpPolicy, toggleDlpPolicy, deleteDlpPolicy,
  fetchNetworkPolicies, createNetworkPolicy, toggleNetworkPolicy, deleteNetworkPolicy,
  fetchFilesystemPolicies, createFilesystemPolicy, toggleFilesystemPolicy, deleteFilesystemPolicy,
  fetchSignatures, createSignature, toggleSignature, deleteSignature,
  fetchYaraRules, createYaraRule, toggleYaraRule, deleteYaraRule,
} from '@/lib/api'
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

// ─── Shell Rules ──────────────────────────────────────────────────────────────

export function useShellRules(params?: { category?: string; active?: string }) {
  return useQuery({
    queryKey: ['shellRules', params],
    queryFn: () => fetchShellRules(params),
    refetchInterval: 30_000,
  })
}

export function useCreateShellRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: createShellRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['shellRules'] }),
  })
}

export function useToggleShellRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => toggleShellRule(id, active),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['shellRules'] }),
  })
}

export function useDeleteShellRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: deleteShellRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['shellRules'] }),
  })
}

// ─── DLP Policies ─────────────────────────────────────────────────────────────

export function useDlpPolicies(params?: { category?: string; active?: string }) {
  return useQuery({
    queryKey: ['dlpPolicies', params],
    queryFn: () => fetchDlpPolicies(params),
    refetchInterval: 30_000,
  })
}

export function useCreateDlpPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: createDlpPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dlpPolicies'] }),
  })
}

export function useToggleDlpPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => toggleDlpPolicy(id, active),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dlpPolicies'] }),
  })
}

export function useDeleteDlpPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: deleteDlpPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dlpPolicies'] }),
  })
}

// ─── Network Policies ─────────────────────────────────────────────────────────

export function useNetworkPolicies(params?: { type?: string; category?: string; active?: string }) {
  return useQuery({
    queryKey: ['networkPolicies', params],
    queryFn: () => fetchNetworkPolicies(params),
    refetchInterval: 30_000,
  })
}

export function useCreateNetworkPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: createNetworkPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['networkPolicies'] }),
  })
}

export function useToggleNetworkPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => toggleNetworkPolicy(id, active),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['networkPolicies'] }),
  })
}

export function useDeleteNetworkPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: deleteNetworkPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['networkPolicies'] }),
  })
}

// ─── Filesystem Policies ──────────────────────────────────────────────────────

export function useFilesystemPolicies(params?: { category?: string; active?: string }) {
  return useQuery({
    queryKey: ['filesystemPolicies', params],
    queryFn: () => fetchFilesystemPolicies(params),
    refetchInterval: 30_000,
  })
}

export function useCreateFilesystemPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: createFilesystemPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['filesystemPolicies'] }),
  })
}

export function useToggleFilesystemPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => toggleFilesystemPolicy(id, active),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['filesystemPolicies'] }),
  })
}

export function useDeleteFilesystemPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: deleteFilesystemPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['filesystemPolicies'] }),
  })
}

// ─── Threat Signatures ────────────────────────────────────────────────────────

export function useSignatures(params?: { category?: string; active?: string; limit?: number }) {
  return useQuery({
    queryKey: ['signatures', params],
    queryFn: () => fetchSignatures(params),
    refetchInterval: 30_000,
  })
}

export function useCreateSignature() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: createSignature,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['signatures'] }),
  })
}

export function useToggleSignature() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => toggleSignature(id, active),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['signatures'] }),
  })
}

export function useDeleteSignature() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: deleteSignature,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['signatures'] }),
  })
}

// ─── YARA Rules ───────────────────────────────────────────────────────────────

export function useYaraRules(params?: { category?: string; active?: string; limit?: number }) {
  return useQuery({
    queryKey: ['yaraRules', params],
    queryFn: () => fetchYaraRules(params),
    refetchInterval: 30_000,
  })
}

export function useCreateYaraRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: createYaraRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yaraRules'] }),
  })
}

export function useToggleYaraRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => toggleYaraRule(id, active),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yaraRules'] }),
  })
}

export function useDeleteYaraRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: deleteYaraRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yaraRules'] }),
  })
}
