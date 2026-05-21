import { create } from 'zustand'
import type { SecurityEvent } from '@/lib/types'

interface EventStore {
  events: SecurityEvent[]
  connected: boolean
  addEvent: (evt: SecurityEvent) => void
  setConnected: (v: boolean) => void
  clear: () => void
}

export const useEventStore = create<EventStore>((set) => ({
  events: [],
  connected: false,
  addEvent: (evt) =>
    set((s) => ({
      events: [evt, ...s.events].slice(0, 500),
    })),
  setConnected: (v) => set({ connected: v }),
  clear: () => set({ events: [] }),
}))
