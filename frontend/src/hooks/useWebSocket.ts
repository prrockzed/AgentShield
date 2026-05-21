'use client'

import { useEffect, useRef } from 'react'
import { useEventStore } from '@/store/events'
import type { SecurityEvent } from '@/lib/types'

const BASE_WS = (process.env.NEXT_PUBLIC_GATEWAY_URL ?? 'http://localhost:8080')
  .replace(/^http/, 'ws')

const MAX_BACKOFF = 30_000

export function useWebSocket() {
  const addEvent    = useEventStore((s) => s.addEvent)
  const setConnected = useEventStore((s) => s.setConnected)
  const retryDelay  = useRef(1000)
  const timerRef    = useRef<ReturnType<typeof setTimeout> | null>(null)
  const wsRef       = useRef<WebSocket | null>(null)

  useEffect(() => {
    let cancelled = false

    function connect() {
      if (cancelled) return
      const ws = new WebSocket(`${BASE_WS}/ws/events`)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        retryDelay.current = 1000
      }

      ws.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data) as SecurityEvent
          addEvent(evt)
        } catch {
          // ignore malformed frames
        }
      }

      ws.onclose = () => {
        setConnected(false)
        if (!cancelled) {
          timerRef.current = setTimeout(() => {
            retryDelay.current = Math.min(retryDelay.current * 2, MAX_BACKOFF)
            connect()
          }, retryDelay.current)
        }
      }

      ws.onerror = () => ws.close()
    }

    connect()

    return () => {
      cancelled = true
      if (timerRef.current) clearTimeout(timerRef.current)
      wsRef.current?.close()
    }
  }, [addEvent, setConnected])
}
