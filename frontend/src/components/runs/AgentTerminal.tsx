'use client'

import { useEffect, useRef } from 'react'
import { Terminal } from 'xterm'
import { FitAddon } from '@xterm/addon-fit'
import 'xterm/css/xterm.css'

interface Props {
  output: string | null
}

export default function AgentTerminal({ output }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef      = useRef<Terminal | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    let term: Terminal | null = null
    let observer: ResizeObserver | null = null

    // Defer the entire initialisation until after the browser has painted and
    // laid out the container. xterm.js accesses this._renderer.value.dimensions
    // inside term.open(), which throws when the element has zero dimensions at
    // call time (React renders the div, but the layout pass hasn't run yet).
    const rafId = requestAnimationFrame(() => {
      if (!containerRef.current) return

      term = new Terminal({
        theme: {
          background: '#0a0e1a',
          foreground: '#c9d1d9',
          cursor:     '#58a6ff',
        },
        fontFamily: '"Fira Code", "Cascadia Code", monospace',
        fontSize: 13,
        convertEol: true,
        disableStdin: true,
        scrollback: 2000,
      })

      const fit = new FitAddon()
      term.loadAddon(fit)
      term.open(containerRef.current)
      fit.fit()
      termRef.current = term

      if (output) {
        const highlighted = output.replace(
          /\[REDACTED:[^\]]*\]/g,
          (m) => `\x1b[35m${m}\x1b[0m`
        )
        term.write(highlighted)
      } else {
        term.write('\x1b[90mNo output yet…\x1b[0m')
      }

      observer = new ResizeObserver(() => fit.fit())
      observer.observe(containerRef.current!)
    })

    return () => {
      cancelAnimationFrame(rafId)
      observer?.disconnect()
      term?.dispose()
    }
  }, [output])

  return <div ref={containerRef} className="h-64 w-full rounded-md overflow-hidden" />
}
