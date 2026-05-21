'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { LayoutDashboard, Plus, List, Radio, Shield } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/store/events'

const nav = [
  { href: '/',           label: 'Dashboard',  icon: LayoutDashboard },
  { href: '/runs/new',   label: 'New Run',     icon: Plus },
  { href: '/runs',       label: 'Runs',        icon: List },
  { href: '/events',     label: 'Events',      icon: Radio },
  { href: '/policies',   label: 'Policies',    icon: Shield },
]

export default function Sidebar() {
  const pathname   = usePathname()
  const connected  = useEventStore((s) => s.connected)

  return (
    <aside className="w-56 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col h-screen">
      <div className="px-4 py-5 border-b border-gray-800">
        <span className="text-lg font-bold text-white tracking-tight">AgentShield</span>
      </div>

      <nav className="flex-1 px-2 py-4 space-y-1">
        {nav.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || (href !== '/' && pathname.startsWith(href))
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                active
                  ? 'bg-gray-800 text-white'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </Link>
          )
        })}
      </nav>

      <div className="px-4 py-4 border-t border-gray-800 flex items-center gap-2">
        <span
          className={cn(
            'h-2 w-2 rounded-full',
            connected ? 'bg-green-500' : 'bg-gray-600'
          )}
        />
        <span className="text-xs text-gray-400">
          {connected ? 'Live' : 'Disconnected'}
        </span>
      </div>
    </aside>
  )
}
