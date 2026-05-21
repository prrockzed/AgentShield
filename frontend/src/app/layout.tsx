import type { Metadata } from 'next'
import './globals.css'
import Providers from '@/providers'

export const metadata: Metadata = {
  title: 'AgentShield',
  description: 'Secure AI Agent Runtime',
  icons: { icon: '/favicon.svg' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body><Providers>{children}</Providers></body>
    </html>
  )
}
