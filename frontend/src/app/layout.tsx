import type { Metadata } from 'next'
import './globals.css'
import Providers from '@/providers'
import Sidebar from '@/components/layout/Sidebar'
import WebSocketInit from '@/components/layout/WebSocketInit'

export const metadata: Metadata = {
  title: 'AgentShield',
  description: 'Secure AI Agent Runtime',
  icons: { icon: '/favicon.svg' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <Providers>
          <WebSocketInit />
          <div className="flex h-screen">
            <Sidebar />
            <main className="flex-1 overflow-auto p-6">
              {children}
            </main>
          </div>
        </Providers>
      </body>
    </html>
  )
}
