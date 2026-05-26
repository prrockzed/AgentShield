'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useSecuritySettings, useUpdateSecuritySettings } from '@/hooks/useGateway'
import type { SecuritySettings } from '@/lib/types'

interface ToggleRowProps {
  label: string
  description: string
  checked: boolean
  onChange: (value: boolean) => void
}

function ToggleRow({ label, description, checked, onChange }: ToggleRowProps) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-gray-800 last:border-0">
      <div className="flex-1 min-w-0 pr-4">
        <p className="text-sm font-medium text-gray-200">{label}</p>
        <p className="text-xs text-gray-500 mt-0.5">{description}</p>
      </div>
      <button
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none ${
          checked ? 'bg-blue-600' : 'bg-gray-600'
        }`}
      >
        <span
          className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition duration-200 ${
            checked ? 'translate-x-5' : 'translate-x-0'
          }`}
        />
      </button>
    </div>
  )
}

interface Section {
  title: string
  checks: Array<{
    key: keyof SecuritySettings
    label: string
    description: string
  }>
}

const SECTIONS: Section[] = [
  {
    title: 'Input Security',
    checks: [
      {
        key: 'prompt_scan',
        label: 'Prompt Injection Detection',
        description: 'Blocks jailbreaks, hidden injections, encoded payloads',
      },
    ],
  },
  {
    title: 'Execution Security',
    checks: [
      {
        key: 'tool_intercept',
        label: 'Tool Firewall',
        description: 'Blocks rm -rf, reverse shells, crypto miners',
      },
      {
        key: 'behavioral_alert',
        label: 'Behavioral Analysis',
        description: 'Auto-terminates runaway loops and shell-heavy patterns',
      },
      {
        key: 'code_scan',
        label: 'Antivirus / Code Scan',
        description: 'YARA rules scan generated scripts for malware',
      },
      {
        key: 'network_intercept',
        label: 'Network Request Filtering',
        description: 'Domain allowlists/blocklists, DNS filtering',
      },
      {
        key: 'filesystem_intercept',
        label: 'Filesystem Access Control',
        description: 'Blocks reads/writes to ~/.ssh, /etc/shadow, .env',
      },
      {
        key: 'browser_intercept',
        label: 'Browser Security',
        description: 'Scans fetched HTML for injections and phishing',
      },
    ],
  },
  {
    title: 'Output Security',
    checks: [
      {
        key: 'output_scan',
        label: 'Data Leakage Prevention',
        description: 'Redacts AWS keys, tokens, PII before output',
      },
      {
        key: 'hallucination_detection',
        label: 'Hallucination Detection',
        description: 'Flags fabricated actions vs. actual execution',
      },
    ],
  },
]

export default function SettingsPage() {
  const { data: settings, isLoading } = useSecuritySettings()
  const mutation = useUpdateSecuritySettings()

  function handleToggle(key: keyof SecuritySettings, value: boolean) {
    if (!settings) return
    mutation.mutate({ ...settings, [key]: value })
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Security Settings</h1>
        <p className="text-sm text-gray-400 mt-1">Per-user security check profile</p>
      </div>

      <div className="rounded-md border border-yellow-600/40 bg-yellow-900/20 px-4 py-3 text-sm text-yellow-300">
        Disabled checks are skipped for all future runs. Changes take effect immediately.
      </div>

      {isLoading ? (
        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="p-6 space-y-4">
            {Array.from({ length: 9 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full bg-gray-800" />
            ))}
          </CardContent>
        </Card>
      ) : settings ? (
        SECTIONS.map((section) => (
          <Card key={section.title} className="bg-gray-900 border-gray-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
                {section.title}
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              {section.checks.map((check) => (
                <ToggleRow
                  key={check.key}
                  label={check.label}
                  description={check.description}
                  checked={settings[check.key] as boolean}
                  onChange={(value) => handleToggle(check.key, value)}
                />
              ))}
            </CardContent>
          </Card>
        ))
      ) : (
        <p className="text-gray-500 text-sm">Failed to load settings.</p>
      )}
    </div>
  )
}
