import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/table'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const SHELL_RULES = [
  {
    category: 'destructive',
    description: 'Commands that delete or overwrite files/system state',
    examples: ['rm -rf', 'shred', 'truncate', 'dd if=', 'wipefs'],
  },
  {
    category: 'privilege_escalation',
    description: 'Commands that elevate privileges',
    examples: ['sudo', 'su -', 'chmod 777', 'chown root', 'setuid'],
  },
  {
    category: 'remote_execution',
    description: 'Remote shell or code execution',
    examples: ['curl … | bash', 'wget … | sh', 'nc -e', 'python -c exec', 'eval'],
  },
  {
    category: 'backdoor',
    description: 'Persistence mechanisms and backdoor installation',
    examples: ['crontab', '/etc/rc.local', '.bashrc append', 'systemctl enable', 'at now'],
  },
  {
    category: 'crypto_miner',
    description: 'Cryptocurrency mining activity',
    examples: ['xmrig', 'minerd', 'stratum+tcp', 'ethminer', 'nbminer'],
  },
]

const DLP_POLICIES = [
  { type: 'AWS Access Key',    pattern: 'AKIA[0-9A-Z]{16}' },
  { type: 'AWS Secret Key',    pattern: '[A-Za-z0-9/+=]{40}' },
  { type: 'GitHub Token',      pattern: 'ghp_[A-Za-z0-9]{36}' },
  { type: 'OpenAI Key',        pattern: 'sk-[A-Za-z0-9]{48}' },
  { type: 'Stripe Key',        pattern: 'sk_live_[A-Za-z0-9]{24,}' },
  { type: 'Slack Token',       pattern: 'xox[bpas]-[A-Za-z0-9-]+' },
  { type: 'Twilio SID',        pattern: 'AC[0-9a-fA-F]{32}' },
  { type: 'Generic API Key',   pattern: 'api[_-]?key[\\s=:]+[A-Za-z0-9]{20,}' },
  { type: 'Email Address',     pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' },
  { type: 'Phone Number',      pattern: '\\+?[1-9]\\d{9,14}' },
  { type: 'SSN',               pattern: '\\d{3}-\\d{2}-\\d{4}' },
  { type: 'Credit Card',       pattern: '[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}' },
  { type: 'File Path',         pattern: '(/etc/|/var/|/root/|C:\\\\Windows\\\\)\\S+' },
  { type: 'High-Entropy Token','pattern': '[A-Za-z0-9+/=]{40,}' },
  { type: 'JWT',               pattern: 'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+' },
]

const INJECTION_SIGS = [
  { category: 'direct_injection',          weight: 0.9, description: 'Explicit instruction override attempts' },
  { category: 'jailbreak',                 weight: 0.85, description: 'DAN, roleplay, and persona switching prompts' },
  { category: 'safety_bypass',             weight: 0.8, description: 'Attempts to disable or bypass safety filters' },
  { category: 'system_prompt_extraction',  weight: 0.75, description: 'Probing for system prompt contents' },
  { category: 'instruction_override',      weight: 0.7, description: 'Overriding or appending new instructions' },
  { category: 'identity_claim',            weight: 0.6, description: 'False identity claims (I am your developer…)' },
  { category: 'data_exfiltration',         weight: 0.8, description: 'Prompts designed to leak private context' },
  { category: 'social_engineering',        weight: 0.65, description: 'Urgency/authority manipulation patterns' },
]

export default function PoliciesPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Policies</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Active security policies enforced by the runtime security engine.
        </p>
      </div>

      <Tabs defaultValue="shell">
        <TabsList>
          <TabsTrigger value="shell">Shell Rules</TabsTrigger>
          <TabsTrigger value="dlp">DLP Policies</TabsTrigger>
          <TabsTrigger value="injection">Injection Signatures</TabsTrigger>
        </TabsList>

        <TabsContent value="shell">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Shell Command Firewall</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <Thead>
                  <Tr>
                    <Th>Category</Th>
                    <Th>Description</Th>
                    <Th>Example Patterns</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {SHELL_RULES.map((r) => (
                    <Tr key={r.category}>
                      <Td className="font-mono text-xs text-orange-400">{r.category}</Td>
                      <Td className="text-sm text-muted-foreground">{r.description}</Td>
                      <Td className="font-mono text-xs text-muted-foreground">
                        {r.examples.join(', ')}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="dlp">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Data Loss Prevention Patterns</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <Thead>
                  <Tr>
                    <Th>Type</Th>
                    <Th>Regex Pattern</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {DLP_POLICIES.map((p) => (
                    <Tr key={p.type}>
                      <Td className="text-sm font-medium">{p.type}</Td>
                      <Td className="font-mono text-xs text-muted-foreground break-all">{p.pattern}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="injection">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Prompt Injection Signatures</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <Thead>
                  <Tr>
                    <Th>Category</Th>
                    <Th>Weight</Th>
                    <Th>Description</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {INJECTION_SIGS.map((s) => (
                    <Tr key={s.category}>
                      <Td className="font-mono text-xs text-purple-400">{s.category}</Td>
                      <Td className="text-sm text-yellow-400">{s.weight}</Td>
                      <Td className="text-sm text-muted-foreground">{s.description}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <p className="text-xs text-muted-foreground">
        Policy management UI in Phase 17.
      </p>
    </div>
  )
}
