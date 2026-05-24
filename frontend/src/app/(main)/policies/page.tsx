'use client'

import { useState } from 'react'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/table'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import {
  useShellRules, useCreateShellRule, useToggleShellRule, useDeleteShellRule,
  useDlpPolicies, useCreateDlpPolicy, useToggleDlpPolicy, useDeleteDlpPolicy,
  useNetworkPolicies, useCreateNetworkPolicy, useToggleNetworkPolicy, useDeleteNetworkPolicy,
  useFilesystemPolicies, useCreateFilesystemPolicy, useToggleFilesystemPolicy, useDeleteFilesystemPolicy,
  useSignatures, useCreateSignature, useToggleSignature, useDeleteSignature,
  useYaraRules, useCreateYaraRule, useToggleYaraRule, useDeleteYaraRule,
} from '@/hooks/useGateway'

// ─── Severity badge helper ───────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const colours: Record<string, string> = {
    CRITICAL: 'bg-red-900/40 text-red-400 border-red-800',
    HIGH:     'bg-orange-900/40 text-orange-400 border-orange-800',
    MEDIUM:   'bg-yellow-900/40 text-yellow-400 border-yellow-800',
    LOW:      'bg-blue-900/40 text-blue-400 border-blue-800',
    INFO:     'bg-gray-800 text-gray-400 border-gray-700',
  }
  return (
    <span className={`inline-block text-xs px-1.5 py-0.5 rounded border ${colours[severity] ?? colours['INFO']}`}>
      {severity}
    </span>
  )
}

// ─── Active toggle button ────────────────────────────────────────────────────

function ToggleBtn({ active, onClick }: { active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="text-lg leading-none focus:outline-none"
      title={active ? 'Disable' : 'Enable'}
    >
      {active
        ? <span className="text-green-400">●</span>
        : <span className="text-muted-foreground">○</span>
      }
    </button>
  )
}

// ─── Loading skeleton rows ───────────────────────────────────────────────────

function SkeletonRows({ cols }: { cols: number }) {
  return (
    <>
      {[1, 2, 3].map((i) => (
        <Tr key={i}>
          {Array.from({ length: cols }).map((_, j) => (
            <Td key={j}><Skeleton className="h-4 w-full" /></Td>
          ))}
        </Tr>
      ))}
    </>
  )
}

// ─── Tab 1: Shell Rules ──────────────────────────────────────────────────────

function ShellRulesTab() {
  const { data: rules = [], isLoading } = useShellRules({ active: 'all' })
  const createMut   = useCreateShellRule()
  const toggleMut   = useToggleShellRule()
  const deleteMut   = useDeleteShellRule()

  const [showForm, setShowForm] = useState(false)
  const [pattern,  setPattern]  = useState('')
  const [reason,   setReason]   = useState('')
  const [category, setCategory] = useState('')

  function handleCreate() {
    if (!pattern || !reason || !category) return
    createMut.mutate({ pattern, reason, category }, {
      onSuccess: () => { setShowForm(false); setPattern(''); setReason(''); setCategory('') },
    })
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">
          Shell Rules
          <span className="ml-2 text-xs font-normal text-muted-foreground">({rules.length})</span>
        </CardTitle>
        <Button size="sm" onClick={() => setShowForm((v) => !v)}>Add Rule</Button>
      </CardHeader>
      {showForm && (
        <div className="px-6 pb-4 flex flex-wrap gap-2 items-end border-b border-border">
          <Input placeholder="Pattern" value={pattern} onChange={(e) => setPattern(e.target.value)} className="w-48" />
          <Input placeholder="Reason" value={reason} onChange={(e) => setReason(e.target.value)} className="w-48" />
          <Input placeholder="Category" value={category} onChange={(e) => setCategory(e.target.value)} className="w-40" />
          <Button size="sm" onClick={handleCreate} disabled={createMut.isPending}>Create</Button>
          <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
        </div>
      )}
      <CardContent className="p-0">
        <Table>
          <Thead>
            <Tr>
              <Th>Pattern</Th>
              <Th>Reason</Th>
              <Th>Category</Th>
              <Th>Source</Th>
              <Th>Active</Th>
              <Th>Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {isLoading ? <SkeletonRows cols={6} /> : rules.length === 0 ? (
              <Tr><Td colSpan={6} className="text-center text-muted-foreground text-sm py-6">No shell rules yet. Add one above.</Td></Tr>
            ) : rules.map((r) => (
              <Tr key={r.id}>
                <Td className="font-mono text-xs text-orange-400">{r.pattern}</Td>
                <Td className="text-sm">{r.reason}</Td>
                <Td className="text-sm">{r.category}</Td>
                <Td className="text-xs text-muted-foreground">{r.source}</Td>
                <Td><ToggleBtn active={r.active} onClick={() => toggleMut.mutate({ id: r.id, active: !r.active })} /></Td>
                <Td>
                  <Button
                    size="sm" variant="ghost"
                    className={`text-red-400 hover:text-red-300 ${r.source !== 'custom' ? 'opacity-30 cursor-not-allowed' : ''}`}
                    disabled={r.source !== 'custom'}
                    onClick={() => deleteMut.mutate(r.id)}
                  >
                    Delete
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ─── Tab 2: DLP Policies ─────────────────────────────────────────────────────

function DlpPoliciesTab() {
  const { data: policies = [], isLoading } = useDlpPolicies({ active: 'all' })
  const createMut = useCreateDlpPolicy()
  const toggleMut = useToggleDlpPolicy()
  const deleteMut = useDeleteDlpPolicy()

  const [showForm, setShowForm] = useState(false)
  const [category, setCategory] = useState('')
  const [pattern,  setPattern]  = useState('')
  const [label,    setLabel]    = useState('')
  const [action,   setAction]   = useState('REDACT')
  const [severity, setSeverity] = useState('HIGH')

  function handleCreate() {
    if (!category || !pattern || !label) return
    createMut.mutate({ category, pattern, label, action, severity }, {
      onSuccess: () => { setShowForm(false); setCategory(''); setPattern(''); setLabel(''); setAction('REDACT'); setSeverity('HIGH') },
    })
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">
          DLP Policies
          <span className="ml-2 text-xs font-normal text-muted-foreground">({policies.length})</span>
        </CardTitle>
        <Button size="sm" onClick={() => setShowForm((v) => !v)}>Add Rule</Button>
      </CardHeader>
      {showForm && (
        <div className="px-6 pb-4 flex flex-wrap gap-2 items-end border-b border-border">
          <Input placeholder="Category" value={category} onChange={(e) => setCategory(e.target.value)} className="w-36" />
          <Input placeholder="Pattern (regex)" value={pattern} onChange={(e) => setPattern(e.target.value)} className="w-48" />
          <Input placeholder="Label" value={label} onChange={(e) => setLabel(e.target.value)} className="w-36" />
          <Select value={action} onValueChange={setAction}>
            <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
            <SelectContent>
              {['REDACT', 'BLOCK', 'FLAG'].map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
            <SelectContent>
              {['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button size="sm" onClick={handleCreate} disabled={createMut.isPending}>Create</Button>
          <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
        </div>
      )}
      <CardContent className="p-0">
        <Table>
          <Thead>
            <Tr>
              <Th>Category</Th>
              <Th>Label</Th>
              <Th>Pattern</Th>
              <Th>Action</Th>
              <Th>Severity</Th>
              <Th>Active</Th>
              <Th>Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {isLoading ? <SkeletonRows cols={7} /> : policies.length === 0 ? (
              <Tr><Td colSpan={7} className="text-center text-muted-foreground text-sm py-6">No DLP policies found.</Td></Tr>
            ) : policies.map((p) => (
              <Tr key={p.id}>
                <Td className="text-sm">{p.category}</Td>
                <Td className="text-sm font-medium">{p.label}</Td>
                <Td className="font-mono text-xs text-muted-foreground max-w-xs truncate">{p.pattern}</Td>
                <Td><Badge variant="outline" className="text-xs">{p.action}</Badge></Td>
                <Td><SeverityBadge severity={p.severity} /></Td>
                <Td><ToggleBtn active={p.active} onClick={() => toggleMut.mutate({ id: p.id, active: !p.active })} /></Td>
                <Td>
                  <Button
                    size="sm" variant="ghost"
                    className={`text-red-400 hover:text-red-300 ${p.source !== 'custom' ? 'opacity-30 cursor-not-allowed' : ''}`}
                    disabled={p.source !== 'custom'}
                    onClick={() => deleteMut.mutate(p.id)}
                  >
                    Delete
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ─── Tab 3: Network Policies ─────────────────────────────────────────────────

function NetworkPoliciesTab() {
  const { data: policies = [], isLoading } = useNetworkPolicies({ active: 'all' })
  const createMut = useCreateNetworkPolicy()
  const toggleMut = useToggleNetworkPolicy()
  const deleteMut = useDeleteNetworkPolicy()

  const [showForm, setShowForm] = useState(false)
  const [domain,   setDomain]   = useState('')
  const [category, setCategory] = useState('')
  const [reason,   setReason]   = useState('')

  function handleCreate() {
    if (!domain || !category) return
    createMut.mutate({ domain, category, reason: reason || undefined }, {
      onSuccess: () => { setShowForm(false); setDomain(''); setCategory(''); setReason('') },
    })
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">
          Network Policies
          <span className="ml-2 text-xs font-normal text-muted-foreground">({policies.length})</span>
        </CardTitle>
        <Button size="sm" onClick={() => setShowForm((v) => !v)}>Add Rule</Button>
      </CardHeader>
      {showForm && (
        <div className="px-6 pb-4 flex flex-wrap gap-2 items-end border-b border-border">
          <Input placeholder="Domain" value={domain} onChange={(e) => setDomain(e.target.value)} className="w-48" />
          <Input placeholder="Category" value={category} onChange={(e) => setCategory(e.target.value)} className="w-36" />
          <Input placeholder="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} className="w-48" />
          <Button size="sm" onClick={handleCreate} disabled={createMut.isPending}>Create</Button>
          <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
        </div>
      )}
      <CardContent className="p-0">
        <Table>
          <Thead>
            <Tr>
              <Th>Type</Th>
              <Th>Domain</Th>
              <Th>Category</Th>
              <Th>Source</Th>
              <Th>Active</Th>
              <Th>Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {isLoading ? <SkeletonRows cols={6} /> : policies.length === 0 ? (
              <Tr><Td colSpan={6} className="text-center text-muted-foreground text-sm py-6">No network policies found.</Td></Tr>
            ) : policies.map((p) => (
              <Tr key={p.id}>
                <Td><Badge variant="outline" className="text-xs">{p.type}</Badge></Td>
                <Td className="font-mono text-xs">{p.domain}</Td>
                <Td className="text-sm">{p.category}</Td>
                <Td className="text-xs text-muted-foreground">{p.source}</Td>
                <Td><ToggleBtn active={p.active} onClick={() => toggleMut.mutate({ id: p.id, active: !p.active })} /></Td>
                <Td>
                  <Button
                    size="sm" variant="ghost"
                    className={`text-red-400 hover:text-red-300 ${p.source !== 'custom' ? 'opacity-30 cursor-not-allowed' : ''}`}
                    disabled={p.source !== 'custom'}
                    onClick={() => deleteMut.mutate(p.id)}
                  >
                    Delete
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ─── Tab 4: Filesystem Policies ──────────────────────────────────────────────

function FilesystemPoliciesTab() {
  const { data: policies = [], isLoading } = useFilesystemPolicies({ active: 'all' })
  const createMut = useCreateFilesystemPolicy()
  const toggleMut = useToggleFilesystemPolicy()
  const deleteMut = useDeleteFilesystemPolicy()

  const [showForm,     setShowForm]     = useState(false)
  const [pathPattern,  setPathPattern]  = useState('')
  const [category,     setCategory]     = useState('')
  const [operation,    setOperation]    = useState('ALL')
  const [decision,     setDecision]     = useState('BLOCKED')

  function handleCreate() {
    if (!pathPattern || !category) return
    createMut.mutate({ path_pattern: pathPattern, category, operation, decision }, {
      onSuccess: () => { setShowForm(false); setPathPattern(''); setCategory(''); setOperation('ALL'); setDecision('BLOCKED') },
    })
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">
          Filesystem Policies
          <span className="ml-2 text-xs font-normal text-muted-foreground">({policies.length})</span>
        </CardTitle>
        <Button size="sm" onClick={() => setShowForm((v) => !v)}>Add Rule</Button>
      </CardHeader>
      {showForm && (
        <div className="px-6 pb-4 flex flex-wrap gap-2 items-end border-b border-border">
          <Input placeholder="Path pattern" value={pathPattern} onChange={(e) => setPathPattern(e.target.value)} className="w-48" />
          <Input placeholder="Category" value={category} onChange={(e) => setCategory(e.target.value)} className="w-36" />
          <Select value={operation} onValueChange={setOperation}>
            <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
            <SelectContent>
              {['ALL', 'READ', 'WRITE', 'EXECUTE', 'DELETE'].map((o) => <SelectItem key={o} value={o}>{o}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={decision} onValueChange={setDecision}>
            <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
            <SelectContent>
              {['BLOCKED', 'ALLOWED', 'FLAGGED'].map((d) => <SelectItem key={d} value={d}>{d}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button size="sm" onClick={handleCreate} disabled={createMut.isPending}>Create</Button>
          <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
        </div>
      )}
      <CardContent className="p-0">
        <Table>
          <Thead>
            <Tr>
              <Th>Path Pattern</Th>
              <Th>Operation</Th>
              <Th>Decision</Th>
              <Th>Severity</Th>
              <Th>Category</Th>
              <Th>Active</Th>
              <Th>Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {isLoading ? <SkeletonRows cols={7} /> : policies.length === 0 ? (
              <Tr><Td colSpan={7} className="text-center text-muted-foreground text-sm py-6">No filesystem policies found.</Td></Tr>
            ) : policies.map((p) => (
              <Tr key={p.id}>
                <Td className="font-mono text-xs">{p.path_pattern}</Td>
                <Td className="text-sm">{p.operation}</Td>
                <Td><Badge variant="outline" className="text-xs">{p.decision}</Badge></Td>
                <Td><SeverityBadge severity={p.severity} /></Td>
                <Td className="text-sm">{p.category}</Td>
                <Td><ToggleBtn active={p.active} onClick={() => toggleMut.mutate({ id: p.id, active: !p.active })} /></Td>
                <Td>
                  <Button
                    size="sm" variant="ghost"
                    className={`text-red-400 hover:text-red-300 ${p.source !== 'custom' ? 'opacity-30 cursor-not-allowed' : ''}`}
                    disabled={p.source !== 'custom'}
                    onClick={() => deleteMut.mutate(p.id)}
                  >
                    Delete
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ─── Tab 5: Threat Signatures ────────────────────────────────────────────────

function ThreatSignaturesTab() {
  const { data, isLoading } = useSignatures({ active: 'all', limit: 200 })
  const signatures = data?.items ?? []
  const createMut  = useCreateSignature()
  const toggleMut  = useToggleSignature()
  const deleteMut  = useDeleteSignature()

  const [showForm,     setShowForm]     = useState(false)
  const [category,     setCategory]     = useState('')
  const [pattern,      setPattern]      = useState('')
  const [patternType,  setPatternType]  = useState('REGEX')
  const [severity,     setSeverity]     = useState('HIGH')
  const [description,  setDescription]  = useState('')

  function handleCreate() {
    if (!category || !pattern) return
    createMut.mutate({ category, pattern, pattern_type: patternType, severity, description: description || undefined }, {
      onSuccess: () => { setShowForm(false); setCategory(''); setPattern(''); setPatternType('REGEX'); setSeverity('HIGH'); setDescription('') },
    })
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">
          Threat Signatures
          <span className="ml-2 text-xs font-normal text-muted-foreground">({data?.total ?? 0})</span>
        </CardTitle>
        <Button size="sm" onClick={() => setShowForm((v) => !v)}>Add Rule</Button>
      </CardHeader>
      {showForm && (
        <div className="px-6 pb-4 flex flex-wrap gap-2 items-end border-b border-border">
          <Input placeholder="Category" value={category} onChange={(e) => setCategory(e.target.value)} className="w-36" />
          <Input placeholder="Pattern" value={pattern} onChange={(e) => setPattern(e.target.value)} className="w-48" />
          <Select value={patternType} onValueChange={setPatternType}>
            <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
            <SelectContent>
              {['REGEX', 'SUBSTRING', 'SEMANTIC'].map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
            <SelectContent>
              {['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
            </SelectContent>
          </Select>
          <Input placeholder="Description (optional)" value={description} onChange={(e) => setDescription(e.target.value)} className="w-48" />
          <Button size="sm" onClick={handleCreate} disabled={createMut.isPending}>Create</Button>
          <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
        </div>
      )}
      <CardContent className="p-0">
        <Table>
          <Thead>
            <Tr>
              <Th>Category</Th>
              <Th>Pattern</Th>
              <Th>Type</Th>
              <Th>Severity</Th>
              <Th>Source</Th>
              <Th>Active</Th>
              <Th>Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {isLoading ? <SkeletonRows cols={7} /> : signatures.length === 0 ? (
              <Tr><Td colSpan={7} className="text-center text-muted-foreground text-sm py-6">No threat signatures found.</Td></Tr>
            ) : signatures.map((s) => (
              <Tr key={s.id}>
                <Td className="text-sm">{s.category}</Td>
                <Td className="font-mono text-xs text-muted-foreground max-w-xs truncate">{s.pattern}</Td>
                <Td className="text-xs">{s.pattern_type}</Td>
                <Td><SeverityBadge severity={s.severity} /></Td>
                <Td className="text-xs text-muted-foreground">{s.source}</Td>
                <Td><ToggleBtn active={s.active} onClick={() => toggleMut.mutate({ id: s.id, active: !s.active })} /></Td>
                <Td>
                  <Button
                    size="sm" variant="ghost"
                    className={`text-red-400 hover:text-red-300 ${s.source !== 'custom' ? 'opacity-30 cursor-not-allowed' : ''}`}
                    disabled={s.source !== 'custom'}
                    onClick={() => deleteMut.mutate(s.id)}
                  >
                    Delete
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ─── Tab 6: YARA Rules ───────────────────────────────────────────────────────

function YaraRulesTab() {
  const { data, isLoading } = useYaraRules({ active: 'all', limit: 200 })
  const yaraRules = data?.items ?? []
  const createMut = useCreateYaraRule()
  const toggleMut = useToggleYaraRule()
  const deleteMut = useDeleteYaraRule()

  const [showForm,    setShowForm]    = useState(false)
  const [name,        setName]        = useState('')
  const [category,    setCategory]    = useState('')
  const [ruleText,    setRuleText]    = useState('')
  const [severity,    setSeverity]    = useState('HIGH')
  const [description, setDescription] = useState('')

  function handleCreate() {
    if (!name || !category || !ruleText) return
    createMut.mutate({ name, category, rule_text: ruleText, severity, description: description || undefined }, {
      onSuccess: () => { setShowForm(false); setName(''); setCategory(''); setRuleText(''); setSeverity('HIGH'); setDescription('') },
    })
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">
          YARA Rules
          <span className="ml-2 text-xs font-normal text-muted-foreground">({data?.total ?? 0})</span>
        </CardTitle>
        <Button size="sm" onClick={() => setShowForm((v) => !v)}>Add Rule</Button>
      </CardHeader>
      {showForm && (
        <div className="px-6 pb-4 space-y-2 border-b border-border">
          <div className="flex flex-wrap gap-2 items-end">
            <Input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} className="w-40" />
            <Input placeholder="Category" value={category} onChange={(e) => setCategory(e.target.value)} className="w-36" />
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
              <SelectContent>
                {['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
              </SelectContent>
            </Select>
            <Input placeholder="Description (optional)" value={description} onChange={(e) => setDescription(e.target.value)} className="w-48" />
          </div>
          <Textarea
            placeholder="YARA rule text"
            value={ruleText}
            onChange={(e) => setRuleText(e.target.value)}
            className="font-mono text-xs h-28"
          />
          <div className="flex gap-2">
            <Button size="sm" onClick={handleCreate} disabled={createMut.isPending}>Create</Button>
            <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
          </div>
        </div>
      )}
      <CardContent className="p-0">
        <Table>
          <Thead>
            <Tr>
              <Th>Name</Th>
              <Th>Category</Th>
              <Th>Severity</Th>
              <Th>Description</Th>
              <Th>Active</Th>
              <Th>Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {isLoading ? <SkeletonRows cols={6} /> : yaraRules.length === 0 ? (
              <Tr><Td colSpan={6} className="text-center text-muted-foreground text-sm py-6">No YARA rules found.</Td></Tr>
            ) : yaraRules.map((y) => (
              <Tr key={y.id}>
                <Td className="font-mono text-xs">{y.name}</Td>
                <Td className="text-sm">{y.category}</Td>
                <Td><SeverityBadge severity={y.severity} /></Td>
                <Td className="text-xs text-muted-foreground max-w-xs truncate">{y.description ?? '—'}</Td>
                <Td><ToggleBtn active={y.active} onClick={() => toggleMut.mutate({ id: y.id, active: !y.active })} /></Td>
                <Td>
                  <Button
                    size="sm" variant="ghost"
                    className="text-red-400 hover:text-red-300"
                    onClick={() => deleteMut.mutate(y.id)}
                  >
                    Delete
                  </Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function PoliciesPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Policies</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage active security policies enforced by the runtime security engine.
        </p>
      </div>

      <Tabs defaultValue="shell">
        <TabsList>
          <TabsTrigger value="shell">Shell Rules</TabsTrigger>
          <TabsTrigger value="dlp">DLP Policies</TabsTrigger>
          <TabsTrigger value="network">Network</TabsTrigger>
          <TabsTrigger value="filesystem">Filesystem</TabsTrigger>
          <TabsTrigger value="signatures">Threat Signatures</TabsTrigger>
          <TabsTrigger value="yara">YARA Rules</TabsTrigger>
        </TabsList>

        <TabsContent value="shell">
          <ShellRulesTab />
        </TabsContent>
        <TabsContent value="dlp">
          <DlpPoliciesTab />
        </TabsContent>
        <TabsContent value="network">
          <NetworkPoliciesTab />
        </TabsContent>
        <TabsContent value="filesystem">
          <FilesystemPoliciesTab />
        </TabsContent>
        <TabsContent value="signatures">
          <ThreatSignaturesTab />
        </TabsContent>
        <TabsContent value="yara">
          <YaraRulesTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}
