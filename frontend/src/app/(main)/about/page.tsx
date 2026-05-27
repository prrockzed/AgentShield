'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Shield, Zap, Lock, Eye, Network, FolderLock, Brain,
  Globe, Code2, Cpu, Database, Activity, Users, Terminal, GitBranch,
} from 'lucide-react'

const checks = [
  {
    icon: Shield,
    name: 'Prompt Injection Detection',
    event: 'PROMPT_SCAN',
    desc: 'Scans every user input before it reaches the agent. Detects jailbreaks, role-play escapes, base64-encoded payloads, many-shot bypasses, and instruction-override attempts. Blocks the run and logs a PROMPT_SCAN event when a threat is found.',
  },
  {
    icon: Terminal,
    name: 'Tool Firewall',
    event: 'TOOL_INTERCEPT',
    desc: 'Intercepts every shell command the agent wants to execute. Blocks destructive patterns (rm -rf, mkfs, dd), reverse shells, crypto miners, privilege-escalation attempts (sudo su, chmod 777 /), and fork bombs before they reach the sandbox.',
  },
  {
    icon: Activity,
    name: 'Behavioral Analysis',
    event: 'BEHAVIORAL_ALERT',
    desc: 'Monitors the sequence of tool calls throughout a run. Detects runaway loops (same tool called excessively), shell-heavy patterns that indicate exfiltration, and anomalous command chains. Auto-terminates the run when the threat score exceeds the threshold.',
  },
  {
    icon: Code2,
    name: 'Antivirus / Code Scan',
    event: 'CODE_SCAN',
    desc: 'Runs 50+ YARA rules against every script the agent generates. Catches embedded malware, web shells, dropper stubs, obfuscated payloads, and known malware family signatures before the code is executed in the sandbox.',
  },
  {
    icon: Network,
    name: 'Network Request Filtering',
    event: 'NETWORK_INTERCEPT',
    desc: 'Evaluates every outbound HTTP/HTTPS request the agent attempts. Enforces domain allow-lists and block-lists, blocks metadata service endpoints (169.254.169.254), private IP ranges, and flagged domains. Fires before the request leaves the sandbox.',
  },
  {
    icon: FolderLock,
    name: 'Filesystem Access Control',
    event: 'FILESYSTEM_INTERCEPT',
    desc: 'Guards sensitive paths inside the sandbox. Blocks reads and writes to ~/.ssh/*, /etc/shadow, /etc/passwd, .env files, and private key locations. Alerts on any attempt to exfiltrate credentials or modify system files.',
  },
  {
    icon: Globe,
    name: 'Browser Security',
    event: 'BROWSER_INTERCEPT',
    desc: 'Scans HTML returned by browser tool calls for malicious content. Detects XSS payloads, prompt-injection hidden in page content, phishing indicators, and JavaScript obfuscation patterns before the content is processed by the agent.',
  },
  {
    icon: Eye,
    name: 'Data Leakage Prevention',
    event: 'OUTPUT_SCAN',
    desc: 'Inspects the agent\'s final output before it is returned to the caller. Redacts AWS access keys, bearer tokens, private SSH keys, credit card numbers, and other PII patterns. Returns the redacted output and logs a FLAGGED or REDACTED event.',
  },
  {
    icon: Brain,
    name: 'Hallucination Detection',
    event: 'HALLUCINATION_DETECTION',
    desc: 'Compares the agent\'s stated actions against the actual tool calls recorded during the run. Flags responses that claim success for operations that never happened or cite non-existent resources. Produces a confidence score per run.',
  },
]

const techStack = [
  { layer: 'Frontend',         tech: 'Next.js 14, React, TypeScript, Tailwind CSS, shadcn/ui, TanStack Query, Zustand' },
  { layer: 'Gateway',          tech: 'Go 1.22, Gin, golang-migrate, zerolog, Prometheus client, JWT (RS256)' },
  { layer: 'Runtime',          tech: 'Python 3.11, FastAPI, LiteLLM, yara-python' },
  { layer: 'Security Engine',  tech: 'Python 3.11, FastAPI, psycopg2, YARA' },
  { layer: 'Sandbox Manager',  tech: 'Python 3.11, FastAPI, Docker SDK' },
  { layer: 'Database',         tech: 'PostgreSQL 15' },
  { layer: 'Message Bus',      tech: 'NATS' },
  { layer: 'Cache',            tech: 'Redis 7' },
  { layer: 'Observability',    tech: 'Prometheus, Grafana' },
  { layer: 'Auth',             tech: 'JWT (access + refresh tokens), RBAC (admin / viewer roles)' },
  { layer: 'TLS',              tech: 'Optional gateway-level TLS; Nginx + Let\'s Encrypt in production' },
]

const agentTypes = [
  { name: 'default',       desc: 'General-purpose ReAct agent. Uses shell, search, and http tools. Good for most tasks.' },
  { name: 'coding_agent',  desc: 'Specialised for code generation and execution. Has access to a Python interpreter inside the sandbox.' },
  { name: 'browser_agent', desc: 'Can fetch and parse web pages. Network and browser interceptors are especially relevant here.' },
]

export default function AboutPage() {
  return (
    <div className="space-y-8 max-w-4xl">
      {/* Hero */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">About AgentShield</h1>
        <p className="mt-2 text-sm text-muted-foreground leading-relaxed">
          AgentShield is an open-source AI agent security platform that intercepts, inspects, and controls
          everything an LLM agent does — before it can cause damage. Every tool call, shell command, network
          request, and generated script is checked against a multi-layer security engine in real time.
          Runs that violate policy are blocked immediately; all security events are logged, streamed live,
          and stored for audit.
        </p>
      </div>

      {/* Security Checks */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Lock className="h-4 w-4" />
            Security Capabilities
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          {checks.map(({ icon: Icon, name, event, desc }) => (
            <div key={event} className="flex gap-3">
              <div className="mt-0.5 flex-shrink-0 h-8 w-8 rounded-md bg-gray-800 flex items-center justify-center">
                <Icon className="h-4 w-4 text-primary" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-foreground">{name}</span>
                  <span className="font-mono text-[10px] text-muted-foreground bg-gray-800 px-1.5 py-0.5 rounded">
                    {event}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{desc}</p>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* How to use */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-4 w-4" />
            How to Use
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm text-muted-foreground">
          <div className="space-y-3">
            <Step n={1} title="Submit a Run">
              Go to <span className="text-foreground font-medium">New Run</span> in the sidebar. Choose an agent
              type (<code className="text-xs bg-gray-800 px-1 rounded">default</code>,{' '}
              <code className="text-xs bg-gray-800 px-1 rounded">coding_agent</code>, or{' '}
              <code className="text-xs bg-gray-800 px-1 rounded">browser_agent</code>), select a model,
              and type a task. Click <span className="text-foreground font-medium">Submit</span>.
            </Step>
            <Step n={2} title="Watch Security Events">
              Switch to the <span className="text-foreground font-medium">Events</span> page. The Live Feed
              at the bottom shows events as they arrive over WebSocket. The table above shows the full
              history with severity, decision, and detail for each check that fired.
            </Step>
            <Step n={3} title="Inspect the Run">
              Click a run ID in the <span className="text-foreground font-medium">Runs</span> page to open
              its detail view. You can see every event the run triggered, the final status
              (completed / blocked / failed), and the task output.
            </Step>
            <Step n={4} title="Tune Security Policies">
              Go to <span className="text-foreground font-medium">Policies</span> to add allow/deny rules
              for tools, domains, and file paths. Rules take effect immediately for subsequent runs.
            </Step>
            <Step n={5} title="Configure Your Security Profile">
              Go to <span className="text-foreground font-medium">Settings</span> to toggle individual
              security checks on or off for your account. Disabled checks are skipped entirely for your
              runs. Changes take effect immediately — no restart required.
            </Step>
            <Step n={6} title="Run Adversarial Tests">
              Use the <span className="text-foreground font-medium">Red Team</span> page to run the
              built-in 26-case adversarial suite. It probes all nine interceptors with known-bad payloads
              and reports a pass rate. A healthy deployment should score ≥ 90%.
            </Step>
          </div>
        </CardContent>
      </Card>

      {/* Agent Types */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Cpu className="h-4 w-4" />
            Agent Types
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {agentTypes.map(({ name, desc }) => (
              <div key={name} className="flex gap-3">
                <code className="text-xs bg-gray-800 px-2 py-1 rounded self-start mt-0.5 whitespace-nowrap text-primary">
                  {name}
                </code>
                <p className="text-xs text-muted-foreground leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Architecture */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <GitBranch className="h-4 w-4" />
            Architecture
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p>
            AgentShield runs as a set of Docker services. Every request flows through a layered pipeline:
          </p>
          <ol className="space-y-1.5 list-none">
            {[
              ['Frontend (Next.js :3000)', 'Provides the dashboard UI and submits run requests to the Gateway.'],
              ['Gateway (Go :8080)', 'Authenticates requests, enforces RBAC, reads the caller\'s security profile, and proxies augmented requests to the Runtime. All security events pass through here to be persisted and broadcast.'],
              ['Runtime (Python :8000)', 'Hosts the LiteLLM-backed agent loop. Calls interceptor stubs before and after every tool invocation. Streams events to the Gateway via NATS.'],
              ['Security Engine (Python :8001)', 'Stateless micro-service that evaluates each interceptor decision (YARA scans, policy look-ups, behavioral scoring, etc.). Called synchronously by the Runtime stubs.'],
              ['Sandbox Manager (Python :8002)', 'Spawns an ephemeral Docker container per run. The agent\'s shell commands execute inside this container, isolated from the host.'],
              ['PostgreSQL :5432', 'Persistent store for users, runs, events, policies, red-team results, and security settings.'],
              ['Redis :6379', 'Token cache and refresh-token revocation list.'],
              ['NATS :4222', 'Message bus that decouples the Runtime from the Gateway for event streaming.'],
            ].map(([svc, desc]) => (
              <li key={svc} className="flex gap-2">
                <span className="font-mono text-[11px] text-foreground bg-gray-800 px-1.5 py-0.5 rounded self-start mt-0.5 whitespace-nowrap">
                  {svc}
                </span>
                <span className="text-xs leading-relaxed">{desc}</span>
              </li>
            ))}
          </ol>
        </CardContent>
      </Card>

      {/* Tech Stack */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Database className="h-4 w-4" />
            Tech Stack
          </CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-xs">
            <tbody>
              {techStack.map(({ layer, tech }) => (
                <tr key={layer} className="border-b border-gray-800 last:border-0">
                  <td className="py-2 pr-4 font-medium text-foreground w-36 align-top">{layer}</td>
                  <td className="py-2 text-muted-foreground leading-relaxed">{tech}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {/* Observability */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Observability
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            The Gateway exposes a <code className="text-xs bg-gray-800 px-1 rounded">/metrics</code> endpoint
            in Prometheus format. A pre-built Grafana dashboard (port 3001) displays request rates,
            error rates, event counts by type, and blocked-run totals.
          </p>
          <p>
            In production, Grafana and Prometheus are kept off the public internet. Access them via an
            SSH tunnel:
          </p>
          <pre className="bg-gray-900 text-gray-300 text-xs rounded p-3 overflow-x-auto">
{`ssh -L 3001:localhost:3001 -L 9090:localhost:9090 ubuntu@<VM_IP>
# Then open http://localhost:3001  (Grafana)
#          http://localhost:9090  (Prometheus)`}
          </pre>
        </CardContent>
      </Card>

      {/* RBAC */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Users className="h-4 w-4" />
            Access Control
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            AgentShield uses JWT-based authentication with two roles:
          </p>
          <ul className="space-y-1 list-disc list-inside">
            <li>
              <span className="text-foreground font-medium">admin</span> — full access: can submit runs,
              manage policies, view all events, and trigger red-team runs.
            </li>
            <li>
              <span className="text-foreground font-medium">viewer</span> — read-only: can view runs and
              events but cannot submit new runs or modify policies.
            </li>
          </ul>
          <p>
            Tokens expire after 15 minutes; refresh tokens last 7 days and are stored in an HTTP-only
            cookie. The refresh-token revocation list is held in Redis.
          </p>
        </CardContent>
      </Card>

      {/* Footer note */}
      <p className="text-xs text-muted-foreground pb-4">
        AgentShield is open source — contributions welcome at{' '}
        <span className="font-mono">github.com/prrockzed/AgentShield</span>.
      </p>
    </div>
  )
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="flex-shrink-0 h-5 w-5 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center font-bold mt-0.5">
        {n}
      </span>
      <div>
        <span className="text-foreground font-medium text-sm">{title} — </span>
        <span className="text-xs leading-relaxed">{children}</span>
      </div>
    </div>
  )
}
