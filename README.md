# AgentShield

**Runtime Security Platform for Autonomous AI Agents**

AgentShield is a security firewall for AI agents. Modern agents can run shell commands, edit files, browse the internet, and call APIs — creating entirely new attack surfaces. AgentShield intercepts every action before it executes, enforces configurable security policies, and gives operators a live security console to watch it all happen in real time.

> Never trust autonomous agents blindly.

---

## What It Does

Every action an agent attempts — shell command, file read, HTTP fetch, output — passes through a dedicated interceptor before execution. The interceptor evaluates it against all active policies and returns `ALLOW` or `BLOCK`. Nothing runs without approval.

**12 security capabilities:**

| Capability | What it catches |
|-----------|----------------|
| **Prompt Injection Detection** | `ignore previous instructions`, jailbreaks, hidden HTML injections, base64-encoded payloads |
| **Tool Firewall** | `rm -rf`, `curl \| bash`, reverse shells, crypto miners, privilege escalation |
| **Data Leakage Prevention** | AWS keys, SSH private keys, GitHub tokens, JWTs, PII — redacted before output |
| **Docker Sandbox Isolation** | Every agent run in an isolated container; seccomp, dropped capabilities, no internet by default |
| **Network Security** | Domain allowlists/blocklists, DNS filtering, egress control |
| **Filesystem Protection** | Blocks reads/writes to `~/.ssh`, `/etc/shadow`, `.env` files |
| **Behavioral Analysis** | Detects runaway loops, excessive retries, shell-heavy patterns, auto-terminates |
| **Hallucination Detection** | Cross-references claimed actions with actual execution — flags fabricated results |
| **Browser Security** | Scans fetched HTML for hidden injections, malicious scripts, phishing signals |
| **AI Runtime Antivirus** | YARA rules scan generated code and downloaded scripts for malware patterns |
| **Threat Intelligence** | Signature library of 100+ known injection patterns, jailbreaks, shell exploits |
| **Adversarial Red Teaming** | Automated self-attack suite — validates every defense is working |

---

## Quick Start

**Requirements:** Docker and Docker Compose only. No Go, Python, or Node.js needed on the host.

```bash
# 1. Clone
git clone https://github.com/prrockzed/AgentShield.git
cd AgentShield

# 2. Configure (minimum: set JWT_SECRET and ADMIN_PASSWORD)
cp .env.example .env
# edit .env — set JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, and your LLM provider

# 3. Start everything with one command
docker compose up --build

# 4. Open the security console
# Navigate to http://localhost:3000 in your browser
```

Log in with the credentials you set in `.env`. Submit an agent task from `/runs/new` and watch security events appear in real time.

**Everything is free.** All dependencies are open-source. LLM options: Ollama (local, fully free) or Groq (cloud, free tier — no credit card required).

---

## Architecture

Five custom services, all containerized, communicating over an internal Docker network:

```
Browser
  │
  │ HTTPS / WSS
  ▼
Frontend (Next.js :3000)
  │
  │ REST + WebSocket
  ▼
API Gateway (Go :8080)  ─── JWT auth, rate limiting, routing
  │                  │
  │ REST             │ subscribe
  ▼                  ▼
Agent Runtime     NATS JetStream ◄── Security Engine publishes events
(Python :8000)        │
  │ every action       │ persist + broadcast
  │ intercepted        ▼
  ▼              PostgreSQL + WebSocket clients
Security Engine
(Python :8001)
  │
  │ container lifecycle
  ▼
Sandbox Manager
(Go :8002)
  │
  ▼
Docker sandbox (isolated per run)
```

**When an agent wants to run a shell command:**
```
Agent → ToolInterceptor → Security Engine → ALLOW/BLOCK
                                               │
                    BLOCKED: event to NATS → DB + live UI
                    ALLOWED: command runs inside isolated Docker container
```

---

## Tech Stack

| Layer | Technology | Cost |
|-------|-----------|------|
| Frontend | Next.js, TypeScript, Tailwind CSS, shadcn/ui | Free |
| API Gateway | Go, Gin | Free |
| Agent Runtime | Python, FastAPI, LangGraph, LiteLLM | Free |
| Security Engine | Python, FastAPI, YARA, BeautifulSoup | Free |
| Sandbox Manager | Go, Docker SDK | Free |
| Database | PostgreSQL 16 | Free |
| Cache | Redis | Free |
| Event Bus | NATS JetStream | Free |
| LLM (local) | Ollama | Free |
| LLM (cloud) | Groq free tier | Free |
| Monitoring | Prometheus, Grafana | Free |

**Total cost to run: $0.**

---

## Service Ports

| Service | URL | Purpose |
|---------|-----|---------|
| Security Console | http://localhost:3000 | Main operator UI |
| API Gateway | http://localhost:8080 | REST API + WebSocket |
| API Docs | http://localhost:8080/api/docs | Auto-generated Swagger |
| Prometheus | http://localhost:9090 | Metrics |
| Grafana | http://localhost:3001 | Live dashboards |
| PostgreSQL | localhost:5432 | Direct DB access (dev) |

---

## Project Status

**Current milestone:** M1 — Core Security Foundation (Phases 0–5)

| Milestone | Phases | Status |
|-----------|--------|--------|
| M1 — Core Security Foundation | 0–5 | Not started |
| M2 — Sandbox & Real-Time Platform | 6–9 | Not started |
| M3 — Advanced Threat Detection | 10–13 | Not started |
| M4 — Full Security Coverage | 14–17 | Not started |
| M5 — Self-Testing & Production | 18–20 | Not started |

---

## Stopping the Project

```bash
# Stop containers (data preserved)
docker compose stop

# Remove containers (data preserved)
docker compose down

# Remove containers + wipe all data
docker compose down -v
```
