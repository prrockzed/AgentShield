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

# 2. Configure — create .env from the template
cp .env.example .env
```

Now open `.env` in any editor and fill in the three required values:

```bash
# Generate a secure JWT secret (copy the output into .env)
openssl rand -hex 32

# Set these three in .env:
JWT_SECRET=<paste the openssl output here>
ADMIN_EMAIL=you@example.com
ADMIN_PASSWORD=choose-a-strong-password
```

```bash
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

| Port | Service | URL | Notes |
|------|---------|-----|-------|
| 3000 | Frontend | http://localhost:3000 | Operator security console (Next.js) |
| 8080 | Gateway | http://localhost:8080 | REST API (`/api/*`) + WebSocket (`/ws/events`) |
| 8000 | Runtime | http://localhost:8000 | Agent execution — `/execute`, `/agents`, `/models` |
| 8001 | Security Engine | http://localhost:8001 | Interceptors — `/intercept/prompt`, `/intercept/tool`, `/intercept/output`, `/intercept/network` |
| 8002 | Sandbox Manager | http://localhost:8002 | Container lifecycle — `/sandbox/*` |
| 4222 | NATS | nats://localhost:4222 | JetStream event bus (TCP) |
| 8222 | NATS monitoring | http://localhost:8222 | NATS HTTP monitoring UI |
| 5432 | PostgreSQL | localhost:5432 | Direct DB access (dev) |
| 6379 | Redis | localhost:6379 | Cache (dev) |
| 9090 | Prometheus | http://localhost:9090 | Metrics query UI (Phase 19) |
| 3001 | Grafana | http://localhost:3001 | Live dashboards (Phase 19) |

---

## Project Status

**Current milestone:** M3 — Advanced Threat Detection (Phases 10–13) — **In progress (3/4)**

| Milestone | Phases | Status |
|-----------|--------|--------|
| M1 — Core Security Foundation | 0–5 | **Complete** |
| M2 — Sandbox & Real-Time Platform | 6–9 | **Complete** |
| M3 — Advanced Threat Detection | 10–13 | In progress — Phases 10–12 complete |
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

---

## Running Locally (without Docker for app services)

You can run any app service directly on your machine while Docker handles infrastructure
(PostgreSQL, Redis, NATS). This removes the image-rebuild cycle and is the fastest inner
loop when actively working on a specific service.

**Prerequisites**

| Service | What you need |
|---------|--------------|
| gateway | Go 1.22+ |
| sandbox-manager | Go 1.25+ |
| runtime, security-engine | Python 3.12+, pip |
| frontend | Node.js 20+, npm |

**Step 1 — Start only infrastructure**

```bash
make infra
# equivalent: docker compose up -d postgres redis nats
```

PostgreSQL is exposed on `localhost:5432`. App services default to `localhost` when
`POSTGRES_HOST` is not set, so no extra env config is needed.

**Step 2 — Install local dependencies**

```bash
make install-gateway           # go mod download
make install-sandbox-manager   # go mod download
make install-frontend          # npm install

# For Python services, use a virtual environment to keep deps isolated:
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
make install-runtime           # pip install -r requirements.txt
make install-security-engine   # pip install -r requirements.txt
```

Activate the venv in every terminal where you run a Python service.

**Step 3 — Source `.env` into your shell**

```bash
set -a && source .env && set +a
```

**Step 4 — Run services, each in its own terminal**

```bash
make run-gateway           # Go     → http://localhost:8080
make run-runtime           # Python → http://localhost:8000  (auto-reloads on save)
make run-security-engine   # Python → http://localhost:8001  (auto-reloads on save)
make run-sandbox-manager   # Go     → http://localhost:8002
make run-frontend          # Next.js → http://localhost:3000 (auto-reloads on save)
```

Python and Next.js watch the filesystem and reload automatically. Go services do not —
re-run the `make run-*` command after editing Go source.

---

## Updating a Single Service (Docker workflow)

When the full stack is running via `docker compose up --build`, you never need to stop
everything to update one service. Open a **second terminal** and run:

```bash
# Rebuild the image and restart just that service
docker compose up --build -d gateway

# Restart without rebuilding (e.g. only an env var changed, no code change)
docker compose restart runtime

# Makefile shorthands for the same operations
make rebuild svc=gateway
make restart svc=runtime

# Follow logs of a specific service
docker compose logs -f gateway
```
