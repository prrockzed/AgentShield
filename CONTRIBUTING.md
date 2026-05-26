# Contributing to AgentShield

Thank you for considering a contribution to AgentShield.

---

## Prerequisites

| Tool | Minimum version |
|------|----------------|
| Go | 1.22+ |
| Python | 3.12+ |
| Node.js | 20+ |
| Docker + Docker Compose | latest stable |

---

## Local Development Setup

### 1. Clone and configure

```bash
git clone https://github.com/prrockzed/AgentShield.git
cd AgentShield
cp .env.example .env
# Edit .env — fill in ADMIN_EMAIL, ADMIN_PASSWORD, JWT_SECRET
```

### 2. Start infrastructure

```bash
docker compose up -d postgres redis nats
# Wait ~5 seconds for postgres to become healthy
```

### 3. Run each service

**Gateway (Go)**
```bash
cd gateway
go run ./cmd/gateway
```

**Security Engine (Python)**
```bash
cd security-engine
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8001 --reload
```

**Runtime (Python)**
```bash
cd runtime
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000 --reload
```

**Frontend (Node.js)**
```bash
cd frontend
npm install
npm run dev
```

### 4. Full stack with Docker (alternative)

```bash
docker compose up --build -d
```

---

## Regenerating Swagger Docs

After modifying gateway handler annotations, regenerate the docs:

```bash
cd gateway
swag init -g cmd/gateway/main.go -o docs
go build ./...
```

---

## Branch Naming

| Prefix | Use for |
|--------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `chore/` | Build, CI, docs, dependency updates |
| `refactor/` | Code changes with no behaviour change |

Examples: `feat/rate-limit-by-ip`, `fix/jwt-refresh-role`, `chore/update-deps`

---

## PR Checklist

Before opening a pull request, ensure:

- [ ] `go build ./...` passes in `gateway/`
- [ ] `docker compose up --build` starts all services without error
- [ ] New endpoints have Swagger annotations and `swag init` has been re-run
- [ ] New DB schema changes have a migration pair (`000NNN_name.up.sql` + `.down.sql`)
- [ ] No secrets, credentials, or TLS certificates committed

---

## Architecture

For a detailed description of service boundaries, data flow, and security design decisions, see [docs/Plan.md](docs/Plan.md).

A high-level overview is in [README.md](README.md).
