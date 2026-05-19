.PHONY: help \
        up up-d down down-v build logs ps \
        infra infra-down \
        install-gateway install-sandbox-manager install-runtime install-security-engine install-frontend \
        run-gateway run-runtime run-security-engine run-sandbox-manager run-frontend

# ── Help ──────────────────────────────────────────────────────────────────────
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2}'

# ── Full stack via Docker ─────────────────────────────────────────────────────
up: ## Build and start all services (foreground, shows all logs)
	docker compose up --build

up-d: ## Build and start all services (background / detached)
	docker compose up --build -d

down: ## Stop and remove containers  (volumes preserved)
	docker compose down

down-v: ## Stop and remove containers + wipe all data volumes
	docker compose down -v

build: ## Rebuild all images without starting containers
	docker compose build

logs: ## Tail logs from all running services
	docker compose logs -f

ps: ## Show status of all containers
	docker compose ps

# ── Rebuild / restart a single service ───────────────────────────────────────
# Usage:  make rebuild svc=gateway
rebuild: ## Rebuild and restart one service  (usage: make rebuild svc=gateway)
	docker compose up --build -d $(svc)

# Usage:  make restart svc=runtime
restart: ## Restart one service without rebuilding  (usage: make restart svc=runtime)
	docker compose restart $(svc)

# ── Infrastructure only (postgres + redis + nats) ─────────────────────────────
infra: ## Start only infrastructure containers (for local app development)
	docker compose up -d postgres redis nats

infra-down: ## Stop infrastructure containers
	docker compose stop postgres redis nats

# ── Install local dependencies ────────────────────────────────────────────────
install-gateway: ## Download Go modules for gateway  [requires: Go 1.22+]
	cd gateway && go mod download

install-sandbox-manager: ## Download Go modules for sandbox-manager  [requires: Go 1.22+]
	cd sandbox-manager && go mod download

install-runtime: ## Install Python deps for runtime  [requires: Python 3.12+, activate venv first]
	cd runtime && pip install -r requirements.txt

install-security-engine: ## Install Python deps for security-engine  [requires: Python 3.12+, activate venv first]
	cd security-engine && pip install -r requirements.txt

install-frontend: ## Install Node.js deps for frontend  [requires: Node.js 20+]
	cd frontend && npm install

# ── Run services locally (infra must be running: make infra) ─────────────────
run-gateway: ## Run gateway locally  [requires: Go 1.22+]
	cd gateway && go run ./cmd/gateway

run-sandbox-manager: ## Run sandbox-manager locally  [requires: Go 1.22+]
	cd sandbox-manager && go run ./cmd/sandbox-manager

run-runtime: ## Run runtime locally with auto-reload  [requires: Python 3.12+]
	cd runtime && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

run-security-engine: ## Run security-engine locally with auto-reload  [requires: Python 3.12+]
	cd security-engine && uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload

run-frontend: ## Run frontend dev server locally  [requires: Node.js 20+]
	cd frontend && npm run dev
