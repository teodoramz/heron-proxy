GO      ?= go
COMPOSE ?= docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env

.PHONY: help build test test-all lint fmt vet web up down logs migrate clean

help: ## Show the available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build both binaries into bin/
	$(GO) build -trimpath -o bin/proxy ./cmd/proxy
	$(GO) build -trimpath -o bin/api ./cmd/api

test: ## Run the unit tests that need no databases
	$(GO) test ./...

# -p 1 is required: the database-backed suites share one Postgres and one
# ClickHouse, and each resets its own tables. Running them in parallel would
# have them truncate each other's fixtures.
test-all: ## Run every test, including those needing Postgres and ClickHouse
	POSTGRES_TEST_DSN=$${POSTGRES_TEST_DSN:-postgres://postgres:test@127.0.0.1:55432/proxywaf?sslmode=disable} \
	CLICKHOUSE_TEST_DSN=$${CLICKHOUSE_TEST_DSN:-clickhouse://default:test@127.0.0.1:59000/proxywaf} \
	$(GO) test -p 1 -timeout 20m ./... ./test/...

fmt: ## Format the Go sources
	gofmt -w cmd internal test

vet: ## Run go vet
	$(GO) vet ./...

lint: fmt vet ## Format and vet

web: ## Build the frontend
	cd web && npm ci && npm run build

up: ## Start the compose stack
	$(COMPOSE) up -d --build

down: ## Stop the compose stack
	$(COMPOSE) down

logs: ## Follow the stack logs
	$(COMPOSE) logs -f

clean: ## Remove build output
	rm -rf bin web/dist
