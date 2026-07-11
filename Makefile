# pdns-manager - development helpers.
#
# Dev infrastructure (PostgreSQL + PowerDNS) lives in docker-compose.dev.yml and is
# NOT the default compose file: it is only used through the targets below.

COMPOSE     := docker compose -f docker-compose.dev.yml
GO          := go
PNPM        := pnpm

# PowerDNS API endpoint the local app connects to (the PDNS service publishes 8081
# to the host). These values must match docker/dev/pdns.conf.
PDNS_API_URL ?= http://localhost:8081/api/v1
PDNS_API_KEY ?= dev-secret-key

.DEFAULT_GOAL := help

.PHONY: dev-up dev-down dev-restart dev-logs dev-clean dev-psql dev-run
.PHONY: build run test fmt vet tidy css watch-css help

## Dev infrastructure

dev-up: ## Start PostgreSQL + PowerDNS (detached, waits for healthchecks)
	$(COMPOSE) up -d --wait

dev-down: ## Stop and remove dev containers (keeps data volumes)
	$(COMPOSE) down

dev-restart: ## Restart the dev containers
	$(COMPOSE) restart

dev-logs: ## Tail dev container logs
	$(COMPOSE) logs -f

dev-clean: ## Stop dev containers AND delete their data volumes (fresh databases)
	$(COMPOSE) down -v

dev-psql: ## Open a psql shell in the dev PostgreSQL container (app database)
	$(COMPOSE) exec postgres psql -U postgres -d postgres

dev-run: ## Run the app on the host against the dev infrastructure
	PDNS_API_URL=$(PDNS_API_URL) PDNS_API_KEY=$(PDNS_API_KEY) $(GO) run . start

## Go / frontend helpers

build: ## Build the pdns-manager binary into ./bin
	$(GO) build -o bin/pdns-manager .

run: ## Run the app (no PDNS env)
	$(GO) run . start

test: ## Run tests
	$(GO) test ./...

fmt: ## Format Go code
	$(GO) fmt ./...

vet: ## Run go vet
	$(GO) vet ./...

tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

css: ## Build the CSS once (Tailwind)
	$(PNPM) build:css

watch-css: ## Watch and rebuild CSS on change (Tailwind)
	$(PNPM) watch:css

help: ## Show this help
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
