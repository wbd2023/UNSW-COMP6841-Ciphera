SHELL := /usr/bin/env bash
GO ?= go

GOOS := $(shell $(GO) env GOOS)
ifeq ($(GOOS),windows)
	$(error This Makefile targets Linux/macOS. On Windows, use WSL or Git-Bash, or use the instructions in the README)
endif

BIN_DIR := bin
CIPHERA := $(BIN_DIR)/ciphera
RELAY   := $(BIN_DIR)/relay
PKGS    := ./...

HAVE_PKILL := $(shell command -v pkill >/dev/null 2>&1 && echo yes || echo no)
HAVE_VENDOR := $(shell [ -d vendor ] && echo yes || echo no)
MODFLAG := $(if $(filter yes,$(HAVE_VENDOR)),-mod=vendor,)

.PHONY: all build clean fmt vet lint tidy test-go test-bash relay run-relay stop-relay print-platform

all: build

print-platform:
	@echo "GOOS=$(GOOS)"

build: ## Build ciphera and relay
	@mkdir -p "$(BIN_DIR)"
	$(GO) build $(MODFLAG) -o "$(CIPHERA)" ./cmd/ciphera
	$(GO) build $(MODFLAG) -o "$(RELAY)"   ./cmd/relay

clean: ## Remove build artefacts
	rm -rf "$(BIN_DIR)"

fmt: ## go fmt
	$(GO) fmt $(PKGS)

vet: ## go vet
	$(GO) vet $(PKGS)

lint: ## golangci‑lint (optional)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Run make install-lint"; \
	fi

install-lint: ## Install golangci‑lint
	@curl -sSfL https://raw.githubusercontent.com/golangci-lint/golangci-lint/master/install.sh | \
		sh -s -- -b "$$(go env GOPATH)/bin" v1.58.0

tidy: ## go mod tidy
	$(GO) mod tidy

test-go: ## Run Go unit tests
	$(GO) test ./...

test-bash: build ## Run Bash integration scripts
	set -e; \
	for f in ./scripts/tests/*.sh; do \
		echo ""; \
		echo "---------- Running $$f ----------"; \
		bash "$$f"; \
		echo "--------------------------------------------------"; \
	done

run-relay: build ## Start relay in background
	@if [ "$(HAVE_PKILL)" = "yes" ]; then \
		pkill -f "$(RELAY)" >/dev/null 2>&1 || true; \
	else \
		pgrep -f "$(RELAY)" 2>/dev/null | xargs -r kill || true; \
	fi
	@"$(RELAY)" > /tmp/ciphera-relay.log 2>&1 & \
	 echo $$! > /tmp/ciphera-relay.pid; \
	 echo "Relay started (pid $$(cat /tmp/ciphera-relay.pid)) at http://127.0.0.1:8080"

stop-relay:
	@if [ -f /tmp/ciphera-relay.pid ]; then \
		kill "$$(cat /tmp/ciphera-relay.pid)" >/dev/null 2>&1 || true; \
		rm /tmp/ciphera-relay.pid; \
		echo "Relay stopped"; \
	else \
		echo "No relay running"; \
	fi
